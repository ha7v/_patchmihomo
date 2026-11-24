#!/usr/bin/env python3
"""Offline kernel preflight checker for droid_lkm (read-only, run with `sudo python3`).

Auto-extracts symbol and struct layout contracts directly from repository sources
(ds_ksym.h, direct *_sym() sites, ds_ti.c, vendor/*.c, native/shim.c, hook install
sites) and checks them against the live target device:
  1. /proc/kallsyms  (core kernel symbols & __ksymtab_* exports, ignoring LKM shims)
  2. /sys/kernel/btf/vmlinux  (pure-Python BTF v1 parser: offsets, sizes, widths)
  3. /proc/config.gz (critical GKI / hardening / CFI / BTI / BTF / MODVERSIONS flags)
  4. Optional baseline save & OTA diff (--save-baseline / --diff-baseline)
  5. Optional built .ko ELF preflight (--ko path/to/droid_lkm.ko)
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Pure-Python Linux BTF v1 Parser (/sys/kernel/btf/vmlinux)
# ---------------------------------------------------------------------------

BTF_MAGIC = 0xEB9F

BTF_KIND_UNKN = 0
BTF_KIND_INT = 1
BTF_KIND_PTR = 2
BTF_KIND_ARRAY = 3
BTF_KIND_STRUCT = 4
BTF_KIND_UNION = 5
BTF_KIND_ENUM = 6
BTF_KIND_FWD = 7
BTF_KIND_TYPEDEF = 8
BTF_KIND_VOLATILE = 9
BTF_KIND_CONST = 10
BTF_KIND_RESTRICT = 11
BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13
BTF_KIND_VAR = 14
BTF_KIND_DATASEC = 15
BTF_KIND_FLOAT = 16
BTF_KIND_DECL_TAG = 17
BTF_KIND_TYPE_TAG = 18
BTF_KIND_ENUM64 = 19


class BtfParser:
    def __init__(self, data: bytes) -> None:
        if len(data) < 24:
            raise ValueError(f"BTF data too short ({len(data)} bytes)")
        magic, version, flags, hdr_len = struct.unpack_from("<HBBI", data, 0)
        if magic != BTF_MAGIC:
            raise ValueError(f"invalid BTF magic 0x{magic:x}")
        if version != 1:
            raise ValueError(f"unsupported BTF version {version}")
        if hdr_len < 24 or hdr_len > len(data):
            raise ValueError(f"invalid BTF hdr_len {hdr_len}")
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, 8)
        type_start = hdr_len + type_off
        type_end = type_start + type_len
        str_start = hdr_len + str_off
        str_end = str_start + str_len
        if type_end > len(data) or str_end > len(data):
            raise ValueError(
                f"BTF section bounds exceed file size (types={type_end}, strs={str_end}, len={len(data)})"
            )
        self.data = data
        self.str_start = str_start
        self.str_end = str_end
        self.types: List[Optional[Dict[str, Any]]] = [None]  # 1-indexed
        self.structs_by_name: Dict[str, List[int]] = {}
        self._parse_types(type_start, type_end)

    def get_str(self, off: int) -> str:
        if off == 0:
            return ""
        pos = self.str_start + off
        if pos >= self.str_end:
            return ""
        end = self.data.find(b"\x00", pos, self.str_end)
        if end < 0:
            end = self.str_end
        return self.data[pos:end].decode("utf-8", errors="replace")

    def _parse_types(self, off: int, end: int) -> None:
        tid = 1
        data = self.data
        while off < end:
            if off + 12 > end:
                raise ValueError(f"truncated BTF type header at offset {off}")
            name_off, info, size_or_type = struct.unpack_from("<III", data, off)
            off += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            name = self.get_str(name_off)
            entry: Dict[str, Any] = {
                "id": tid,
                "name": name,
                "kind": kind,
                "vlen": vlen,
                "kflag": kflag,
                "size_or_type": size_or_type,
            }
            if kind == BTF_KIND_INT:
                off += 4
            elif kind == BTF_KIND_ARRAY:
                elem_type, idx_type, nelems = struct.unpack_from("<III", data, off)
                entry["elem_type"] = elem_type
                entry["nelems"] = nelems
                off += 12
            elif kind in (BTF_KIND_STRUCT, BTF_KIND_UNION):
                members = []
                for _ in range(vlen):
                    m_name_off, m_type, m_off = struct.unpack_from("<III", data, off)
                    off += 12
                    if kflag:
                        bit_off = m_off & 0xFFFFFF
                        bit_sz = (m_off >> 24) & 0xFF
                    else:
                        bit_off = m_off
                        bit_sz = 0
                    members.append((self.get_str(m_name_off), m_type, bit_off, bit_sz))
                entry["members"] = members
                if kind == BTF_KIND_STRUCT and name:
                    self.structs_by_name.setdefault(name, []).append(tid)
            elif kind == BTF_KIND_ENUM:
                off += vlen * 8
            elif kind == BTF_KIND_FUNC_PROTO:
                off += vlen * 8
            elif kind == BTF_KIND_VAR:
                off += 4
            elif kind == BTF_KIND_DATASEC:
                off += vlen * 12
            elif kind == BTF_KIND_DECL_TAG:
                off += 4
            elif kind == BTF_KIND_ENUM64:
                off += vlen * 12
            elif kind > BTF_KIND_ENUM64:
                raise ValueError(f"unsupported BTF kind {kind} at type id {tid}")
            if off > end:
                raise ValueError(f"BTF type {tid} (kind={kind}) overflows type section")
            self.types.append(entry)
            tid += 1

    def follow_type(self, tid: int) -> Optional[Dict[str, Any]]:
        seen = 0
        while 0 < tid < len(self.types) and seen < 32:
            t = self.types[tid]
            if not t:
                return None
            if t["kind"] in (
                BTF_KIND_TYPEDEF,
                BTF_KIND_VOLATILE,
                BTF_KIND_CONST,
                BTF_KIND_RESTRICT,
                BTF_KIND_TYPE_TAG,
            ):
                tid = t["size_or_type"]
                seen += 1
                continue
            return t
        return None

    def type_size(self, tid: int) -> Optional[int]:
        t = self.follow_type(tid)
        if not t:
            return None
        k = t["kind"]
        if k in (
            BTF_KIND_INT,
            BTF_KIND_STRUCT,
            BTF_KIND_UNION,
            BTF_KIND_ENUM,
            BTF_KIND_FLOAT,
            BTF_KIND_ENUM64,
        ):
            return int(t["size_or_type"])
        if k == BTF_KIND_PTR:
            return 8
        if k == BTF_KIND_ARRAY:
            es = self.type_size(t["elem_type"])
            return None if es is None else es * int(t["nelems"])
        return None

    def find_struct_id(self, name: str) -> Optional[int]:
        ids = self.structs_by_name.get(name)
        if not ids:
            return None
        for tid in ids:
            t = self.types[tid]
            if t and t["size_or_type"] > 0:
                return tid
        return ids[0]

    def find_member(self, struct_tid: int, member: str, base_bit: int = 0) -> Optional[Tuple[int, int, int]]:
        """Return (bit_off, bit_sz, member_type_id), recursing anonymous structs/unions."""
        t = self.types[struct_tid]
        if not t or t["kind"] not in (BTF_KIND_STRUCT, BTF_KIND_UNION):
            return None
        for m_name, m_type, m_bit_off, m_bit_sz in t["members"]:
            if m_name == member:
                return (base_bit + m_bit_off, m_bit_sz, m_type)
            if m_name == "":
                sub = self.follow_type(m_type)
                if sub and sub["kind"] in (BTF_KIND_STRUCT, BTF_KIND_UNION):
                    hit = self.find_member(sub["id"], member, base_bit + m_bit_off)
                    if hit is not None:
                        return hit
        return None


# ---------------------------------------------------------------------------
# Source-code contract extractors
# ---------------------------------------------------------------------------

def strip_c_comments(text: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)


def extract_ksym_contracts() -> Dict[str, List[str]]:
    ksym_h = strip_c_comments((ROOT / "src/main/core/ds_ksym.h").read_text(encoding="utf-8", errors="replace"))
    ksym_c = strip_c_comments((ROOT / "src/main/core/ds_ksym.c").read_text(encoding="utf-8", errors="replace"))
    vendor_c = strip_c_comments((ROOT / "src/compat/vendor/vendor_syms.c").read_text(encoding="utf-8", errors="replace"))
    native_c = strip_c_comments((ROOT / "src/native/shim.c").read_text(encoding="utf-8", errors="replace"))

    main_syms: List[str] = []
    for m in re.finditer(r'\bX\(\s*[A-Za-z0-9_]+\s*,\s*"([^"]+)"\s*\)', ksym_h):
        if m.group(1) not in main_syms:
            main_syms.append(m.group(1))
    for extra in ("sysctl_overcommit_memory", "tasklist_lock", "ipcns_operations"):
        if extra not in main_syms and f'"{extra}"' in ksym_c:
            main_syms.append(extra)

    required_main = [
        "proc_alloc_inum",
        "proc_free_inum",
        "disable_pid_allocation",
        "group_send_sig_info",
        "kernel_wait4",
    ]
    text_patch_syms = ["_text", "_end", "kimage_voffset", "vmalloc_to_pfn", "__set_fixmap"]

    # Vendor symbol table
    vendor_syms = re.findall(r'\{\s*"([^"]+)"\s*,\s*\(void \*\*\)&dlc_vendor_syms', vendor_c)

    # Native PID symbols
    native_syms = sorted(set(re.findall(r'droid_lkm_sym\(\s*"([^"]+)"\s*\)', native_c)))

    # Hook targets across active src/ (excluding src/misc/ and src/hook/)
    hook_targets: List[str] = []
    hook_pat = re.compile(
        r'\b(?:ds_hook_install(?:_guard|_text|_kprobe|_critical|_slot|_slot_critical)?|'
        r'hk_redir_install)\s*\([^;]*?"([A-Za-z0-9_]+)"\s*,\s*"[A-Za-z0-9_]+"',
        re.S,
    )
    direct_sym_pat = re.compile(
        r'\b(?:droid_lkm_sym|ds_compat_sym|ds_anchor_sym)\s*\(\s*"([A-Za-z0-9_]+)"'
    )
    direct_main: List[str] = []
    main_set = set(main_syms)

    for p in sorted((ROOT / "src").rglob("*.c")):
        rp = str(p.relative_to(ROOT))
        if rp.startswith("src/misc/") or rp.startswith("src/hook/") or rp.startswith("src/native/"):
            continue
        txt = strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in hook_pat.finditer(txt):
            s = m.group(1)
            if s not in hook_targets:
                hook_targets.append(s)
        if not rp.startswith("src/compat/vendor/") and rp != "src/main/core/main.c":
            for m in direct_sym_pat.finditer(txt):
                s = m.group(1)
                if s not in main_set and s not in direct_main:
                    direct_main.append(s)

    return {
        "required_main": required_main,
        "text_patch": text_patch_syms,
        "hook_targets": hook_targets,
        "direct_main": direct_main,
        "vendor": vendor_syms,
        "native": native_syms,
        "main_all": main_syms,
    }


def extract_layout_contracts() -> Tuple[
    List[Tuple[str, str, bool]],
    List[str],
    List[Tuple[str, str]],
    List[str],
]:
    """Return (main_fields, main_types, vendor_fields, vendor_types)."""
    ti_raw = strip_c_comments((ROOT / "src/main/core/ds_ti.c").read_text(encoding="utf-8", errors="replace"))
    ti_lines: List[str] = []
    skip_cont = False
    for ln in ti_raw.splitlines():
        if skip_cont:
            skip_cont = ln.rstrip().endswith("\\")
            continue
        if ln.lstrip().startswith("#define"):
            skip_cont = ln.rstrip().endswith("\\")
            continue
        ti_lines.append(ln)
    ti_c = "\n".join(ti_lines)

    req_pairs: Set[Tuple[str, str]] = set()
    req_block = re.search(r"req\[\]\s*=\s*\{(.*?)\};", ti_c, re.S)
    if req_block:
        for m in re.finditer(r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\}', req_block.group(1)):
            req_pairs.add((m.group(1), m.group(2)))

    fields: List[Tuple[str, str, bool]] = []
    seen_f: Set[Tuple[str, str]] = set()
    for m in re.finditer(
        r"DROID_LKM_FIELD(?:_SYSV|_MQ|_ARR|_SYSV_ARR)?\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)",
        ti_c,
    ):
        pair = (m.group(1), m.group(2))
        if pair not in seen_f:
            seen_f.add(pair)
            fields.append((pair[0], pair[1], pair in req_pairs))

    types: List[str] = []
    for m in re.finditer(r"DROID_LKM_TYPE\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)\s*\)", ti_c):
        if m.group(1) not in types:
            types.append(m.group(1))

    # Vendor layout contracts (ghost.c, ddl_hit.c, etc.)
    vendor_fields: List[Tuple[str, str]] = []
    seen_vf: Set[Tuple[str, str]] = set()
    vendor_types: List[str] = []
    vendor_dir = ROOT / "src/compat/vendor"
    if vendor_dir.exists():
        for vp in sorted(vendor_dir.glob("*.c")):
            vtxt = strip_c_comments(vp.read_text(encoding="utf-8", errors="replace"))
            for m in re.finditer(
                r'\.type\s*=\s*"([A-Za-z0-9_]+)"\s*,\s*\.member\s*=\s*"([A-Za-z0-9_]+)"',
                vtxt,
            ):
                pair = (m.group(1), m.group(2))
                if pair not in seen_vf:
                    seen_vf.add(pair)
                    vendor_fields.append(pair)
            for m in re.finditer(
                r"ds_compat_type\s+[A-Za-z0-9_]+\[\]\s*=\s*\{(.*?)\};",
                vtxt,
                re.S,
            ):
                for tm in re.finditer(r'\.name\s*=\s*"([A-Za-z0-9_]+)"', m.group(1)):
                    if tm.group(1) not in vendor_types:
                        vendor_types.append(tm.group(1))

    return fields, types, vendor_fields, vendor_types


# ---------------------------------------------------------------------------
# Live kernel inspection (read-only)
# ---------------------------------------------------------------------------

def load_kallsyms() -> Tuple[
    Dict[str, List[Tuple[str, str]]],
    Dict[str, List[str]],
    Set[str],
    Dict[str, List[str]],
    bool,
]:
    """Return (core_syms, mod_syms, core_exported, mod_exported, addresses_visible)."""
    core: Dict[str, List[Tuple[str, str]]] = {}
    mod: Dict[str, List[str]] = {}
    core_exp: Set[str] = set()
    mod_exp: Dict[str, List[str]] = {}
    nonzero = False
    path = Path("/proc/kallsyms")
    if not path.exists():
        return core, mod, core_exp, mod_exp, False
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                addr, sym_type, name = parts[0], parts[1], parts[2]
                if addr != "0000000000000000" and addr != "0":
                    nonzero = True
                is_mod = len(parts) >= 4 and parts[3].startswith("[")
                mname = parts[3].strip("[]") if is_mod else ""
                if is_mod:
                    mod.setdefault(name, []).append(mname)
                    if name.startswith("__ksymtab_"):
                        mod_exp.setdefault(name[len("__ksymtab_") :], []).append(mname)
                else:
                    core.setdefault(name, []).append((addr, sym_type))
                    if name.startswith("__ksymtab_"):
                        core_exp.add(name[len("__ksymtab_") :])
    except PermissionError:
        return core, mod, core_exp, mod_exp, False
    return core, mod, core_exp, mod_exp, nonzero


def load_kernel_config() -> Dict[str, str]:
    keys = [
        "CONFIG_SYSVIPC",
        "CONFIG_POSIX_MQUEUE",
        "CONFIG_PID_NS",
        "CONFIG_IPC_NS",
        "CONFIG_USER_NS",
        "CONFIG_DEVTMPFS",
        "CONFIG_CFI_CLANG",
        "CONFIG_CFI_PERMISSIVE",
        "CONFIG_ARM64_BTI_KERNEL",
        "CONFIG_DEBUG_INFO_BTF",
        "CONFIG_KALLSYMS_ALL",
        "CONFIG_KPROBES",
        "CONFIG_MODULES",
        "CONFIG_MODVERSIONS",
        "CONFIG_TRIM_UNUSED_KSYMS",
        "CONFIG_COMPAT",
    ]
    found: Dict[str, str] = {}
    cfg = Path("/proc/config.gz")
    if not cfg.exists():
        return found
    try:
        with gzip.open(cfg, "rt", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln.startswith("# CONFIG_") and ln.endswith(" is not set"):
                    k = ln[2 : -len(" is not set")]
                    if k in keys:
                        found[k] = "n"
                elif "=" in ln:
                    k, v = ln.split("=", 1)
                    if k in keys:
                        found[k] = v
    except OSError:
        pass
    return found


def parse_live_features_layout() -> Dict[str, Tuple[str, int, int]]:
    """Parse /proc/droid_lkm/features layout table if module is loaded."""
    res: Dict[str, Tuple[str, int, int]] = {}
    p = Path("/proc/droid_lkm/features")
    if not p.exists():
        return res
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return res
    for ln in text.splitlines():
        m = re.match(r"^([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)\s+([a-z-]+)\s+(\d+)/(\d+)$", ln.strip())
        if m:
            res[m.group(1)] = (m.group(2), int(m.group(3)), int(m.group(4)))
        m2 = re.match(r"^sizeof\(([a-zA-Z0-9_]+)\s*\)\s+([a-z-]+)\s+(\d+)/(\d+)$", ln.strip())
        if m2:
            res[f"sizeof({m2.group(1)})"] = (m2.group(2), int(m2.group(3)), int(m2.group(4)))
    return res


def run_binutils(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"tool '{cmd[0]}' not found in PATH"
    except Exception as exc:
        return 1, "", str(exc)


def collect_ko_exports(ko_paths: List[Path]) -> Dict[str, str]:
    """Collect strictly EXPORT_SYMBOL(__ksymtab_*) symbols from passed .ko files."""
    exports: Dict[str, str] = {}
    for kp in ko_paths:
        if not kp.exists():
            continue
        rc, out, _ = run_binutils(["nm", "--defined-only", str(kp)])
        if rc != 0:
            continue
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 3 and parts[2].startswith("__ksymtab_"):
                exports[parts[2][len("__ksymtab_") :]] = kp.name
    return exports


def inspect_ko_file(
    ko_path: Path,
    core_syms: Dict[str, List[Tuple[str, str]]],
    core_exported: Set[str],
    peer_exports: Dict[str, str],
    mod_syms: Dict[str, List[str]],
    mod_exported: Dict[str, List[str]],
    kernel_rel: str,
    config: Dict[str, str],
) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "path": str(ko_path),
        "vermagic": None,
        "vermagic_match": None,
        "import_ns": [],
        "undefined_count": 0,
        "peer_resolved": [],
        "missing_from_core_kallsyms": [],
        "unexported_und_syms": [],
        "has_bti_property": False,
        "has_modversions_sec": False,
        "ksymtab_checked": bool(core_exported),
        "issues": [],
    }
    if not ko_path.exists():
        info["issues"].append("file not found")
        return info

    # Extract .modinfo strings via readelf -p .modinfo
    rc_mod, out_mod, err_mod = run_binutils(["readelf", "-p", ".modinfo", str(ko_path)])
    if rc_mod != 0:
        info["issues"].append(f"readelf .modinfo failed: {err_mod.strip()}")
    else:
        for ln in out_mod.splitlines():
            m = re.search(r"vermagic=(.+)$", ln)
            if m:
                vm = m.group(1).strip()
                info["vermagic"] = vm
                mm_live = re.match(r"^(\d+\.\d+)", kernel_rel)
                mm_ko = re.match(r"^(\d+\.\d+)", vm)
                if mm_live and mm_ko:
                    same_mm = mm_live.group(1) == mm_ko.group(1)
                    same_arch = "aarch64" in vm
                    at_live = re.search(r"(android\d+)", kernel_rel)
                    at_ko = re.search(r"(android\d+)", vm)
                    same_at = (not at_ko) or (at_live is not None and at_live.group(1) == at_ko.group(1))
                    info["vermagic_match"] = same_mm and same_arch and same_at
                else:
                    info["vermagic_match"] = vm.split()[0] == kernel_rel
            m_ns = re.search(r"import_ns=(.+)$", ln)
            if m_ns and m_ns.group(1).strip() not in info["import_ns"]:
                info["import_ns"].append(m_ns.group(1).strip())

    # Check GNU property note for AArch64 BTI
    rc_note, out_note, _ = run_binutils(["readelf", "-n", str(ko_path)])
    if rc_note == 0 and "BTI" in out_note:
        info["has_bti_property"] = True
    if config.get("CONFIG_ARM64_BTI_KERNEL") == "y" and not info["has_bti_property"]:
        info["issues"].append("kernel has CONFIG_ARM64_BTI_KERNEL=y but .ko lacks GNU BTI property note")

    # Check __versions section when kernel enforces CONFIG_MODVERSIONS
    rc_sec, out_sec, _ = run_binutils(["readelf", "-W", "-S", str(ko_path)])
    if rc_sec == 0 and re.search(r"\b__versions\b", out_sec):
        info["has_modversions_sec"] = True
    if config.get("CONFIG_MODVERSIONS") == "y":
        if not info["has_modversions_sec"]:
            info["issues"].append("kernel has CONFIG_MODVERSIONS=y but .ko lacks __versions section")
        if info["vermagic"] and "modversions" not in info["vermagic"].split():
            info["issues"].append("kernel has CONFIG_MODVERSIONS=y but .ko vermagic omits 'modversions'")

    # Check undefined symbols against live __ksymtab_* exports (+ peer .ko exports)
    rc_nm, out_nm, err_nm = run_binutils(["nm", "-u", str(ko_path)])
    if rc_nm != 0:
        info["issues"].append(f"nm -u failed: {err_nm.strip()}")
    else:
        undefs: List[str] = []
        for ln in out_nm.splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[0] == "U":
                undefs.append(parts[1])
        info["undefined_count"] = len(undefs)
        if core_syms:
            missing: List[str] = []
            unexported: List[str] = []
            peer_res: List[str] = []
            use_ksymtab = bool(core_exported)
            for s in undefs:
                if use_ksymtab:
                    if s in core_exported:
                        continue
                    if s in peer_exports and peer_exports[s] != ko_path.name:
                        peer_res.append(f"{s}<-{peer_exports[s]}")
                        continue
                    if s in mod_exported:
                        peer_res.append(f"{s}<-[{','.join(mod_exported[s])}]")
                        continue
                    if s in core_syms:
                        unexported.append(s)
                    else:
                        missing.append(s)
                else:
                    if s in core_syms:
                        continue
                    if s in peer_exports and peer_exports[s] != ko_path.name:
                        peer_res.append(f"{s}<-{peer_exports[s]}")
                    elif s in mod_syms:
                        peer_res.append(f"{s}<-[{','.join(mod_syms[s])}]")
                    else:
                        missing.append(s)
            info["peer_resolved"] = peer_res
            info["missing_from_core_kallsyms"] = missing
            info["unexported_und_syms"] = unexported
            if missing:
                info["issues"].append(f"{len(missing)} UND symbols absent from kernel/peer exports")
            if unexported:
                info["issues"].append(
                    f"{len(unexported)} UND symbols exist in kallsyms but lack __ksymtab_ export "
                    f"(insmod will fail with Unknown symbol): {', '.join(unexported[:8])}"
                )

    if info["vermagic_match"] is False:
        info["issues"].append(f"vermagic mismatch: ko='{info['vermagic']}' vs live='{kernel_rel}'")

    return info


def diff_baselines(old: Dict[str, Any], new: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (all_diffs, regression_diffs)."""
    diffs: List[str] = []
    regressions: List[str] = []

    if old.get("kernel_release") != new.get("kernel_release"):
        diffs.append(f"kernel: {old.get('kernel_release')} -> {new.get('kernel_release')}")

    old_cfg = old.get("config", {})
    new_cfg = new.get("config", {})
    for k in sorted(set(old_cfg) & set(new_cfg)):
        if old_cfg.get(k) != new_cfg.get(k):
            msg = f"config {k}: {old_cfg.get(k)} -> {new_cfg.get(k)}"
            diffs.append(msg)
            regressions.append(msg)

    old_syms = old.get("symbols", {})
    new_syms = new.get("symbols", {})
    for group in sorted(set(old_syms) & set(new_syms)):
        om = set(old_syms.get(group, {}).get("missing", []))
        nm = set(new_syms.get(group, {}).get("missing", []))
        for s in sorted(nm - om):
            msg = f"symbol REGRESSION [{group}]: '{s}' disappeared"
            diffs.append(msg)
            regressions.append(msg)
        for s in sorted(om - nm):
            diffs.append(f"symbol GAINED [{group}]: '{s}' now present")

    for section_key, label in (
        ("btf_fields", "BTF field"),
        ("vendor_btf_fields", "vendor BTF field"),
    ):
        old_btf = old.get(section_key, {})
        new_btf = new.get(section_key, {})
        for k in sorted(set(old_btf) & set(new_btf)):
            if old_btf.get(k) != new_btf.get(k):
                msg = f"{label} {k}: {old_btf.get(k)} -> {new_btf.get(k)}"
                diffs.append(msg)
                regressions.append(msg)

    for section_key, label in (
        ("btf_types", "BTF sizeof"),
        ("vendor_btf_types", "vendor BTF sizeof"),
    ):
        old_types = old.get(section_key, {})
        new_types = new.get(section_key, {})
        for k in sorted(set(old_types) & set(new_types)):
            if old_types.get(k) != new_types.get(k):
                msg = f"{label}({k}): {old_types.get(k)} -> {new_types.get(k)}"
                diffs.append(msg)
                regressions.append(msg)

    return diffs, regressions


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only live kernel preflight for droid_lkm")
    ap.add_argument("--save-baseline", metavar="JSON", help="save snapshot JSON for future OTA diff")
    ap.add_argument("--diff-baseline", metavar="JSON", help="compare live kernel against saved JSON")
    ap.add_argument(
        "--allow-baseline-diff",
        action="store_true",
        help="do not fail exit code on baseline symbol/BTF/config regressions",
    )
    ap.add_argument("--ko", action="append", default=[], help="inspect built .ko file(s) against live kernel")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("--verbose", action="store_true", help="print every BTF field offset")
    args = ap.parse_args()

    kernel_rel = os.uname().release
    is_root = os.geteuid() == 0
    contracts = extract_ksym_contracts()
    layout_fields, layout_types, vendor_fields, vendor_types = extract_layout_contracts()

    core_syms, mod_syms, core_exported, mod_exported, ksym_visible = load_kallsyms()
    config = load_kernel_config()
    live_feat = parse_live_features_layout()

    sym_report: Dict[str, Dict[str, Any]] = {}
    critical_failures: List[str] = []
    warnings: List[str] = []

    for group, syms in contracts.items():
        present = []
        missing = []
        mod_only = []
        for s in syms:
            if s in core_syms:
                present.append(s)
            else:
                missing.append(s)
                if s in mod_syms:
                    mod_only.append(f"{s}[{','.join(mod_syms[s])}]")
        sym_report[group] = {
            "total": len(syms),
            "present": len(present),
            "missing": missing,
            "module_only_shadows": mod_only,
        }
        if group == "required_main" and missing:
            critical_failures.append(f"missing required main symbols: {', '.join(missing)}")
        if group == "text_patch" and missing:
            warnings.append(
                f"text-patch symbols missing (inline hooks will fallback to kprobe): {', '.join(missing)}"
            )

    # Parse /sys/kernel/btf/vmlinux
    btf_path = Path("/sys/kernel/btf/vmlinux")
    btf_available = btf_path.exists()
    btf_fields: Dict[str, Any] = {}
    btf_types: Dict[str, Any] = {}
    vendor_btf_fields: Dict[str, Any] = {}
    vendor_btf_types: Dict[str, Any] = {}
    btf_missing_req: List[str] = []
    vendor_btf_missing: List[str] = []
    btf_vs_loaded_drift: List[str] = []

    if btf_available:
        try:
            btf = BtfParser(btf_path.read_bytes())
            for st_name, mem_name, is_req in layout_fields:
                key = f"{st_name}.{mem_name}"
                sid = btf.find_struct_id(st_name)
                if sid is None:
                    btf_fields[key] = None
                    if is_req:
                        btf_missing_req.append(key)
                    continue
                hit = btf.find_member(sid, mem_name)
                if hit is None:
                    btf_fields[key] = None
                    if is_req:
                        btf_missing_req.append(key)
                    continue
                bit_off, bit_sz, m_tid = hit
                byte_off = bit_off // 8
                byte_sz = (bit_sz // 8) if bit_sz else btf.type_size(m_tid)
                btf_fields[key] = {"offset": byte_off, "size": byte_sz, "required": is_req}
                if key in live_feat:
                    st, live_off, build_off = live_feat[key]
                    if live_off != byte_off:
                        btf_vs_loaded_drift.append(
                            f"{key}: btf={byte_off} vs loaded /proc/droid_lkm/features={live_off} (build={build_off}, state={st})"
                        )
            for tname in layout_types:
                sid = btf.find_struct_id(tname)
                sz = btf.type_size(sid) if sid else None
                btf_types[tname] = sz
                fkey = f"sizeof({tname})"
                if sz is not None and fkey in live_feat:
                    st, live_sz, build_sz = live_feat[fkey]
                    if live_sz != sz:
                        btf_vs_loaded_drift.append(
                            f"{fkey}: btf={sz} vs loaded={live_sz} (build={build_sz}, state={st})"
                        )

            for st_name, mem_name in vendor_fields:
                key = f"{st_name}.{mem_name}"
                sid = btf.find_struct_id(st_name)
                hit = btf.find_member(sid, mem_name) if sid is not None else None
                if hit is None:
                    vendor_btf_fields[key] = None
                    vendor_btf_missing.append(key)
                else:
                    bit_off, bit_sz, m_tid = hit
                    vendor_btf_fields[key] = {
                        "offset": bit_off // 8,
                        "size": (bit_sz // 8) if bit_sz else btf.type_size(m_tid),
                    }
            for tname in vendor_types:
                sid = btf.find_struct_id(tname)
                vendor_btf_types[tname] = btf.type_size(sid) if sid else None
        except Exception as exc:
            btf_available = False
            critical_failures.append(f"BTF parse error: {exc}")

    mm_live = re.match(r"^(\d+\.\d+)", kernel_rel)
    vendor_applicable = (mm_live is not None and mm_live.group(1) in ("6.6", "6.12")) or any(
        "vendor" in Path(k).name for k in args.ko
    )
    if btf_missing_req:
        critical_failures.append(f"required main BTF fields missing: {', '.join(btf_missing_req)}")
    if vendor_btf_missing:
        msg = f"vendor BTF fields missing: {', '.join(vendor_btf_missing)}"
        if vendor_applicable:
            critical_failures.append(msg)
        else:
            warnings.append(f"{msg} (non-6.6/6.12 kernel; droid_lkm_vendor.ko not built here)")
    if btf_vs_loaded_drift:
        critical_failures.append(
            f"BTF vs loaded /proc/droid_lkm/features drift ({len(btf_vs_loaded_drift)} mismatch)"
        )

    ko_paths = [Path(k) for k in args.ko]
    peer_exports = collect_ko_exports(ko_paths)
    ko_reports = [
        inspect_ko_file(
            kp, core_syms, core_exported, peer_exports, mod_syms, mod_exported, kernel_rel, config
        )
        for kp in ko_paths
    ]
    for kr in ko_reports:
        for iss in kr["issues"]:
            critical_failures.append(f"ko {Path(kr['path']).name}: {iss}")

    snapshot: Dict[str, Any] = {
        "kernel_release": kernel_rel,
        "euid": os.geteuid(),
        "kallsyms_addresses_visible": ksym_visible,
        "ksymtab_export_count": len(core_exported),
        "btf_available": btf_available,
        "config": config,
        "symbols": sym_report,
        "btf_fields": btf_fields,
        "btf_types": btf_types,
        "vendor_btf_fields": vendor_btf_fields,
        "vendor_btf_types": vendor_btf_types,
        "btf_missing_required": btf_missing_req,
        "vendor_btf_missing": vendor_btf_missing,
        "btf_vs_loaded_drift": btf_vs_loaded_drift,
        "ko_reports": ko_reports,
        "warnings": warnings,
        "critical_failures": critical_failures,
    }

    if args.save_baseline:
        out_p = Path(args.save_baseline)
        created_parent = not out_p.parent.exists()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if os.geteuid() == 0:
            try:
                st = ROOT.stat()
                if st.st_uid != 0:
                    os.chown(out_p, st.st_uid, st.st_gid)
                    if created_parent:
                        os.chown(out_p.parent, st.st_uid, st.st_gid)
            except OSError:
                pass

    diffs: List[str] = []
    baseline_regs: List[str] = []
    if args.diff_baseline:
        old = json.loads(Path(args.diff_baseline).read_text(encoding="utf-8"))
        diffs, baseline_regs = diff_baselines(old, snapshot)
        snapshot["baseline_diffs"] = diffs
        snapshot["baseline_regressions"] = baseline_regs
        if baseline_regs and not args.allow_baseline_diff:
            critical_failures.append(
                f"baseline diff detected {len(baseline_regs)} regression(s) (pass --allow-baseline-diff to ignore)"
            )

    if args.json:
        print(json.dumps(snapshot, indent=2, sort_keys=True))
    else:
        print("== droid_lkm live kernel preflight ==")
        print(f"kernel : {kernel_rel}")
        print(
            f"euid   : {os.geteuid()} "
            f"({'root' if is_root else 'non-root; rerun with sudo python3 for full visibility'})"
        )
        print(
            f"kallsyms core symbols: {len(core_syms)} "
            f"(__ksymtab_ exports={len(core_exported)}, addrs_visible={ksym_visible})"
        )
        print(f"vmlinux BTF: {'available' if btf_available else 'MISSING (non-GKI anchor path required)'}")

        if config:
            important = [f"{k}={config[k]}" for k in sorted(config)]
            print("config : " + ", ".join(important))

        print("\n-- Symbol contract audit (core kernel only, excluding LKM shims) --")
        for g in ("required_main", "text_patch", "hook_targets", "direct_main", "vendor", "native", "main_all"):
            r = sym_report[g]
            status = "OK" if not r["missing"] else ("FAIL" if g == "required_main" else "INFO")
            print(f"  [{status:4s}] {g:14s}: {r['present']}/{r['total']} present")
            if r["missing"]:
                print(f"         missing: {', '.join(r['missing'])}")
            if r["module_only_shadows"]:
                print(f"         note (present only in loaded LKM, NOT core): {', '.join(r['module_only_shadows'])}")

        print("\n-- BTF layout contract audit (ds_ti.c + compat/vendor) --")
        resolved_f = sum(1 for v in btf_fields.values() if v is not None)
        resolved_vf = sum(1 for v in vendor_btf_fields.values() if v is not None)
        ipc_keys = [k for k in btf_fields if k.startswith("ipc_namespace.")]
        ipc_ok = sum(1 for k in ipc_keys if btf_fields[k] is not None)
        print(
            f"  main   : {resolved_f}/{len(btf_fields)} fields resolved "
            f"(missing required: {len(btf_missing_req)}, ipc_namespace: {ipc_ok}/{len(ipc_keys)})"
        )
        print(
            f"  vendor : {resolved_vf}/{len(vendor_btf_fields)} fields resolved "
            f"(missing: {len(vendor_btf_missing)})"
        )
        for tname, sz in btf_types.items():
            print(f"  sizeof(struct {tname}) = {sz}")
        for tname, sz in vendor_btf_types.items():
            if tname not in btf_types:
                print(f"  sizeof(struct {tname}) = {sz} [vendor]")
        if btf_vs_loaded_drift:
            print("  DRIFT vs loaded /proc/droid_lkm/features:")
            for d in btf_vs_loaded_drift:
                print(f"    ! {d}")
        elif live_feat:
            print("  cross-check vs loaded /proc/droid_lkm/features: 100% match")
        if args.verbose:
            for k, v in btf_fields.items():
                if v is None:
                    print(f"    MISSING {k}")
                else:
                    req_tag = "*" if v["required"] else " "
                    print(f"   {req_tag}{k:34s} off={v['offset']:<5d} size={v['size']}")
            for k, v in vendor_btf_fields.items():
                if v is None:
                    print(f"    MISSING [vendor] {k}")
                else:
                    print(f"   v{k:34s} off={v['offset']:<5d} size={v['size']}")

        if ko_reports:
            print("\n-- Built .ko ELF preflight --")
            for kr in ko_reports:
                print(f"  {kr['path']}:")
                print(f"    vermagic : {kr['vermagic']} (kmi_match={kr['vermagic_match']})")
                print(
                    f"    BTI note : {kr['has_bti_property']}  __versions: {kr['has_modversions_sec']}  "
                    f"import_ns: {kr['import_ns']}"
                )
                print(
                    f"    UND syms : {kr['undefined_count']} total, "
                    f"missing: {len(kr['missing_from_core_kallsyms'])}, "
                    f"unexported: {len(kr['unexported_und_syms'])} "
                    f"(ksymtab_checked={kr['ksymtab_checked']})"
                )
                if kr["peer_resolved"]:
                    print(f"    peer/mod : {', '.join(kr['peer_resolved'])}")
                if kr["unexported_und_syms"]:
                    print(f"    UNEXPORTED: {', '.join(kr['unexported_und_syms'][:20])}")
                if kr["missing_from_core_kallsyms"]:
                    print(f"    missing  : {', '.join(kr['missing_from_core_kallsyms'][:20])}")

        if args.diff_baseline:
            print(f"\n-- Baseline diff vs {args.diff_baseline} --")
            if not diffs:
                print("  no changes detected")
            else:
                for d in diffs:
                    print(f"  * {d}")

        if args.save_baseline:
            print(f"\nsaved baseline -> {args.save_baseline}")

        if warnings:
            print("\nWARNINGS:")
            for w in warnings:
                print(f"  - {w}")

        if critical_failures:
            print("\n!! CRITICAL FINDINGS:")
            for cf in critical_failures:
                print(f"  - {cf}")

    return 1 if critical_failures else 0


if __name__ == "__main__":
    sys.exit(main())
