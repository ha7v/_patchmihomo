#!/usr/bin/env python3
"""Read-only device & droid_lkm runtime diagnostic snapshot (run with `sudo python3`).

Collects device fingerprint, inferred KMI, kernel config flags, loaded droid_lkm*
modules, /proc/droid_lkm/features summary, /proc/droid_lkm_misc/status, module
parameters, phdroid state (/data/adb/modules/phdroid & /data/adb/phdroid), and
filtered dmesg lines without mutating any system state.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def run_cmd(cmd: List[str], timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def getprop(key: str) -> str:
    return run_cmd(["getprop", key])


def read_text_safe(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def infer_kmi(release: str, first_api: str, android_ver: str) -> str:
    mm = re.match(r"^(\d+\.\d+)", release)
    kver = mm.group(1) if mm else "?"
    at = re.search(r"(android\d+)", release)
    if at:
        return f"{at.group(1)}-{kver}"
    if android_ver.isdigit():
        return f"android{android_ver}-{kver}"
    return f"unknown-{kver} (first_api={first_api or '?'})"


def read_config_flags() -> Dict[str, str]:
    wanted = [
        "CONFIG_SYSVIPC",
        "CONFIG_POSIX_MQUEUE",
        "CONFIG_PID_NS",
        "CONFIG_IPC_NS",
        "CONFIG_USER_NS",
        "CONFIG_DEVTMPFS",
        "CONFIG_CFI_CLANG",
        "CONFIG_ARM64_BTI_KERNEL",
        "CONFIG_DEBUG_INFO_BTF",
        "CONFIG_KALLSYMS_ALL",
        "CONFIG_KPROBES",
        "CONFIG_TRIM_UNUSED_KSYMS",
    ]
    out: Dict[str, str] = {}
    cfg = Path("/proc/config.gz")
    if not cfg.exists():
        return out
    try:
        with gzip.open(cfg, "rt", encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln.startswith("# CONFIG_") and ln.endswith(" is not set"):
                    k = ln[2 : -len(" is not set")]
                    if k in wanted:
                        out[k] = "n"
                elif "=" in ln:
                    k, v = ln.split("=", 1)
                    if k in wanted:
                        out[k] = v
    except OSError:
        pass
    return out


def read_loaded_modules() -> List[Dict[str, str]]:
    mods: List[Dict[str, str]] = []
    txt = read_text_safe(Path("/proc/modules"))
    for ln in txt.splitlines():
        if ln.startswith("droid_lkm"):
            parts = ln.split()
            mods.append(
                {
                    "name": parts[0],
                    "size": parts[1] if len(parts) > 1 else "?",
                    "refcnt": parts[2] if len(parts) > 2 else "?",
                    "holders": parts[3] if len(parts) > 3 else "-",
                    "state": parts[4] if len(parts) > 4 else "?",
                }
            )
    return mods


def read_mod_params(mod: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    pdir = Path(f"/sys/module/{mod}/parameters")
    if not pdir.is_dir():
        return res
    for p in sorted(pdir.iterdir()):
        try:
            res[p.name] = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            res[p.name] = "<unreadable>"
    return res


def summarize_features(raw: str) -> Dict[str, Any]:
    if not raw:
        return {"available": False}
    lines = raw.splitlines()
    features: List[str] = []
    hooks: List[str] = []
    runtime: List[str] = []
    layout_trusted = None
    layout_counts: Dict[str, int] = {}
    layout_non_ok: List[str] = []
    section = ""
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("feature "):
            section = "feature"
            continue
        if s.startswith("layout trusted:"):
            layout_trusted = s.split(":", 1)[1].strip()
            continue
        if s.startswith("layout "):
            section = "layout"
            continue
        if s.startswith("hook "):
            section = "hook"
            continue
        if s.startswith("runtime "):
            section = "runtime"
            continue

        if section == "feature":
            features.append(s)
        elif section == "layout":
            parts = s.split()
            if len(parts) >= 2:
                # Handle "sizeof(upid ) ok 16/16" or "task_struct.pid ok 1560/1560"
                st = parts[-2]
                layout_counts[st] = layout_counts.get(st, 0) + 1
                if st not in ("ok", "verified", "anchored"):
                    layout_non_ok.append(s)
        elif section == "hook":
            hooks.append(s)
        elif section == "runtime":
            runtime.append(s)

    return {
        "available": True,
        "layout_trusted": layout_trusted,
        "layout_state_counts": layout_counts,
        "layout_non_ok": layout_non_ok,
        "features": features,
        "hooks": hooks,
        "runtime": runtime,
    }


def read_phdroid_state() -> Dict[str, Any]:
    mod_dir = Path("/data/adb/modules/phdroid")
    data_dir = Path("/data/adb/phdroid")
    state: Dict[str, Any] = {
        "module_installed": mod_dir.is_dir(),
        "module_prop": read_text_safe(mod_dir / "module.prop"),
        "ko_files": [],
        "data_dir_exists": data_dir.is_dir(),
        "auto_enabled": (data_dir / "auto").exists(),
        "inflight_mark": (data_dir / "insmod").exists() or (mod_dir / "insmod.inflight").exists(),
        "blocked": (data_dir / "blocked").exists() or (mod_dir / "blocked").exists(),
        "config": read_text_safe(data_dir / "config.conf") or read_text_safe(mod_dir / "config.conf"),
        "log_tail": [],
    }
    for sub in (mod_dir / "bin", mod_dir / "ko"):
        if sub.is_dir():
            for ko in sorted(sub.rglob("*.ko")):
                state["ko_files"].append(str(ko.relative_to(mod_dir)))
    for log_p in (data_dir / "phdroid.log", mod_dir / "phdroid.log"):
        if log_p.is_file():
            txt = read_text_safe(log_p)
            if txt:
                state["log_tail"] = txt.splitlines()[-25:]
                break
    return state


def read_filtered_dmesg(limit: int = 40) -> List[str]:
    raw = run_cmd(["dmesg"], timeout=6)
    if not raw:
        return []
    pat = re.compile(
        r"droid_lkm|phDroid|kallrecon|hookern|kerncall|type_info|selftest|thunk|"
        r"kcfi|cfi:|bti|unhandled|unable to handle|panic|oops|cut here|WARNING:|BUG:|"
        r"KASAN:|KFENCE:|UBSAN:|refcount_t:|use-after-free|pc :|lr :|Comm:",
        re.I,
    )
    out = [
        ln
        for ln in raw.splitlines()
        if pat.search(ln)
        and "binder_debug" not in ln
        and "Modules linked in:" not in ln
    ]
    return out[-limit:]


def read_last_crash_summary() -> Dict[str, Any]:
    """Read-only summary of OPLUS/Android crash logs (SYSTEM_LAST_KMSG, critical.log, minidump)."""
    summary: Dict[str, Any] = {
        "pstore_files": [],
        "last_kmsg_path": None,
        "last_kmsg_mtime": None,
        "minidump_mtime": None,
        "last_panic_entry": [],
    }
    pstore = Path("/sys/fs/pstore")
    if pstore.is_dir():
        try:
            summary["pstore_files"] = sorted(p.name for p in pstore.iterdir())
        except OSError:
            pass
    for kmsg_p in (
        Path("/data/persist_log/backup/SYSTEM_LAST_KMSG.txt"),
        Path("/proc/last_kmsg"),
    ):
        if kmsg_p.is_file():
            try:
                st = kmsg_p.stat()
                summary["last_kmsg_path"] = str(kmsg_p)
                summary["last_kmsg_mtime"] = int(st.st_mtime)
                summary["last_kmsg_size"] = st.st_size
                break
            except OSError:
                pass
    md = Path("/data/persist_log/DCS/minidump/minidump.bin")
    if md.is_file():
        try:
            summary["minidump_mtime"] = int(md.stat().st_mtime)
        except OSError:
            pass
    crit = Path("/data/persist_log/criticallog/persist/critical.log")
    if crit.is_file():
        try:
            # Read tail chunk only (file can be several MB)
            with crit.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                sz = fh.tell()
                fh.seek(max(0, sz - 65536))
                tail = fh.read().decode("utf-8", errors="replace")
            blocks = re.findall(r"<kernel-panic-begin>(.*?)<kernel-panic-end>", tail, re.S)
            if blocks:
                summary["last_panic_entry"] = [
                    ln.strip() for ln in blocks[-1].splitlines() if ln.strip()
                ]
        except OSError:
            pass
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only device & droid_lkm diagnostic snapshot")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--full-features", action="store_true", help="include full /proc/droid_lkm/features layout table")
    args = ap.parse_args()

    release = os.uname().release
    brand = getprop("ro.product.vendor.brand") or getprop("ro.product.brand")
    model = getprop("ro.product.vendor.model") or getprop("ro.product.model")
    device = getprop("ro.product.vendor.device") or getprop("ro.product.device")
    android_ver = getprop("ro.build.version.release")
    first_api = getprop("ro.product.first_api_level")
    sec_patch = getprop("ro.build.version.security_patch")
    kmi = infer_kmi(release, first_api, android_ver)

    raw_features = read_text_safe(Path("/proc/droid_lkm/features"))
    raw_misc_status = read_text_safe(Path("/proc/droid_lkm_misc/status"))
    raw_misc_ver = read_text_safe(Path("/proc/droid_lkm_misc/version"))

    mods = read_loaded_modules()
    params = {m["name"]: read_mod_params(m["name"]) for m in mods}

    data: Dict[str, Any] = {
        "euid": os.geteuid(),
        "device": {
            "brand": brand,
            "model": model,
            "device": device,
            "android_version": android_ver,
            "first_api_level": first_api,
            "security_patch": sec_patch,
            "kernel_release": release,
            "inferred_kmi": kmi,
        },
        "kernel_config": read_config_flags(),
        "btf_vmlinux_exists": Path("/sys/kernel/btf/vmlinux").exists(),
        "loaded_modules": mods,
        "module_parameters": params,
        "droid_lkm_features": summarize_features(raw_features),
        "droid_lkm_misc_version": raw_misc_ver,
        "droid_lkm_misc_status": raw_misc_status.splitlines() if raw_misc_status else [],
        "phdroid_install": read_phdroid_state(),
        "crash_logs": read_last_crash_summary(),
        "dmesg_tail": read_filtered_dmesg(),
    }
    if args.full_features and raw_features:
        data["droid_lkm_features_raw"] = raw_features

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    d = data["device"]
    print("## Device & droid_lkm Diagnostic Snapshot")
    print(f"- **Device**: {d['brand']} {d['model']} (`{d['device']}`), Android {d['android_version']} (first_api={d['first_api_level']}, patch={d['security_patch']})")
    print(f"- **Kernel**: `{d['kernel_release']}` -> KMI `{d['inferred_kmi']}`")
    print(f"- **BTF**: `{'present' if data['btf_vmlinux_exists'] else 'absent'}` | **euid**: `{data['euid']}`")
    if data["kernel_config"]:
        cfg_str = ", ".join(f"`{k}={v}`" for k, v in sorted(data["kernel_config"].items()))
        print(f"- **Config**: {cfg_str}")

    print("\n### Loaded Modules")
    if not mods:
        print("- (none)")
    else:
        for m in mods:
            print(f"- `{m['name']}` size={m['size']} refcnt={m['refcnt']} holders=`{m['holders']}` state={m['state']}")

    feat = data["droid_lkm_features"]
    print("\n### /proc/droid_lkm/features")
    if not feat.get("available"):
        print("- unavailable (module not loaded or need `sudo python3`)")
    else:
        print(f"- **layout trusted**: `{feat['layout_trusted']}` | counts: `{feat['layout_state_counts']}`")
        if feat["layout_non_ok"]:
            print("- **non-ok layout entries**:")
            for ln in feat["layout_non_ok"]:
                print(f"  - `{ln}`")
        if feat["features"]:
            print("- **features**:")
            for ln in feat["features"]:
                print(f"  - `{ln}`")
        if feat["hooks"]:
            print("- **hooks**:")
            for ln in feat["hooks"]:
                print(f"  - `{ln}`")
        if feat["runtime"]:
            print("- **runtime**:")
            for ln in feat["runtime"]:
                print(f"  - `{ln}`")

    print("\n### /proc/droid_lkm_misc/status")
    if not data["droid_lkm_misc_status"]:
        print("- unavailable")
    else:
        print(f"- ABI version: `{data['droid_lkm_misc_version']}`")
        for ln in data["droid_lkm_misc_status"]:
            print(f"  - `{ln}`")

    print("\n### Module Parameters")
    for mname, mp in params.items():
        if mp:
            kv = " ".join(f"{k}={v}" for k, v in mp.items())
            print(f"- `{mname}`: `{kv}`")

    ph = data["phdroid_install"]
    print("\n### phDroid Module State (/data/adb)")
    print(f"- installed=`{ph['module_installed']}` auto=`{ph['auto_enabled']}` inflight=`{ph['inflight_mark']}` blocked=`{ph['blocked']}`")
    if ph["ko_files"]:
        print(f"- ko files: {', '.join(f'`{x}`' for x in ph['ko_files'])}")
    if ph["module_prop"]:
        ver = next((l for l in ph["module_prop"].splitlines() if l.startswith("version=")), "")
        code = next((l for l in ph["module_prop"].splitlines() if l.startswith("versionCode=")), "")
        print(f"- module.prop: `{ver}` `{code}`")
    if ph["config"]:
        print(f"- active config:\n```\n{ph['config']}\n```")
    if ph["log_tail"]:
        print("- recent phdroid.log:\n```\n" + "\n".join(ph["log_tail"][-12:]) + "\n```")

    cl = data["crash_logs"]
    print("\n### Crash / Panic Logs (read-only)")
    if cl["pstore_files"]:
        print(f"- `/sys/fs/pstore`: {', '.join(cl['pstore_files'])}")
    if cl["last_kmsg_path"]:
        print(f"- last kmsg: `{cl['last_kmsg_path']}` (size={cl.get('last_kmsg_size', '?')})")
    if cl["last_panic_entry"]:
        print("- latest `<kernel-panic>` in `/data/persist_log/criticallog/persist/critical.log`:")
        for ln in cl["last_panic_entry"]:
            print(f"  - `{ln}`")
    elif not cl["pstore_files"] and not cl["last_kmsg_path"]:
        print("- (none detected)")

    print("\n### Filtered dmesg")
    if not data["dmesg_tail"]:
        print("- (no matching lines in current ring buffer; boot messages may have rotated out)")
    else:
        print("```\n" + "\n".join(data["dmesg_tail"]) + "\n```")

    if args.full_features and raw_features:
        print("\n### Raw /proc/droid_lkm/features\n```\n" + raw_features + "\n```")
    return 0


if __name__ == "__main__":
    sys.exit(main())
