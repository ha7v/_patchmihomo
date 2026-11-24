#!/usr/bin/env python3
"""Static invariant checks for droid_lkm (fast pre-compile / pre-boot guard).

Catches high-risk kernel module mistakes that CI's compiler + zero-warning gate
will NOT catch, including:
  - Missing KCFI (__nocfi), noinline, or AArch64 BTI (DROID_LKM_ENTRY) on hook
    wrappers, hk_redir_install_at targets, syscall slot handlers, and IPC thunks
  - Missing __nocfi on functions calling hook trampolines (*_orig / orig /
    droid_lkm_orig_*) or kallsyms-resolved function pointers (droid_lkm_ks.*,
    dlc_vendor_syms.*, and file-local symbol-bound function pointers)
  - Direct kallrecon_klp() calls bypassing hidden-symbol/shim guards
  - Cross-kernel ABI regressions (raw MODULE_IMPORT_NS, direct ns_common::ops)
  - Missing .write = hk_write_kernel in struct hk_cfg (MTK fixmap protection)
  - Direct dereferences of BTF/anchor layout-managed struct fields (type-aware)
  - Kbuild object / shell / Gradle packaging drift

Run with `--self-test` to verify every rule against synthetic positive/negative
C snippets.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Finding:
    level: str  # "ERROR" or "WARN"
    rule: str
    path: str
    line: int
    message: str


@dataclass
class CFunction:
    name: str
    header_raw: str
    header_masked: str
    body_raw: str
    body_masked: str
    header_line: int
    body_start: int
    body_end: int
    is_syscall_define: bool = False


def rel(p: Path, root: Path = ROOT) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# C lexical sanitization & function block parser
# ---------------------------------------------------------------------------

def strip_c_comments(text: str) -> str:
    """Replace C comments with spaces/newlines while preserving line numbers."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str: Optional[str] = None
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i + 1 < n:
                out.append("  ")
                i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def mask_preprocessor(text: str) -> str:
    """Blank out preprocessor directives (including backslash-continued lines),
    preserving exact character offsets and line count."""
    out_lines: List[str] = []
    in_pp = False
    for ln in text.splitlines(keepends=True):
        nl = "\n" if ln.endswith("\n") else ""
        body = ln[:-1] if nl else ln
        stripped = body.lstrip()
        if in_pp or stripped.startswith("#"):
            out_lines.append(" " * len(body) + nl)
            in_pp = body.rstrip().endswith("\\")
        else:
            out_lines.append(ln)
    return "".join(out_lines)


def mask_c_strings(text: str) -> str:
    """Replace contents of string/char literals with spaces so braces/parens/
    keywords inside strings never confuse lexical scanning, preserving offsets."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str: Optional[str] = None
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                out.append(" ")
                out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if ch == in_str:
                out.append(ch)
                in_str = None
                i += 1
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def preprocess_c_source(raw: str) -> Tuple[str, str, str]:
    """Return (no_comments, no_pp, masked) with identical length & line numbers.
    `no_comments` keeps string literals & preprocessor lines intact;
    `no_pp` blanks out preprocessor blocks while keeping string literals (for BTI attrs);
    `masked` blanks out comments, preprocessor blocks, and string contents."""
    no_comments = strip_c_comments(raw)
    no_pp = mask_preprocessor(no_comments)
    masked = mask_c_strings(no_pp)
    return no_comments, no_pp, masked


def extract_fn_name_from_header(header_masked: str) -> Tuple[Optional[str], bool]:
    """Extract function name from a C function header preceding '{'."""
    m_sys = re.search(
        r"\b((?:COMPAT_)?SYSCALL_DEFINE\d)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)",
        header_masked,
    )
    if m_sys:
        return f"{m_sys.group(1)}({m_sys.group(2)})", True

    # Find the parameter list '(' matching the final ')' before '{'
    s = header_masked.rstrip()
    if not s.endswith(")"):
        return None, False
    depth = 0
    open_idx = -1
    for i in range(len(s) - 1, -1, -1):
        ch = s[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                open_idx = i
                break
    if open_idx <= 0:
        return None, False

    before = s[:open_idx].rstrip()
    # Reject struct/array/initializer assignments like `static struct foo bar = {`
    if "=" in before:
        return None, False
    m_name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", before)
    if not m_name:
        return None, False
    name = m_name.group(1)
    if name in ("if", "for", "while", "switch", "sizeof", "typeof", "return", "else", "do"):
        return None, False
    # Reject function-like macro invocations with no return type/specifier prefix
    prefix_before_name = before[: m_name.start()].strip()
    if not prefix_before_name:
        return None, False
    return name, False


def iter_c_functions(no_pp: str, masked: str) -> List[CFunction]:
    """Parse top-level C function definitions from preprocessed source."""
    funcs: List[CFunction] = []
    n = len(masked)
    i = 0
    while i < n:
        if masked[i] == "{":
            body_start = i
            j = i + 1
            d = 1
            while j < n and d > 0:
                if masked[j] == "{":
                    d += 1
                elif masked[j] == "}":
                    d -= 1
                j += 1
            body_end = j

            bound = max(masked.rfind(";", 0, body_start), masked.rfind("}", 0, body_start))
            h_start = bound + 1
            header_masked = masked[h_start:body_start]
            fn_name, is_sc = extract_fn_name_from_header(header_masked)
            if fn_name:
                # Line number of function name / header start (first non-space char)
                first_non_ws = h_start
                while first_non_ws < body_start and masked[first_non_ws].isspace():
                    first_non_ws += 1
                hline = masked.count("\n", 0, first_non_ws) + 1
                funcs.append(
                    CFunction(
                        name=fn_name,
                        header_raw=no_pp[h_start:body_start],
                        header_masked=header_masked,
                        body_raw=no_pp[body_start:body_end],
                        body_masked=masked[body_start:body_end],
                        header_line=hline,
                        body_start=body_start,
                        body_end=body_end,
                        is_syscall_define=is_sc,
                    )
                )
            i = body_end
            continue
        i += 1
    return funcs


def has_bti_entry_attr(header_raw: str) -> bool:
    """Return True iff header carries DROID_LKM_ENTRY or explicit BTI target attr."""
    if re.search(r"\bDROID_LKM_ENTRY\b", header_raw):
        return True
    if re.search(r'\btarget\s*\(\s*"[^"]*branch-protection=bti[^"]*"\s*\)', header_raw):
        return True
    return False


def has_token(text: str, tok: str) -> bool:
    return bool(re.search(rf"\b{re.escape(tok)}\b", text))


# ---------------------------------------------------------------------------
# Active source file discovery (Kbuild-aware)
# ---------------------------------------------------------------------------

def active_native_relpaths(root: Path = ROOT) -> Set[str]:
    """Return active src/native/ files referenced by Makefile NATIVE_PID_OBJ plus its headers."""
    active: Set[str] = set()
    mk = root / "Makefile"
    if mk.exists():
        txt = mk.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"\b(src/native/[A-Za-z0-9_./-]+\.o)\b", txt):
            c_rel = m.group(1)[:-2] + ".c"
            active.add(c_rel)
            h_rel = m.group(1)[:-2] + ".h"
            if (root / h_rel).exists():
                active.add(h_rel)
    for extra in ("src/native/names.h", "src/native/native_compat.h", "src/native/native_pid.h"):
        if (root / extra).exists():
            active.add(extra)
    return active


def iter_c_files(base: Path, include_misc: bool = False, root: Path = ROOT) -> List[Path]:
    native_active = active_native_relpaths(root)
    files: List[Path] = []
    for p in sorted(base.rglob("*")):
        if p.suffix not in (".c", ".h"):
            continue
        r = rel(p, root)
        if not include_misc and r.startswith("src/misc/"):
            continue
        if r.startswith("src/native/") and native_active and r not in native_active:
            continue
        files.append(p)
    return files


# ---------------------------------------------------------------------------
# Rule 1: Indirect entry points (hooks, _at hooks, syscall slots, IPC thunks)
# ---------------------------------------------------------------------------

def find_indirect_entries(
    c_files: Iterable[Path], root: Path = ROOT
) -> List[Tuple[str, str, str, Path, int]]:
    """Extract (kind, target_sym, wrapper_name, file, line) for all indirect entry points."""
    results: List[Tuple[str, str, str, Path, int]] = []

    pat_two = re.compile(
        r"\b(ds_hook_install(?:_guard|_text|_kprobe|_critical)?|"
        r"hk_inline_hook|hk_redir_install)\s*\("
        r"[^;]*?\"([A-Za-z0-9_]+)\"\s*,\s*\"([A-Za-z0-9_]+)\"",
        re.S,
    )
    pat_slot = re.compile(
        r"\bds_hook_install_slot(?:_critical)?\s*\("
        r"[^;]*?,\s*(?:\([^)]*\)\s*)?&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*"
        r"\"([A-Za-z0-9_]+)\"\s*,\s*\"([A-Za-z0-9_]+)\"",
        re.S,
    )
    pat_at = re.compile(
        r"\bhk_redir_install_at\s*\("
        r"[^,;]+,\s*[^,;]+,\s*(?:\([^)]*\)\s*)?&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
        re.S,
    )
    pat_syscall_slot = re.compile(
        r"\bdroid_lkm_slot_patch\s*\(\s*[^,;]+,\s*([A-Za-z0-9_]+)\s*,\s*"
        r"(?:\([^)]*\)\s*)?&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*,",
        re.S,
    )

    for p in c_files:
        r = rel(p, root)
        if r in ("src/hook/ds_hook.c", "src/hook/ds_hook.h"):
            continue
        raw = p.read_text(encoding="utf-8", errors="replace")
        no_comments = strip_c_comments(raw)
        seen_spans: Set[int] = set()

        for m in pat_slot.finditer(no_comments):
            seen_spans.add(m.start())
            repl, sym, wrap = m.group(1), m.group(2), m.group(3)
            line = no_comments.count("\n", 0, m.start()) + 1
            results.append(("hook-slot", sym, wrap, p, line))
            if repl != wrap:
                results.append(("hook-slot-mismatch", f"{sym}:{repl}!={wrap}", repl, p, line))

        for m in pat_two.finditer(no_comments):
            if m.start() in seen_spans:
                continue
            seen_spans.add(m.start())
            sym, wrap = m.group(2), m.group(3)
            line = no_comments.count("\n", 0, m.start()) + 1
            results.append(("hook", sym, wrap, p, line))

        for m in pat_at.finditer(no_comments):
            wrap = m.group(1)
            line = no_comments.count("\n", 0, m.start()) + 1
            results.append(("hook-at", "<addr>", wrap, p, line))

        for m in pat_syscall_slot.finditer(no_comments):
            nr_sym, fn = m.group(1), m.group(2)
            # Ignore generic loop variable `s->fn` or `fn` parameters inside helper definitions
            if fn in ("fn", "fn32"):
                continue
            line = no_comments.count("\n", 0, m.start()) + 1
            results.append(("syscall-slot", nr_sym, fn, p, line))

    return results


def check_hook_and_slot_entries(
    c_files: List[Path],
    fn_index: Dict[str, Tuple[Path, CFunction]],
    findings: List[Finding],
    root: Path = ROOT,
) -> int:
    entries = find_indirect_entries(c_files, root)
    checked = 0
    seen_wraps: Set[str] = set()

    for kind, sym, wrap, call_path, call_line in entries:
        if kind == "hook-slot-mismatch":
            findings.append(
                Finding(
                    "ERROR",
                    "hook-slot-name-mismatch",
                    rel(call_path, root),
                    call_line,
                    f"ds_hook_install_slot repl/wrap mismatch ({sym})",
                )
            )
            continue
        if wrap in seen_wraps:
            continue
        seen_wraps.add(wrap)
        checked += 1

        hit = fn_index.get(wrap)
        if not hit:
            findings.append(
                Finding(
                    "ERROR",
                    "hook-wrapper-missing",
                    rel(call_path, root),
                    call_line,
                    f"{kind} entry '{wrap}' (for '{sym}') definition not found in active src/",
                )
            )
            continue

        dp, fn = hit
        dr = rel(dp, root)
        is_misc = dr.startswith("src/misc/")
        hdr_raw = fn.header_raw

        if not has_token(hdr_raw, "__nocfi"):
            findings.append(
                Finding(
                    "ERROR",
                    "kcfi-missing-nocfi",
                    dr,
                    fn.header_line,
                    f"{kind} entry '{wrap}' (for '{sym}') definition is missing __nocfi (KCFI trap risk on 6.1+)",
                )
            )
        if not has_token(hdr_raw, "noinline"):
            findings.append(
                Finding(
                    "ERROR",
                    "hook-missing-noinline",
                    dr,
                    fn.header_line,
                    f"{kind} entry '{wrap}' (for '{sym}') definition is missing noinline",
                )
            )
        if not has_bti_entry_attr(hdr_raw):
            findings.append(
                Finding(
                    "WARN" if is_misc else "ERROR",
                    "bti-missing-entry",
                    dr,
                    fn.header_line,
                    f"{kind} entry '{wrap}' (for '{sym}') definition is missing DROID_LKM_ENTRY (BTI landing pad)",
                )
            )

        # Check forward prototypes in the same TU for attribute drift
        raw_text = strip_c_comments(dp.read_text(encoding="utf-8", errors="replace"))
        no_pp = mask_preprocessor(raw_text)
        proto_pat = re.compile(
            rf"(?:^|[;}}])\s*([^;{{}}]*?\b{re.escape(wrap)}\s*\([^;{{}}]*\))\s*;",
            re.S,
        )
        for pm in proto_pat.finditer(no_pp):
            proto = pm.group(1)
            # Ignore calls like `foo(wrap);` or assignments
            if "=" in proto or "return" in proto.split():
                continue
            pline = no_pp.count("\n", 0, pm.start(1)) + 1
            if pline == fn.header_line:
                continue
            if has_bti_entry_attr(hdr_raw) and not has_bti_entry_attr(proto):
                findings.append(
                    Finding(
                        "WARN",
                        "entry-proto-mismatch",
                        dr,
                        pline,
                        f"forward prototype of '{wrap}' omits DROID_LKM_ENTRY present on definition",
                    )
                )

    # Also verify macro-generated syscall thunks (DROID_LKM_IPC_THUNK / THUNK32)
    for p in c_files:
        if p.suffix != ".c":
            continue
        raw = strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        for macro_name in ("DROID_LKM_IPC_THUNK", "DROID_LKM_IPC_THUNK32"):
            m = re.search(
                rf"#\s*define\s+{macro_name}\s*\([^)]*\)(.*?)(?:\n(?!.*\\)|\Z)",
                raw,
                re.S,
            )
            if not m:
                continue
            # Grab full backslash-continued macro definition
            start = m.start()
            lines = raw[start:].splitlines()
            block_lines = []
            for ln in lines:
                block_lines.append(ln)
                if not ln.rstrip().endswith("\\"):
                    break
            block = "\n".join(block_lines)
            if "droid_lkm_thunk" in block:
                checked += 1
                if not has_bti_entry_attr(block):
                    line = raw.count("\n", 0, start) + 1
                    findings.append(
                        Finding(
                            "ERROR",
                            "bti-missing-entry",
                            rel(p, root),
                            line,
                            f"syscall thunk macro '{macro_name}' is missing DROID_LKM_ENTRY",
                        )
                    )

    return checked


# ---------------------------------------------------------------------------
# Rule 2: KCFI __nocfi enforcement on ALL trampoline & ksym indirect callers
# ---------------------------------------------------------------------------

def collect_sym_bound_fnptrs(no_comments: str, masked: str) -> Set[str]:
    """Identify file-local/local function pointer identifiers bound via *_sym()
    or hook .orig fields, or explicitly declared as `(*name)(...)`."""
    ptrs: Set[str] = set()
    # Assignments from droid_lkm_sym / ds_compat_sym / dlc_vendor_syms.* / .orig
    pat_assign = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;]*\)\s*)?"
        r"(?:droid_lkm_sym|ds_compat_sym|droid_lkm_misc_sym)\s*\(",
        re.S,
    )
    for m in pat_assign.finditer(no_comments):
        ptrs.add(m.group(1))

    pat_orig_assign = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;]*\)\s*)?"
        r"(?:READ_ONCE\s*\(\s*)?[A-Za-z_][A-Za-z0-9_]*(?:\.orig|_orig\b)",
        re.S,
    )
    for m in pat_orig_assign.finditer(masked):
        ptrs.add(m.group(1))

    pat_symtab_copy = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;]*\)\s*)?"
        r"(?:dlc_vendor_syms|droid_lkm_ks)\.[A-Za-z0-9_]+",
        re.S,
    )
    for m in pat_symtab_copy.finditer(masked):
        ptrs.add(m.group(1))

    # Also ignore common non-fnptr locals like `addr`, `sym_addr`, `ret`
    ptrs -= {"addr", "sym_addr", "fn_addr", "ret", "val", "p", "raw_text"}
    return ptrs


def check_kcfi_indirect_calls(
    c_files: List[Path],
    parsed: Dict[Path, Tuple[str, str, List[CFunction]]],
    findings: List[Finding],
    root: Path = ROOT,
) -> int:
    """Ensure every C function invoking a hook trampoline or kallsyms-resolved
    function pointer carries __nocfi."""
    # Direct patterns always requiring __nocfi
    always_pat = re.compile(
        r"\b(?:"
        r"([A-Za-z_][A-Za-z0-9_]*_orig)\s*\(|"
        r"(droid_lkm_orig(?:32)?_[A-Za-z0-9_]+)\s*\(|"
        r"(droid_lkm_ks\.[A-Za-z_][A-Za-z0-9_]*)\s*\(|"
        r"(dlc_vendor_syms\.[A-Za-z_][A-Za-z0-9_]*)\s*\(|"
        r"\(\s*\*\s*(orig)\s*\)\s*\("
        r")"
    )
    # Cast-and-call of resolved address: `((type (*)(...))fn)(...)`
    cast_call_pat = re.compile(r"\(\s*\([^)]*\(\s*\*\s*\)\s*\([^)]*\)\s*\)\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(")

    checked = 0
    for p in c_files:
        r = rel(p, root)
        no_comments, masked, funcs = parsed[p]
        bound_ptrs = collect_sym_bound_fnptrs(no_comments, masked)
        bound_pat = (
            re.compile(r"\b(" + "|".join(re.escape(x) for x in sorted(bound_ptrs)) + r")\s*\(")
            if bound_ptrs
            else None
        )

        for fn in funcs:
            calls: List[Tuple[int, str]] = []
            for m in always_pat.finditer(fn.body_masked):
                callee = next(g for g in m.groups() if g is not None)
                # Exclude `droid_lkm_ks.field` when preceded by `->` or `.`? Not possible with \b.
                calls.append((m.start(), callee))
            for m in cast_call_pat.finditer(fn.body_masked):
                calls.append((m.start(), "<cast-fnptr>"))
            if bound_pat:
                for m in bound_pat.finditer(fn.body_masked):
                    callee = m.group(1)
                    # Skip function pointer declarations like `(*orig)(...)` inside typedef/decl
                    before = fn.body_masked[max(0, m.start() - 8) : m.start()]
                    if re.search(r"typeof\s*\(\s*&?\s*$", before):
                        continue
                    calls.append((m.start(), callee))

            if not calls:
                continue

            checked += 1
            calls.sort(key=lambda x: x[0])
            first_off, first_callee = calls[0]
            call_line = masked.count("\n", 0, fn.body_start + first_off) + 1

            if fn.is_syscall_define:
                # SYSCALL_DEFINE puts body in inner __do_sys_* where outer __nocfi does not apply!
                findings.append(
                    Finding(
                        "WARN",
                        "kcfi-syscall-define-indirect",
                        r,
                        call_line,
                        f"{fn.name} invokes '{first_callee}()' directly inside SYSCALL_DEFINE body; "
                        f"move call into a static __nocfi noinline helper",
                    )
                )
            elif not has_token(fn.header_raw, "__nocfi"):
                findings.append(
                    Finding(
                        "ERROR",
                        "kcfi-call-missing-nocfi",
                        r,
                        call_line,
                        f"function '{fn.name}' invoking '{first_callee}()' is missing __nocfi",
                    )
                )

    return checked


# ---------------------------------------------------------------------------
# Rule 3: Raw kallrecon_klp() guard (scoped exemption for ds_ksym.c verbose block)
# ---------------------------------------------------------------------------

def check_raw_kallrecon_klp(c_files: List[Path], findings: List[Finding], root: Path = ROOT) -> None:
    allow_files = {"src/compat/ds_compat.c"}
    pat = re.compile(r"\bkallrecon_klp\s*\(")
    for p in c_files:
        r = rel(p, root)
        if r in allow_files:
            continue
        no_comments = strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in pat.finditer(no_comments):
            line = no_comments.count("\n", 0, m.start()) + 1
            # Narrow exemption: ds_ksym.c verbose diagnostic probe inside `if (droid_lkm_verbose) { ... }`
            if r == "src/main/core/ds_ksym.c":
                ctx_before = no_comments[max(0, m.start() - 400) : m.start()]
                if "if (droid_lkm_verbose)" in ctx_before and "}" not in ctx_before.split("if (droid_lkm_verbose)")[-1]:
                    continue
            level = "WARN" if r.startswith("src/misc/") else "ERROR"
            findings.append(
                Finding(
                    level,
                    "raw-kallrecon-klp",
                    r,
                    line,
                    "direct kallrecon_klp() call bypasses kallsyms_name_to_addr fallback & shim guard; use ds_compat_sym()/droid_lkm_sym()",
                )
            )


# ---------------------------------------------------------------------------
# Rule 4: Cross-kernel ABI & vendorcompat guards
# ---------------------------------------------------------------------------

def check_import_ns_macro(c_files: List[Path], findings: List[Finding], root: Path = ROOT) -> None:
    pat = re.compile(r"\bMODULE_IMPORT_NS\s*\(")
    for p in c_files:
        r = rel(p, root)
        if r == "src/main/core/ds.h":
            continue
        no_comments = strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in pat.finditer(no_comments):
            line = no_comments.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    "ERROR",
                    "raw-module-import-ns",
                    r,
                    line,
                    "raw MODULE_IMPORT_NS() breaks Linux 6.18 stringified namespace ABI; use DROID_LKM_IMPORT_NS()",
                )
            )


def check_ns_common_ops(
    c_files: List[Path],
    parsed: Dict[Path, Tuple[str, str, List[CFunction]]],
    findings: List[Finding],
    root: Path = ROOT,
) -> None:
    """Detect direct writes to struct ns_common::ops in src/main/ (must use droid_lkm_ns_set_ops)."""
    pat_dot_ns = re.compile(r"\.\s*ns\s*\.\s*ops\s*=(?!=)")
    pat_arrow_ns = re.compile(r"->\s*ns\s*\.\s*ops\s*=(?!=)")

    for p in c_files:
        r = rel(p, root)
        if not r.startswith("src/main/") or r == "src/main/core/ds.h":
            continue
        no_comments, masked, funcs = parsed[p]

        # Static/global `.ns.ops = ...` initializers (allow when `.ns.ns_type =` is right beside it for 6.18+)
        for m in pat_dot_ns.finditer(masked):
            tail_window = no_comments[m.end() : m.end() + 240]
            if re.search(r"\.\s*ns\s*\.\s*ns_type\s*=", tail_window):
                continue
            line = masked.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    "WARN",
                    "raw-ns-common-ops",
                    r,
                    line,
                    "direct '.ns.ops =' skips Linux 6.18 ns_common::ns_type initialization; verify 6.18 compat or use droid_lkm_ns_set_ops()",
                )
            )

        for fn in funcs:
            for m in pat_arrow_ns.finditer(fn.body_masked):
                line = masked.count("\n", 0, fn.body_start + m.start()) + 1
                findings.append(
                    Finding(
                        "ERROR",
                        "raw-ns-common-ops",
                        r,
                        line,
                        f"direct '->ns.ops =' in '{fn.name}' bypasses droid_lkm_ns_set_ops() (breaks Linux 6.18 ns_type)",
                    )
                )

            # Type-aware check for `struct ns_common *<var>` -> `<var>->ops = ...`
            # droid_lkm_ns_neutralize intentionally swaps ops in-place while preserving ns_type.
            if fn.name == "droid_lkm_ns_neutralize":
                continue
            scope = fn.header_masked + "\n" + fn.body_masked
            ns_vars = set(
                re.findall(r"\bstruct\s+ns_common\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\b", scope)
            )
            if ns_vars:
                vpat = re.compile(
                    r"\b(" + "|".join(re.escape(v) for v in sorted(ns_vars)) + r")\s*->\s*ops\s*=(?!=)"
                )
                for m in vpat.finditer(fn.body_masked):
                    line = masked.count("\n", 0, fn.body_start + m.start()) + 1
                    findings.append(
                        Finding(
                            "WARN",
                            "raw-ns-common-ops",
                            r,
                            line,
                            f"direct '{m.group(1)}->ops =' in '{fn.name}' bypasses droid_lkm_ns_set_ops() (verify Linux 6.18 ns_type)",
                        )
                    )


def check_ti_and_mqueue_invariants(
    c_files: List[Path],
    parsed: Dict[Path, Tuple[str, str, List[CFunction]]],
    findings: List[Finding],
    root: Path = ROOT,
) -> None:
    """Guard against recurring P0 kernel hazards:
      1. ti_init() must be guarded by ti_ready() to prevent duplicate module_notifier registration
      2. Modules calling ds_compat_layout_init() must pair with ds_compat_layout_exit()
      3. droid_lkm_mq_kill_sb must invoke kill_litter_super or d_genocide (prevent fs/super.c BUG)
    """
    for p in c_files:
        r = rel(p, root)
        no_comments, masked, funcs = parsed[p]

        for fn in funcs:
            # 1. Unguarded ti_init()
            if re.search(r"\bti_init\s*\(", fn.body_masked):
                if not re.search(r"\bti_ready\s*\(", fn.body_masked):
                    m = re.search(r"\bti_init\s*\(", fn.body_masked)
                    line = masked.count("\n", 0, fn.body_start + (m.start() if m else 0)) + 1
                    findings.append(
                        Finding(
                            "ERROR",
                            "ti-init-unguarded",
                            r,
                            line,
                            f"'{fn.name}' calls ti_init() without ti_ready() guard (duplicate register_module_notifier risk)",
                        )
                    )

            # 2. mqueue kill_sb must run kill_litter_super or d_genocide
            if fn.name == "droid_lkm_mq_kill_sb":
                combined = fn.body_masked
                # Also follow single-hop helper if droid_lkm_mq_kill_sb delegates to *_call()
                m_helper = re.search(r"\b(droid_lkm_mq_kill_sb_[A-Za-z0-9_]+)\s*\(", combined)
                if m_helper:
                    hname = m_helper.group(1)
                    for ofn in funcs:
                        if ofn.name == hname:
                            combined += "\n" + ofn.body_masked
                if not re.search(r"\b(?:kill_litter_super|d_genocide|droid_lkm_p_kill_litter_super|droid_lkm_p_d_genocide)\b", combined):
                    findings.append(
                        Finding(
                            "ERROR",
                            "mq-kill-sb-unsafe",
                            r,
                            fn.header_line,
                            "droid_lkm_mq_kill_sb does not invoke kill_litter_super/d_genocide (triggers VFS Busy inodes BUG at umount)",
                        )
                    )

    # Check that each module domain using ds_compat_layout_init also calls ds_compat_layout_exit
    for domain, prefix in (("main", "src/main/"), ("vendor", "src/compat/vendor/")):
        dom_files = [p for p in c_files if rel(p, root).startswith(prefix) and p.suffix == ".c"]
        if not dom_files:
            continue
        has_init = any(
            re.search(r"\bds_compat_layout_init\s*\(", parsed[p][1]) for p in dom_files
        )
        has_exit = any(
            re.search(r"\bds_compat_layout_exit\s*\(", parsed[p][1]) for p in dom_files
        )
        if has_init and not has_exit:
            findings.append(
                Finding(
                    "ERROR",
                    "ti-exit-missing",
                    prefix,
                    1,
                    f"module domain '{domain}' calls ds_compat_layout_init() but never calls ds_compat_layout_exit() (dangling module notifier on unload/init-fail)",
                )
            )


def check_hk_cfg_write_path(c_files: List[Path], findings: List[Finding], root: Path = ROOT) -> None:
    """Warn if a struct hk_cfg initializer omits `.write = hk_write_kernel`."""
    pat = re.compile(r"\bstruct\s+hk_cfg\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{([^}]*)\}", re.S)
    for p in c_files:
        r = rel(p, root)
        if r.startswith("src/misc/"):
            continue
        no_comments = strip_c_comments(p.read_text(encoding="utf-8", errors="replace"))
        for m in pat.finditer(no_comments):
            body = m.group(1)
            if not re.search(r"\.write\s*=\s*hk_write_kernel\b", body):
                line = no_comments.count("\n", 0, m.start()) + 1
                findings.append(
                    Finding(
                        "WARN",
                        "hk-cfg-write-path",
                        r,
                        line,
                        "struct hk_cfg omits '.write = hk_write_kernel' (risk of fixmap protection fault on MTK/OEM kernels)",
                    )
                )


# ---------------------------------------------------------------------------
# Rule 5: Type-aware layout-managed struct field deref check
# ---------------------------------------------------------------------------

def extract_managed_layout_fields(root: Path = ROOT) -> Dict[str, Set[str]]:
    """Collect {struct_name: {member_names}} managed by ds_ti.c & vendor layout tables."""
    managed: Dict[str, Set[str]] = {}
    ti = root / "src/main/core/ds_ti.c"
    if ti.exists():
        no_pp = mask_preprocessor(strip_c_comments(ti.read_text(encoding="utf-8", errors="replace")))
        for m in re.finditer(
            r"DROID_LKM_FIELD(?:_SYSV|_MQ|_ARR|_SYSV_ARR)?\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\)",
            no_pp,
        ):
            managed.setdefault(m.group(1), set()).add(m.group(2))

    # Also collect vendor ds_compat_field tables
    vendor_dir = root / "src/compat/vendor"
    if vendor_dir.exists():
        for vp in sorted(vendor_dir.glob("*.c")):
            txt = strip_c_comments(vp.read_text(encoding="utf-8", errors="replace"))
            for m in re.finditer(
                r'\.type\s*=\s*"([A-Za-z0-9_]+)"\s*,\s*\.member\s*=\s*"([A-Za-z0-9_]+)"',
                txt,
            ):
                managed.setdefault(m.group(1), set()).add(m.group(2))

    # Note: ipc_namespace in src/main/ipcns/ is accessed through module-owned helpers/macros
    # when CONFIG_IPC_NS=n; keep kernel-owned structures always audited here.
    return managed


def check_layout_direct_deref(
    parsed: Dict[Path, Tuple[str, str, List[CFunction]]],
    findings: List[Finding],
    root: Path = ROOT,
    managed_override: Optional[Dict[str, Set[str]]] = None,
) -> int:
    """Type-aware detection of direct dereferences to layout-managed struct fields."""
    managed = managed_override if managed_override is not None else extract_managed_layout_fields(root)
    # Focus on kernel-owned structs where compile-time offset drift breaks OEM kernels.
    # (ipc_namespace is checked separately because IPC port code owns its fields via macros in ipc_compat.)
    audited_structs = {
        k: v
        for k, v in managed.items()
        if k in ("task_struct", "nsproxy", "pid_namespace", "pid", "upid", "seq_file")
    }
    if not audited_structs:
        return 0

    skip_files = {
        "src/main/core/ds.h",
        "src/main/core/ds_ti.h",
        "src/main/core/ds_ti.c",
        "src/compat/ds_layout_anchor.c",
    }
    struct_alt = "|".join(re.escape(s) for s in sorted(audited_structs))
    decl_pat = re.compile(
        rf"\bstruct\s+({struct_alt})\s*(?:const\s+)?\*\s*(?:__rcu\s+|__user\s+)?([A-Za-z_][A-Za-z0-9_]*)\b"
    )
    sizeof_pat = re.compile(r"\bsizeof\s*\(\s*struct\s+(pid_namespace|upid|ipc_ids)\s*\)")

    count = 0
    for p, (no_comments, masked, funcs) in sorted(parsed.items()):
        r = rel(p, root)
        if not (r.startswith("src/main/") or r.startswith("src/compat/vendor/")):
            continue
        if r in skip_files:
            continue

        # Check raw sizeof(struct pid_namespace|upid|ipc_ids) outside layout-aware size helpers
        for m in sizeof_pat.finditer(masked):
            pos = m.start()
            enclosing = next((fn for fn in funcs if fn.body_start <= pos < fn.body_end), None)
            if enclosing and "droid_lkm_layout_type_size" in enclosing.body_masked:
                continue
            line = masked.count("\n", 0, pos) + 1
            count += 1
            findings.append(
                Finding(
                    "WARN",
                    "layout-direct-sizeof",
                    r,
                    line,
                    f"direct 'sizeof(struct {m.group(1)})' uses compile-time size; prefer layout size helper",
                )
            )

        # File-scope pointers to audited structs (strip function bodies before scanning globals)
        file_vars: Dict[str, str] = {"current": "task_struct"}
        top_parts: List[str] = []
        cursor = 0
        for fn in funcs:
            top_parts.append(masked[cursor : fn.body_start])
            cursor = fn.body_end
        top_parts.append(masked[cursor:])
        file_scope_text = "\n".join(top_parts)
        for dm in decl_pat.finditer(file_scope_text):
            file_vars[dm.group(2)] = dm.group(1)

        for fn in funcs:
            fn_vars = dict(file_vars)
            scope = fn.header_masked + "\n" + fn.body_masked
            for dm in decl_pat.finditer(scope):
                st_type, var_name = dm.group(1), dm.group(2)
                fn_vars[var_name] = st_type

            # Check `<var>-><member>` for every known variable of an audited struct
            for var_name, st_type in sorted(fn_vars.items()):
                fields = audited_structs.get(st_type)
                if not fields:
                    continue
                f_alt = "|".join(re.escape(f) for f in sorted(fields))
                use_pat = re.compile(rf"\b{re.escape(var_name)}\s*->\s*({f_alt})\b")
                for um in use_pat.finditer(fn.body_masked):
                    # Ignore `->` preceded by `.` or `->` (e.g. `nsset->nsproxy->ipc_ns` is handled if nsproxy var,
                    # wait: `a->b->c` should NOT match `b` as a standalone variable of different struct!).
                    prev = fn.body_masked[max(0, um.start() - 2) : um.start()]
                    if prev.endswith(".") or prev.endswith("->"):
                        continue
                    line = masked.count("\n", 0, fn.body_start + um.start()) + 1
                    count += 1
                    findings.append(
                        Finding(
                            "WARN",
                            "layout-direct-deref",
                            r,
                            line,
                            f"direct '{var_name}->{um.group(1)}' (struct {st_type}) uses compile-time offset; prefer layout helper",
                        )
                    )

    return count


# ---------------------------------------------------------------------------
# Rule 6: Kbuild / shell / Gradle packaging & deps checks
# ---------------------------------------------------------------------------

def check_makefile_objects(findings: List[Finding], root: Path = ROOT) -> int:
    mk = root / "Makefile"
    if not mk.exists():
        return 0
    text = mk.read_text(encoding="utf-8", errors="replace")
    active_lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    active = "\n".join(active_lines)
    misc_enabled = bool(re.search(r"^\s*obj-\$\(DLKM_OPT\)\s*\+=\s*droid_lkm_misc\.o", active, re.M))
    checked = 0
    for m in re.finditer(r"\b(src/[A-Za-z0-9_./-]+\.o)\b", active):
        obj = m.group(1)
        if not misc_enabled and obj.startswith("src/misc/"):
            continue
        checked += 1
        c_file = root / (obj[:-2] + ".c")
        s_file = root / (obj[:-2] + ".S")
        if not c_file.exists() and not s_file.exists():
            findings.append(
                Finding(
                    "ERROR",
                    "makefile-missing-src",
                    "Makefile",
                    1,
                    f"active object '{obj}' has no corresponding .c or .S source",
                )
            )
    return checked


def check_shell_and_packaging(findings: List[Finding], root: Path = ROOT) -> int:
    sh_files: List[Path] = []
    for folder in (root / "module", root / "scripts"):
        if folder.exists():
            sh_files.extend(sorted(folder.rglob("*.sh")))

    checked = 0
    for sf in sh_files:
        checked += 1
        res = subprocess.run(["sh", "-n", str(sf)], capture_output=True, text=True)
        if res.returncode != 0:
            findings.append(
                Finding(
                    "ERROR",
                    "shell-syntax",
                    rel(sf, root),
                    1,
                    res.stderr.strip() or "sh -n failed",
                )
            )

    placeholders = [
        (root / "module/customize.sh", "# @@PHDROID_CUSTOMIZE_VARIANTS@@"),
        (root / "module/service.sh", "# @@PHDROID_SERVICE_VARIANTS@@"),
    ]
    for path, token in placeholders:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            if token not in content:
                findings.append(
                    Finding(
                        "ERROR",
                        "gradle-placeholder-missing",
                        rel(path, root),
                        1,
                        f"expected Gradle injection placeholder '{token}' not found",
                    )
                )

    for variant in ("standard", "native", "both"):
        for kind in ("customize", "service"):
            vp = root / f"module/variants/{kind}_{variant}.sh"
            if (root / "module/variants").exists() and not vp.exists():
                findings.append(
                    Finding(
                        "ERROR",
                        "variant-snippet-missing",
                        rel(vp, root),
                        1,
                        "variant snippet referenced by build.gradle is missing",
                    )
                )
    return checked


def check_deps_present(findings: List[Finding], root: Path = ROOT) -> None:
    deps_lst = root / "deps.lst"
    if not deps_lst.exists():
        return
    for ln in deps_lst.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        name, rev = parts[0], parts[1]
        p = (root / ".sdk" / "builtin" / name) if rev == "-" else (root / "deps" / name)
        if not p.exists():
            findings.append(
                Finding(
                    "WARN",
                    "deps-not-fetched",
                    "deps.lst",
                    1,
                    f"dependency '{name}' ({rev}) missing at {rel(p, root)}; run scripts/fetch-deps.sh",
                )
            )


# ---------------------------------------------------------------------------
# Driver & built-in self-test suite
# ---------------------------------------------------------------------------

def run_checks(
    root: Path = ROOT,
    include_misc: bool = False,
    managed_override: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[List[Finding], Dict[str, int]]:
    findings: List[Finding] = []
    c_files = iter_c_files(root / "src", include_misc=include_misc, root=root)

    parsed: Dict[Path, Tuple[str, str, List[CFunction]]] = {}
    fn_index: Dict[str, Tuple[Path, CFunction]] = {}
    for p in c_files:
        raw = p.read_text(encoding="utf-8", errors="replace")
        no_comments, no_pp, masked = preprocess_c_source(raw)
        funcs = iter_c_functions(no_pp, masked)
        parsed[p] = (no_comments, masked, funcs)
        if p.suffix == ".c":
            for fn in funcs:
                fn_index.setdefault(fn.name, (p, fn))

    n_entries = check_hook_and_slot_entries(c_files, fn_index, findings, root=root)
    n_kcfi = check_kcfi_indirect_calls(c_files, parsed, findings, root=root)
    check_raw_kallrecon_klp(c_files, findings, root=root)
    check_import_ns_macro(c_files, findings, root=root)
    check_ns_common_ops(c_files, parsed, findings, root=root)
    check_ti_and_mqueue_invariants(c_files, parsed, findings, root=root)
    check_hk_cfg_write_path(c_files, findings, root=root)
    n_deref = check_layout_direct_deref(
        parsed, findings, root=root, managed_override=managed_override
    )
    n_objs = check_makefile_objects(findings, root=root)
    n_sh = check_shell_and_packaging(findings, root=root)
    check_deps_present(findings, root=root)

    stats = {
        "files": len(c_files),
        "entries": n_entries,
        "kcfi_callers": n_kcfi,
        "derefs": n_deref,
        "objs": n_objs,
        "shells": n_sh,
    }
    return findings, stats


def run_self_test() -> int:
    """Verify every rule catches real regressions and produces 0 false positives on clean code."""
    managed = {
        "task_struct": {"pid", "tgid", "comm", "nsproxy"},
        "nsproxy": {"ipc_ns", "pid_ns_for_children"},
        "pid_namespace": {"level", "child_reaper"},
    }
    cases: List[Tuple[str, str, str, Set[str]]] = [
        (
            "clean_complex_c",
            "src/main/slot/clean.c",
            """
            #ifdef DROID_LKM_ENTRY
            #define NOISE_MACRO(x) \\
                do { if (x) { /* } */ } } while (0)
            #endif
            static DROID_LKM_ENTRY __nocfi noinline long good_wrap(struct task_struct *t)
            {
                const char *braces = "{{{ } }";
                char ch = '}';
                if (braces[0] == ch)
                    return droid_lkm_orig_unshare(0);
                return droid_lkm_ks.kernel_wait4(0, 0, 0, 0);
            }
            static struct hk_cfg good_cfg = {
                .resolve = good_res,
                .write = hk_write_kernel,
            };
            static int init_fn(void)
            {
                ds_hook_install(&h, "foo", "good_wrap");
                droid_lkm_slot_patch(tab, __NR_unshare, (unsigned long)good_wrap, &orig);
                return 0;
            }
            """,
            set(),
        ),
        (
            "pp_cannot_spoof_attrs",
            "src/main/slot/spoof.c",
            """
            #ifdef DROID_LKM_ENTRY
            #define DUMMY __nocfi noinline
            #endif
            static long bad_slot_entry(const struct pt_regs *regs)
            {
                return droid_lkm_orig_unshare(regs);
            }
            static void wire(void)
            {
                droid_lkm_slot_patch(tab, __NR_unshare, (unsigned long)bad_slot_entry, &o);
            }
            """,
            {"kcfi-missing-nocfi", "hook-missing-noinline", "bti-missing-entry", "kcfi-call-missing-nocfi"},
        ),
        (
            "braces_in_strings_cannot_blind_kcfi",
            "src/main/core/strbrace.c",
            """
            static void decoy(void)
            {
                const char *s = "{{{{{{";
                (void)s;
            }
            static void bad_caller(void)
            {
                droid_lkm_ks.proc_free_inum(1);
            }
            """,
            {"kcfi-call-missing-nocfi"},
        ),
        (
            "hk_redir_install_at_and_bound_fnptr",
            "src/compat/vendor/at_case.c",
            """
            static void (*my_helper)(int);
            static void my_wrap(struct task_struct *victim)
            {
                int x = victim->tgid;
                my_helper(x);
            }
            static void init_at(void)
            {
                my_helper = (void *)ds_compat_sym("kernel_fn");
                hk_redir_install_at(&h, addr, (unsigned long)my_wrap, HK_REDIR_KPROBE);
            }
            """,
            {
                "kcfi-missing-nocfi",
                "hook-missing-noinline",
                "bti-missing-entry",
                "kcfi-call-missing-nocfi",
                "layout-direct-deref",
            },
        ),
        (
            "type_aware_nsproxy_and_abi_checks",
            "src/main/pidns/abi_bad.c",
            """
            MODULE_IMPORT_NS(VFS_internal);
            static void bad_abi(struct nsproxy *nsp, struct ns_common *c)
            {
                void *x = nsp->ipc_ns;
                unsigned long k = kallrecon_klp("foo");
                c->ops = x;
                (void)k;
            }
            static struct hk_cfg bad_cfg = { .resolve = foo };
            """,
            {
                "raw-module-import-ns",
                "layout-direct-deref",
                "raw-kallrecon-klp",
                "raw-ns-common-ops",
                "hk-cfg-write-path",
            },
        ),
        (
            "ipc_thunk_macro_missing_bti",
            "src/main/slot/thunk_bad.c",
            """
            #define DROID_LKM_IPC_THUNK(name) \\
                static long droid_lkm_thunk_##name(const struct pt_regs *regs) \\
                { return 0; }
            """,
            {"bti-missing-entry"},
        ),
        (
            "ti_init_unguarded_and_unsafe_mq_kill_sb",
            "src/main/ipcns/mqueue/bad_mq.c",
            """
            static bool bad_layout(struct ds_compat_layout *l)
            {
                if (ti_init(&res))
                    return false;
                return ds_compat_layout_init(l);
            }
            void droid_lkm_mq_kill_sb(struct super_block *sb)
            {
                kill_anon_super(sb);
            }
            """,
            {"ti-init-unguarded", "ti-exit-missing", "mq-kill-sb-unsafe"},
        ),
        (
            "file_scope_global_task_ptr_deref",
            "src/compat/vendor/global_deref.c",
            """
            static struct task_struct *g_sentinel;
            static int bad_global_read(void)
            {
                return g_sentinel->pid;
            }
            """,
            {"layout-direct-deref"},
        ),
    ]

    failures = 0
    for cname, relpath, src, expected_rules in cases:
        with tempfile.TemporaryDirectory(prefix="dlkm_selftest_") as td:
            troot = Path(td)
            fpath = troot / relpath
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(src, encoding="utf-8")
            findings, _ = run_checks(root=troot, include_misc=False, managed_override=managed)
            got_rules = {f.rule for f in findings}
            if got_rules != expected_rules:
                failures += 1
                print(
                    f"[FAIL] self-test '{cname}': expected={sorted(expected_rules)} got={sorted(got_rules)}"
                )
                for f in findings:
                    print(f"       [{f.level}] ({f.rule}) {f.path}:{f.line}: {f.message}")
            else:
                print(f"[PASS] self-test '{cname}' -> {sorted(got_rules) or ['clean']}")

    print(f"\nself-test summary: {len(cases) - failures}/{len(cases)} passed")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Static invariant guard for droid_lkm")
    ap.add_argument("--include-misc", action="store_true", help="also scan src/misc/")
    ap.add_argument("--strict", action="store_true", help="treat WARN as exit-code failure")
    ap.add_argument("--self-test", action="store_true", help="run built-in positive/negative checker tests")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()

    findings, stats = run_checks(root=ROOT, include_misc=args.include_misc)
    errors = [f for f in findings if f.level == "ERROR"]
    warns = [f for f in findings if f.level == "WARN"]

    print("== droid_lkm static invariant check ==")
    print(
        f"scanned: {stats['files']} active C/H files, {stats['entries']} indirect entries, "
        f"{stats['kcfi_callers']} KCFI indirect callers, {stats['objs']} Kbuild objects, "
        f"{stats['shells']} shell scripts"
    )
    print(f"result : {len(errors)} ERROR, {len(warns)} WARN (layout hits: {stats['derefs']})")
    for f in findings:
        print(f"[{f.level}] ({f.rule}) {f.path}:{f.line}: {f.message}")

    if errors or (args.strict and warns):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
