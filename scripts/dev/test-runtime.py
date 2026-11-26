#!/usr/bin/env python3
"""Safe userspace runtime regression tests for droid_lkm & droid_lkm_misc.

Runs completely in userspace with ephemeral child processes and strict cleanup.
NEVER touches insmod/rmmod, /data/adb, reboot with valid magic, or system config.

Usage:
  sudo python3 scripts/dev/test-runtime.py              # host-side safe suite
  sudo python3 scripts/dev/test-runtime.py --lyra       # host + ssh lyra safe suite
  sudo python3 scripts/dev/test-runtime.py --stress     # include fault-injection / teardown / concurrency stress
  python3 scripts/dev/test-runtime.py --only-lyra       # container-side tests only
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import mmap
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple


# AArch64 Linux syscall numbers (asm-generic/unistd.h; bionic omits SysV IPC / mq_*)
NR_UNSHARE = 97
NR_PRCTL = 167
NR_GETPID = 172
NR_MQ_OPEN = 180
NR_MQ_UNLINK = 181
NR_MQ_TIMEDSEND = 182
NR_MQ_TIMEDRECEIVE = 183
NR_MQ_GETSETATTR = 185
NR_MSGGET = 186
NR_MSGCTL = 187
NR_MSGRCV = 188
NR_MSGSND = 189
NR_SEMGET = 190
NR_SEMCTL = 191
NR_SEMOP = 193
NR_SHMGET = 194
NR_SHMCTL = 195
NR_SHMAT = 196
NR_SHMDT = 197
NR_CLONE = 220
NR_SETNS = 268
NR_CLONE3 = 435

IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
IPC_NOWAIT = 0o4000
IPC_RMID = 0
IPC_STAT = 2
SHM_RDONLY = 0o10000
SEM_UNDO = 0x1000
SETVAL = 16
GETVAL = 12

SIGCHLD = int(signal.SIGCHLD)
CLONE_NEWTIME = 0x00000080
CLONE_THREAD = 0x00010000
CLONE_NEWNS = 0x00020000
CLONE_SYSVSEM = 0x00040000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

O_RDWR = 2
O_CREAT = 0o100
O_EXCL = 0o200
O_NONBLOCK = 0o4000

PROT_READ = 1


class Sembuf(ctypes.Structure):
    _fields_ = [
        ("sem_num", ctypes.c_ushort),
        ("sem_op", ctypes.c_short),
        ("sem_flg", ctypes.c_short),
    ]


class MqAttr(ctypes.Structure):
    _fields_ = [
        ("mq_flags", ctypes.c_long),
        ("mq_maxmsg", ctypes.c_long),
        ("mq_msgsize", ctypes.c_long),
        ("mq_curmsgs", ctypes.c_long),
        ("__reserved", ctypes.c_long * 4),
    ]


class Msgbuf(ctypes.Structure):
    _fields_ = [
        ("mtype", ctypes.c_long),
        ("mtext", ctypes.c_char * 64),
    ]


class Timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    ]


class CloneArgs(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("pidfd", ctypes.c_uint64),
        ("child_tid", ctypes.c_uint64),
        ("parent_tid", ctypes.c_uint64),
        ("exit_signal", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint64),
        ("tls", ctypes.c_uint64),
        ("set_tid", ctypes.c_uint64),
        ("set_tid_size", ctypes.c_uint64),
        ("cgroup", ctypes.c_uint64),
    ]


_LIBC: Optional[ctypes.CDLL] = None


def get_libc() -> ctypes.CDLL:
    global _LIBC
    if _LIBC is None:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        _LIBC = libc
    return _LIBC


def sys_call(nr: int, *args: object) -> Tuple[int, int]:
    libc = get_libc()
    ctypes.set_errno(0)
    c_args = []
    for a in args:
        if isinstance(a, int):
            c_args.append(ctypes.c_long(a))
        else:
            c_args.append(a)
    ret = int(libc.syscall(ctypes.c_long(nr), *c_args))
    err = ctypes.get_errno()
    return ret, err


def raw_getpid() -> int:
    """Bypass any libc PID caching after raw clone/clone3 syscalls."""
    pid, _ = sys_call(NR_GETPID)
    return pid


def u64_addr(val: int) -> int:
    return val & 0xFFFFFFFFFFFFFFFF


def read_ns_link(kind: str, pid: str = "self") -> str:
    p = f"/proc/{pid}/ns/{kind}"
    try:
        return os.readlink(p)
    except OSError:
        return ""


@dataclass
class TestResult:
    name: str
    status: str  # PASS, FAIL, SKIP
    detail: str


def run_in_child(fn: Callable[[], Tuple[str, str]], timeout: float = 10.0) -> Tuple[str, str]:
    """Run an isolated test inside a forked child and return (status, detail)."""
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        try:
            st, detail = fn()
        except Exception as exc:
            st, detail = "FAIL", f"exception: {exc!r}"
        payload = json.dumps([st, detail]).encode("utf-8")
        try:
            view = memoryview(payload)
            while view:
                written = os.write(w_fd, view)
                view = view[written:]
        except OSError:
            pass
        finally:
            try:
                os.close(w_fd)
            except OSError:
                pass
            os._exit(0)

    os.close(w_fd)
    deadline = time.monotonic() + timeout
    while True:
        wpid, wstatus = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            break
        if time.monotonic() > deadline:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            os.close(r_fd)
            return "FAIL", f"child timed out after {timeout}s"
        time.sleep(0.02)

    chunks = []
    while True:
        b = os.read(r_fd, 4096)
        if not b:
            break
        chunks.append(b)
    os.close(r_fd)

    if os.WIFSIGNALED(wstatus):
        return "FAIL", f"child killed by signal {os.WTERMSIG(wstatus)}"
    if not chunks:
        return "FAIL", f"child exited with status {os.WEXITSTATUS(wstatus)} without output"
    try:
        data = json.loads(b"".join(chunks).decode("utf-8"))
        return data[0], data[1]
    except Exception as exc:
        return "FAIL", f"invalid child JSON payload: {exc!r}"


def run_in_raw_clone(
    use_clone3: bool,
    flags: int,
    child_fn: Callable[[], Tuple[str, str]],
    timeout: float = 8.0,
) -> Tuple[str, str, Optional[int], int]:
    """Execute child_fn in a child spawned via raw clone(2) or clone3(2).
    Returns (status, detail, clone_ret_or_none, errno)."""
    r_fd, w_fd = os.pipe()
    cargs = CloneArgs(flags=flags, exit_signal=SIGCHLD) if use_clone3 else None
    orig_flags = flags

    if use_clone3:
        pid, err = sys_call(NR_CLONE3, ctypes.byref(cargs), ctypes.sizeof(cargs))
    else:
        pid, err = sys_call(NR_CLONE, flags | SIGCHLD, 0, 0, 0, 0)

    if pid == 0:
        os.close(r_fd)
        try:
            st, detail = child_fn()
        except Exception as exc:
            st, detail = "FAIL", f"exception: {exc!r}"
        payload = json.dumps([st, detail]).encode("utf-8")
        try:
            os.write(w_fd, payload)
        except OSError:
            pass
        finally:
            try:
                os.close(w_fd)
            except OSError:
                pass
            os._exit(0)

    os.close(w_fd)
    if pid < 0:
        os.close(r_fd)
        return "FAIL", f"syscall failed: errno={err} ({os.strerror(err)})", pid, err

    # Verify clone3 restored userland clone_args.flags after kernel call
    flags_corrupted = use_clone3 and cargs is not None and cargs.flags != orig_flags

    deadline = time.monotonic() + timeout
    while True:
        wpid, wstatus = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            break
        if time.monotonic() > deadline:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            os.close(r_fd)
            return "FAIL", f"cloned child timed out after {timeout}s", pid, 0
        time.sleep(0.02)

    chunks = []
    while True:
        b = os.read(r_fd, 4096)
        if not b:
            break
        chunks.append(b)
    os.close(r_fd)

    if flags_corrupted:
        return (
            "FAIL",
            f"clone3 corrupted caller uargs.flags: expected 0x{orig_flags:x} got 0x{cargs.flags:x}",
            pid,
            0,
        )
    if os.WIFSIGNALED(wstatus):
        return "FAIL", f"cloned child killed by signal {os.WTERMSIG(wstatus)}", pid, 0
    if not chunks:
        return "FAIL", f"cloned child exited {os.WEXITSTATUS(wstatus)} without output", pid, 0
    try:
        data = json.loads(b"".join(chunks).decode("utf-8"))
        return data[0], data[1], pid, 0
    except Exception as exc:
        return "FAIL", f"bad cloned child output: {exc!r}", pid, 0


# ---------------------------------------------------------------------------
# Individual test cases
# ---------------------------------------------------------------------------

def test_sysv_shm() -> Tuple[str, str]:
    shmid, err = sys_call(NR_SHMGET, IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
    if shmid < 0:
        return "FAIL", f"shmget failed: errno={err} ({os.strerror(err)})"
    try:
        addr, err = sys_call(NR_SHMAT, shmid, 0, 0)
        if addr == -1:
            return "FAIL", f"shmat failed: errno={err} ({os.strerror(err)})"
        uaddr = u64_addr(addr)
        try:
            marker = b"droid_lkm_shm_ok\x00"
            ctypes.memmove(ctypes.c_void_p(uaddr), marker, len(marker))
            got = ctypes.string_at(uaddr, len(marker))
            if got != marker:
                return "FAIL", f"shm data mismatch: got={got!r}"

            # Cross-process read via SHM_RDONLY + IPC_STAT sanity
            stat_buf = ctypes.create_string_buffer(256)
            rc, serr = sys_call(NR_SHMCTL, shmid, IPC_STAT, stat_buf)
            if rc < 0:
                return "FAIL", f"shmctl(IPC_STAT) failed: errno={serr}"

            def reader() -> Tuple[str, str]:
                raddr, rerr = sys_call(NR_SHMAT, shmid, 0, SHM_RDONLY)
                if raddr == -1:
                    return "FAIL", f"child shmat(SHM_RDONLY) failed: errno={rerr}"
                try:
                    rgot = ctypes.string_at(u64_addr(raddr), len(marker))
                    if rgot != marker:
                        return "FAIL", f"child shm read mismatch: {rgot!r}"
                    return "PASS", "ok"
                finally:
                    sys_call(NR_SHMDT, raddr)

            cst, cdet = run_in_child(reader)
            if cst != "PASS":
                return "FAIL", f"cross-process shm read failed: {cdet}"
        finally:
            sys_call(NR_SHMDT, addr)
    finally:
        sys_call(NR_SHMCTL, shmid, IPC_RMID, 0)
    return "PASS", f"shmget/shmat/IPC_STAT/cross-proc SHM_RDONLY/shmdt/IPC_RMID ok (shmid={shmid})"


def test_sysv_sem() -> Tuple[str, str]:
    semid, err = sys_call(NR_SEMGET, IPC_PRIVATE, 1, IPC_CREAT | 0o600)
    if semid < 0:
        return "FAIL", f"semget failed: errno={err} ({os.strerror(err)})"
    try:
        ret, err = sys_call(NR_SEMCTL, semid, 0, SETVAL, 1)
        if ret < 0:
            return "FAIL", f"semctl(SETVAL) failed: errno={err} ({os.strerror(err)})"
        op_dec = Sembuf(0, -1, 0)
        ret, err = sys_call(NR_SEMOP, semid, ctypes.byref(op_dec), 1)
        if ret < 0:
            return "FAIL", f"semop(-1) failed: errno={err} ({os.strerror(err)})"
        val, err = sys_call(NR_SEMCTL, semid, 0, GETVAL, 0)
        if val != 0:
            return "FAIL", f"semctl(GETVAL) expected 0 got {val} (errno={err})"
        op_inc = Sembuf(0, 1, 0)
        ret, err = sys_call(NR_SEMOP, semid, ctypes.byref(op_inc), 1)
        if ret < 0:
            return "FAIL", f"semop(+1) failed: errno={err} ({os.strerror(err)})"

        # Verify SEM_UNDO is rolled back on child exit (exercises exit_sem hook)
        def undo_child() -> Tuple[str, str]:
            op_u = Sembuf(0, -1, SEM_UNDO)
            r, e = sys_call(NR_SEMOP, semid, ctypes.byref(op_u), 1)
            if r < 0:
                return "FAIL", f"child semop(SEM_UNDO) failed: errno={e}"
            v, _ = sys_call(NR_SEMCTL, semid, 0, GETVAL, 0)
            if v != 0:
                return "FAIL", f"child GETVAL expected 0 got {v}"
            return "PASS", "ok"

        ust, udet = run_in_child(undo_child)
        if ust != "PASS":
            return "FAIL", f"SEM_UNDO child failed: {udet}"
        val_after, err = sys_call(NR_SEMCTL, semid, 0, GETVAL, 0)
        if val_after != 1:
            return "FAIL", f"SEM_UNDO regression: expected 1 after child exit, got {val_after} (errno={err})"
    finally:
        sys_call(NR_SEMCTL, semid, 0, IPC_RMID, 0)
    return "PASS", f"semget/SETVAL/semop/GETVAL/SEM_UNDO/IPC_RMID ok (semid={semid})"


def test_sysv_msg() -> Tuple[str, str]:
    msqid, err = sys_call(NR_MSGGET, IPC_PRIVATE, IPC_CREAT | 0o600)
    if msqid < 0:
        return "FAIL", f"msgget failed: errno={err} ({os.strerror(err)})"
    try:
        # Empty queue IPC_NOWAIT must return ENOMSG
        rx = Msgbuf()
        n0, err0 = sys_call(NR_MSGRCV, msqid, ctypes.byref(rx), 64, 0, IPC_NOWAIT)
        if n0 >= 0 or err0 != errno.ENOMSG:
            return "FAIL", f"empty msgrcv(IPC_NOWAIT) expected ENOMSG, got n={n0} errno={err0}"

        tx = Msgbuf(mtype=7, mtext=b"hello_droid_lkm")
        ret, err = sys_call(NR_MSGSND, msqid, ctypes.byref(tx), 15, 0)
        if ret < 0:
            return "FAIL", f"msgsnd failed: errno={err} ({os.strerror(err)})"

        stat_buf = ctypes.create_string_buffer(256)
        rc, serr = sys_call(NR_MSGCTL, msqid, IPC_STAT, stat_buf)
        if rc < 0:
            return "FAIL", f"msgctl(IPC_STAT) failed: errno={serr}"

        n, err = sys_call(NR_MSGRCV, msqid, ctypes.byref(rx), 64, 7, 0)
        if n != 15 or rx.mtext[:15] != b"hello_droid_lkm":
            return "FAIL", f"msgrcv mismatch: n={n} data={rx.mtext[:15]!r} errno={err}"
    finally:
        sys_call(NR_MSGCTL, msqid, IPC_RMID, 0)
    return "PASS", f"msgget/IPC_NOWAIT/msgsnd/IPC_STAT/msgrcv/IPC_RMID ok (msqid={msqid})"


def test_posix_mqueue() -> Tuple[str, str]:
    # Kernel mq_open syscall takes name WITHOUT leading '/'
    qname = f"dlkm_rt_{os.getpid()}_{int(time.time() * 1000) % 100000}".encode("ascii")
    attr = MqAttr(mq_flags=0, mq_maxmsg=4, mq_msgsize=64)
    # Open blocking (no O_NONBLOCK) so we can also exercise mq_timedreceive timeout path
    mqd, err = sys_call(NR_MQ_OPEN, ctypes.c_char_p(qname), O_RDWR | O_CREAT | O_EXCL, 0o600, ctypes.byref(attr))
    if mqd < 0:
        return "FAIL", f"mq_open failed: errno={err} ({os.strerror(err)})"
    try:
        # Priority ordering: send prio=1 then prio=5, must receive prio=5 first
        m_low = b"low_prio_1"
        m_hi = b"hi_prio_5"
        ret, err = sys_call(NR_MQ_TIMEDSEND, mqd, ctypes.c_char_p(m_low), len(m_low), 1, 0)
        if ret < 0:
            return "FAIL", f"mq_timedsend(low) failed: errno={err}"
        ret, err = sys_call(NR_MQ_TIMEDSEND, mqd, ctypes.c_char_p(m_hi), len(m_hi), 5, 0)
        if ret < 0:
            return "FAIL", f"mq_timedsend(hi) failed: errno={err}"

        cur = MqAttr()
        rc, gerr = sys_call(NR_MQ_GETSETATTR, mqd, 0, ctypes.byref(cur))
        if rc < 0 or cur.mq_curmsgs != 2:
            return "FAIL", f"mq_getsetattr expected curmsgs=2 got rc={rc} cur={cur.mq_curmsgs} errno={gerr}"

        buf = ctypes.create_string_buffer(64)
        prio = ctypes.c_uint(0)
        n1, err = sys_call(NR_MQ_TIMEDRECEIVE, mqd, buf, 64, ctypes.byref(prio), 0)
        if n1 != len(m_hi) or buf.raw[:n1] != m_hi or prio.value != 5:
            return "FAIL", f"prio order mismatch #1: n={n1} prio={prio.value} data={buf.raw[:n1]!r} errno={err}"
        n2, err = sys_call(NR_MQ_TIMEDRECEIVE, mqd, buf, 64, ctypes.byref(prio), 0)
        if n2 != len(m_low) or buf.raw[:n2] != m_low or prio.value != 1:
            return "FAIL", f"prio order mismatch #2: n={n2} prio={prio.value} data={buf.raw[:n2]!r} errno={err}"

        # Empty queue with short absolute timeout -> must return ETIMEDOUT
        now_ns = time.clock_gettime_ns(time.CLOCK_REALTIME) + 30_000_000  # +30ms
        ts = Timespec(tv_sec=now_ns // 1_000_000_000, tv_nsec=now_ns % 1_000_000_000)
        n3, terr = sys_call(NR_MQ_TIMEDRECEIVE, mqd, buf, 64, ctypes.byref(prio), ctypes.byref(ts))
        if n3 >= 0 or terr != errno.ETIMEDOUT:
            return "FAIL", f"mq_timedreceive timeout expected ETIMEDOUT, got n={n3} errno={terr}"
    finally:
        os.close(mqd)
        sys_call(NR_MQ_UNLINK, ctypes.c_char_p(qname))
    return "PASS", "mq_open/prio-order/getsetattr/ETIMEDOUT/unlink ok"


def test_ipc_ns_isolation(implicit_teardown: bool = False) -> Tuple[str, str]:
    if os.geteuid() != 0:
        return "SKIP", "requires root for unshare(CLONE_NEWIPC)"
    key = 0x514C4B4D ^ (os.getpid() & 0xFFFF)
    qname = f"dlkm_iso_{os.getpid()}_{int(time.time() * 1000) % 100000}".encode("ascii")
    parent_shm, err = sys_call(NR_SHMGET, key, 4096, IPC_CREAT | IPC_EXCL | 0o600)
    if parent_shm < 0:
        return "FAIL", f"parent shmget(key=0x{key:x}) failed: errno={err}"
    attr = MqAttr(mq_flags=0, mq_maxmsg=4, mq_msgsize=64)
    parent_mq, mq_err = sys_call(
        NR_MQ_OPEN, ctypes.c_char_p(qname), O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK, 0o600, ctypes.byref(attr)
    )
    if parent_mq < 0:
        sys_call(NR_SHMCTL, parent_shm, IPC_RMID, 0)
        return "FAIL", f"parent mq_open failed: errno={mq_err}"
    try:
        parent_ns = read_ns_link("ipc")

        def child() -> Tuple[str, str]:
            ret, err = sys_call(NR_UNSHARE, CLONE_NEWIPC)
            if ret < 0:
                return "FAIL", f"unshare(CLONE_NEWIPC) failed: errno={err} ({os.strerror(err)})"
            child_ns = read_ns_link("ipc")
            if parent_ns and child_ns and parent_ns == child_ns:
                return "FAIL", f"/proc/self/ns/ipc unchanged ({parent_ns})"
            # 1. Parent keyed shm must be invisible
            got, err = sys_call(NR_SHMGET, key, 4096, 0)
            if got >= 0 or err != errno.ENOENT:
                return "FAIL", f"SysV shm isolation leak: shmid={got} errno={err}"
            # 2. Parent mqueue must be invisible (O_CREAT|O_EXCL with same name must succeed)
            cmq, cerr = sys_call(
                NR_MQ_OPEN, ctypes.c_char_p(qname), O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK, 0o600, ctypes.byref(attr)
            )
            if cmq < 0:
                return "FAIL", f"POSIX mqueue isolation leak (O_EXCL failed): errno={cerr}"
            os.close(cmq)
            if not implicit_teardown:
                # Safe default mode explicitly unlinks mqueue (older droid_lkm without kill_litter_super
                # panics at fs/super.c:703 if busy mqueue inodes remain at kern_unmount time).
                sys_call(NR_MQ_UNLINK, ctypes.c_char_p(qname))
                return "PASS", f"unshare(CLONE_NEWIPC) isolated shm+mq ({parent_ns or 'n/a'} -> {child_ns or 'n/a'})"
            # Stress mode deliberately leaves mqueue + SysV objects un-removed to verify kill_litter_super/teardown
            cshm, _ = sys_call(NR_SHMGET, IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
            csem, _ = sys_call(NR_SEMGET, IPC_PRIVATE, 1, IPC_CREAT | 0o600)
            cmsg, _ = sys_call(NR_MSGGET, IPC_PRIVATE, IPC_CREAT | 0o600)
            if cshm < 0 or csem < 0 or cmsg < 0:
                return "FAIL", f"failed creating objects inside child IPC NS ({cshm},{csem},{cmsg})"
            return "PASS", f"implicit IPC NS teardown (un-unlinked mq + SysV) ok ({parent_ns or 'n/a'} -> {child_ns or 'n/a'})"

        return run_in_child(child)
    finally:
        os.close(parent_mq)
        sys_call(NR_MQ_UNLINK, ctypes.c_char_p(qname))
        sys_call(NR_SHMCTL, parent_shm, IPC_RMID, 0)


def test_ipc_ns_implicit_teardown() -> Tuple[str, str]:
    """Stress/regression test: exit a private IPC NS with an un-unlinked POSIX mqueue.
    Requires patched droid_lkm_mq_kill_sb (kill_litter_super / d_genocide)."""
    return test_ipc_ns_isolation(implicit_teardown=True)


def test_pid_ns_nested_and_status() -> Tuple[str, str]:
    if os.geteuid() != 0:
        return "SKIP", "requires root for unshare(CLONE_NEWPID)"
    parent_ns = read_ns_link("pid")
    nspid_append_param = Path("/sys/module/droid_lkm/parameters/nspid_append")
    expect_inline_pos = (
        nspid_append_param.exists()
        and nspid_append_param.read_text(encoding="utf-8", errors="replace").strip() in ("N", "0")
    )

    def level1_parent() -> Tuple[str, str]:
        ret, err = sys_call(NR_UNSHARE, CLONE_NEWPID)
        if ret < 0:
            return "FAIL", f"unshare(CLONE_NEWPID) failed: errno={err} ({os.strerror(err)})"
        # After unshare(CLONE_NEWPID), self/ns/pid stays parent_ns while pid_for_children changes
        after_pid_ns = read_ns_link("pid")
        pfc_ns = read_ns_link("pid_for_children")
        if parent_ns and after_pid_ns and after_pid_ns != parent_ns:
            return "FAIL", f"unshare(CLONE_NEWPID) unexpectedly changed self/ns/pid ({parent_ns} -> {after_pid_ns})"
        if parent_ns and pfc_ns and pfc_ns == parent_ns:
            return "FAIL", f"unshare(CLONE_NEWPID) left pid_for_children unchanged ({pfc_ns})"
        # Second unshare(CLONE_NEWPID) before fork must fail with EINVAL
        ret2, err2 = sys_call(NR_UNSHARE, CLONE_NEWPID)
        if ret2 == 0 or err2 != errno.EINVAL:
            return "FAIL", f"double unshare(CLONE_NEWPID) expected EINVAL, got ret={ret2} errno={err2}"

        def level1_init() -> Tuple[str, str]:
            g_ns = read_ns_link("pid")
            if pfc_ns and g_ns and g_ns != pfc_ns:
                return "FAIL", f"child ns/pid ({g_ns}) != parent pid_for_children ({pfc_ns})"
            status = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
            lines = [ln.strip() for ln in status.splitlines()]
            tags = {ln.split(":", 1)[0]: ln for ln in lines if ":" in ln}
            for req_tag in ("NStgid", "NSpid", "NSpgid", "NSsid"):
                if req_tag not in tags:
                    return "FAIL", f"missing '{req_tag}:' in /proc/self/status"
            toks = tags["NSpid"].split()[1:]
            if len(toks) < 2 or toks[-1] != "1":
                return "FAIL", f"unexpected L1 NSpid='{tags['NSpid']}' (getpid={raw_getpid()})"

            if expect_inline_pos:
                idx_groups = next((i for i, ln in enumerate(lines) if ln.startswith("Groups:")), -1)
                idx_nstgid = next((i for i, ln in enumerate(lines) if ln.startswith("NStgid:")), -1)
                if idx_groups >= 0 and idx_nstgid != idx_groups + 1:
                    return "FAIL", f"NStgid not inserted right after Groups: (Groups@{idx_groups}, NStgid@{idx_nstgid})"

            # Nested L2 PID NS inside L1
            r_l2, e_l2 = sys_call(NR_UNSHARE, CLONE_NEWPID)
            if r_l2 < 0:
                return "FAIL", f"nested L2 unshare(CLONE_NEWPID) failed: errno={e_l2}"

            def level2_init() -> Tuple[str, str]:
                s2 = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
                nsp2 = next((ln.strip() for ln in s2.splitlines() if ln.startswith("NSpid:")), "")
                t2 = nsp2.split()[1:]
                if len(t2) < 3 or t2[-1] != "1":
                    return "FAIL", f"unexpected L2 nested NSpid='{nsp2}'"
                return "PASS", nsp2

            st2, det2 = run_in_child(level2_init)
            if st2 != "PASS":
                return "FAIL", f"nested L2 PID NS failed: {det2}"

            return "PASS", f"L1({tags['NSpid']}) + L2({det2}) + pid_for_children + status pos ok"

        return run_in_child(level1_init)

    return run_in_child(level1_parent)


def test_pid_ns_reaper_cleanup() -> Tuple[str, str]:
    """When PID 1 in a PID NS exits, sibling/child sleepers in that NS must be reaped."""
    if os.geteuid() != 0:
        return "SKIP", "requires root for unshare(CLONE_NEWPID)"

    def wrapper() -> Tuple[str, str]:
        ret, err = sys_call(NR_UNSHARE, CLONE_NEWPID)
        if ret < 0:
            return "FAIL", f"unshare(CLONE_NEWPID) failed: errno={err}"

        r_fd, w_fd = os.pipe()
        init_pid = os.fork()
        if init_pid == 0:
            os.close(r_fd)
            sleeper = os.fork()
            if sleeper == 0:
                # Report sleeper's own host-visible PID via /proc/self/status NSpid[0]
                # (PID 1 cannot read /proc/<sleeper> on host-mounted /proc where PID 2 is kthreadd).
                try:
                    st = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
                    nsp = next((ln for ln in st.splitlines() if ln.startswith("NSpid:")), "")
                    host_sleeper = nsp.split()[1] if len(nsp.split()) >= 2 else ""
                    os.write(w_fd, host_sleeper.encode("ascii"))
                except OSError:
                    pass
                os.close(w_fd)
                time.sleep(30)
                os._exit(0)
            os.close(w_fd)
            # Give sleeper a moment to report its host PID, then PID 1 exits without killing sleeper
            time.sleep(0.05)
            os._exit(0)

        os.close(w_fd)
        host_sleeper_raw = os.read(r_fd, 64).decode("ascii", errors="replace").strip()
        os.close(r_fd)
        os.waitpid(init_pid, 0)

        if not host_sleeper_raw.isdigit():
            return "PASS", "PID 1 exited cleanly (host sleeper pid unavailable in proc)"

        spid = int(host_sleeper_raw)
        deadline = time.monotonic() + 2.0
        alive = True
        while time.monotonic() < deadline:
            if not Path(f"/proc/{spid}").exists():
                alive = False
                break
            try:
                os.kill(spid, 0)
            except ProcessLookupError:
                alive = False
                break
            except PermissionError:
                pass
            time.sleep(0.05)

        if alive:
            try:
                os.kill(spid, signal.SIGKILL)
            except OSError:
                pass
            return "FAIL", f"child process pid={spid} survived PID 1 exit (zap_pid_ns_processes regression)"
        return "PASS", f"PID 1 exit cleanly reaped member process (host pid={spid})"

    return run_in_child(wrapper)


def test_clone_and_clone3_ns(include_fault_inject: bool = False) -> Tuple[str, str]:
    """Exercise ds_slot.c droid_lkm_sys_clone, droid_lkm_sys_clone3, cn_wrap, cnn_wrap,
    invalid flag rejection, and (in stress mode) read-only clone3 uargs EFAULT rollback
    + nested clone(CLONE_NEWPID) inside a private IPC NS."""
    if os.geteuid() != 0:
        return "SKIP", "requires root for clone/clone3 CLONE_NEWPID|CLONE_NEWIPC"

    def runner() -> Tuple[str, str]:
        key = 0x514C4B4E ^ (os.getpid() & 0xFFFF)
        pshm, err = sys_call(NR_SHMGET, key, 4096, IPC_CREAT | IPC_EXCL | 0o600)
        if pshm < 0:
            return "FAIL", f"parent shmget failed: errno={err}"
        try:
            p_pid_ns = read_ns_link("pid")
            p_ipc_ns = read_ns_link("ipc")

            def verify_ns() -> Tuple[str, str]:
                c_pid_ns = read_ns_link("pid")
                c_ipc_ns = read_ns_link("ipc")
                if p_pid_ns and c_pid_ns and c_pid_ns == p_pid_ns:
                    return "FAIL", f"pid ns unchanged ({c_pid_ns})"
                if p_ipc_ns and c_ipc_ns and c_ipc_ns == p_ipc_ns:
                    return "FAIL", f"ipc ns unchanged ({c_ipc_ns})"
                got, gerr = sys_call(NR_SHMGET, key, 4096, 0)
                if got >= 0 or gerr != errno.ENOENT:
                    return "FAIL", f"ipc isolation leak: got={got} errno={gerr}"
                st = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
                nsp = next((ln.strip() for ln in st.splitlines() if ln.startswith("NSpid:")), "")
                toks = nsp.split()[1:]
                if len(toks) < 2 or toks[-1] != "1":
                    return "FAIL", f"bad NSpid '{nsp}'"
                return "PASS", f"pid={raw_getpid()} {nsp}"

            # 1. clone(CLONE_NEWPID | CLONE_NEWIPC)
            st1, det1, _, _ = run_in_raw_clone(False, CLONE_NEWPID | CLONE_NEWIPC, verify_ns)
            if st1 != "PASS":
                return "FAIL", f"clone(NEWPID|NEWIPC) failed: {det1}"

            # 2. clone3(CLONE_NEWPID | CLONE_NEWIPC) + verify uargs.flags restored
            st2, det2, _, _ = run_in_raw_clone(True, CLONE_NEWPID | CLONE_NEWIPC, verify_ns)
            if st2 != "PASS":
                return "FAIL", f"clone3(NEWPID|NEWIPC) failed: {det2}"

            # 3. Invalid flag combinations must fail with EINVAL
            r_inv1, e_inv1 = sys_call(NR_CLONE, CLONE_NEWIPC | CLONE_SYSVSEM | SIGCHLD, 0, 0, 0, 0)
            if r_inv1 >= 0 or e_inv1 != errno.EINVAL:
                return "FAIL", f"clone(NEWIPC|SYSVSEM) expected EINVAL, got ret={r_inv1} errno={e_inv1}"

            bad_ca = CloneArgs(flags=CLONE_THREAD | CLONE_NEWPID, exit_signal=0)
            r_inv2, e_inv2 = sys_call(NR_CLONE3, ctypes.byref(bad_ca), ctypes.sizeof(bad_ca))
            if r_inv2 >= 0 or e_inv2 != errno.EINVAL:
                return "FAIL", f"clone3(THREAD|NEWPID) expected EINVAL, got ret={r_inv2} errno={e_inv2}"

            if not include_fault_inject:
                return "PASS", f"clone({det1}) + clone3({det2}) + EINVAL ok"

            # 4. Read-only clone3 uargs page -> copy_to_user must EFAULT cleanly without corrupting nsproxy
            mm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            cbuf = None
            try:
                ro_ca = CloneArgs(flags=CLONE_NEWPID | CLONE_NEWIPC, exit_signal=SIGCHLD)
                mm.write(bytes(ro_ca))
                cbuf = ctypes.c_char.from_buffer(mm)
                buf_addr = ctypes.addressof(cbuf)
                if get_libc().mprotect(ctypes.c_void_p(buf_addr), 4096, PROT_READ) != 0:
                    return "FAIL", f"mprotect(PROT_READ) failed: errno={ctypes.get_errno()}"
                r_ro, e_ro = sys_call(NR_CLONE3, ctypes.c_void_p(buf_addr), ctypes.sizeof(ro_ca))
                if r_ro >= 0 or e_ro != errno.EFAULT:
                    return "FAIL", f"clone3(RO uargs) expected EFAULT, got ret={r_ro} errno={e_ro}"
            finally:
                cbuf = None
                mm.close()

            if read_ns_link("pid") != p_pid_ns or read_ns_link("ipc") != p_ipc_ns:
                return "FAIL", "parent nsproxy changed after clone3(RO uargs) EFAULT rollback!"
            if read_ns_link("pid_for_children") != p_pid_ns:
                return "FAIL", "parent pid_for_children leaked after clone3(RO uargs) EFAULT rollback!"

            # 5. Inside a private IPC NS, clone(CLONE_NEWPID) must keep parent's IPC NS alive after child exits
            #    (regression test for droid_lkm_clone_ctx_{enter,leave} ipc_ns refcount UAF)
            def priv_ipc_clone_pid() -> Tuple[str, str]:
                rc, uerr = sys_call(NR_UNSHARE, CLONE_NEWIPC)
                if rc < 0:
                    return "FAIL", f"unshare(NEWIPC) failed: errno={uerr}"
                cshm, serr = sys_call(NR_SHMGET, IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
                if cshm < 0:
                    return "FAIL", f"private shmget failed: errno={serr}"
                try:
                    stc, detc, _, _ = run_in_raw_clone(
                        False, CLONE_NEWPID, lambda: ("PASS", f"subpid={raw_getpid()}")
                    )
                    if stc != "PASS":
                        return "FAIL", f"nested clone(NEWPID) in private IPC NS failed: {detc}"
                    # Parent's private IPC NS must still be valid & usable after child exits
                    stbuf = ctypes.create_string_buffer(256)
                    if sys_call(NR_SHMCTL, cshm, IPC_STAT, stbuf)[0] < 0:
                        return "FAIL", "parent private IPC NS broken after clone(NEWPID) child exited"
                    return "PASS", "ok"
                finally:
                    sys_call(NR_SHMCTL, cshm, IPC_RMID, 0)

            stp, detp = run_in_child(priv_ipc_clone_pid)
            if stp != "PASS":
                return "FAIL", f"private-ipc + clone(NEWPID) refcount test failed: {detp}"

            return "PASS", f"clone({det1}) + clone3({det2}) + EINVAL + RO-uargs EFAULT + priv-ipc refcount ok"
        finally:
            sys_call(NR_SHMCTL, pshm, IPC_RMID, 0)

    return run_in_child(runner)


def test_clone3_stress_and_refcount() -> Tuple[str, str]:
    """Stress/regression test for clone3 RO-uargs rollback & private-IPC clone(NEWPID) refcount."""
    return test_clone_and_clone3_ns(include_fault_inject=True)


def test_setns_ipc_and_pid() -> Tuple[str, str]:
    """Exercise /proc/<pid>/ns/{ipc,pid} + setns(2) cross-process entry."""
    if os.geteuid() != 0:
        return "SKIP", "requires root for setns(CLONE_NEWIPC|CLONE_NEWPID)"

    def runner() -> Tuple[str, str]:
        key = 0x514C4B4F ^ (os.getpid() & 0xFFFF)
        marker = b"setns_ipc_shared_ok\x00"
        r_ready, w_ready = os.pipe()
        r_done, w_done = os.pipe()

        # Target child creates isolated IPC + PID NS and a keyed shm inside it
        holder = os.fork()
        if holder == 0:
            os.close(r_ready)
            os.close(w_done)
            rc, _ = sys_call(NR_UNSHARE, CLONE_NEWIPC | CLONE_NEWPID)
            if rc < 0:
                os.write(w_ready, b"ERR")
                os._exit(1)
            sub = os.fork()
            if sub == 0:
                shm, _ = sys_call(NR_SHMGET, key, 4096, IPC_CREAT | IPC_EXCL | 0o600)
                if shm >= 0:
                    addr, _ = sys_call(NR_SHMAT, shm, 0, 0)
                    if addr != -1:
                        ctypes.memmove(ctypes.c_void_p(u64_addr(addr)), marker, len(marker))
                        sys_call(NR_SHMDT, addr)
                os.write(w_ready, f"OK:{shm}".encode("ascii"))
                os.close(w_ready)
                os.read(r_done, 16)
                if shm >= 0:
                    sys_call(NR_SHMCTL, shm, IPC_RMID, 0)
                os._exit(0)
            os.close(w_ready)
            os.close(r_done)
            os.waitpid(sub, 0)
            os._exit(0)

        os.close(w_ready)
        os.close(r_done)
        try:
            msg = os.read(r_ready, 64).decode("ascii", errors="replace").strip()
            os.close(r_ready)
            if not msg.startswith("OK:"):
                return "FAIL", f"holder setup failed: {msg!r}"

            # Find holder's child PID via /proc/<holder>/task/<holder>/children (or fallback to holder for IPC)
            children_p = Path(f"/proc/{holder}/task/{holder}/children")
            target_pid = holder
            if children_p.exists():
                kids = children_p.read_text(encoding="utf-8", errors="replace").split()
                if kids and kids[0].isdigit():
                    target_pid = int(kids[0])

            target_ipc_ns = read_ns_link("ipc", str(target_pid))
            target_pid_ns = read_ns_link("pid", str(target_pid))

            def joiner() -> Tuple[str, str]:
                # 1. Join IPC NS via setns and read the keyed shm
                ipc_fd = os.open(f"/proc/{target_pid}/ns/ipc", os.O_RDONLY)
                try:
                    rc, err = sys_call(NR_SETNS, ipc_fd, CLONE_NEWIPC)
                    if rc < 0:
                        return "FAIL", f"setns(CLONE_NEWIPC) failed: errno={err} ({os.strerror(err)})"
                finally:
                    os.close(ipc_fd)

                if target_ipc_ns and read_ns_link("ipc") != target_ipc_ns:
                    return "FAIL", f"setns(NEWIPC) link mismatch: got {read_ns_link('ipc')} want {target_ipc_ns}"

                shm, err = sys_call(NR_SHMGET, key, 4096, 0)
                if shm < 0:
                    return "FAIL", f"shmget inside joined IPC NS failed: errno={err}"
                addr, err = sys_call(NR_SHMAT, shm, 0, SHM_RDONLY)
                if addr == -1:
                    return "FAIL", f"shmat inside joined IPC NS failed: errno={err}"
                try:
                    got = ctypes.string_at(u64_addr(addr), len(marker))
                    if got != marker:
                        return "FAIL", f"joined IPC shm data mismatch: {got!r}"
                finally:
                    sys_call(NR_SHMDT, addr)

                # 2. Join PID NS via setns and fork a child into target PID NS
                pid_fd = os.open(f"/proc/{target_pid}/ns/pid", os.O_RDONLY)
                try:
                    rc, err = sys_call(NR_SETNS, pid_fd, CLONE_NEWPID)
                    if rc < 0:
                        return "FAIL", f"setns(CLONE_NEWPID) failed: errno={err} ({os.strerror(err)})"
                finally:
                    os.close(pid_fd)

                def entered_child() -> Tuple[str, str]:
                    cur_pid_ns = read_ns_link("pid")
                    if target_pid_ns and cur_pid_ns != target_pid_ns:
                        return "FAIL", f"entered child pid ns mismatch: {cur_pid_ns} != {target_pid_ns}"
                    return "PASS", f"entered {cur_pid_ns}"

                return run_in_child(entered_child)

            st, det = run_in_child(joiner)
            if st != "PASS":
                return "FAIL", det
            return "PASS", f"setns(CLONE_NEWIPC) shm read + setns(CLONE_NEWPID) fork ok ({det})"
        finally:
            try:
                os.write(w_done, b"X")
            except OSError:
                pass
            os.close(w_done)
            try:
                os.waitpid(holder, 0)
            except OSError:
                pass

    return run_in_child(runner)


def test_unpriv_ns_perm() -> Tuple[str, str]:
    """Verify unprivileged processes cannot bypass CAP_SYS_ADMIN on CLONE_NEWIPC/CLONE_NEWPID."""
    if os.geteuid() != 0:
        # Already unprivileged; verify direct unshare without CLONE_NEWUSER returns EPERM
        def direct_check() -> Tuple[str, str]:
            r1, e1 = sys_call(NR_UNSHARE, CLONE_NEWIPC)
            if r1 == 0 or e1 != errno.EPERM:
                return "FAIL", f"unpriv unshare(NEWIPC) expected EPERM, got ret={r1} errno={e1}"
            r2, e2 = sys_call(NR_UNSHARE, CLONE_NEWPID)
            if r2 == 0 or e2 != errno.EPERM:
                return "FAIL", f"unpriv unshare(NEWPID) expected EPERM, got ret={r2} errno={e2}"
            return "PASS", "unprivileged unshare(NEWIPC/NEWPID) rejected with EPERM"

        return run_in_child(direct_check)

    def dropped_child() -> Tuple[str, str]:
        os.setgid(65534)
        os.setuid(65534)
        r1, e1 = sys_call(NR_UNSHARE, CLONE_NEWIPC)
        if r1 == 0 or e1 != errno.EPERM:
            return "FAIL", f"uid=65534 unshare(NEWIPC) expected EPERM, got ret={r1} errno={e1}"
        r2, e2 = sys_call(NR_UNSHARE, CLONE_NEWPID)
        if r2 == 0 or e2 != errno.EPERM:
            return "FAIL", f"uid=65534 unshare(NEWPID) expected EPERM, got ret={r2} errno={e2}"
        return "PASS", "uid=65534 unshare(NEWIPC/NEWPID) rejected with EPERM"

    return run_in_child(dropped_child)


def test_ns_concurrency_stress() -> Tuple[str, str]:
    """Short concurrent unshare+fork+shm stress to catch nsproxy refcount / list races."""
    if os.geteuid() != 0:
        return "SKIP", "requires root for concurrent unshare(CLONE_NEWIPC|CLONE_NEWPID)"

    workers = 4
    iters = 6

    def worker_fn() -> Tuple[str, str]:
        for i in range(iters):
            def one_round() -> Tuple[str, str]:
                rc, err = sys_call(NR_UNSHARE, CLONE_NEWIPC | CLONE_NEWPID)
                if rc < 0:
                    return "FAIL", f"iter {i} unshare failed: errno={err}"
                shm, err = sys_call(NR_SHMGET, IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
                if shm < 0:
                    return "FAIL", f"iter {i} shmget failed: errno={err}"
                pid = os.fork()
                if pid == 0:
                    _ = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
                    _ = read_ns_link("pid")
                    _ = read_ns_link("ipc")
                    os._exit(0)
                os.waitpid(pid, 0)
                sys_call(NR_SHMCTL, shm, IPC_RMID, 0)
                return "PASS", "ok"

            st, det = run_in_child(one_round, timeout=5.0)
            if st != "PASS":
                return "FAIL", det
        return "PASS", f"{iters} iters ok"

    # Spawn workers in parallel
    pipes: List[Tuple[int, int]] = []
    pids: List[int] = []
    for _ in range(workers):
        r_fd, w_fd = os.pipe()
        p = os.fork()
        if p == 0:
            os.close(r_fd)
            st, det = worker_fn()
            try:
                os.write(w_fd, json.dumps([st, det]).encode("utf-8"))
            finally:
                os.close(w_fd)
                os._exit(0)
        os.close(w_fd)
        pipes.append((p, r_fd))
        pids.append(p)

    errors: List[str] = []
    for p, r_fd in pipes:
        _, wst = os.waitpid(p, 0)
        raw = os.read(r_fd, 4096)
        os.close(r_fd)
        if os.WIFSIGNALED(wst):
            errors.append(f"worker {p} killed by signal {os.WTERMSIG(wst)}")
            continue
        try:
            st, det = json.loads(raw.decode("utf-8"))
            if st != "PASS":
                errors.append(det)
        except Exception as exc:
            errors.append(f"bad worker payload: {exc!r}")

    if errors:
        return "FAIL", "; ".join(errors[:3])
    return "PASS", f"{workers} parallel workers x {iters} rounds (unshare+fork+shm+proc) ok"


def test_userns_state_machine() -> Tuple[str, str]:
    misc_status = Path("/proc/droid_lkm_misc/status")
    has_userns_mod = False
    if misc_status.exists():
        try:
            has_userns_mod = "userns                   ready" in misc_status.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

    def child() -> Tuple[str, str]:
        ret, err = sys_call(NR_UNSHARE, CLONE_NEWUSER)
        if ret < 0:
            if not has_userns_mod and err in (errno.EINVAL, errno.ENOSYS, errno.EPERM):
                return "SKIP", f"CLONE_NEWUSER unavailable (errno={err})"
            return "FAIL", f"unshare(CLONE_NEWUSER) failed: errno={err} ({os.strerror(err)})"

        ns_link = read_ns_link("user")
        if not ns_link:
            return "FAIL", "/proc/self/ns/user missing after unshare(CLONE_NEWUSER)"

        # 1. setgroups monotonic: write 'deny', then attempt 'allow' (must EPERM)
        sg = Path("/proc/self/setgroups")
        if sg.exists():
            sg.write_text("deny\n", encoding="ascii")
            try:
                sg.write_text("allow\n", encoding="ascii")
                return "FAIL", "setgroups regression: 'deny -> allow' succeeded (must EPERM)"
            except PermissionError:
                pass
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    return "FAIL", f"setgroups 'deny -> allow' unexpected errno={exc.errno}"

        # 2. uid_map One-Shot Rule
        um = Path("/proc/self/uid_map")
        uid = os.geteuid()
        um.write_text(f"0 {uid} 1\n", encoding="ascii")
        try:
            um.write_text(f"0 {uid} 1\n", encoding="ascii")
            return "FAIL", "uid_map one-shot regression: second write succeeded (must EPERM)"
        except PermissionError:
            pass
        except OSError as exc:
            if exc.errno != errno.EPERM:
                return "FAIL", f"uid_map second write unexpected errno={exc.errno}"

        # 3. gid_map One-Shot Rule + setgroups lock after gid_map
        gm = Path("/proc/self/gid_map")
        gid = os.getegid()
        gm.write_text(f"0 {gid} 1\n", encoding="ascii")
        try:
            gm.write_text(f"0 {gid} 1\n", encoding="ascii")
            return "FAIL", "gid_map one-shot regression: second write succeeded (must EPERM)"
        except PermissionError:
            pass
        except OSError as exc:
            if exc.errno != errno.EPERM:
                return "FAIL", f"gid_map second write unexpected errno={exc.errno}"

        if sg.exists():
            try:
                sg.write_text("deny\n", encoding="ascii")
                return "FAIL", "setgroups regression: write after gid_map succeeded (must EPERM)"
            except PermissionError:
                pass
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    return "FAIL", f"setgroups after gid_map unexpected errno={exc.errno}"

        # 4. execve inside fake userns exercises set_cred_ucounts + release_task
        #    dec_rlimit_ucounts balance (no kernel/ucount.c WARN_ON_ONCE).
        #    Prefer /system/bin/true on Android so Termux libtermux-exec.so does
        #    not rewrite /bin/true into a 0700 app-private path.
        for true_bin in ("/system/bin/true", "/bin/true", "/usr/bin/true"):
            if os.path.exists(true_bin):
                r = subprocess.run([true_bin], capture_output=True, timeout=5)
                if r.returncode != 0:
                    return "FAIL", f"execve {true_bin} inside userns failed rc={r.returncode}"
                break

        return "PASS", f"unshare(CLONE_NEWUSER) + one-shot uid/gid_map + monotonic setgroups + execve ok ({ns_link})"

    return run_in_child(child)


def test_userns_lpe_guard() -> Tuple[str, str]:
    """Regression guard for P0-1: confined fake userns must block CAP_SETUID/GID LPE."""
    misc_status = Path("/proc/droid_lkm_misc/status")
    has_userns_mod = False
    if misc_status.exists():
        try:
            has_userns_mod = "userns                   ready" in misc_status.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass

    canary_dir: Optional[str] = None
    canary_path: Optional[str] = None
    if os.geteuid() == 0:
        base = "/data/local/tmp" if os.path.isdir("/data/local/tmp") else "/tmp"
        canary_dir = tempfile.mkdtemp(prefix="dlm_lpe_", dir=base)
        os.chmod(canary_dir, 0o755)
        canary_path = os.path.join(canary_dir, "root_only")
        with open(canary_path, "wb") as f:
            f.write(b"root-secret\n")
        os.chown(canary_path, 0, 0)
        os.chmod(canary_path, 0o600)

    def child() -> Tuple[str, str]:
        if os.geteuid() == 0:
            os.setgroups([])
            os.setresgid(65534, 65534, 65534)
            os.setresuid(65534, 65534, 65534)
            # PR_SET_DUMPABLE = 4
            sys_call(NR_PRCTL, 4, 1, 0, 0, 0)

        start_uid = os.geteuid()
        start_gid = os.getegid()
        if start_uid == 0:
            return "SKIP", "could not drop to unprivileged uid"

        ret, err = sys_call(NR_UNSHARE, CLONE_NEWUSER)
        if ret < 0:
            if not has_userns_mod and err in (errno.EINVAL, errno.ENOSYS, errno.EPERM):
                return "SKIP", f"CLONE_NEWUSER unavailable (errno={err})"
            return "FAIL", f"unshare(CLONE_NEWUSER) failed: errno={err}"

        # 1. setresuid / setuid / setresgid to root or foreign ID must fail EPERM
        for label, fn in (
            ("setresuid(0,0,0)", lambda: os.setresuid(0, 0, 0)),
            ("setuid(0)", lambda: os.setuid(0)),
            ("setresgid(0,0,0)", lambda: os.setresgid(0, 0, 0)),
            ("setresgid(42,42,42)", lambda: os.setresgid(42, 42, 42)),
        ):
            try:
                fn()
                return "FAIL", f"LPE regression: {label} succeeded from uid={start_uid}"
            except PermissionError:
                pass
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    return "FAIL", f"{label} unexpected errno={exc.errno}"

        # 2. setfsuid(0) / setfsgid(0) must NOT switch fsuid/fsgid away from caller
        NR_SETFSUID = 151
        NR_SETFSGID = 152
        sys_call(NR_SETFSUID, 0)
        cur_fsuid, _ = sys_call(NR_SETFSUID, 0xFFFFFFFF)
        if cur_fsuid == 0:
            return "FAIL", f"LPE regression: setfsuid(0) switched fsuid to 0 from uid={start_uid}"
        sys_call(NR_SETFSGID, 0)
        cur_fsgid, _ = sys_call(NR_SETFSGID, 0xFFFFFFFF)
        if cur_fsgid == 0:
            return "FAIL", f"LPE regression: setfsgid(0) switched fsgid to 0 from gid={start_gid}"

        # 3. Root-only file access must still fail EACCES
        probe_file = canary_path if canary_path else ("/etc/shadow" if os.path.exists("/etc/shadow") else None)
        if probe_file:
            try:
                with open(probe_file, "rb") as f:
                    _ = f.read(16)
                return "FAIL", f"LPE regression: unprivileged fake userns read {probe_file}"
            except PermissionError:
                pass

        # 4. kill(1, 0) against outside root init must still fail EPERM
        try:
            os.kill(1, 0)
            return "FAIL", "LPE regression: kill(1, 0) allowed from unprivileged fake userns"
        except PermissionError:
            pass
        except ProcessLookupError:
            pass

        return "PASS", f"unprivileged fake userns blocked set*uid/setfsuid/set*gid/root-file/kill(1) (uid={start_uid})"

    try:
        return run_in_child(child)
    finally:
        if canary_path and os.path.exists(canary_path):
            try:
                os.unlink(canary_path)
            except OSError:
                pass
        if canary_dir and os.path.isdir(canary_dir):
            try:
                os.rmdir(canary_dir)
            except OSError:
                pass


def test_userns_object_leak_guard() -> Tuple[str, str]:
    """Verify 0 fake userns object leaks across all 7 child namespaces + pinned nsfs fds."""
    misc_status = Path("/proc/droid_lkm_misc/status")
    if not misc_status.exists():
        return "SKIP", "/proc/droid_lkm_misc/status not present"

    def read_live() -> Optional[int]:
        try:
            txt = misc_status.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        m = re.search(r"^userns objects\s+ready\s+(\d+)\s+live of\s+\d+", txt, re.M)
        return int(m.group(1)) if m else None

    if read_live() is None:
        return "SKIP", "/proc/droid_lkm_misc/status unreadable or userns inactive"

    def wait_live_le(target: int, timeout: float = 5.0) -> int:
        deadline = time.monotonic() + timeout
        cur = read_live()
        while cur is not None and cur > target and time.monotonic() < deadline:
            time.sleep(0.05)
            cur = read_live()
        return cur if cur is not None else target

    # Let any async RCU / cleanup_net work from earlier tests settle first
    prev = read_live()
    assert prev is not None
    for _ in range(25):
        time.sleep(0.08)
        cur = read_live()
        assert cur is not None
        if cur == prev:
            break
        prev = cur
    base = cur  # type: ignore[assignment]

    combos = [
        ("USER", CLONE_NEWUSER),
        ("USER+NS", CLONE_NEWUSER | CLONE_NEWNS),
        ("USER+UTS", CLONE_NEWUSER | CLONE_NEWUTS),
        ("USER+IPC", CLONE_NEWUSER | CLONE_NEWIPC),
        ("USER+PID", CLONE_NEWUSER | CLONE_NEWPID),
        ("USER+NET", CLONE_NEWUSER | CLONE_NEWNET),
        ("USER+CGROUP", CLONE_NEWUSER | CLONE_NEWCGROUP),
        ("USER+TIME", CLONE_NEWUSER | CLONE_NEWTIME),
    ]
    checked: List[str] = []

    for label, flags in combos:
        pid = os.fork()
        if pid == 0:
            try:
                ret, err = sys_call(NR_UNSHARE, flags)
                if ret < 0:
                    if flags != CLONE_NEWUSER and err in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP):
                        os._exit(2)
                    os._exit(1)
                if flags & (CLONE_NEWPID | CLONE_NEWTIME):
                    gcpid = os.fork()
                    if gcpid == 0:
                        os._exit(0)
                    os.waitpid(gcpid, 0)
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, wstatus = os.waitpid(pid, 0)
        rc = os.waitstatus_to_exitcode(wstatus)
        if rc == 2:
            continue
        if rc != 0:
            return "FAIL", f"{label} child unshare failed (rc={rc})"
        after = wait_live_le(base, timeout=5.0)
        if after > base:
            return "FAIL", f"{label} leaked {after - base} userns object(s) (base={base}, live={after})"
        base = min(base, after)
        checked.append(label)

    # Exercise delayed nsfs eviction (mntns_operations.put + netns_put -> pernet_ops.exit)
    if os.geteuid() == 0:
        ready_r, ready_w = os.pipe()
        go_r, go_w = os.pipe()
        fds: List[int] = []
        pid = os.fork()
        if pid == 0:
            os.close(ready_r)
            os.close(go_w)
            try:
                ret, _ = sys_call(NR_UNSHARE, CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET)
                os.write(ready_w, b"1" if ret == 0 else b"0")
                os.close(ready_w)
                _ = os.read(go_r, 1)
                os.close(go_r)
                os._exit(0 if ret == 0 else 1)
            except BaseException:
                os._exit(1)
        os.close(ready_w)
        os.close(go_r)
        try:
            tok = os.read(ready_r, 1)
            os.close(ready_r)
            if tok != b"1":
                os.close(go_w)
                os.waitpid(pid, 0)
                return "FAIL", "pinned_nsfs child unshare(USER|NS|NET) failed"
            for kind in ("mnt", "net", "user"):
                fds.append(os.open(f"/proc/{pid}/ns/{kind}", os.O_RDONLY))
            os.close(go_w)
            os.waitpid(pid, 0)
            # While nsfs fds are still open after task exit, userns MUST stay alive (no UAF)
            pinned_live = read_live()
            if pinned_live is not None and pinned_live <= base:
                return "FAIL", f"premature userns drop while nsfs fds still open (base={base}, live={pinned_live})"
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
        after = wait_live_le(base, timeout=5.0)
        if after > base:
            return "FAIL", f"pinned nsfs (mnt+net+user) leaked {after - base} userns object(s) (base={base}, live={after})"
        checked.append("pinned_nsfs(mnt+net+user)")

    return "PASS", f"0 leaked userns objects across {', '.join(checked)} (baseline={base})"


def test_devtmpfs_registered() -> Tuple[str, str]:
    fs = Path("/proc/filesystems").read_text(encoding="utf-8", errors="replace")
    if re.search(r"\bdevtmpfs\b", fs):
        return "PASS", "devtmpfs registered in /proc/filesystems"
    return "SKIP", "devtmpfs not present in /proc/filesystems (droid_lkm_misc not loaded or disabled)"


def test_bwrap_smoke() -> Tuple[str, str]:
    r_which = subprocess.run(["which", "bwrap"], capture_output=True, text=True)
    if r_which.returncode != 0:
        return "SKIP", "bwrap not installed in this environment"

    outer_user = read_ns_link("user")
    outer_pid = read_ns_link("pid")
    outer_ipc = read_ns_link("ipc")

    inner_sh = (
        "set -e; "
        'printf "user=%s\\n" "$(readlink /proc/self/ns/user)"; '
        'printf "pid=%s\\n" "$(readlink /proc/self/ns/pid)"; '
        'printf "ipc=%s\\n" "$(readlink /proc/self/ns/ipc)"; '
        'printf "sh_pid=%s\\n" "$$"; '
        'printf "pid1_ns=%s\\n" "$(grep "^NSpid:" /proc/1/status | tr "\\t" " ")"; '
        'grep "^NSpid:" /proc/self/status'
    )
    cmd = [
        "bwrap",
        "--unshare-all",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "/bin/sh", "-c", inner_sh,
    ]
    # Run multiple rounds so async cleanup_net -> dec_ucount workqueues execute
    # after fake userns teardown (regression test for ucounts->ns UAF).
    kv = {}
    nspid_line = ""
    for rnd in range(3):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return "FAIL", f"bwrap --unshare-all round {rnd + 1} failed (rc={r.returncode}): {(r.stderr or r.stdout).strip()}"

        kv = {}
        nspid_line = ""
        for ln in r.stdout.splitlines():
            s = ln.strip()
            if s.startswith("NSpid:"):
                nspid_line = s
            elif "=" in s:
                k, v = s.split("=", 1)
                kv[k] = v

        for k, outer in (("user", outer_user), ("pid", outer_pid), ("ipc", outer_ipc)):
            inner = kv.get(k, "")
            if not inner or not inner.startswith(f"{k}:["):
                return "FAIL", f"bwrap invalid inner ns/{k}: {inner!r}"
            if outer and inner == outer:
                return "FAIL", f"bwrap ns/{k} not isolated (still {inner})"

        # bwrap --proc /proc mounts a fresh procfs in the inner PID namespace, so
        # NSpid starts at that namespace level (1 column): /proc/1/status must show
        # NSpid 1, sh itself is PID 1 or 2, and self/status NSpid is a single inner PID.
        pid1_toks = kv.get("pid1_ns", "").split()[1:]
        if pid1_toks != ["1"]:
            return "FAIL", f"bwrap unexpected /proc/1/status {kv.get('pid1_ns', '')!r}"
        if kv.get("sh_pid", "") not in ("1", "2"):
            return "FAIL", f"bwrap unexpected shell pid={kv.get('sh_pid', '')!r}"
        toks = nspid_line.split()[1:] if nspid_line else []
        if len(toks) != 1 or not toks[0].isdigit() or int(toks[0]) < 1:
            return "FAIL", f"bwrap unexpected inner {nspid_line!r}"
    time.sleep(0.4)

    return "PASS", f"bwrap --unshare-all x3 verified: {kv['user']} | {kv['pid']} | {kv['ipc']} | sh_pid={kv['sh_pid']} {nspid_line}"


def run_local_suite(include_bwrap: bool = False, include_stress: bool = False) -> List[TestResult]:
    tests: List[Tuple[str, Callable[[], Tuple[str, str]]]] = [
        ("sysv_shm", test_sysv_shm),
        ("sysv_sem", test_sysv_sem),
        ("sysv_msg", test_sysv_msg),
        ("posix_mqueue", test_posix_mqueue),
        ("ipc_ns_isolation", test_ipc_ns_isolation),
        ("pid_ns_nested_and_status", test_pid_ns_nested_and_status),
        ("clone_and_clone3_ns", test_clone_and_clone3_ns),
        ("setns_ipc_and_pid", test_setns_ipc_and_pid),
        ("unpriv_ns_perm", test_unpriv_ns_perm),
        ("userns_state_machine", test_userns_state_machine),
        ("userns_lpe_guard", test_userns_lpe_guard),
        ("devtmpfs_registered", test_devtmpfs_registered),
    ]
    if include_stress:
        tests.extend(
            [
                ("stress:ipc_ns_implicit_teardown", test_ipc_ns_implicit_teardown),
                ("stress:clone3_fault_refcount", test_clone3_stress_and_refcount),
                ("stress:pid_ns_reaper_cleanup", test_pid_ns_reaper_cleanup),
                ("stress:ns_concurrency", test_ns_concurrency_stress),
            ]
        )
    if include_bwrap:
        tests.append(("bwrap_smoke", test_bwrap_smoke))
    tests.append(("userns_object_leak_guard", test_userns_object_leak_guard))

    results: List[TestResult] = []
    for name, fn in tests:
        try:
            st, detail = fn()
        except Exception as exc:
            st, detail = "FAIL", f"unhandled exception: {exc!r}"
        results.append(TestResult(name, st, detail))
    return results


def run_via_ssh(host: str, include_stress: bool = False) -> List[TestResult]:
    script_src = Path(__file__).read_text(encoding="utf-8")
    remote_args = ["python3", "-", "--local-json", "--include-bwrap"]
    if include_stress:
        remote_args.append("--stress")
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", host, *remote_args],
        input=script_src,
        capture_output=True,
        text=True,
        timeout=60 if include_stress else 45,
    )
    if r.returncode not in (0, 1) or not r.stdout.strip():
        return [TestResult(f"ssh:{host}", "FAIL", f"ssh exec failed (rc={r.returncode}): {r.stderr.strip()}")]
    try:
        arr = json.loads(r.stdout)
        return [TestResult(f"{host}:{item['name']}", item["status"], item["detail"]) for item in arr]
    except Exception as exc:
        return [TestResult(f"ssh:{host}", "FAIL", f"bad json from {host}: {exc}; stdout={r.stdout[:200]!r}")]


def capture_dmesg_anchor() -> Tuple[float, List[str]]:
    """Capture last numeric timestamp and tail lines as an exact post-run anchor."""
    try:
        r = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return -1.0, []
        lines = r.stdout.splitlines()
        ts = -1.0
        for ln in reversed(lines):
            m = re.match(r"^\[\s*(\d+\.\d+)\]", ln)
            if m:
                ts = float(m.group(1))
                break
        return ts, lines[-8:]
    except Exception:
        return -1.0, []


def check_dmesg_delta(since_ts: float, tail_anchor: List[str]) -> TestResult:
    """Detect any kernel WARNING/BUG/Oops/CFI/BTI/refcount/KASAN triggered during test run."""
    if since_ts < 0:
        return TestResult("kernel_dmesg_delta", "SKIP", "dmesg unavailable (run with sudo python3)")
    try:
        r = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return TestResult("kernel_dmesg_delta", "SKIP", "dmesg read failed")
    except Exception as exc:
        return TestResult("kernel_dmesg_delta", "SKIP", f"dmesg error: {exc}")

    lines = r.stdout.splitlines()
    new_lines: List[str] = []

    # Locate exact end of tail_anchor in current dmesg ring buffer
    matched_idx = -1
    if tail_anchor:
        k = len(tail_anchor)
        for idx in range(len(lines) - k, -1, -1):
            if lines[idx : idx + k] == tail_anchor:
                matched_idx = idx + k
                break

    if matched_idx >= 0:
        new_lines = lines[matched_idx:]
    else:
        for ln in lines:
            m = re.match(r"^\[\s*(\d+\.\d+)\]", ln)
            if m and float(m.group(1)) > since_ts:
                new_lines.append(ln)

    warn_pat = re.compile(
        r"WARNING:|BUG:|Oops|Internal error|CFI failure|Branch Target|\bBTI\b|"
        r"Unhandled.*fault|Unable to handle kernel|Kernel panic|"
        r"KASAN:|KFENCE:|UBSAN:|refcount_t:|list_add corruption|list_del corruption|"
        r"use-after-free|Bad mode|Bad page|rcu.*stall",
        re.I,
    )
    hits: List[str] = []
    for ln in new_lines:
        if warn_pat.search(ln):
            hits.append(ln.strip())

    if hits:
        preview = " ; ".join(hits[:3])
        return TestResult("kernel_dmesg_delta", "FAIL", f"{len(hits)} new kernel warning(s): {preview}")
    return TestResult(
        "kernel_dmesg_delta",
        "PASS",
        f"no new kernel WARNING/BUG/Oops/CFI/BTI/refcount in {len(new_lines)} new dmesg line(s) since t={since_ts:.3f}s",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Safe userspace runtime regression tests for droid_lkm")
    ap.add_argument("--lyra", action="store_true", help="also run container-side suite via `ssh lyra`")
    ap.add_argument("--only-lyra", action="store_true", help="only run container-side suite via `ssh lyra`")
    ap.add_argument("--ssh-host", default="lyra", help="SSH host alias for Droidspaces container (default: lyra)")
    ap.add_argument("--include-bwrap", action="store_true", help="run bwrap smoke test locally")
    ap.add_argument(
        "--stress",
        action="store_true",
        help="run fault-injection / implicit-teardown / concurrency stress tests (DO NOT run on unpatched old LKM)",
    )
    ap.add_argument("--no-dmesg-check", action="store_true", help="skip before/after dmesg warning delta check")
    ap.add_argument("--local-json", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.local_json:
        res = run_local_suite(include_bwrap=args.include_bwrap, include_stress=args.stress)
        print(json.dumps([r.__dict__ for r in res]))
        return 1 if any(r.status == "FAIL" for r in res) else 0

    dmesg_before, dmesg_anchor = (
        (-1.0, []) if (args.no_dmesg_check or os.geteuid() != 0) else capture_dmesg_anchor()
    )

    all_res: List[TestResult] = []
    if not args.only_lyra:
        print(f"== droid_lkm userspace runtime tests (host: {os.uname().release}, euid={os.geteuid()}) ==")
        if os.geteuid() != 0:
            print("note: running as non-root; namespace tests may SKIP (use `sudo python3` on Termux host)")
        all_res.extend(run_local_suite(include_bwrap=args.include_bwrap, include_stress=args.stress))

    if args.lyra or args.only_lyra:
        print(f"== container tests via `ssh {args.ssh_host}` ==")
        all_res.extend(run_via_ssh(args.ssh_host, include_stress=args.stress))

    if not args.no_dmesg_check and os.geteuid() == 0:
        all_res.append(check_dmesg_delta(dmesg_before, dmesg_anchor))

    fails = 0
    passes = 0
    skips = 0
    for r in all_res:
        if r.status == "PASS":
            passes += 1
        elif r.status == "FAIL":
            fails += 1
        else:
            skips += 1
        print(f"  [{r.status:4s}] {r.name:30s} {r.detail}")

    print(f"\nsummary: {passes} PASS, {fails} FAIL, {skips} SKIP")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
