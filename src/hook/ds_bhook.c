// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <asm/barrier.h>

#include "core.h"
#include "ds_compat.h"
#include "ds_bhook.h"
#include "hk.h"

#define DS_BHOOK_TAG		"droid_lkm/bhook"
#define ds_bhook_info(fmt, ...)	pr_info("[I] [" DS_BHOOK_TAG "] " fmt, ##__VA_ARGS__)
#define ds_bhook_warn(fmt, ...)	pr_warn("[W] [" DS_BHOOK_TAG "] " fmt, ##__VA_ARGS__)

#define DS_BHOOK_MAX_SLOTS	16
#define DS_BHOOK_SLOT_STRIDE	32
#define DS_BHOOK_ORIG_OFF	16

#define DS_INSN_NOP		0xD503201Fu
#define DS_INSN_XPACLRI		0xD50320FFu
#define DS_INSN_PACIASP		0xD503233Fu
#define DS_INSN_BTI_C		0xD503245Fu
#define DS_INSN_BTI_JC		0xD50324DFu
#define DS_INSN_MOV_X9_LR	0xAA1E03E9u

extern char ds_bhook_slot_pool[];

typedef int (*ds_bhook_patch_text_t)(void *addrs[], u32 insns[], int cnt);
typedef unsigned long (*ds_bhook_ftrace_loc_t)(unsigned long start,
					       unsigned long end);

static ds_bhook_patch_text_t ds_bhook_patch_fn;
static ds_bhook_ftrace_loc_t ds_bhook_ftrace_loc_fn;
static bool ds_bhook_inited;
static bool ds_bhook_usable;

static DEFINE_MUTEX(ds_bhook_lock);
static bool ds_bhook_slot_busy[DS_BHOOK_MAX_SLOTS];
static unsigned long ds_bhook_slot_patch_addr[DS_BHOOK_MAX_SLOTS];
static unsigned int ds_bhook_slot_cursor;

static __nocfi noinline int ds_bhook_call_patch(void *addrs[], u32 insns[],
						int cnt)
{
	if (!ds_bhook_patch_fn)
		return -ENOENT;
	return ds_bhook_patch_fn(addrs, insns, cnt);
}

static __nocfi noinline unsigned long ds_bhook_call_ftrace_loc(
	unsigned long start, unsigned long end)
{
	if (!ds_bhook_ftrace_loc_fn)
		return 0;
	return ds_bhook_ftrace_loc_fn(start, end);
}

/*
 * Return true iff a single AArch64 instruction executes identically when moved
 * into an out-of-line trampoline slot (no PC-relative addressing, no control
 * transfer, no exception/trap, no PAC/AUT/BTI/unknown HINT).
 */
static bool ds_bhook_insn_relocatable(u32 insn)
{
	/* UDF / unmapped zero */
	if ((insn & 0xFFFF0000u) == 0x00000000u)
		return false;

	/* B / BL */
	if ((insn & 0x7C000000u) == 0x14000000u)
		return false;

	/* B.cond / BC.cond */
	if ((insn & 0xFF000000u) == 0x54000000u)
		return false;

	/* CBZ / CBNZ / TBZ / TBNZ */
	if ((insn & 0x7E000000u) == 0x34000000u ||
	    (insn & 0x7E000000u) == 0x36000000u)
		return false;

	/* BR / BLR / RET / ERET / DRPS / BRAA / BLRAA / RETAA / RETAB */
	if ((insn & 0xFE000000u) == 0xD6000000u)
		return false;

	/* SVC / HVC / SMC / BRK / HLT / DCPS */
	if ((insn & 0xFF000000u) == 0xD4000000u)
		return false;

	/* ADR / ADRP */
	if ((insn & 0x1F000000u) == 0x10000000u)
		return false;

	/* Load register (literal) GPR + SIMD/FP + PRFM literal */
	if ((insn & 0x3B000000u) == 0x18000000u)
		return false;

	/* System HINT space: allow plain NOP only; reject BTI/PAC/AUT/PACM/... */
	if ((insn & 0xFFFFF01Fu) == 0xD503201Fu)
		return insn == DS_INSN_NOP;

	/* Data-processing 1-source PAC / AUT / XPAC space */
	if ((insn & 0xFFFF8000u) == 0xDAC10000u)
		return false;

	return true;
}

static bool ds_bhook_encode_b(unsigned long from, unsigned long to, u32 *out)
{
	s64 delta = (s64)to - (s64)from;

	if ((delta & 3LL) != 0)
		return false;
	if (delta < -0x08000000LL || delta > 0x07FFFFFCLL)
		return false;
	*out = 0x14000000u | ((u32)(delta >> 2) & 0x03FFFFFFu);
	return true;
}

static int ds_bhook_classify_prologue(const u32 w[3], u32 *patch_off,
				      u32 *orig_insn, bool *need_xpac)
{
	/* Reject ftrace patchable-function-entry / active ftrace prologues */
	if (w[0] == DS_INSN_MOV_X9_LR || w[1] == DS_INSN_MOV_X9_LR)
		return -EOPNOTSUPP;
	if ((w[0] == DS_INSN_NOP && w[1] == DS_INSN_NOP) ||
	    (w[1] == DS_INSN_NOP && w[2] == DS_INSN_NOP))
		return -EOPNOTSUPP;

	if (w[0] == DS_INSN_PACIASP) {
		if (!ds_bhook_insn_relocatable(w[1]))
			return -EOPNOTSUPP;
		*patch_off = 4;
		*orig_insn = w[1];
		*need_xpac = true;
		return 0;
	}

	if (w[0] == DS_INSN_BTI_C || w[0] == DS_INSN_BTI_JC) {
		if (w[1] == DS_INSN_PACIASP) {
			if (!ds_bhook_insn_relocatable(w[2]))
				return -EOPNOTSUPP;
			*patch_off = 8;
			*orig_insn = w[2];
			*need_xpac = true;
			return 0;
		}
		if (!ds_bhook_insn_relocatable(w[1]))
			return -EOPNOTSUPP;
		*patch_off = 4;
		*orig_insn = w[1];
		*need_xpac = false;
		return 0;
	}

	if (!ds_bhook_insn_relocatable(w[0]))
		return -EOPNOTSUPP;
	*patch_off = 0;
	*orig_insn = w[0];
	*need_xpac = false;
	return 0;
}

static int ds_bhook_alloc_slot_locked(unsigned long patch_addr)
{
	unsigned int i;

	for (i = 0; i < DS_BHOOK_MAX_SLOTS; i++) {
		if (ds_bhook_slot_busy[i] &&
		    ds_bhook_slot_patch_addr[i] == patch_addr)
			return -EBUSY;
	}

	for (i = 0; i < DS_BHOOK_MAX_SLOTS; i++) {
		unsigned int idx =
			(ds_bhook_slot_cursor + i) % DS_BHOOK_MAX_SLOTS;

		if (!ds_bhook_slot_busy[idx]) {
			ds_bhook_slot_busy[idx] = true;
			ds_bhook_slot_patch_addr[idx] = patch_addr;
			ds_bhook_slot_cursor = (idx + 1) % DS_BHOOK_MAX_SLOTS;
			return (int)idx;
		}
	}

	return -ENOSPC;
}

static int ds_bhook_install_core(struct ds_bhook *h, unsigned long target,
				 unsigned long repl, const char *name)
{
	unsigned long patch_addr, resume_addr, slot_entry, slot_orig;
	u32 w[3], patch_off = 0, orig_insn = 0;
	u32 b_target = 0, b_wrap = 0, b_resume = 0;
	void *addrs[6];
	u32 insns[6];
	bool need_xpac = false;
	int slot_idx, cnt, ret;

	if (!h || !target || !repl)
		return -EINVAL;
	if ((target & 3UL) || (repl & 3UL))
		return -EINVAL;
	if (!ds_bhook_patch_fn)
		return -EOPNOTSUPP;

	if (safe_read(w, (void *)target, sizeof(w)))
		return -EFAULT;

	if (ds_bhook_ftrace_loc_fn &&
	    ds_bhook_call_ftrace_loc(target, target + 15))
		return -EOPNOTSUPP;

	ret = ds_bhook_classify_prologue(w, &patch_off, &orig_insn, &need_xpac);
	if (ret)
		return ret;

	patch_addr = target + patch_off;
	resume_addr = patch_addr + 4;

	mutex_lock(&ds_bhook_lock);
	slot_idx = ds_bhook_alloc_slot_locked(patch_addr);
	if (slot_idx < 0) {
		mutex_unlock(&ds_bhook_lock);
		return slot_idx;
	}

	slot_entry = (unsigned long)&ds_bhook_slot_pool[slot_idx *
							DS_BHOOK_SLOT_STRIDE];
	slot_orig = slot_entry + DS_BHOOK_ORIG_OFF;

	if (!ds_bhook_encode_b(slot_orig + 8, resume_addr, &b_resume)) {
		ret = -ERANGE;
		goto err_slot;
	}

	if (need_xpac) {
		if (!ds_bhook_encode_b(patch_addr, slot_entry, &b_target) ||
		    !ds_bhook_encode_b(slot_entry + 4, repl, &b_wrap)) {
			ret = -ERANGE;
			goto err_slot;
		}
		addrs[0] = (void *)(slot_orig + 0);
		insns[0] = DS_INSN_PACIASP;
		addrs[1] = (void *)(slot_orig + 4);
		insns[1] = orig_insn;
		addrs[2] = (void *)(slot_orig + 8);
		insns[2] = b_resume;
		addrs[3] = (void *)(slot_entry + 0);
		insns[3] = DS_INSN_XPACLRI;
		addrs[4] = (void *)(slot_entry + 4);
		insns[4] = b_wrap;
		/* Target instruction is written last inside the same stop_machine */
		addrs[5] = (void *)patch_addr;
		insns[5] = b_target;
		cnt = 6;
	} else {
		if (!ds_bhook_encode_b(patch_addr, repl, &b_target)) {
			ret = -ERANGE;
			goto err_slot;
		}
		addrs[0] = (void *)(slot_orig + 0);
		insns[0] = DS_INSN_BTI_C;
		addrs[1] = (void *)(slot_orig + 4);
		insns[1] = orig_insn;
		addrs[2] = (void *)(slot_orig + 8);
		insns[2] = b_resume;
		addrs[3] = (void *)patch_addr;
		insns[3] = b_target;
		cnt = 4;
	}

	memset(h, 0, sizeof(*h));
	h->addr = target;
	h->patch_addr = patch_addr;
	h->orig = slot_orig;
	h->repl = repl;
	h->orig_insn = orig_insn;
	h->slot_idx = slot_idx;
	h->need_xpac = need_xpac;
	/* Publish h->orig before target becomes live so wrappers never see NULL */
	smp_wmb();

	ret = ds_bhook_call_patch(addrs, insns, cnt);
	if (ret) {
		memset(h, 0, sizeof(*h));
		h->slot_idx = -1;
		goto err_slot;
	}

	WRITE_ONCE(h->live, true);
	mutex_unlock(&ds_bhook_lock);
	return 0;

err_slot:
	ds_bhook_slot_busy[slot_idx] = false;
	ds_bhook_slot_patch_addr[slot_idx] = 0;
	mutex_unlock(&ds_bhook_lock);
	if (name && ret == -ERANGE)
		ds_bhook_warn("%s: target 0x%lx out of +/-128MiB B range (slot 0x%lx)\n",
			      name, patch_addr, slot_entry);
	return ret;
}

int ds_bhook_remove(struct ds_bhook *h)
{
	void *addr;
	u32 insn;
	int slot_idx, ret;

	if (!h || !READ_ONCE(h->live))
		return -EINVAL;

	mutex_lock(&ds_bhook_lock);
	if (!h->live) {
		mutex_unlock(&ds_bhook_lock);
		return -EINVAL;
	}

	addr = (void *)h->patch_addr;
	insn = h->orig_insn;
	slot_idx = h->slot_idx;

	ret = ds_bhook_call_patch(&addr, &insn, 1);
	if (ret) {
		mutex_unlock(&ds_bhook_lock);
		ds_bhook_warn("restore 0x%lx failed (%d)\n", h->patch_addr, ret);
		return ret;
	}

	WRITE_ONCE(h->live, false);
	mutex_unlock(&ds_bhook_lock);

	/*
	 * Two tasks-RCU grace periods + regular RCU sync to drain any core
	 * that fetched the trampoline/wrapper right before restore.
	 */
	hk_wait_tasks_rcu();
	hk_wait_tasks_rcu();
	synchronize_rcu();

	mutex_lock(&ds_bhook_lock);
	if (slot_idx >= 0 && slot_idx < DS_BHOOK_MAX_SLOTS) {
		ds_bhook_slot_busy[slot_idx] = false;
		ds_bhook_slot_patch_addr[slot_idx] = 0;
	}
	h->slot_idx = -1;
	mutex_unlock(&ds_bhook_lock);
	return 0;
}

/*
 * Boot-time self-test canary: non-leaf function compiled with the module's own
 * branch-protection flags (paciasp on PAC kernels) to verify PAC/FPAC/BTI/SCS
 * and aarch64_insn_patch_text round-trip before touching any kernel symbol.
 */
static notrace noinline void ds_bhook_canary_sink(volatile int *p)
{
	barrier();
	*p = *p + 1;
	barrier();
}

static notrace noinline int ds_bhook_canary_target(int x)
{
	volatile int v = x;

	ds_bhook_canary_sink(&v);
	return v;
}

static struct ds_bhook ds_bhook_canary_h;

static notrace DROID_LKM_ENTRY __nocfi noinline int ds_bhook_canary_wrap(int x)
{
	int (*orig)(int) = (int (*)(int))READ_ONCE(ds_bhook_canary_h.orig);

	if (!orig)
		return -1;
	return orig(x) + 100;
}

static bool ds_bhook_selftest(void)
{
	int before, during, after, ret;

	before = ds_bhook_canary_target(41);
	if (before != 42)
		return false;

	ret = ds_bhook_install_core(&ds_bhook_canary_h,
				    (unsigned long)ds_bhook_canary_target,
				    (unsigned long)ds_bhook_canary_wrap,
				    "ds_bhook_canary");
	if (ret) {
		ds_bhook_warn("canary install failed (%d), bhook disabled\n", ret);
		return false;
	}

	during = ds_bhook_canary_target(41);
	ret = ds_bhook_remove(&ds_bhook_canary_h);
	after = ds_bhook_canary_target(41);

	if (during != 142 || ret || after != 42) {
		ds_bhook_warn("canary mismatch (during=%d rm=%d after=%d), bhook disabled\n",
			      during, ret, after);
		return false;
	}

	ds_bhook_info("canary passed (patch_off=%lu xpac=%d)\n",
		      ds_bhook_canary_h.patch_addr - ds_bhook_canary_h.addr,
		      ds_bhook_canary_h.need_xpac ? 1 : 0);
	return true;
}

void ds_bhook_init(bool run_selftest)
{
	if (ds_bhook_inited)
		return;
	ds_bhook_inited = true;

	ds_bhook_patch_fn = (ds_bhook_patch_text_t)ds_compat_sym(
		"aarch64_insn_patch_text");
	ds_bhook_ftrace_loc_fn = (ds_bhook_ftrace_loc_t)ds_compat_sym(
		"ftrace_location_range");

	if (!ds_bhook_patch_fn) {
		ds_bhook_warn("aarch64_insn_patch_text unavailable, bhook disabled\n");
		ds_bhook_usable = false;
		return;
	}

	if (run_selftest)
		ds_bhook_usable = ds_bhook_selftest();
	else
		ds_bhook_usable = true;
}

bool ds_bhook_ready(void)
{
	return ds_bhook_usable;
}

int ds_bhook_install_at(struct ds_bhook *h, unsigned long target,
			unsigned long repl, const char *name)
{
	if (!ds_bhook_inited)
		ds_bhook_init(true);
	if (!ds_bhook_usable)
		return -EOPNOTSUPP;
	return ds_bhook_install_core(h, target, repl, name);
}

int ds_bhook_install(struct ds_bhook *h, const char *sym, const char *wrap)
{
	unsigned long target, repl;

	if (!h || !sym || !wrap)
		return -EINVAL;
	target = ds_compat_sym(sym);
	if (!target)
		return -ENOENT;
	repl = ds_compat_sym(wrap);
	if (!repl)
		return -ENOENT;
	return ds_bhook_install_at(h, target, repl, sym);
}
