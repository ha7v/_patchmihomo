// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef DS_BHOOK_H
#define DS_BHOOK_H

#include <linux/types.h>

/*
 * Single-instruction 4-byte ARM64 B inline hook engine.
 *
 * Patches exactly one instruction (at +0, +4 after paciasp/bti, or +8 after
 * bti+paciasp) via aarch64_insn_patch_text(), routing calls through a static
 * .text trampoline slot in THIS_MODULE. Preserves PAC/FPAC, BTI, Dynamic SCS,
 * W^X, and KCFI without stop_machine stack scanning.
 */
struct ds_bhook {
	unsigned long addr;		/* target function entry */
	unsigned long patch_addr;	/* exact 4-byte patched site */
	unsigned long orig;		/* trampoline entry to call original */
	unsigned long repl;		/* C wrapper entry */
	u32 orig_insn;			/* original instruction at patch_addr */
	int slot_idx;			/* index in ds_bhook_slot_pool, or -1 */
	bool need_xpac;
	bool live;
};

void ds_bhook_init(bool run_selftest);
bool ds_bhook_ready(void);
int ds_bhook_install_at(struct ds_bhook *h, unsigned long target,
			unsigned long repl, const char *name);
int ds_bhook_install(struct ds_bhook *h, const char *sym, const char *wrap);
int ds_bhook_remove(struct ds_bhook *h);

#endif
