// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * Static executable trampoline slot pool for single-instruction B hooks.
 * Linked into each module's own .text section so every slot stays within
 * +/-128MiB of module wrappers and kernel .text (standard KASLR), inherits
 * native RX / BTI page attributes, and is patchable via the kernel's own
 * aarch64_insn_patch_text().
 *
 * Layout per 32-byte (16-byte aligned) slot:
 *   +0  .. +15 : entry stub  (xpaclri; b <wrapper>; brk #0; brk #0)
 *   +16 .. +31 : orig tramp  (paciasp|bti c; <orig_insn>; b <target+next>; brk #0)
 */

	.section .text, "ax", @progbits
	.balign	16
	.global	ds_bhook_slot_pool
	.type	ds_bhook_slot_pool, %function
ds_bhook_slot_pool:
	.rept	16
	brk	#0
	brk	#0
	brk	#0
	brk	#0
	brk	#0
	brk	#0
	brk	#0
	brk	#0
	.endr
	.size	ds_bhook_slot_pool, . - ds_bhook_slot_pool
