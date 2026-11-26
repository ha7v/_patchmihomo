// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Dere3046
 */

#ifndef DS_HOOK_H
#define DS_HOOK_H

#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/types.h>

#include "ds_bhook.h"
#include "hk_redir.h"

enum ds_hook_route {
	DS_HOOK_NONE = 0,	/* nothing is in place */
	DS_HOOK_SLOT,		/* a pointer in a kernel table was replaced */
	DS_HOOK_BHOOK,		/* single-instruction 4-byte B inline hook */
	DS_HOOK_TEXT,		/* legacy HooKern multi-instruction text hook */
	DS_HOOK_KPROBE,		/* kprobe breakpoint redirect */
};

enum ds_hook_mode {
	DS_HOOK_AUTO = 0,
	DS_HOOK_TEXT_ONLY,
	DS_HOOK_KPROBE_ONLY,
};

struct ds_hook {
	struct list_head node;	/* intrusive link into tracked hooks list */
	const char *name;	/* target symbol name for reporting */
	struct hk_redir *redir;	/* active kprobe/legacy-text transport */
	struct hk_redir own;	/* owned transport record */
	struct ds_bhook bhook;	/* single-instruction B hook record */
	void **slot;		/* kernel table slot address (DS_HOOK_SLOT) */
	unsigned long addr;	/* entry address */
	unsigned long orig;	/* original / trampoline callable address */
	enum ds_hook_route route;
	bool live;
	bool tracked;
};

/* apply module parameters and run bhook canary before the first install */
void ds_hook_policy_apply(void);

const char *ds_hook_route_name(enum ds_hook_route route);
const char *ds_hook_mode_name(void);

/*
 * Hot-path auto install: single-instruction B hook first (unless route=2),
 * automatic fallback to kprobe with the requested guard.
 */
int ds_hook_install(struct ds_hook *h, const char *sym, const char *wrap);
int ds_hook_install_guard(struct ds_hook *h, const char *sym, const char *wrap,
			  enum hk_redir_guard guard);

/*
 * Low-frequency install: prefers kprobe directly in auto mode (zero kernel
 * .text patching), uses bhook/text only when route=1.
 */
int ds_hook_install_kprobe(struct ds_hook *h, const char *sym,
			   const char *wrap);
int ds_hook_install_kprobe_guard(struct ds_hook *h, const char *sym,
				 const char *wrap, enum hk_redir_guard guard);

int ds_hook_install_text(struct ds_hook *h, const char *sym, const char *wrap);

/*
 * Table slot install: verifies *slot matches sym before patching via private
 * vmap alias, falling back to function routes on mismatch or write refusal.
 */
int ds_hook_install_slot(struct ds_hook *h, void **slot, const void *repl,
			 const char *sym, const char *wrap);
int ds_hook_install_slot_guard(struct ds_hook *h, void **slot, const void *repl,
			       const char *sym, const char *wrap,
			       enum hk_redir_guard guard);

/* critical variants: absence refuses load unless degrade=1 */
int ds_hook_install_critical(struct ds_hook *h, const char *sym,
			     const char *wrap);
int ds_hook_install_critical_guard(struct ds_hook *h, const char *sym,
				   const char *wrap, enum hk_redir_guard guard);
int ds_hook_install_critical_kprobe_guard(struct ds_hook *h, const char *sym,
					  const char *wrap,
					  enum hk_redir_guard guard);
int ds_hook_install_slot_critical(struct ds_hook *h, void **slot,
				  const void *repl, const char *sym,
				  const char *wrap);
bool ds_hook_critical_ok(void);
bool ds_hook_degrade_enabled(void);

/* inline fast path: zero call overhead on bhook/slot/text/caller-guard routes */
static inline void ds_hook_leave(struct ds_hook *h)
{
	if (unlikely(h && h->route == DS_HOOK_KPROBE && h->redir &&
		     h->redir->guard == HK_REDIR_GUARD_TASK))
		hk_redir_leave(h->redir);
}

/* mark task guard before deliberate module-initiated call into orig */
static inline bool ds_hook_enter(struct ds_hook *h)
{
	if (unlikely(h && h->route == DS_HOOK_KPROBE && h->redir)) {
		if (h->redir->guard != HK_REDIR_GUARD_TASK)
			return true;
		return hk_redir_guard_enter(h->redir);
	}
	return false;
}

int ds_hook_remove(struct ds_hook *h);
void ds_hook_exit(void);
void ds_hook_report(void);

/* walk tracked installs for reporting, non-zero return stops the walk */
int ds_hook_enum(int (*fn)(void *ctx, const struct ds_hook *h), void *ctx);

#endif
