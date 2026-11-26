// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Dere3046
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/barrier.h>

#include "core.h"
#include "ds_compat.h"
#include "ds_bhook.h"
#include "ds_hook.h"
#include "hk_patch.h"
#include "hk_redir.h"

#define DS_HOOK_TAG "droid_lkm/hook"

#define ds_hook_info(fmt, ...) pr_info("[I] [" DS_HOOK_TAG "] " fmt, ##__VA_ARGS__)
#define ds_hook_warn(fmt, ...) pr_warn("[W] [" DS_HOOK_TAG "] " fmt, ##__VA_ARGS__)

/*
 * 0 auto (hot hooks take single-insn bhook -> kprobe fallback; low-freq hooks
 * take kprobe directly), 1 entry write only, 2 breakpoint only.
 */
static uint ds_hook_mode;
module_param_named(route, ds_hook_mode, uint, 0444);
MODULE_PARM_DESC(route, "0 auto (default), 1 entry write only, 2 breakpoint only");

static bool ds_hook_degrade;
module_param_named(degrade, ds_hook_degrade, bool, 0444);
MODULE_PARM_DESC(degrade,
	"1 keeps running when a container critical hook cannot install, 0 refuses the load");

static DEFINE_MUTEX(ds_hook_list_lock);
static LIST_HEAD(ds_hook_head);
static bool ds_hook_critical_missing;

void ds_hook_policy_apply(void)
{
	ds_hook_info("policy: route=%u degrade=%d\n", ds_hook_mode,
		     ds_hook_degrade);
	if (ds_hook_mode != DS_HOOK_KPROBE_ONLY)
		ds_bhook_init(true);
}

const char *ds_hook_route_name(enum ds_hook_route route)
{
	static const char *const names[] = {
		[DS_HOOK_NONE] = "none",
		[DS_HOOK_SLOT] = "slot",
		[DS_HOOK_BHOOK] = "bhook",
		[DS_HOOK_TEXT] = "text",
		[DS_HOOK_KPROBE] = "kprobe",
	};

	if (route > DS_HOOK_KPROBE)
		return "?";
	return names[route];
}

const char *ds_hook_mode_name(void)
{
	if (ds_hook_mode == DS_HOOK_TEXT_ONLY)
		return "text";
	if (ds_hook_mode == DS_HOOK_KPROBE_ONLY)
		return "kprobe";
	return "auto";
}

static void ds_hook_track(struct ds_hook *h)
{
	mutex_lock(&ds_hook_list_lock);
	if (!h->tracked) {
		INIT_LIST_HEAD(&h->node);
		list_add_tail(&h->node, &ds_hook_head);
		h->tracked = true;
	}
	mutex_unlock(&ds_hook_list_lock);
}

static void ds_hook_untrack(struct ds_hook *h)
{
	mutex_lock(&ds_hook_list_lock);
	if (h->tracked) {
		list_del_init(&h->node);
		h->tracked = false;
	}
	mutex_unlock(&ds_hook_list_lock);
}

static int ds_hook_try_bhook(struct ds_hook *h, const char *sym,
			     const char *wrap)
{
	int ret;

	ret = ds_bhook_install(&h->bhook, sym, wrap);
	if (ret)
		return ret;

	h->route = DS_HOOK_BHOOK;
	h->addr = h->bhook.addr;
	h->orig = h->bhook.orig;
	smp_wmb();
	WRITE_ONCE(h->live, true);
	return 0;
}

static int ds_hook_try_redir(struct ds_hook *h, const char *sym,
			     const char *wrap, enum ds_hook_route route,
			     enum hk_redir_guard guard)
{
	enum hk_redir_how how = route == DS_HOOK_TEXT ? HK_REDIR_TEXT :
							HK_REDIR_KPROBE;
	int ret;

	memset(&h->own, 0, sizeof(h->own));
	if (route == DS_HOOK_TEXT) {
		h->own.ret_mode = HK_INLINE_RET_X17;
	} else {
		h->own.adjust = hk_kprobe_adjust_pad;
		h->own.guard = guard;
	}

	ret = hk_redir_install(&h->own, sym, wrap, how);
	if (ret)
		return ret;

	h->redir = &h->own;
	h->route = route;
	h->addr = h->own.addr;
	h->orig = h->own.orig;
	smp_wmb();
	WRITE_ONCE(h->live, true);
	return 0;
}

static int ds_hook_try_entry_write(struct ds_hook *h, const char *sym,
				   const char *wrap)
{
	struct hk_inline_probe probe;
	int ret;

	ret = ds_hook_try_bhook(h, sym, wrap);
	if (!ret)
		return 0;

	/* Legacy multi-insn fallback only if target is plain (no PAC/thunk) */
	memset(&probe, 0, sizeof(probe));
	if (!hk_inline_probe(sym, &probe) && probe.state == HK_INLINE_PLAIN)
		return ds_hook_try_redir(h, sym, wrap, DS_HOOK_TEXT,
					 HK_REDIR_GUARD_TASK);

	return ret;
}

int ds_hook_install_guard(struct ds_hook *h, const char *sym, const char *wrap,
			  enum hk_redir_guard guard)
{
	int ret;

	if (!h || !sym || !wrap)
		return -EINVAL;
	if (guard != HK_REDIR_GUARD_TASK && guard != HK_REDIR_GUARD_CALLER)
		return -EINVAL;

	memset(h, 0, sizeof(*h));
	INIT_LIST_HEAD(&h->node);
	h->bhook.slot_idx = -1;
	h->name = sym;

	switch (ds_hook_mode) {
	case DS_HOOK_KPROBE_ONLY:
		ret = ds_hook_try_redir(h, sym, wrap, DS_HOOK_KPROBE, guard);
		break;
	case DS_HOOK_TEXT_ONLY:
		ret = ds_hook_try_entry_write(h, sym, wrap);
		break;
	default:
		ret = ds_hook_try_bhook(h, sym, wrap);
		if (ret)
			ret = ds_hook_try_redir(h, sym, wrap, DS_HOOK_KPROBE,
						guard);
		break;
	}

	if (ret) {
		ds_hook_warn("hook %s: no route took it (%d)\n", sym, ret);
		return ret;
	}

	ds_hook_track(h);
	ds_hook_info("hook %s on the %s route (entry 0x%016lx orig 0x%016lx)\n",
		     sym, ds_hook_route_name(h->route), h->addr, h->orig);
	return 0;
}

int ds_hook_install(struct ds_hook *h, const char *sym, const char *wrap)
{
	return ds_hook_install_guard(h, sym, wrap, HK_REDIR_GUARD_TASK);
}

int ds_hook_install_kprobe_guard(struct ds_hook *h, const char *sym,
				 const char *wrap, enum hk_redir_guard guard)
{
	int ret;

	if (!h || !sym || !wrap)
		return -EINVAL;
	if (guard != HK_REDIR_GUARD_TASK && guard != HK_REDIR_GUARD_CALLER)
		return -EINVAL;

	memset(h, 0, sizeof(*h));
	INIT_LIST_HEAD(&h->node);
	h->bhook.slot_idx = -1;
	h->name = sym;

	if (ds_hook_mode == DS_HOOK_TEXT_ONLY) {
		ret = ds_hook_try_entry_write(h, sym, wrap);
	} else {
		ret = ds_hook_try_redir(h, sym, wrap, DS_HOOK_KPROBE, guard);
	}

	if (ret) {
		ds_hook_warn("hook %s: kprobe route failed %d\n", sym, ret);
		return ret;
	}

	ds_hook_track(h);
	ds_hook_info("hook %s on the %s route (entry 0x%016lx orig 0x%016lx)\n",
		     sym, ds_hook_route_name(h->route), h->addr, h->orig);
	return 0;
}

int ds_hook_install_kprobe(struct ds_hook *h, const char *sym,
			   const char *wrap)
{
	return ds_hook_install_kprobe_guard(h, sym, wrap, HK_REDIR_GUARD_TASK);
}

int ds_hook_install_text(struct ds_hook *h, const char *sym, const char *wrap)
{
	int ret;

	if (!h || !sym || !wrap)
		return -EINVAL;
	if (ds_hook_mode == DS_HOOK_KPROBE_ONLY)
		return -EOPNOTSUPP;

	memset(h, 0, sizeof(*h));
	INIT_LIST_HEAD(&h->node);
	h->bhook.slot_idx = -1;
	h->name = sym;

	ret = ds_hook_try_entry_write(h, sym, wrap);
	if (ret) {
		ds_hook_warn("hook %s: entry write route failed %d\n", sym, ret);
		return ret;
	}

	ds_hook_track(h);
	ds_hook_info("hook %s on the %s route (entry 0x%016lx orig 0x%016lx)\n",
		     sym, ds_hook_route_name(h->route), h->addr, h->orig);
	return 0;
}

int ds_hook_install_slot_guard(struct ds_hook *h, void **slot, const void *repl,
			       const char *sym, const char *wrap,
			       enum hk_redir_guard guard)
{
	unsigned long val = (unsigned long)repl;
	unsigned long old = 0, expected, field;
	int ret;

	if (!h || !slot || !repl || !sym || !wrap)
		return -EINVAL;

	if (safe_read(&old, slot, sizeof(old)) || !old) {
		ds_hook_warn("hook %s: slot 0x%016lx unreadable or empty, falling back\n",
			     sym, (unsigned long)slot);
		return ds_hook_install_guard(h, sym, wrap, guard);
	}

	/* Verify the slot holds the expected symbol before patching */
	expected = ds_compat_sym(sym);
	if (expected && old != expected) {
		ds_hook_warn("hook %s: slot 0x%016lx holds 0x%lx != expected 0x%lx, falling back\n",
			     sym, (unsigned long)slot, old, expected);
		return ds_hook_install_guard(h, sym, wrap, guard);
	}

	memset(h, 0, sizeof(*h));
	INIT_LIST_HEAD(&h->node);
	h->bhook.slot_idx = -1;
	h->name = sym;
	h->slot = slot;
	h->addr = (unsigned long)slot;
	h->orig = old;
	h->route = DS_HOOK_SLOT;
	/* Publish h->orig before writing the slot so concurrent callers see it */
	smp_wmb();

	field = (unsigned long)slot;
	ret = ds_compat_write(slot, val);
	if (!ret) {
		WRITE_ONCE(h->live, true);
		ds_hook_track(h);
		ds_hook_info("hook %s on the slot route (field 0x%016lx orig 0x%016lx)\n",
			     sym, field, old);
		return 0;
	}

	ds_hook_warn("hook %s: slot write refused (%d field=0x%016lx level=%d writable=%d pa=0x%lx), falling back\n",
		     sym, ret, field, hk_va_level(field), hk_va_writable(field),
		     hk_va_to_pa(field));

	return ds_hook_install_guard(h, sym, wrap, guard);
}

int ds_hook_install_slot(struct ds_hook *h, void **slot, const void *repl,
			 const char *sym, const char *wrap)
{
	return ds_hook_install_slot_guard(h, slot, repl, sym, wrap,
					  HK_REDIR_GUARD_CALLER);
}

int ds_hook_install_critical_guard(struct ds_hook *h, const char *sym,
				   const char *wrap, enum hk_redir_guard guard)
{
	int ret = ds_hook_install_guard(h, sym, wrap, guard);

	if (ret)
		ds_hook_critical_missing = true;
	return ret;
}

int ds_hook_install_critical(struct ds_hook *h, const char *sym,
			     const char *wrap)
{
	return ds_hook_install_critical_guard(h, sym, wrap,
					      HK_REDIR_GUARD_TASK);
}

int ds_hook_install_critical_kprobe_guard(struct ds_hook *h, const char *sym,
					  const char *wrap,
					  enum hk_redir_guard guard)
{
	int ret = ds_hook_install_kprobe_guard(h, sym, wrap, guard);

	if (ret)
		ds_hook_critical_missing = true;
	return ret;
}

int ds_hook_install_slot_critical(struct ds_hook *h, void **slot,
				  const void *repl, const char *sym,
				  const char *wrap)
{
	int ret = ds_hook_install_slot(h, slot, repl, sym, wrap);

	if (ret)
		ds_hook_critical_missing = true;
	return ret;
}

bool ds_hook_critical_ok(void)
{
	return !ds_hook_critical_missing;
}

bool ds_hook_degrade_enabled(void)
{
	return ds_hook_degrade;
}

int ds_hook_remove(struct ds_hook *h)
{
	int ret = 0;

	if (!h || !READ_ONCE(h->live))
		return -EINVAL;

	switch (h->route) {
	case DS_HOOK_SLOT:
		ret = ds_compat_write(h->slot, h->orig);
		break;
	case DS_HOOK_BHOOK:
		ret = ds_bhook_remove(&h->bhook);
		break;
	case DS_HOOK_TEXT:
	case DS_HOOK_KPROBE:
		ret = hk_redir_remove(h->redir);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret)
		ds_hook_warn("hook %s did not come back (%d)\n", h->name, ret);
	WRITE_ONCE(h->live, false);
	ds_hook_untrack(h);
	return ret;
}

void ds_hook_exit(void)
{
	struct ds_hook *h, *tmp;
	LIST_HEAD(strays);

	mutex_lock(&ds_hook_list_lock);
	list_splice_init(&ds_hook_head, &strays);
	list_for_each_entry(h, &strays, node)
		h->tracked = false;
	mutex_unlock(&ds_hook_list_lock);

	list_for_each_entry_safe(h, tmp, &strays, node) {
		list_del_init(&h->node);
		if (READ_ONCE(h->live)) {
			ds_hook_warn("hook %s still live at exit, removing\n",
				     h->name ? h->name : "?");
			ds_hook_remove(h);
		}
	}
}

int ds_hook_enum(int (*fn)(void *ctx, const struct ds_hook *h), void *ctx)
{
	struct ds_hook *h;
	int ret = 0;

	mutex_lock(&ds_hook_list_lock);
	list_for_each_entry(h, &ds_hook_head, node) {
		ret = fn(ctx, h);
		if (ret)
			break;
	}
	mutex_unlock(&ds_hook_list_lock);
	return ret;
}

void ds_hook_report(void)
{
	struct ds_hook *h;
	unsigned int live = 0, total = 0;

	mutex_lock(&ds_hook_list_lock);
	list_for_each_entry(h, &ds_hook_head, node) {
		total++;
		if (h->live)
			live++;
		ds_hook_info("hook: %s %s on the %s route\n", h->name,
			     h->live ? "installed" : "NOT installed",
			     ds_hook_route_name(h->route));
	}
	mutex_unlock(&ds_hook_list_lock);
	ds_hook_info("hooks: %u/%u installed\n", live, total);
}
