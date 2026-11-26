// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * Native LSM security_hook_heads integration for fake user namespace
 * credential lifecycle accounting (cred_prepare, cred_free, cred_transfer).
 *
 * Advantages over hooking prepare_creds() / security_cred_free():
 *   - Zero text patching or kprobe traps on credential hot paths.
 *   - Head-inserted cred_prepare + idempotent cred_free closes the F2
 *     prepare_creds() failure UAF window (both lsm_cred_alloc -ENOMEM and
 *     downstream LSM failure double security_cred_free).
 *   - cred_transfer closes the F1-b KEYCTL_SESSION_TO_PARENT escape vector
 *     where key_change_session_keyring() resets user_ns via stub get_user_ns().
 *   - All struct layouts are read from live BTF; kernels without BTF or
 *     without hlist-based security_hook_heads (e.g. Linux 6.12+ static-call
 *     LSMs) cleanly return -EOPNOTSUPP and fall back to ds_hook.
 */

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <asm/barrier.h>

#include "btf.h"
#include "core.h"
#include "ds_compat.h"
#include "hk_patch.h"
#include "misc.h"
#include "misc_proc.h"
#include "type_info.h"
#include "userns.h"

#define DROID_LKM_LSM_NODE_BUF_SZ	64
#define DROID_LKM_LSM_MAX_MAPS		6

enum {
	DROID_LKM_LSM_PREPARE = 0,
	DROID_LKM_LSM_FREE,
	DROID_LKM_LSM_TRANSFER,
	DROID_LKM_LSM_COUNT,
};

struct droid_lkm_lsm_layout {
	u32 head_off[DROID_LKM_LSM_COUNT];
	u32 list_size;
	u32 m_list;
	u32 m_head;
	u32 m_hook;
	u32 m_lsm;
};

struct droid_lkm_lsm_slot_ctx {
	struct hlist_head *head;
	struct hlist_node *expected_first;
	struct hlist_node *new_list;
	struct hlist_node **head_first_w;
	struct hlist_node ***old_pprev_w;
};

struct droid_lkm_lsm_splice_ctx {
	struct droid_lkm_lsm_slot_ctx slots[DROID_LKM_LSM_COUNT];
};

static const char droid_lkm_lsm_name[] = "droid_lkm_misc";

/*
 * Resident static storage for the 3 security_hook_list nodes. Never freed
 * or unlinked once spliced into security_hook_heads.
 */
static u8 droid_lkm_lsm_nodes[DROID_LKM_LSM_COUNT][DROID_LKM_LSM_NODE_BUF_SZ]
	__aligned(16);

static bool droid_lkm_userns_lsm_is_active;

bool droid_lkm_userns_lsm_active(void)
{
	return droid_lkm_userns_lsm_is_active;
}

static DROID_LKM_ENTRY __nocfi noinline int
droid_lkm_userns_lsm_cred_prepare(struct cred *new, const struct cred *old,
				  gfp_t gfp)
{
	struct droid_lkm_userns *u;

	(void)old;
	(void)gfp;

	if (likely(!new || READ_ONCE(new->user_ns) == droid_lkm_userns_init_uns))
		return 0;

	u = droid_lkm_userns_from_ns(new->user_ns);
	if (u && !droid_lkm_userns_get(u)) {
		droid_lkm_userns_cred_fail_closed(new);
		return -ENOMEM;
	}
	return 0;
}

static DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_lsm_cred_free(struct cred *cred)
{
	struct user_namespace *old_uns;
	struct droid_lkm_userns *u;

	if (likely(!cred || READ_ONCE(cred->user_ns) == droid_lkm_userns_init_uns))
		return;

	/*
	 * F2 guard: if lsm_cred_alloc() failed inside prepare_creds(),
	 * cred_prepare never ran (0 refs taken), yet abort_creds() still
	 * calls security_cred_free().
	 */
	if (droid_lkm_userns_has_cred_security && !cred->security) {
		WRITE_ONCE(cred->user_ns, droid_lkm_userns_init_uns);
		return;
	}

	/* Atomic reset guarantees idempotency if security_cred_free runs twice */
	old_uns = xchg(&cred->user_ns, droid_lkm_userns_init_uns);
	u = droid_lkm_userns_from_ns(old_uns);
	if (u)
		droid_lkm_userns_put(u);
}

static DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_lsm_cred_transfer(struct cred *new, const struct cred *old)
{
	struct droid_lkm_userns *old_u, *new_u;

	if (likely(!new || !old))
		return;
	if (likely(READ_ONCE(old->user_ns) == droid_lkm_userns_init_uns &&
		   READ_ONCE(new->user_ns) == droid_lkm_userns_init_uns))
		return;

	old_u = droid_lkm_userns_from_ns(READ_ONCE(old->user_ns));
	new_u = droid_lkm_userns_from_ns(READ_ONCE(new->user_ns));
	if (old_u == new_u)
		return;

	if (old_u) {
		if (droid_lkm_userns_get(old_u))
			WRITE_ONCE(new->user_ns, &old_u->uns);
		else
			droid_lkm_userns_cred_fail_closed(new);
	} else {
		WRITE_ONCE(new->user_ns, droid_lkm_userns_init_uns);
	}

	if (new_u)
		droid_lkm_userns_put(new_u);
}

static int droid_lkm_lsm_member(u32 tid, const char *name, u32 expect_sz,
				u32 *off_out)
{
	u32 mtype = 0, bit_off = 0, bit_sz = 0, sz;

	if (ti_member_info(ti_base(), tid, name, &mtype, &bit_off, &bit_sz))
		return -ENOENT;
	if (bit_sz || (bit_off & 7U))
		return -EINVAL;
	if (ti_follow(ti_base(), mtype, &mtype))
		return -EINVAL;
	sz = ti_type_size(ti_base(), mtype);
	if (sz != expect_sz)
		return -EINVAL;
	*off_out = bit_off / 8U;
	return 0;
}

static int droid_lkm_lsm_probe_btf(struct droid_lkm_lsm_layout *l)
{
	u32 heads_tid = 0, list_tid = 0;

	if (!ti_ready() || !ti_btf_available())
		return -EOPNOTSUPP;

	if (ti_type_by_name(ti_base(), "security_hook_heads",
			    BIT(BTF_KIND_STRUCT), &heads_tid))
		return -EOPNOTSUPP;
	if (ti_type_by_name(ti_base(), "security_hook_list",
			    BIT(BTF_KIND_STRUCT), &list_tid))
		return -EOPNOTSUPP;

	memset(l, 0, sizeof(*l));
	l->list_size = ti_type_size(ti_base(), list_tid);
	if (l->list_size < 32U || l->list_size > DROID_LKM_LSM_NODE_BUF_SZ)
		return -ERANGE;

	if (droid_lkm_lsm_member(heads_tid, "cred_prepare",
				 sizeof(struct hlist_head),
				 &l->head_off[DROID_LKM_LSM_PREPARE]) ||
	    droid_lkm_lsm_member(heads_tid, "cred_free",
				 sizeof(struct hlist_head),
				 &l->head_off[DROID_LKM_LSM_FREE]) ||
	    droid_lkm_lsm_member(heads_tid, "cred_transfer",
				 sizeof(struct hlist_head),
				 &l->head_off[DROID_LKM_LSM_TRANSFER]))
		return -EOPNOTSUPP;

	if (droid_lkm_lsm_member(list_tid, "list", sizeof(struct hlist_node),
				 &l->m_list) ||
	    droid_lkm_lsm_member(list_tid, "head", sizeof(void *),
				 &l->m_head) ||
	    droid_lkm_lsm_member(list_tid, "hook", sizeof(void *),
				 &l->m_hook) ||
	    droid_lkm_lsm_member(list_tid, "lsm", sizeof(void *), &l->m_lsm))
		return -EOPNOTSUPP;

	if (l->m_list + sizeof(struct hlist_node) > l->list_size ||
	    l->m_head + sizeof(void *) > l->list_size ||
	    l->m_hook + sizeof(void *) > l->list_size ||
	    l->m_lsm + sizeof(void *) > l->list_size)
		return -ERANGE;

	return 0;
}

static bool droid_lkm_lsm_hook_ptr_ok(unsigned long fn)
{
	return fn >= 0xffff000000000000UL && !(fn & 3UL);
}

static int droid_lkm_lsm_map_ptr(struct ds_compat_rodata_map *maps, int *nmaps,
				 void *ptr, void **writable_out)
{
	unsigned long va = (unsigned long)ptr;
	unsigned long pa, pfn;
	int i, ret;

	pa = hk_va_walk_pa(va);
	if (!pa)
		pa = hk_va_to_pa(va);
	if (!pa)
		return -ENOENT;
	pfn = pa >> PAGE_SHIFT;

	for (i = 0; i < *nmaps; i++) {
		if (maps[i].pfn != pfn)
			continue;
		if (maps[i].owned) {
			*writable_out = (char *)maps[i].vmap_base +
					(va & ~PAGE_MASK);
			return 0;
		}
		if (hk_va_writable(va)) {
			*writable_out = ptr;
			return 0;
		}
	}

	if (*nmaps >= DROID_LKM_LSM_MAX_MAPS)
		return -ENOSPC;

	ret = ds_compat_rodata_map(ptr, sizeof(void *), &maps[*nmaps]);
	if (ret)
		return ret;
	*writable_out = maps[*nmaps].writable;
	(*nmaps)++;
	return 0;
}

static int droid_lkm_lsm_splice_cb(void *data)
{
	struct droid_lkm_lsm_splice_ctx *ctx = data;
	int i;

	/* Pass 1: verify all 3 heads are unchanged before mutating any */
	for (i = 0; i < DROID_LKM_LSM_COUNT; i++) {
		struct droid_lkm_lsm_slot_ctx *s = &ctx->slots[i];

		if (READ_ONCE(s->head->first) != s->expected_first)
			return -EAGAIN;
	}

	/* Pass 2: atomic 64-bit head insertion on all 3 lists */
	for (i = 0; i < DROID_LKM_LSM_COUNT; i++) {
		struct droid_lkm_lsm_slot_ctx *s = &ctx->slots[i];
		struct hlist_node *old_first = s->expected_first;

		s->new_list->next = old_first;
		s->new_list->pprev = &s->head->first;
		smp_wmb();

		if (old_first && s->old_pprev_w)
			WRITE_ONCE(*s->old_pprev_w, &s->new_list->next);
		WRITE_ONCE(*s->head_first_w, s->new_list);
	}
	dsb(ish);
	return 0;
}

int droid_lkm_userns_lsm_init(void)
{
	void *cbs[DROID_LKM_LSM_COUNT] = {
		[DROID_LKM_LSM_PREPARE] = (void *)droid_lkm_userns_lsm_cred_prepare,
		[DROID_LKM_LSM_FREE] = (void *)droid_lkm_userns_lsm_cred_free,
		[DROID_LKM_LSM_TRANSFER] = (void *)droid_lkm_userns_lsm_cred_transfer,
	};
	struct ds_compat_rodata_map maps[DROID_LKM_LSM_MAX_MAPS];
	struct droid_lkm_lsm_splice_ctx ctx;
	struct droid_lkm_lsm_layout l;
	unsigned long heads_addr;
	int nmaps = 0, i, ret;

	if (droid_lkm_userns_lsm_is_active)
		return 0;

	if (!IS_ENABLED(CONFIG_SECURITY))
		return -EOPNOTSUPP;
	if (!droid_lkm_userns_init_uns)
		return -ENOENT;

	ret = droid_lkm_lsm_probe_btf(&l);
	if (ret) {
		droid_lkm_misc_info("userns lsm: BTF layout unavailable (%d), using hook fallback\n",
				    ret);
		return ret;
	}

	heads_addr = droid_lkm_misc_sym("security_hook_heads");
	if (!heads_addr) {
		droid_lkm_misc_info("userns lsm: security_hook_heads absent, using hook fallback\n");
		return -ENOENT;
	}

	memset(maps, 0, sizeof(maps));
	memset(&ctx, 0, sizeof(ctx));

	for (i = 0; i < DROID_LKM_LSM_COUNT; i++) {
		struct hlist_head *head =
			(struct hlist_head *)(heads_addr + l.head_off[i]);
		struct hlist_node *first = NULL;
		u8 *node = droid_lkm_lsm_nodes[i];
		void *wptr = NULL;

		if (safe_read(&first, &head->first, sizeof(first))) {
			ret = -EFAULT;
			goto out_unmap;
		}

		/* Cross-verify existing entry layout before trusting offsets */
		if (first) {
			unsigned long entry_base = (unsigned long)first - l.m_list;
			void *entry_head = NULL;
			unsigned long entry_hook = 0;

			if (safe_read(&entry_head,
				      (void *)(entry_base + l.m_head),
				      sizeof(entry_head)) ||
			    safe_read(&entry_hook,
				      (void *)(entry_base + l.m_hook),
				      sizeof(entry_hook))) {
				ret = -EFAULT;
				goto out_unmap;
			}
			if (entry_head != (void *)head ||
			    !droid_lkm_lsm_hook_ptr_ok(entry_hook)) {
				droid_lkm_misc_warn("userns lsm: slot %d cross-check failed (head=0x%lx!=0x%lx hook=0x%lx)\n",
						    i, (unsigned long)entry_head,
						    (unsigned long)head,
						    entry_hook);
				ret = -EINVAL;
				goto out_unmap;
			}
		}

		memset(node, 0, DROID_LKM_LSM_NODE_BUF_SZ);
		*(void **)(node + l.m_head) = (void *)head;
		*(void **)(node + l.m_hook) = cbs[i];
		*(const char **)(node + l.m_lsm) = droid_lkm_lsm_name;

		ctx.slots[i].head = head;
		ctx.slots[i].expected_first = first;
		ctx.slots[i].new_list = (struct hlist_node *)(node + l.m_list);

		ret = droid_lkm_lsm_map_ptr(maps, &nmaps, &head->first, &wptr);
		if (ret)
			goto out_unmap;
		ctx.slots[i].head_first_w = (struct hlist_node **)wptr;

		if (first) {
			ret = droid_lkm_lsm_map_ptr(maps, &nmaps, &first->pprev,
						    &wptr);
			if (ret)
				goto out_unmap;
			ctx.slots[i].old_pprev_w =
				(struct hlist_node ***)wptr;
		}
	}

	smp_wmb();
	ret = stop_machine(droid_lkm_lsm_splice_cb, &ctx, NULL);

out_unmap:
	for (i = 0; i < nmaps; i++)
		ds_compat_rodata_unmap(&maps[i]);

	if (ret) {
		droid_lkm_misc_warn("userns lsm: splice failed (%d), falling back to hooks\n",
				    ret);
		return ret;
	}

	droid_lkm_userns_lsm_is_active = true;
	droid_lkm_userns_stay_resident("LSM security_hook_heads cred callbacks");
	droid_lkm_misc_report("userns cred lsm", "ready",
			      "security_hook_heads (prepare/free/transfer)");
	droid_lkm_misc_info("userns lsm: cred_prepare/cred_free/cred_transfer spliced via BTF (list_size=%u)\n",
			    l.list_size);
	return 0;
}
