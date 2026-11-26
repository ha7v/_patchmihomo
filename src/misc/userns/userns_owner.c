// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * The owners the kernel filled in through a stub.
 *
 * get_user_ns() and current_user_ns() are both compiled against
 * CONFIG_USER_NS. Without it the first returns the initial namespace whatever
 * it is handed, and the second does not read the credential at all. Every
 * object the kernel fills in through one of them, and every decision it makes
 * from one of them, therefore names the host where it should name the
 * container.
 *
 * may_mount() is the sharp end. It is one line, so the compiler inlines it into
 * path_mount() and no hook can reach the copy that runs, while ns_capable()
 * refuses a capability question about the initial namespace to a credential
 * that sits below it - the level test that makes a user namespace an isolation
 * boundary in the first place. A container that owns a user namespace then
 * cannot mount anything, so the state is corrected here instead of the
 * decisions.
 *
 * copy_mnt_ns() is the one place a task's mount namespace is created and the
 * kernel hands it the owner it means to record. fs_context_for_mount() is where
 * a mount configuration gets its owner, which mount_capable() then asks about
 * and which becomes the superblock's s_user_ns. Both are given the container's
 * own namespace.
 *
 * struct mnt_namespace is private to fs/mount.h and not part of a module build,
 * so that one field is located at runtime: the namespace is identified through
 * ns_common, the value to search for comes from the kernel's own mntns_owner()
 * accessor, and a write is only kept when that accessor reads it back. struct
 * fs_context is public and is written directly.
 */

#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/mnt_namespace.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>

#include "misc.h"
#include "misc_layout.h"
#include "misc_ksym.h"
#include "misc_proc.h"
#include "userns.h"
#include "ds_hook.h"
/* how far above the text base a resolved callback is allowed to sit */
#define DROID_LKM_USERNS_TEXT_WIN (64UL << 20)

typedef struct user_namespace *(*droid_lkm_userns_owner_t)(struct ns_common *ns);

struct uts_namespace;
struct cgroup_namespace;
struct time_namespace;

struct user_namespace *droid_lkm_userns_init_uns;

/*
 * Immortal non-init tombstone written into net->user_ns during pernet .exit.
 *
 * setup_net() writes net->user_ns = user_ns BEFORE running pernet_list .init,
 * so built-in uevent_net_init() skips list_add_tail(&ue_sk->list, ...) when
 * net->user_ns != &init_user_ns.  During reverse-order cleanup_net(), our
 * module pernet_ops.exit runs BEFORE uevent_net_exit().  Swapping net->user_ns
 * to &droid_lkm_userns_dead_uns (immortal static storage, != &init_user_ns,
 * not in droid_lkm_userns_list) keeps net->user_ns != &init_user_ns invariant
 * across uevent_net_exit() while dropping the fake userns ref with zero UAF.
 */
static struct user_namespace droid_lkm_userns_dead_uns;

static struct ds_hook droid_lkm_userns_copymntns_hook;
static struct ds_hook droid_lkm_userns_fsctx_hook;
static struct ds_hook droid_lkm_userns_putmntns_hook;
static struct ds_hook droid_lkm_userns_mntnsput_hook;
static struct ds_hook droid_lkm_userns_copyuts_hook;
static struct ds_hook droid_lkm_userns_freeuts_hook;
static struct ds_hook droid_lkm_userns_copycgroup_hook;
static struct ds_hook droid_lkm_userns_freecgroup_hook;
static struct ds_hook droid_lkm_userns_copytime_hook;
static struct ds_hook droid_lkm_userns_freetime_hook;

static bool droid_lkm_userns_pernet_registered;

static struct mnt_namespace *(*droid_lkm_userns_copymntns_orig)(
		unsigned long flags, struct mnt_namespace *ns,
		struct user_namespace *user_ns, struct fs_struct *new_fs);
static struct fs_context *(*droid_lkm_userns_fsctx_orig)(
		struct file_system_type *type, unsigned int sb_flags);
static void (*droid_lkm_userns_putmntns_orig)(struct mnt_namespace *ns);
static void (*droid_lkm_userns_mntnsput_orig)(struct ns_common *ns);
static struct uts_namespace *(*droid_lkm_userns_copyuts_orig)(
		unsigned long flags, struct user_namespace *user_ns,
		struct uts_namespace *old_ns);
static void (*droid_lkm_userns_freeuts_orig)(struct uts_namespace *ns);
static struct cgroup_namespace *(*droid_lkm_userns_copycgroup_orig)(
		unsigned long flags, struct user_namespace *user_ns,
		struct cgroup_namespace *old_ns);
static void (*droid_lkm_userns_freecgroup_orig)(struct cgroup_namespace *ns);
static struct time_namespace *(*droid_lkm_userns_copytime_orig)(
		unsigned long flags, struct user_namespace *user_ns,
		struct time_namespace *old_ns);
static void (*droid_lkm_userns_freetime_orig)(struct time_namespace *ns);

static const struct proc_ns_operations *droid_lkm_userns_mnt_ops;
static droid_lkm_userns_owner_t droid_lkm_userns_mnt_owner;

static unsigned long droid_lkm_userns_kernel_base;

static bool droid_lkm_userns_is_text(unsigned long addr)
{
	if (droid_lkm_userns_kernel_base)
		return addr >= droid_lkm_userns_kernel_base &&
		       addr - droid_lkm_userns_kernel_base < DROID_LKM_USERNS_TEXT_WIN &&
		       !(addr & (sizeof(u32) - 1));

	return addr >= 0xffff000000000000UL && !(addr & (sizeof(u32) - 1));
}

/*
 * the layout is checked before use: name reads "mnt" and type is CLONE_NEWNS, which pins the
 * two fields the offset follows from
 */
static int droid_lkm_userns_mnt_ops_resolve(void)
{
	struct proc_ns_operations ops;
	char text[8] = { };
	unsigned long addr;

	addr = droid_lkm_misc_sym("mntns_operations");
	if (!addr) {
		droid_lkm_misc_warn("mntns_operations not found\n");
		return -ENOENT;
	}

	if (safe_read(&ops, (void *)addr, sizeof(ops))) {
		droid_lkm_misc_warn("mntns_operations safe_read failed\n");
		return -EFAULT;
	}

	if (!ops.name || safe_read(text, ops.name, 4) || memcmp(text, "mnt", 3)) {
		droid_lkm_misc_warn("mntns_operations name mismatch: text='%s'\n", text);
		return -EINVAL;
	}

	if (ops.type != CLONE_NEWNS) {
		droid_lkm_misc_warn("mntns_operations type mismatch: type=0x%x expected=0x%x\n",
				    ops.type, CLONE_NEWNS);
		return -EINVAL;
	}

	if (!ops.owner || !droid_lkm_userns_is_text((unsigned long)ops.owner)) {
		droid_lkm_misc_warn("mntns_operations owner invalid: owner=0x%lx\n",
				    (unsigned long)ops.owner);
		return -EINVAL;
	}

	if (!ops.put || !droid_lkm_userns_is_text((unsigned long)ops.put)) {
		droid_lkm_misc_warn("mntns_operations put invalid: put=0x%lx\n",
				    (unsigned long)ops.put);
		return -EINVAL;
	}

	droid_lkm_userns_mnt_ops = (const struct proc_ns_operations *)addr;
	droid_lkm_userns_mnt_owner = ops.owner;

	return 0;
}

__nocfi struct user_namespace *droid_lkm_userns_mntns_owner(struct mnt_namespace *mnt_ns)
{
	struct ns_common *ns;

	if (!mnt_ns || !droid_lkm_userns_mnt_owner || !droid_lkm_misc_mntns_ns_ok)
		return NULL;

	ns = (struct ns_common *)((char *)mnt_ns + droid_lkm_misc_mntns_ns_off);
	return droid_lkm_userns_mnt_owner(ns);
}

static __nocfi int droid_lkm_userns_mnt_own(struct mnt_namespace *mnt_ns,
					    struct user_namespace *want)
{
	struct droid_lkm_userns *u = droid_lkm_userns_from_ns(want);
	struct ns_common *ns;
	struct user_namespace *old;
	void **field;
	u32 off = droid_lkm_misc_mntns_user_ns_off;

	if (!mnt_ns || !droid_lkm_misc_mntns_ns_ok || !u)
		return -EINVAL;

	ns = (struct ns_common *)((char *)mnt_ns + droid_lkm_misc_mntns_ns_off);
	if (ns->ops != droid_lkm_userns_mnt_ops)
		return -EINVAL;

	if (droid_lkm_userns_mnt_owner(ns) != want) {
		if (!droid_lkm_misc_mntns_user_ns_ok) {
			droid_lkm_misc_report("userns mount owner", "unsupported",
					      "field not found in BTF");
			return -ENOTSUPP;
		}

		/*
		 * Acquire the reference before writing the pointer. If this fails,
		 * mnt_ns remains untouched with no reference or pointer leakage.
		 */
		if (!droid_lkm_userns_get(u))
			return -EINVAL;

		old = droid_lkm_userns_mnt_owner(ns);
		field = (void **)((char *)mnt_ns + off);
		WRITE_ONCE(*field, want);

		if (droid_lkm_userns_mnt_owner(ns) != want) {
			droid_lkm_misc_warn("mntns owner mismatch at Type_info offset %u\n", off);
			/* Roll back field and return acquired reference on failure */
			WRITE_ONCE(*field, old);
			droid_lkm_userns_put(u);
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Paired attach/detach helpers for BTF-verified namespace ->user_ns fields.
 * Always acquire a reference on u before publishing &u->uns; on failure,
 * fail-closed to init_user_ns so no object ever holds an unrefcounted pointer.
 */
static void droid_lkm_userns_attach_owner(void *obj, u32 off,
					  struct user_namespace *hint)
{
	struct droid_lkm_userns *u = droid_lkm_userns_from_ns(hint);
	void **field = (void **)((char *)obj + off);

	if (!u)
		u = droid_lkm_userns_of(current);
	if (!u)
		return;

	if (droid_lkm_userns_get(u))
		WRITE_ONCE(*field, &u->uns);
	else
		WRITE_ONCE(*field, droid_lkm_userns_init_uns);
}

static struct droid_lkm_userns *droid_lkm_userns_detach_owner(void *obj,
							      u32 off)
{
	void **field = (void **)((char *)obj + off);
	struct user_namespace *old_uns;

	if (likely(READ_ONCE(*field) == droid_lkm_userns_init_uns))
		return NULL;

	old_uns = xchg(field, droid_lkm_userns_init_uns);
	return droid_lkm_userns_from_ns(old_uns);
}

/*
 * Mount namespace teardown pair: put_mnt_ns() + mntns_operations.put (mntns_put).
 * Clang ThinLTO inlines static free_mnt_ns() into put_mnt_ns(), and may also
 * inline put_mnt_ns() into same-TU mntns_put(). Covering both cross-TU
 * put_mnt_ns() and the nsfs ops->put vtable with refcount_dec_not_one() +
 * atomic xchg guarantees exact-once, race-free owner reclamation.
 */
DROID_LKM_ENTRY __nocfi noinline void droid_lkm_userns_putmntns_wrap(struct mnt_namespace *ns)
{
	typeof(droid_lkm_userns_putmntns_orig) orig =
		READ_ONCE(droid_lkm_userns_putmntns_orig);
	struct droid_lkm_userns *u = NULL;
	u32 off = droid_lkm_misc_mntns_user_ns_off;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_putmntns_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_putmntns_hook);
		return;
	}

	if (ns && droid_lkm_misc_mntns_ns_ok) {
		struct ns_common *ns_common =
			(struct ns_common *)((char *)ns + droid_lkm_misc_mntns_ns_off);
		refcount_t *ref = droid_lkm_userns_ns_ref(ns_common);

		if (refcount_dec_not_one(ref)) {
			ds_hook_leave(&droid_lkm_userns_putmntns_hook);
			return;
		}

		if (droid_lkm_misc_mntns_user_ns_ok &&
		    ns_common->ops == droid_lkm_userns_mnt_ops)
			u = droid_lkm_userns_detach_owner(ns, off);
	}

	orig(ns);
	ds_hook_leave(&droid_lkm_userns_putmntns_hook);

	/* Drop userns reference only after orig(ns) finishes mount/ucount teardown */
	if (u)
		droid_lkm_userns_put(u);
}

DROID_LKM_ENTRY __nocfi noinline void droid_lkm_userns_mntnsput_wrap(struct ns_common *ns)
{
	typeof(droid_lkm_userns_mntnsput_orig) orig =
		READ_ONCE(droid_lkm_userns_mntnsput_orig);
	struct droid_lkm_userns *u = NULL;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_mntnsput_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_mntnsput_hook);
		return;
	}

	if (ns && ns->ops == droid_lkm_userns_mnt_ops) {
		refcount_t *ref = droid_lkm_userns_ns_ref(ns);

		if (refcount_dec_not_one(ref)) {
			ds_hook_leave(&droid_lkm_userns_mntnsput_hook);
			return;
		}

		if (droid_lkm_misc_mntns_ns_ok && droid_lkm_misc_mntns_user_ns_ok) {
			struct mnt_namespace *mnt_ns =
				(struct mnt_namespace *)((char *)ns -
							 droid_lkm_misc_mntns_ns_off);
			u = droid_lkm_userns_detach_owner(
				mnt_ns, droid_lkm_misc_mntns_user_ns_off);
		}
	}

	orig(ns);
	ds_hook_leave(&droid_lkm_userns_mntnsput_hook);

	if (u)
		droid_lkm_userns_put(u);
}

DROID_LKM_ENTRY __nocfi noinline struct uts_namespace *
droid_lkm_userns_copyuts_wrap(unsigned long flags,
			      struct user_namespace *user_ns,
			      struct uts_namespace *old_ns)
{
	typeof(droid_lkm_userns_copyuts_orig) orig =
		READ_ONCE(droid_lkm_userns_copyuts_orig);
	struct uts_namespace *new_ns;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_copyuts_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_copyuts_hook);
		return ERR_PTR(-EAGAIN);
	}

	new_ns = orig(flags, user_ns, old_ns);
	ds_hook_leave(&droid_lkm_userns_copyuts_hook);

	if (!IS_ERR_OR_NULL(new_ns) && (flags & CLONE_NEWUTS) &&
	    droid_lkm_misc_utsns_user_ns_ok)
		droid_lkm_userns_attach_owner(
			new_ns, droid_lkm_misc_utsns_user_ns_off, user_ns);
	return new_ns;
}

DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_freeuts_wrap(struct uts_namespace *ns)
{
	typeof(droid_lkm_userns_freeuts_orig) orig =
		READ_ONCE(droid_lkm_userns_freeuts_orig);
	struct droid_lkm_userns *u = NULL;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_freeuts_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_freeuts_hook);
		return;
	}

	if (ns && droid_lkm_misc_utsns_user_ns_ok)
		u = droid_lkm_userns_detach_owner(
			ns, droid_lkm_misc_utsns_user_ns_off);

	orig(ns);
	ds_hook_leave(&droid_lkm_userns_freeuts_hook);

	if (u)
		droid_lkm_userns_put(u);
}

static DROID_LKM_ENTRY __nocfi noinline int
droid_lkm_userns_pernet_init(struct net *net)
{
	struct user_namespace *uns;
	struct droid_lkm_userns *u;

	if (!net || !droid_lkm_misc_netns_user_ns_ok)
		return 0;

	uns = READ_ONCE(*(struct user_namespace **)((char *)net +
						    droid_lkm_misc_netns_user_ns_off));
	if (likely(uns == droid_lkm_userns_init_uns))
		return 0;

	u = droid_lkm_userns_from_ns(uns);
	if (!u)
		return 0;

	if (!droid_lkm_userns_get(u))
		return -ENOMEM;

	return 0;
}

static DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_pernet_exit(struct net *net)
{
	void **field;
	struct user_namespace *cur_uns, *old_uns;
	struct droid_lkm_userns *u;

	if (!net || !droid_lkm_misc_netns_user_ns_ok)
		return;

	field = (void **)((char *)net + droid_lkm_misc_netns_user_ns_off);
	cur_uns = READ_ONCE(*field);
	if (likely(cur_uns == droid_lkm_userns_init_uns ||
		   cur_uns == &droid_lkm_userns_dead_uns))
		return;

	old_uns = xchg(field, &droid_lkm_userns_dead_uns);
	u = droid_lkm_userns_from_ns(old_uns);
	if (u)
		droid_lkm_userns_put(u);
}

static struct pernet_operations droid_lkm_userns_pernet_ops = {
	.init = droid_lkm_userns_pernet_init,
	.exit = droid_lkm_userns_pernet_exit,
};

static __nocfi noinline int
droid_lkm_userns_pernet_register(struct pernet_operations *ops)
{
	if (!droid_lkm_misc_ks.register_pernet_subsys ||
	    !droid_lkm_misc_ks.unregister_pernet_subsys)
		return -ENOENT;
	return droid_lkm_misc_ks.register_pernet_subsys(ops);
}

static __nocfi noinline void
droid_lkm_userns_pernet_unregister(struct pernet_operations *ops)
{
	if (droid_lkm_misc_ks.unregister_pernet_subsys)
		droid_lkm_misc_ks.unregister_pernet_subsys(ops);
}

DROID_LKM_ENTRY __nocfi noinline struct cgroup_namespace *
droid_lkm_userns_copycgroup_wrap(unsigned long flags,
				 struct user_namespace *user_ns,
				 struct cgroup_namespace *old_ns)
{
	typeof(droid_lkm_userns_copycgroup_orig) orig =
		READ_ONCE(droid_lkm_userns_copycgroup_orig);
	struct cgroup_namespace *new_ns;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_copycgroup_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_copycgroup_hook);
		return ERR_PTR(-EAGAIN);
	}

	new_ns = orig(flags, user_ns, old_ns);
	ds_hook_leave(&droid_lkm_userns_copycgroup_hook);

	if (!IS_ERR_OR_NULL(new_ns) && (flags & CLONE_NEWCGROUP) &&
	    droid_lkm_misc_cgroupns_user_ns_ok)
		droid_lkm_userns_attach_owner(
			new_ns, droid_lkm_misc_cgroupns_user_ns_off, user_ns);
	return new_ns;
}

DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_freecgroup_wrap(struct cgroup_namespace *ns)
{
	typeof(droid_lkm_userns_freecgroup_orig) orig =
		READ_ONCE(droid_lkm_userns_freecgroup_orig);
	struct droid_lkm_userns *u = NULL;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_freecgroup_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_freecgroup_hook);
		return;
	}

	if (ns && droid_lkm_misc_cgroupns_user_ns_ok)
		u = droid_lkm_userns_detach_owner(
			ns, droid_lkm_misc_cgroupns_user_ns_off);

	orig(ns);
	ds_hook_leave(&droid_lkm_userns_freecgroup_hook);

	if (u)
		droid_lkm_userns_put(u);
}

DROID_LKM_ENTRY __nocfi noinline struct time_namespace *
droid_lkm_userns_copytime_wrap(unsigned long flags,
			       struct user_namespace *user_ns,
			       struct time_namespace *old_ns)
{
	typeof(droid_lkm_userns_copytime_orig) orig =
		READ_ONCE(droid_lkm_userns_copytime_orig);
	struct time_namespace *new_ns;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_copytime_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_copytime_hook);
		return ERR_PTR(-EAGAIN);
	}

	new_ns = orig(flags, user_ns, old_ns);
	ds_hook_leave(&droid_lkm_userns_copytime_hook);

	if (!IS_ERR_OR_NULL(new_ns) && (flags & CLONE_NEWTIME) &&
	    droid_lkm_misc_timens_user_ns_ok)
		droid_lkm_userns_attach_owner(
			new_ns, droid_lkm_misc_timens_user_ns_off, user_ns);
	return new_ns;
}

DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_freetime_wrap(struct time_namespace *ns)
{
	typeof(droid_lkm_userns_freetime_orig) orig =
		READ_ONCE(droid_lkm_userns_freetime_orig);
	struct droid_lkm_userns *u = NULL;

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_freetime_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_freetime_hook);
		return;
	}

	if (ns && droid_lkm_misc_timens_user_ns_ok)
		u = droid_lkm_userns_detach_owner(
			ns, droid_lkm_misc_timens_user_ns_off);

	orig(ns);
	ds_hook_leave(&droid_lkm_userns_freetime_hook);

	if (u)
		droid_lkm_userns_put(u);
}

DROID_LKM_ENTRY __nocfi noinline struct mnt_namespace *
droid_lkm_userns_copymntns_wrap(unsigned long flags, struct mnt_namespace *ns,
				struct user_namespace *user_ns,
				struct fs_struct *new_fs)
{
	struct mnt_namespace *new_ns;
	struct droid_lkm_userns *u;
	typeof(droid_lkm_userns_copymntns_orig) orig =
		READ_ONCE(droid_lkm_userns_copymntns_orig);

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_copymntns_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_copymntns_hook);
		return ERR_PTR(-EAGAIN);
	}

	new_ns = orig(flags, ns, user_ns, new_fs);
	ds_hook_leave(&droid_lkm_userns_copymntns_hook);

	if (IS_ERR(new_ns) || !(flags & CLONE_NEWNS))
		return new_ns;

	/* user_ns is the owner the kernel was handed, ours only for our own */
	u = droid_lkm_userns_from_ns(user_ns);
	if (!u)
		u = droid_lkm_userns_of(current);
	if (!u)
		return new_ns;

	if (droid_lkm_userns_mnt_own(new_ns, &u->uns))
		droid_lkm_misc_err("mount namespace kept the host as owner, mounts in it will fail\n");

	return new_ns;
}

DROID_LKM_ENTRY __nocfi noinline struct fs_context *
droid_lkm_userns_fsctx_wrap(struct file_system_type *type, unsigned int sb_flags)
{
	struct fs_context *fc;
	struct droid_lkm_userns *u;
	typeof(droid_lkm_userns_fsctx_orig) orig =
		READ_ONCE(droid_lkm_userns_fsctx_orig);

	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(droid_lkm_userns_fsctx_hook.orig);
	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_fsctx_hook);
		return ERR_PTR(-EAGAIN);
	}

	fc = orig(type, sb_flags);
	ds_hook_leave(&droid_lkm_userns_fsctx_hook);

	/*
	 * alloc_fs_context() took the owner from current_user_ns() and get_user_ns() took no
	 * reference, so replacing the field is all
	 */
	u = IS_ERR(fc) ? NULL : droid_lkm_userns_of(current);
	if (u && fc->user_ns != &u->uns) {
		fc->user_ns = &u->uns;
		droid_lkm_misc_dbg("fs_context for %s owned by the container\n", type->name);
	}

	return fc;
}

static bool droid_lkm_userns_install_ns_pair(struct ds_hook *free_h,
					     const char *free_sym,
					     const char *free_wrap,
					     void **free_orig,
					     struct ds_hook *copy_h,
					     const char *copy_sym,
					     const char *copy_wrap,
					     void **copy_orig)
{
	if (!droid_lkm_misc_sym(free_sym) || !droid_lkm_misc_sym(copy_sym))
		return false;

	/* Install teardown accounting BEFORE producer (F3 invariant) */
	if (ds_hook_install_kprobe_guard(free_h, free_sym, free_wrap,
					 HK_REDIR_GUARD_CALLER)) {
		droid_lkm_misc_warn("owner: hook %s failed, skipping %s\n",
				    free_sym, copy_sym);
		return false;
	}
	WRITE_ONCE(*free_orig, (void *)free_h->orig);

	if (ds_hook_install_kprobe_guard(copy_h, copy_sym, copy_wrap,
					 HK_REDIR_GUARD_CALLER)) {
		droid_lkm_misc_warn("owner: hook %s failed, rolling back %s\n",
				    copy_sym, free_sym);
		ds_hook_remove(free_h);
		WRITE_ONCE(*free_orig, NULL);
		return false;
	}
	WRITE_ONCE(*copy_orig, (void *)copy_h->orig);
	return true;
}

static void droid_lkm_userns_remove_ns_hook(struct ds_hook *h, void **orig)
{
	if (h->live) {
		ds_hook_remove(h);
		WRITE_ONCE(*orig, NULL);
	}
}

int droid_lkm_userns_owner_init(void)
{
	static char ns_summary[64];
	size_t pos = 0;
	bool mnt_has_ops_put = false;
	int ret;

	droid_lkm_userns_kernel_base = (unsigned long)droid_lkm_misc_sym("_text");

	droid_lkm_userns_init_uns = (struct user_namespace *)
		droid_lkm_misc_sym("init_user_ns");
	if (!droid_lkm_userns_init_uns) {
		droid_lkm_misc_warn("init_user_ns not found\n");
		return -ENOENT;
	}

	/* Initialize immortal non-init tombstone for net->user_ns teardown */
	droid_lkm_userns_dead_uns.parent = droid_lkm_userns_init_uns;
	droid_lkm_userns_dead_uns.level = 1;
	droid_lkm_userns_dead_uns.owner = GLOBAL_ROOT_UID;
	droid_lkm_userns_dead_uns.group = GLOBAL_ROOT_GID;
	droid_lkm_userns_dead_uns.flags = USERNS_INIT_FLAGS;
	refcount_set(droid_lkm_userns_ns_ref(&droid_lkm_userns_dead_uns.ns), 1);

	ret = droid_lkm_userns_mnt_ops_resolve();
	if (ret) {
		droid_lkm_misc_warn("mntns_operations unusable: %d\n", ret);
		return ret;
	}

	/*
	 * Install mount teardown accounting FIRST before copy_mnt_ns producer:
	 *   1. put_mnt_ns() covers cross-TU nsproxy teardown (free_nsproxy);
	 *   2. mntns_operations.put (mntns_put) covers nsfs inode eviction even
	 *      when Clang ThinLTO inlines put_mnt_ns() into mntns_put().
	 */
	ret = ds_hook_install_kprobe_guard(&droid_lkm_userns_putmntns_hook,
					   "put_mnt_ns",
					   "droid_lkm_userns_putmntns_wrap",
					   HK_REDIR_GUARD_CALLER);
	if (ret) {
		droid_lkm_misc_warn("hook put_mnt_ns failed: %d\n", ret);
		return ret;
	}
	WRITE_ONCE(droid_lkm_userns_putmntns_orig,
		   (typeof(droid_lkm_userns_putmntns_orig))
			   droid_lkm_userns_putmntns_hook.orig);

	if (!ds_hook_install_slot_guard(&droid_lkm_userns_mntnsput_hook,
					(void **)&droid_lkm_userns_mnt_ops->put,
					droid_lkm_userns_mntnsput_wrap,
					"mntns_put",
					"droid_lkm_userns_mntnsput_wrap",
					HK_REDIR_GUARD_CALLER)) {
		WRITE_ONCE(droid_lkm_userns_mntnsput_orig,
			   (typeof(droid_lkm_userns_mntnsput_orig))
				   droid_lkm_userns_mntnsput_hook.orig);
		mnt_has_ops_put = true;
	} else {
		droid_lkm_misc_warn("hook mntns_put unavailable, relying on put_mnt_ns\n");
	}

	ret = ds_hook_install_kprobe_guard(&droid_lkm_userns_copymntns_hook,
					   "copy_mnt_ns",
					   "droid_lkm_userns_copymntns_wrap",
					   HK_REDIR_GUARD_CALLER);
	if (ret) {
		droid_lkm_misc_warn("hook copy_mnt_ns failed: %d\n", ret);
		droid_lkm_userns_remove_ns_hook(
			&droid_lkm_userns_mntnsput_hook,
			(void **)&droid_lkm_userns_mntnsput_orig);
		droid_lkm_userns_remove_ns_hook(
			&droid_lkm_userns_putmntns_hook,
			(void **)&droid_lkm_userns_putmntns_orig);
		return ret;
	}
	WRITE_ONCE(droid_lkm_userns_copymntns_orig,
		   (typeof(droid_lkm_userns_copymntns_orig))
			   droid_lkm_userns_copymntns_hook.orig);

	ret = ds_hook_install_kprobe_guard(&droid_lkm_userns_fsctx_hook,
					   "fs_context_for_mount",
					   "droid_lkm_userns_fsctx_wrap",
					   HK_REDIR_GUARD_CALLER);
	if (ret) {
		droid_lkm_misc_warn("hook fs_context_for_mount failed: %d\n", ret);
		droid_lkm_userns_remove_ns_hook(
			&droid_lkm_userns_copymntns_hook,
			(void **)&droid_lkm_userns_copymntns_orig);
		droid_lkm_userns_remove_ns_hook(
			&droid_lkm_userns_mntnsput_hook,
			(void **)&droid_lkm_userns_mntnsput_orig);
		droid_lkm_userns_remove_ns_hook(
			&droid_lkm_userns_putmntns_hook,
			(void **)&droid_lkm_userns_putmntns_orig);
		return ret;
	}
	WRITE_ONCE(droid_lkm_userns_fsctx_orig,
		   (typeof(droid_lkm_userns_fsctx_orig))
			   droid_lkm_userns_fsctx_hook.orig);

	/* P2-2: Report mount owner readiness eagerly at init time */
	if (droid_lkm_misc_mntns_ns_ok && droid_lkm_misc_mntns_user_ns_ok)
		droid_lkm_misc_report("userns mount owner", "ready",
				      mnt_has_ops_put ?
				      "field verified via Type_info (put_mnt_ns+mntns_put)" :
				      "field verified via Type_info (put_mnt_ns)");
	else
		droid_lkm_misc_report("userns mount owner", "unsupported",
				      "field not found in BTF");

	/*
	 * P0-2 & P1-3: Install refcounted owner pairs for uts/net/cgroup/time
	 * covering both unshare() and clone(). Fail-closed per kind if either
	 * BTF offset or teardown mechanism is unavailable.
	 */
	pos += scnprintf(ns_summary + pos, sizeof(ns_summary) - pos, "mnt ipc");
	if (droid_lkm_misc_utsns_user_ns_ok &&
	    droid_lkm_userns_install_ns_pair(
		    &droid_lkm_userns_freeuts_hook, "free_uts_ns",
		    "droid_lkm_userns_freeuts_wrap",
		    (void **)&droid_lkm_userns_freeuts_orig,
		    &droid_lkm_userns_copyuts_hook, "copy_utsname",
		    "droid_lkm_userns_copyuts_wrap",
		    (void **)&droid_lkm_userns_copyuts_orig))
		pos += scnprintf(ns_summary + pos, sizeof(ns_summary) - pos, " uts");

	/*
	 * Network namespace refcounting uses native register_pernet_subsys()
	 * paired .init/.exit (zero hooks, zero hot-path cost, immune to ThinLTO
	 * inlining, exact kernel-guaranteed 1:1 pairing even on setup_net unwind).
	 */
	if (droid_lkm_misc_netns_user_ns_ok &&
	    !droid_lkm_userns_pernet_register(&droid_lkm_userns_pernet_ops)) {
		droid_lkm_userns_pernet_registered = true;
		pos += scnprintf(ns_summary + pos, sizeof(ns_summary) - pos,
				 " net");
	}

	if (droid_lkm_misc_cgroupns_user_ns_ok &&
	    droid_lkm_userns_install_ns_pair(
		    &droid_lkm_userns_freecgroup_hook, "free_cgroup_ns",
		    "droid_lkm_userns_freecgroup_wrap",
		    (void **)&droid_lkm_userns_freecgroup_orig,
		    &droid_lkm_userns_copycgroup_hook, "copy_cgroup_ns",
		    "droid_lkm_userns_copycgroup_wrap",
		    (void **)&droid_lkm_userns_copycgroup_orig))
		pos += scnprintf(ns_summary + pos, sizeof(ns_summary) - pos, " cgroup");

	if (droid_lkm_misc_timens_user_ns_ok &&
	    droid_lkm_userns_install_ns_pair(
		    &droid_lkm_userns_freetime_hook, "free_time_ns",
		    "droid_lkm_userns_freetime_wrap",
		    (void **)&droid_lkm_userns_freetime_orig,
		    &droid_lkm_userns_copytime_hook, "copy_time_ns",
		    "droid_lkm_userns_copytime_wrap",
		    (void **)&droid_lkm_userns_copytime_orig))
		pos += scnprintf(ns_summary + pos, sizeof(ns_summary) - pos, " time");

	droid_lkm_misc_report("userns ns owners", "ready", ns_summary);
	droid_lkm_misc_dbg("owner: mntns_ops=0x%lx owner=0x%lx ns_owners=[%s]\n",
		(unsigned long)droid_lkm_userns_mnt_ops,
		(unsigned long)droid_lkm_userns_mnt_owner, ns_summary);

	return 0;
}

void droid_lkm_userns_owner_exit(void)
{
	/* Remove producers first, then teardown accounting */
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_copytime_hook,
					(void **)&droid_lkm_userns_copytime_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_freetime_hook,
					(void **)&droid_lkm_userns_freetime_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_copycgroup_hook,
					(void **)&droid_lkm_userns_copycgroup_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_freecgroup_hook,
					(void **)&droid_lkm_userns_freecgroup_orig);
	if (droid_lkm_userns_pernet_registered) {
		droid_lkm_userns_pernet_unregister(&droid_lkm_userns_pernet_ops);
		droid_lkm_userns_pernet_registered = false;
	}
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_copyuts_hook,
					(void **)&droid_lkm_userns_copyuts_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_freeuts_hook,
					(void **)&droid_lkm_userns_freeuts_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_fsctx_hook,
					(void **)&droid_lkm_userns_fsctx_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_copymntns_hook,
					(void **)&droid_lkm_userns_copymntns_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_mntnsput_hook,
					(void **)&droid_lkm_userns_mntnsput_orig);
	droid_lkm_userns_remove_ns_hook(&droid_lkm_userns_putmntns_hook,
					(void **)&droid_lkm_userns_putmntns_orig);
}
