// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 *
 * The chokepoints that cannot be answered by correcting state.
 *
 * Install order (F3 invariant):
 *   1. Credential accounting FIRST (native LSM cred_{prepare,free,transfer}
 *      via security_hook_heads; fallback to ds_hook on prepare_creds,
 *      security_cred_free, and security_transfer_creds).
 *   2. Enforcement & helper hooks (security_capable, capable_wrt_inode_uidgid,
 *      mount_capable, unshare_nsproxy_namespaces, chown_common).
 *   3. Producer hooks LAST (copy_creds, ksys_unshare), gated by
 *      droid_lkm_userns_ready so no fake userns is created until every
 *      accounting and enforcement hook is active.
 */

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/cgroup.h>
#include <linux/ipc_namespace.h>
#include <linux/time_namespace.h>
#include <net/net_namespace.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/path.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/mnt_idmapping.h>
#endif
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/uidgid.h>
#include <asm/barrier.h>
#include <asm/ptrace.h>

#include "misc.h"
#include "misc_layout.h"
#include "misc_ksym.h"
#include "misc_proc.h"
#include "userns.h"
#include "ds_hook.h"
#include "ds_shapes.h"

/* fs/internal.h is not a module header; these are the kernel's own declarations */
bool mount_capable(struct fs_context *fc);
int chown_common(const struct path *path, uid_t user, gid_t group);

bool droid_lkm_userns_has_cred_security;
bool droid_lkm_userns_ready;

static struct ds_hook droid_lkm_userns_unshare_hook;
static struct ds_hook droid_lkm_userns_nsproxy_hook;
static struct ds_hook droid_lkm_userns_creds_hook;
static struct ds_hook droid_lkm_userns_inodecap_hook;
static struct ds_hook droid_lkm_userns_mountcap_hook;
static struct ds_hook droid_lkm_userns_seccap_hook;
static struct ds_hook droid_lkm_userns_chown_hook;
static struct ds_hook droid_lkm_userns_fchownat_hook;
static struct ds_hook droid_lkm_userns_fchown_hook;
static struct ds_hook droid_lkm_userns_incuc_hook;
static struct ds_hook droid_lkm_userns_allocuc_hook;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
static struct ds_hook droid_lkm_userns_setcreduc_hook;
#endif

/* Fallback credential accounting hooks (used only when LSM splice is unavailable) */
static struct ds_hook droid_lkm_userns_prepcred_hook;
static struct ds_hook droid_lkm_userns_putcred_hook;
static struct ds_hook droid_lkm_userns_transfer_hook;

static int (*droid_lkm_userns_unshare_orig)(unsigned long flags);
static int (*droid_lkm_userns_nsproxy_orig)(unsigned long unshare_flags,
					    struct nsproxy **new_nsp,
					    struct cred *new_cred,
					    struct fs_struct *new_fs);
static int (*droid_lkm_userns_creds_orig)(struct task_struct *p,
					  unsigned long clone_flags);

static bool (*droid_lkm_userns_inodecap_orig)(DROID_LKM_IDMAP_PARAM
					      const struct inode *inode, int cap);
static bool (*droid_lkm_userns_mountcap_orig)(struct fs_context *fc);

static struct cred *(*droid_lkm_userns_prepcred_orig)(void);
static void (*droid_lkm_userns_putcred_orig)(struct cred *cred);
static void (*droid_lkm_userns_transfer_orig)(struct cred *new,
					      const struct cred *old);
static int (*droid_lkm_userns_seccap_orig)(const struct cred *cred,
					   struct user_namespace *ns,
					   int cap, unsigned int opts);
static int (*droid_lkm_userns_chown_orig)(const struct path *path,
					  uid_t user, gid_t group);
static long (*droid_lkm_userns_fchownat_orig)(const struct pt_regs *regs);
static long (*droid_lkm_userns_fchown_orig)(const struct pt_regs *regs);
static struct ucounts *(*droid_lkm_userns_incuc_orig)(struct user_namespace *ns,
						      kuid_t uid,
						      enum ucount_type type);
static struct ucounts *(*droid_lkm_userns_allocuc_orig)(struct user_namespace *ns,
							kuid_t uid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
static int (*droid_lkm_userns_setcreduc_orig)(struct cred *new);
#endif

#define DROID_LKM_USERNS_ORIG(_name)                                           \
	({                                                                     \
		typeof(droid_lkm_userns_##_name##_orig) __orig =               \
			READ_ONCE(droid_lkm_userns_##_name##_orig);            \
		if (unlikely(!__orig))                                         \
			__orig = (typeof(__orig))                              \
				READ_ONCE(droid_lkm_userns_##_name##_hook.orig); \
		__orig;                                                        \
	})

DROID_LKM_ENTRY __nocfi noinline struct cred *droid_lkm_userns_prepcred_wrap(void)
{
	struct cred *new;
	struct droid_lkm_userns *u;
	typeof(droid_lkm_userns_prepcred_orig) orig = DROID_LKM_USERNS_ORIG(prepcred);

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_prepcred_hook);
		return NULL;
	}

	new = orig();
	ds_hook_leave(&droid_lkm_userns_prepcred_hook);
	if (!new)
		return NULL;

	/*
	 * In CONFIG_USER_NS=n kernels, prepare_creds() shallow-copies old->user_ns
	 * via memcpy without refcounting. Acquire a reference for our fake userns;
	 * fail closed (strip caps + put_cred + return NULL) if refcount cannot be taken.
	 */
	if (likely(READ_ONCE(new->user_ns) == droid_lkm_userns_init_uns))
		return new;

	u = droid_lkm_userns_from_ns(new->user_ns);
	if (u && !droid_lkm_userns_get(u)) {
		droid_lkm_userns_cred_fail_closed(new);
		put_cred(new);
		return NULL;
	}

	return new;
}

DROID_LKM_ENTRY __nocfi noinline void droid_lkm_userns_putcred_wrap(struct cred *cred)
{
	struct user_namespace *old_uns;
	struct droid_lkm_userns *u = NULL;
	typeof(droid_lkm_userns_putcred_orig) orig = DROID_LKM_USERNS_ORIG(putcred);

	if (cred && unlikely(READ_ONCE(cred->user_ns) != droid_lkm_userns_init_uns)) {
		/*
		 * F2 guard: if lsm_cred_alloc() failed inside prepare_creds(),
		 * no ref was taken; clear user_ns without putting. Otherwise
		 * atomically reset user_ns so double security_cred_free() puts once.
		 */
		if (droid_lkm_userns_has_cred_security && !cred->security) {
			WRITE_ONCE(cred->user_ns, droid_lkm_userns_init_uns);
		} else {
			old_uns = xchg(&cred->user_ns, droid_lkm_userns_init_uns);
			u = droid_lkm_userns_from_ns(old_uns);
		}
	}

	if (orig)
		orig(cred);
	ds_hook_leave(&droid_lkm_userns_putcred_hook);

	if (u)
		droid_lkm_userns_put(u);
}

DROID_LKM_ENTRY __nocfi noinline void
droid_lkm_userns_transfer_wrap(struct cred *new, const struct cred *old)
{
	typeof(droid_lkm_userns_transfer_orig) orig =
		DROID_LKM_USERNS_ORIG(transfer);

	if (new && old &&
	    unlikely(READ_ONCE(old->user_ns) != droid_lkm_userns_init_uns ||
		     READ_ONCE(new->user_ns) != droid_lkm_userns_init_uns)) {
		struct droid_lkm_userns *old_u =
			droid_lkm_userns_from_ns(READ_ONCE(old->user_ns));
		struct droid_lkm_userns *new_u =
			droid_lkm_userns_from_ns(READ_ONCE(new->user_ns));

		if (old_u != new_u) {
			if (old_u) {
				if (droid_lkm_userns_get(old_u))
					WRITE_ONCE(new->user_ns, &old_u->uns);
				else
					droid_lkm_userns_cred_fail_closed(new);
			} else {
				WRITE_ONCE(new->user_ns,
					   droid_lkm_userns_init_uns);
			}
			if (new_u)
				droid_lkm_userns_put(new_u);
		}
	}

	if (orig)
		orig(new, old);
	ds_hook_leave(&droid_lkm_userns_transfer_hook);
}

static __nocfi noinline int
droid_lkm_userns_seccap_eval(const struct cred *cred, struct user_namespace *ns,
			     int cap, unsigned int opts,
			     int (*orig)(const struct cred *,
					 struct user_namespace *, int,
					 unsigned int))
{
	struct droid_lkm_userns *targ_u, *cred_u;

	if (!orig)
		return -EINVAL;

	/* Fast path: host check on host credentials */
	if (likely(ns == droid_lkm_userns_init_uns &&
		   (!cred || cred->user_ns == droid_lkm_userns_init_uns)))
		return orig(cred, ns, cap, opts);

	/*
	 * Security boundary 1: a fake user namespace NEVER holds capabilities
	 * over the initial user namespace (host root).
	 */
	if (ns == droid_lkm_userns_init_uns)
		return -EPERM;

	targ_u = droid_lkm_userns_from_ns(ns);
	if (!targ_u)
		return orig(cred, ns, cap, opts);

	if (!cred)
		return -EPERM;

	cred_u = droid_lkm_userns_from_ns(cred->user_ns);

	/*
	 * Mirrors cap_capable() from security/commoncap.c:
	 * examine target namespace and all of its ancestors.
	 */
	while (targ_u) {
		if (cred_u == targ_u) {
			if (cap_raised(cred->cap_effective, cap))
				return 0;
			return -EPERM;
		}

		if (targ_u->level <= (cred_u ? cred_u->level : 0))
			return -EPERM;

		if (targ_u->uns.parent == (cred_u ? &cred_u->uns : droid_lkm_userns_init_uns)) {
			if (uid_eq(cred->euid, targ_u->uns.owner))
				return 0;
			if (cred_u) {
				if (cap_raised(cred->cap_effective, cap))
					return 0;
			} else {
				if (orig(cred, droid_lkm_userns_init_uns, cap, opts) == 0)
					return 0;
			}
			return -EPERM;
		}

		targ_u = droid_lkm_userns_from_ns(targ_u->uns.parent);
	}

	return -EPERM;
}

/*
 * Direct entry point for module-internal callers (e.g. userns_proc.c): works
 * identically whether security_capable is on bhook or kprobe GUARD_CALLER.
 */
__nocfi noinline int droid_lkm_userns_capable(const struct cred *cred,
					      struct user_namespace *ns,
					      int cap, unsigned int opts)
{
	typeof(droid_lkm_userns_seccap_orig) orig = DROID_LKM_USERNS_ORIG(seccap);

	if (!orig)
		orig = droid_lkm_misc_ks.security_capable;
	return droid_lkm_userns_seccap_eval(cred, ns, cap, opts, orig);
}

DROID_LKM_ENTRY __nocfi noinline int droid_lkm_userns_seccap_wrap(const struct cred *cred,
						  struct user_namespace *ns,
						  int cap, unsigned int opts)
{
	typeof(droid_lkm_userns_seccap_orig) orig = DROID_LKM_USERNS_ORIG(seccap);
	int ret;

	ret = droid_lkm_userns_seccap_eval(cred, ns, cap, opts, orig);
	ds_hook_leave(&droid_lkm_userns_seccap_hook);
	return ret;
}

DROID_LKM_ENTRY __nocfi noinline int droid_lkm_userns_nsproxy_wrap(unsigned long unshare_flags,
						   struct nsproxy **new_nsp,
						   struct cred *new_cred,
						   struct fs_struct *new_fs)
{
	const struct cred *cred = new_cred ? new_cred : current_cred();
	struct droid_lkm_userns *u = cred ? droid_lkm_userns_from_ns(cred->user_ns) : NULL;
	struct nsproxy *nsp;
	typeof(droid_lkm_userns_nsproxy_orig) orig = DROID_LKM_USERNS_ORIG(nsproxy);
	int ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_nsproxy_hook);
		return -EINVAL;
	}

	if (!(unshare_flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			       CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP |
			       CLONE_NEWTIME))) {
		ret = orig(unshare_flags, new_nsp, new_cred, new_fs);
		ds_hook_leave(&droid_lkm_userns_nsproxy_hook);
		return ret;
	}

	if (!u || !cap_raised(cred->cap_effective, CAP_SYS_ADMIN)) {
		ret = orig(unshare_flags, new_nsp, new_cred, new_fs);
		ds_hook_leave(&droid_lkm_userns_nsproxy_hook);
		return ret;
	}

	ds_hook_leave(&droid_lkm_userns_nsproxy_hook);
	nsp = droid_lkm_misc_ks.create_new_namespaces(unshare_flags, current, &u->uns,
						      new_fs ? new_fs : droid_lkm_misc_task_fs(current));
	if (IS_ERR(nsp))
		return PTR_ERR(nsp);

	if (unshare_flags & CLONE_NEWUTS)
		nsp->uts_ns->user_ns = &u->uns;
	if ((unshare_flags & CLONE_NEWIPC) && nsp->ipc_ns)
		nsp->ipc_ns->user_ns = &u->uns;
	if (unshare_flags & CLONE_NEWNET)
		nsp->net_ns->user_ns = &u->uns;
	if (unshare_flags & CLONE_NEWCGROUP)
		nsp->cgroup_ns->user_ns = &u->uns;
	if ((unshare_flags & CLONE_NEWTIME) && nsp->time_ns_for_children)
		nsp->time_ns_for_children->user_ns = &u->uns;

	*new_nsp = nsp;
	return 0;
}

DROID_LKM_ENTRY __nocfi noinline int droid_lkm_userns_unshare_wrap(unsigned long flags)
{
	struct droid_lkm_userns *u;
	const struct cred *old;
	unsigned long rest;
	int ret;
	typeof(droid_lkm_userns_unshare_orig) orig = DROID_LKM_USERNS_ORIG(unshare);

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_unshare_hook);
		return -EINVAL;
	}

	if (!(flags & CLONE_NEWUSER) || !READ_ONCE(droid_lkm_userns_ready)) {
		ret = orig(flags);
		ds_hook_leave(&droid_lkm_userns_unshare_hook);
		return ret;
	}

	/* upstream rejects this pair before it touches anything */
	if (flags & CLONE_FS) {
		ds_hook_leave(&droid_lkm_userns_unshare_hook);
		return -EINVAL;
	}

	/* allocate before the kernel changes anything, so failure is free */
	u = droid_lkm_userns_create(droid_lkm_userns_of(current));
	if (IS_ERR(u)) {
		ds_hook_leave(&droid_lkm_userns_unshare_hook);
		return PTR_ERR(u);
	}

	old = get_task_cred(current);

	ret = droid_lkm_userns_install_current(u);
	if (ret) {
		put_cred(old);
		droid_lkm_userns_put(u);
		ds_hook_leave(&droid_lkm_userns_unshare_hook);
		return ret;
	}

	rest = flags & ~CLONE_NEWUSER;
	ret = orig(rest);
	ds_hook_leave(&droid_lkm_userns_unshare_hook);
	if (ret) {
		droid_lkm_misc_ks.commit_creds((struct cred *)old);
		droid_lkm_userns_put(u);
		return ret;
	}

	put_cred(old);
	droid_lkm_userns_put(u);

	return 0;
}

DROID_LKM_ENTRY __nocfi noinline int droid_lkm_userns_creds_wrap(struct task_struct *p,
						unsigned long clone_flags)
{
	struct droid_lkm_userns *u;
	unsigned long rest;
	int ret;
	typeof(droid_lkm_userns_creds_orig) orig = DROID_LKM_USERNS_ORIG(creds);

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_creds_hook);
		return -EINVAL;
	}

	/* a thread clone shares credentials, so it cannot own a namespace */
	if (!(clone_flags & CLONE_NEWUSER) || (clone_flags & CLONE_THREAD) ||
	    !READ_ONCE(droid_lkm_userns_ready)) {
		ret = orig(p, clone_flags);
		ds_hook_leave(&droid_lkm_userns_creds_hook);
		return ret;
	}

	u = droid_lkm_userns_create(droid_lkm_userns_of(current));
	if (IS_ERR(u)) {
		ds_hook_leave(&droid_lkm_userns_creds_hook);
		return PTR_ERR(u);
	}

	rest = clone_flags & ~CLONE_NEWUSER;
	ret = orig(p, rest);
	ds_hook_leave(&droid_lkm_userns_creds_hook);
	if (ret) {
		droid_lkm_userns_put(u);
		return ret;
	}

	/* the child has not run and copy_creds() built a fresh credential */
	{
		struct cred *p_real = (struct cred *)droid_lkm_misc_task_real_cred(p);
		struct cred *p_cred = (struct cred *)droid_lkm_misc_task_cred(p);

		if (p_real)
			(void)droid_lkm_userns_install_cred(p_real, u);
		if (p_cred && p_cred != p_real)
			(void)droid_lkm_userns_install_cred(p_cred, u);
	}

	droid_lkm_userns_put(u);

	return 0;
}

DROID_LKM_ENTRY __nocfi noinline bool droid_lkm_userns_inodecap_wrap(DROID_LKM_IDMAP_PARAM
						     const struct inode *inode,
						     int cap)
{
	struct droid_lkm_userns *u;
	typeof(droid_lkm_userns_inodecap_orig) orig = DROID_LKM_USERNS_ORIG(inodecap);
	bool ok;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_inodecap_hook);
		return false;
	}

	ok = orig(DROID_LKM_IDMAP_PASS inode, cap);
	ds_hook_leave(&droid_lkm_userns_inodecap_hook);
	if (ok)
		return true;

	/* an idmapped mount is a different rule set, it arrives with the lens */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	if (!droid_lkm_misc_ks.nop_mnt_idmap ||
	    (const void *)idmap != (const void *)droid_lkm_misc_ks.nop_mnt_idmap)
		return false;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (mnt_userns && mnt_userns != &init_user_ns)
		return false;
#endif

	u = droid_lkm_userns_of(current);
	if (!u)
		return false;

	if (!cap_raised(current_cred()->cap_effective, cap))
		return false;

	return droid_lkm_userns_has_mapping(u, __kuid_val(inode->i_uid), true) &&
	       droid_lkm_userns_has_mapping(u, __kgid_val(inode->i_gid), false);
}

DROID_LKM_ENTRY __nocfi noinline bool droid_lkm_userns_mountcap_wrap(struct fs_context *fc)
{
	struct droid_lkm_userns *u;
	typeof(droid_lkm_userns_mountcap_orig) orig = DROID_LKM_USERNS_ORIG(mountcap);
	bool ok;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_mountcap_hook);
		return false;
	}

	ok = orig(fc);
	ds_hook_leave(&droid_lkm_userns_mountcap_hook);
	if (ok)
		return true;

	if (!fc || !fc->fs_type || (fc->fs_type->fs_flags & FS_USERNS_MOUNT))
		return false;

	if (!cap_raised(current_cred()->cap_effective, CAP_SYS_ADMIN))
		return false;

	u = droid_lkm_userns_from_ns(fc->user_ns);
	if (!u || !u->privileged)
		return false;

	return true;
}

/*
 * F8: Intercept chown_common() rather than __arm64_sys_fchownat so fchown,
 * fchownat, compat32 chown*, and io_uring all share one translation point and
 * preserve VFS path-resolution error precedence.
 */
DROID_LKM_ENTRY __nocfi noinline int
droid_lkm_userns_chown_wrap(const struct path *path, uid_t user, gid_t group)
{
	typeof(droid_lkm_userns_chown_orig) orig = DROID_LKM_USERNS_ORIG(chown);
	struct droid_lkm_userns *u;
	u32 id;
	int ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_chown_hook);
		return -EINVAL;
	}

	u = droid_lkm_userns_of(current);
	if (u) {
		if (user != (uid_t)-1) {
			id = droid_lkm_userns_map_down(u, user, true);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_chown_hook);
				return -EINVAL;
			}
			user = id;
		}
		if (group != (gid_t)-1) {
			id = droid_lkm_userns_map_down(u, group, false);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_chown_hook);
				return -EINVAL;
			}
			group = id;
		}
	}

	ret = orig(path, user, group);
	ds_hook_leave(&droid_lkm_userns_chown_hook);
	return ret;
}

/* Syscall-level fallback when ThinLTO inlines chown_common() */
DROID_LKM_ENTRY __nocfi noinline long
droid_lkm_userns_fchownat_wrap(const struct pt_regs *regs)
{
	typeof(droid_lkm_userns_fchownat_orig) orig =
		DROID_LKM_USERNS_ORIG(fchownat);
	struct droid_lkm_userns *u;
	struct pt_regs local_regs;
	u32 id;
	long ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_fchownat_hook);
		return -EINVAL;
	}
	if (!regs) {
		ds_hook_leave(&droid_lkm_userns_fchownat_hook);
		return -EFAULT;
	}

	u = droid_lkm_userns_of(current);
	if (u) {
		local_regs = *regs;

		if ((uid_t)local_regs.regs[2] != (uid_t)-1) {
			id = droid_lkm_userns_map_down(u, (uid_t)local_regs.regs[2], true);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_fchownat_hook);
				return -EINVAL;
			}
			local_regs.regs[2] = id;
		}
		if ((gid_t)local_regs.regs[3] != (gid_t)-1) {
			id = droid_lkm_userns_map_down(u, (gid_t)local_regs.regs[3], false);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_fchownat_hook);
				return -EINVAL;
			}
			local_regs.regs[3] = id;
		}

		ret = orig(&local_regs);
		ds_hook_leave(&droid_lkm_userns_fchownat_hook);
		return ret;
	}

	ret = orig(regs);
	ds_hook_leave(&droid_lkm_userns_fchownat_hook);
	return ret;
}

DROID_LKM_ENTRY __nocfi noinline long
droid_lkm_userns_fchown_wrap(const struct pt_regs *regs)
{
	typeof(droid_lkm_userns_fchown_orig) orig = DROID_LKM_USERNS_ORIG(fchown);
	struct droid_lkm_userns *u;
	struct pt_regs local_regs;
	u32 id;
	long ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_fchown_hook);
		return -EINVAL;
	}
	if (!regs) {
		ds_hook_leave(&droid_lkm_userns_fchown_hook);
		return -EFAULT;
	}

	u = droid_lkm_userns_of(current);
	if (u) {
		local_regs = *regs;

		if ((uid_t)local_regs.regs[1] != (uid_t)-1) {
			id = droid_lkm_userns_map_down(u, (uid_t)local_regs.regs[1], true);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_fchown_hook);
				return -EINVAL;
			}
			local_regs.regs[1] = id;
		}
		if ((gid_t)local_regs.regs[2] != (gid_t)-1) {
			id = droid_lkm_userns_map_down(u, (gid_t)local_regs.regs[2], false);
			if (id == DROID_LKM_USERNS_ID_UNMAPPED) {
				ds_hook_leave(&droid_lkm_userns_fchown_hook);
				return -EINVAL;
			}
			local_regs.regs[2] = id;
		}

		ret = orig(&local_regs);
		ds_hook_leave(&droid_lkm_userns_fchown_hook);
		return ret;
	}

	ret = orig(regs);
	ds_hook_leave(&droid_lkm_userns_fchown_hook);
	return ret;
}

/*
 * CONFIG_USER_NS=n compiles get_user_ns() / put_user_ns() out to no-op stubs,
 * so struct ucounts never pins a fake user_namespace alive. Redirecting every
 * ucounts lookup/allocation for our fake userns to init_user_ns prevents:
 *   1. Async teardown UAF (e.g. cleanup_net -> dec_ucount -> iter->ns->ucounts
 *      dereferencing a freed droid_lkm_userns).
 *   2. UCOUNT_RLIMIT_NPROC underflow WARNING in dec_rlimit_ucounts() when
 *      execve -> set_cred_ucounts() allocates a fresh zero-count ucounts under
 *      a fake userns while commit_creds() skips inc_rlimit_ucounts().
 */
DROID_LKM_ENTRY __nocfi noinline struct ucounts *
droid_lkm_userns_incuc_wrap(struct user_namespace *ns, kuid_t uid,
			    enum ucount_type type)
{
	typeof(droid_lkm_userns_incuc_orig) orig = DROID_LKM_USERNS_ORIG(incuc);
	struct ucounts *ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_incuc_hook);
		return NULL;
	}

	if (unlikely(ns && ns != droid_lkm_userns_init_uns &&
		     droid_lkm_userns_is_ours(ns)))
		ns = droid_lkm_userns_init_uns;

	ret = orig(ns, uid, type);
	ds_hook_leave(&droid_lkm_userns_incuc_hook);
	return ret;
}

DROID_LKM_ENTRY __nocfi noinline struct ucounts *
droid_lkm_userns_allocuc_wrap(struct user_namespace *ns, kuid_t uid)
{
	typeof(droid_lkm_userns_allocuc_orig) orig =
		DROID_LKM_USERNS_ORIG(allocuc);
	struct ucounts *ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_allocuc_hook);
		return NULL;
	}

	if (unlikely(ns && ns != droid_lkm_userns_init_uns &&
		     droid_lkm_userns_is_ours(ns)))
		ns = droid_lkm_userns_init_uns;

	ret = orig(ns, uid);
	ds_hook_leave(&droid_lkm_userns_allocuc_hook);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
DROID_LKM_ENTRY __nocfi noinline int
droid_lkm_userns_setcreduc_wrap(struct cred *new)
{
	typeof(droid_lkm_userns_setcreduc_orig) orig =
		DROID_LKM_USERNS_ORIG(setcreduc);
	struct user_namespace *saved_uns;
	int ret;

	if (!orig) {
		ds_hook_leave(&droid_lkm_userns_setcreduc_hook);
		return 0;
	}

	if (likely(!new ||
		   READ_ONCE(new->user_ns) == droid_lkm_userns_init_uns)) {
		ret = orig(new);
		ds_hook_leave(&droid_lkm_userns_setcreduc_hook);
		return ret;
	}

	saved_uns = READ_ONCE(new->user_ns);
	if (droid_lkm_userns_is_ours(saved_uns)) {
		/* Fast path: execve inside fake userns with unchanged uid */
		if (new->ucounts &&
		    new->ucounts->ns == droid_lkm_userns_init_uns &&
		    uid_eq(new->ucounts->uid, new->uid)) {
			ds_hook_leave(&droid_lkm_userns_setcreduc_hook);
			return 0;
		}
		/*
		 * UID changed (e.g. setuid): temporarily point private
		 * uncommitted cred->user_ns at init_user_ns across orig() so
		 * ThinLTO-inlined alloc_ucounts() still resolves init_user_ns.
		 */
		WRITE_ONCE(new->user_ns, droid_lkm_userns_init_uns);
		ret = orig(new);
		WRITE_ONCE(new->user_ns, saved_uns);
		ds_hook_leave(&droid_lkm_userns_setcreduc_hook);
		return ret;
	}

	ret = orig(new);
	ds_hook_leave(&droid_lkm_userns_setcreduc_hook);
	return ret;
}
#endif

static int droid_lkm_userns_hook_hot(struct ds_hook *h, const char *sym,
				     const char *wrap, void **orig,
				     enum hk_redir_guard guard)
{
	int ret;

	ret = ds_hook_install_guard(h, sym, wrap, guard);
	if (ret) {
		droid_lkm_misc_warn("hook %s failed: %d\n", sym, ret);
		return ret;
	}

	WRITE_ONCE(*orig, (void *)h->orig);
	droid_lkm_misc_dbg("hook %-28s route=%s addr=0x%lx orig=0x%lx\n",
			   sym, ds_hook_route_name(h->route), h->addr, h->orig);
	return 0;
}

static int droid_lkm_userns_hook_lowfreq(struct ds_hook *h, const char *sym,
					 const char *wrap, void **orig,
					 enum hk_redir_guard guard)
{
	int ret;

	ret = ds_hook_install_kprobe_guard(h, sym, wrap, guard);
	if (ret) {
		droid_lkm_misc_warn("hook %s failed: %d\n", sym, ret);
		return ret;
	}

	WRITE_ONCE(*orig, (void *)h->orig);
	droid_lkm_misc_dbg("hook %-28s route=%s addr=0x%lx orig=0x%lx\n",
			   sym, ds_hook_route_name(h->route), h->addr, h->orig);
	return 0;
}

static void droid_lkm_userns_unhook(struct ds_hook *h, void **orig)
{
	if (h->live)
		ds_hook_remove(h);
	if (orig)
		WRITE_ONCE(*orig, NULL);
}

int droid_lkm_userns_hooks_init(void)
{
	const char *putcred_sym;
	int ret;

	WRITE_ONCE(droid_lkm_userns_ready, false);
	droid_lkm_userns_has_cred_security =
		(current_cred() && current_cred()->security != NULL);

	/*
	 * Step 1: Install reversible enforcement & chown hooks first (while
	 * droid_lkm_userns_ready == false so no fake userns can be created yet).
	 * This avoids splicing irreversible LSM hooks if an earlier hook fails.
	 */
	ret = droid_lkm_userns_hook_hot(
		&droid_lkm_userns_seccap_hook, "security_capable",
		"droid_lkm_userns_seccap_wrap",
		(void **)&droid_lkm_userns_seccap_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		return ret;

	ret = droid_lkm_userns_hook_hot(
		&droid_lkm_userns_inodecap_hook, "capable_wrt_inode_uidgid",
		"droid_lkm_userns_inodecap_wrap",
		(void **)&droid_lkm_userns_inodecap_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		goto out_seccap;

	ret = droid_lkm_userns_hook_lowfreq(
		&droid_lkm_userns_mountcap_hook, "mount_capable",
		"droid_lkm_userns_mountcap_wrap",
		(void **)&droid_lkm_userns_mountcap_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		goto out_inodecap;

	ret = droid_lkm_userns_hook_lowfreq(
		&droid_lkm_userns_nsproxy_hook, "unshare_nsproxy_namespaces",
		"droid_lkm_userns_nsproxy_wrap",
		(void **)&droid_lkm_userns_nsproxy_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		goto out_mountcap;

	/*
	 * Pin all struct ucounts allocations/increments for fake userns onto
	 * init_user_ns so async namespace teardown (e.g. cleanup_net ->
	 * dec_ucount) never dereferences a freed fake user_namespace and
	 * execve -> set_cred_ucounts never underflows UCOUNT_RLIMIT_NPROC.
	 */
	ret = droid_lkm_userns_hook_lowfreq(
		&droid_lkm_userns_incuc_hook, "inc_ucount",
		"droid_lkm_userns_incuc_wrap",
		(void **)&droid_lkm_userns_incuc_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		goto out_nsproxy;

	if (droid_lkm_misc_sym("alloc_ucounts")) {
		ret = droid_lkm_userns_hook_lowfreq(
			&droid_lkm_userns_allocuc_hook, "alloc_ucounts",
			"droid_lkm_userns_allocuc_wrap",
			(void **)&droid_lkm_userns_allocuc_orig,
			HK_REDIR_GUARD_CALLER);
		if (ret)
			goto out_incuc;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (droid_lkm_misc_sym("set_cred_ucounts")) {
		ret = droid_lkm_userns_hook_hot(
			&droid_lkm_userns_setcreduc_hook, "set_cred_ucounts",
			"droid_lkm_userns_setcreduc_wrap",
			(void **)&droid_lkm_userns_setcreduc_orig,
			HK_REDIR_GUARD_CALLER);
		if (ret)
			goto out_allocuc;
	}
#endif
	droid_lkm_misc_report("userns ucounts", "ready",
			      "redirected to init_user_ns");

	/* Optional chown translation (F8: chown_common preferred over fchownat) */
	if (droid_lkm_misc_sym("chown_common") &&
	    !droid_lkm_userns_hook_lowfreq(&droid_lkm_userns_chown_hook,
					   "chown_common",
					   "droid_lkm_userns_chown_wrap",
					   (void **)&droid_lkm_userns_chown_orig,
					   HK_REDIR_GUARD_CALLER)) {
		droid_lkm_misc_report("userns chown map", "ready",
				      "uid and gid translated at chown_common");
	} else {
		bool got_at = !droid_lkm_userns_hook_lowfreq(
			&droid_lkm_userns_fchownat_hook, "__arm64_sys_fchownat",
			"droid_lkm_userns_fchownat_wrap",
			(void **)&droid_lkm_userns_fchownat_orig,
			HK_REDIR_GUARD_CALLER);
		bool got_fd = droid_lkm_misc_sym("__arm64_sys_fchown") &&
			      !droid_lkm_userns_hook_lowfreq(
				      &droid_lkm_userns_fchown_hook,
				      "__arm64_sys_fchown",
				      "droid_lkm_userns_fchown_wrap",
				      (void **)&droid_lkm_userns_fchown_orig,
				      HK_REDIR_GUARD_CALLER);

		if (got_at && got_fd)
			droid_lkm_misc_report("userns chown map", "ready",
					      "uid and gid translated at fchownat+fchown");
		else if (got_at)
			droid_lkm_misc_report("userns chown map", "ready",
					      "uid and gid translated at fchownat");
		else
			droid_lkm_misc_report("userns chown map", "unsupported",
					      "chown hooks unavailable, ids pass through");
	}

	/*
	 * Step 2 (F3): Credential accounting BEFORE any producer hook is
	 * installed. Prefer native BTF-verified LSM security_hook_heads;
	 * fall back to ds_hook when LSM splice is unavailable (e.g. 6.12+).
	 */
	if (droid_lkm_userns_lsm_init()) {
		putcred_sym = droid_lkm_misc_sym("security_cred_free") ?
			"security_cred_free" : "__put_cred";

		/* putcred runs in RCU softirq: kprobe fallback MUST use CALLER guard */
		ret = droid_lkm_userns_hook_hot(
			&droid_lkm_userns_putcred_hook, putcred_sym,
			"droid_lkm_userns_putcred_wrap",
			(void **)&droid_lkm_userns_putcred_orig,
			HK_REDIR_GUARD_CALLER);
		if (ret)
			goto out_chown;

		/*
		 * prepare_creds is also called from userns_cred.c inside this
		 * module, so kprobe fallback MUST use GUARD_TASK.
		 */
		ret = droid_lkm_userns_hook_hot(
			&droid_lkm_userns_prepcred_hook, "prepare_creds",
			"droid_lkm_userns_prepcred_wrap",
			(void **)&droid_lkm_userns_prepcred_orig,
			HK_REDIR_GUARD_TASK);
		if (ret)
			goto out_putcred;

		/* Close F1-b KEYCTL_SESSION_TO_PARENT on fallback path too */
		if (droid_lkm_misc_sym("security_transfer_creds")) {
			(void)droid_lkm_userns_hook_lowfreq(
				&droid_lkm_userns_transfer_hook,
				"security_transfer_creds",
				"droid_lkm_userns_transfer_wrap",
				(void **)&droid_lkm_userns_transfer_orig,
				HK_REDIR_GUARD_CALLER);
		}
		droid_lkm_misc_report("userns cred lsm", "fallback",
				      "ds_hook cred accounting");
	}

	/* Step 3 (F3): Producer hooks LAST, gated by droid_lkm_userns_ready */
	ret = droid_lkm_userns_hook_hot(
		&droid_lkm_userns_creds_hook, "copy_creds",
		"droid_lkm_userns_creds_wrap",
		(void **)&droid_lkm_userns_creds_orig, HK_REDIR_GUARD_CALLER);
	if (ret)
		goto out_acct;

	/* ksys_unshare is invoked by userns_selftest.c inside THIS_MODULE -> GUARD_TASK */
	ret = droid_lkm_userns_hook_lowfreq(
		&droid_lkm_userns_unshare_hook, "ksys_unshare",
		"droid_lkm_userns_unshare_wrap",
		(void **)&droid_lkm_userns_unshare_orig, HK_REDIR_GUARD_TASK);
	if (ret)
		goto out_creds;

	smp_wmb();
	WRITE_ONCE(droid_lkm_userns_ready, true);
	droid_lkm_misc_info("userns hooks installed\n");
	return 0;

out_creds:
	droid_lkm_userns_unhook(&droid_lkm_userns_creds_hook,
				(void **)&droid_lkm_userns_creds_orig);
out_acct:
	droid_lkm_userns_unhook(&droid_lkm_userns_transfer_hook,
				(void **)&droid_lkm_userns_transfer_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_prepcred_hook,
				(void **)&droid_lkm_userns_prepcred_orig);
out_putcred:
	droid_lkm_userns_unhook(&droid_lkm_userns_putcred_hook,
				(void **)&droid_lkm_userns_putcred_orig);
out_chown:
	droid_lkm_userns_unhook(&droid_lkm_userns_fchown_hook,
				(void **)&droid_lkm_userns_fchown_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_fchownat_hook,
				(void **)&droid_lkm_userns_fchownat_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_chown_hook,
				(void **)&droid_lkm_userns_chown_orig);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	droid_lkm_userns_unhook(&droid_lkm_userns_setcreduc_hook,
				(void **)&droid_lkm_userns_setcreduc_orig);
out_allocuc:
#endif
	droid_lkm_userns_unhook(&droid_lkm_userns_allocuc_hook,
				(void **)&droid_lkm_userns_allocuc_orig);
out_incuc:
	droid_lkm_userns_unhook(&droid_lkm_userns_incuc_hook,
				(void **)&droid_lkm_userns_incuc_orig);
out_nsproxy:
	droid_lkm_userns_unhook(&droid_lkm_userns_nsproxy_hook,
				(void **)&droid_lkm_userns_nsproxy_orig);
out_mountcap:
	droid_lkm_userns_unhook(&droid_lkm_userns_mountcap_hook,
				(void **)&droid_lkm_userns_mountcap_orig);
out_inodecap:
	droid_lkm_userns_unhook(&droid_lkm_userns_inodecap_hook,
				(void **)&droid_lkm_userns_inodecap_orig);
out_seccap:
	droid_lkm_userns_unhook(&droid_lkm_userns_seccap_hook,
				(void **)&droid_lkm_userns_seccap_orig);
	return ret;
}

void droid_lkm_userns_hooks_exit(void)
{
	WRITE_ONCE(droid_lkm_userns_ready, false);
	smp_wmb();

	droid_lkm_userns_unhook(&droid_lkm_userns_unshare_hook,
				(void **)&droid_lkm_userns_unshare_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_creds_hook,
				(void **)&droid_lkm_userns_creds_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_fchown_hook,
				(void **)&droid_lkm_userns_fchown_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_fchownat_hook,
				(void **)&droid_lkm_userns_fchownat_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_chown_hook,
				(void **)&droid_lkm_userns_chown_orig);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	droid_lkm_userns_unhook(&droid_lkm_userns_setcreduc_hook,
				(void **)&droid_lkm_userns_setcreduc_orig);
#endif
	droid_lkm_userns_unhook(&droid_lkm_userns_allocuc_hook,
				(void **)&droid_lkm_userns_allocuc_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_incuc_hook,
				(void **)&droid_lkm_userns_incuc_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_nsproxy_hook,
				(void **)&droid_lkm_userns_nsproxy_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_mountcap_hook,
				(void **)&droid_lkm_userns_mountcap_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_inodecap_hook,
				(void **)&droid_lkm_userns_inodecap_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_seccap_hook,
				(void **)&droid_lkm_userns_seccap_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_transfer_hook,
				(void **)&droid_lkm_userns_transfer_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_prepcred_hook,
				(void **)&droid_lkm_userns_prepcred_orig);
	droid_lkm_userns_unhook(&droid_lkm_userns_putcred_hook,
				(void **)&droid_lkm_userns_putcred_orig);
}
