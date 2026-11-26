// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */


#ifndef DROID_LKM_PROC_H
#define DROID_LKM_PROC_H

#include <linux/types.h>

struct proc_ns_operations;
struct task_struct;
struct user_namespace;

/*
 * Namespace kinds the main module does not implement itself, registered by an
 * optional module (the user namespace lives in droid_lkm_misc). The callback
 * picks the operations for one task, so the owner can be a fake namespace, the
 * host placeholder, or nothing at all.
 */
struct droid_lkm_ns_kind_reg {
	const char *name;
	const struct proc_ns_operations *(*ops_for)(struct task_struct *task);
	/* Optional external refcounting hooks for fake user_namespace owners */
	struct user_namespace *(*get_user_ns)(struct user_namespace *ns);
	void (*put_user_ns)(struct user_namespace *ns);
};

int droid_lkm_ns_kind_register(const struct droid_lkm_ns_kind_reg *kind);
void droid_lkm_ns_kind_unregister(const struct droid_lkm_ns_kind_reg *kind);

/* Refcount fake user_namespace pointers stored in droid_lkm-owned namespaces */
struct user_namespace *droid_lkm_userns_hold(struct user_namespace *ns);
void droid_lkm_userns_drop(struct user_namespace *ns);

/* Clear surviving fake pid_namespace->user_ns back to init_user_ns on teardown */
void droid_lkm_pidns_detach_user_ns(struct user_namespace *uns);

int droid_lkm_proc_init(void);
void droid_lkm_proc_exit(void);
bool droid_lkm_proc_ready(void);

#endif
