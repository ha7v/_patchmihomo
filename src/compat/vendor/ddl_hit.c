// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Dere3046
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/threads.h>
#include <linux/types.h>

#include "core.h"
#include "ds_compat.h"
#include "ddl_hit.h"
#include "vendor_syms.h"
#include "hk_redir.h"

struct dlc_ddl_entry {
	char comm[TASK_COMM_LEN];
	u64 hit;
};

enum {
	DLC_DDL_F_PID,
	DLC_DDL_F_COMM,
	DLC_DDL_F_COUNT
};

static struct ds_compat_field dlc_ddl_fields[DLC_DDL_F_COUNT] = {
	[DLC_DDL_F_PID] = { .type = "task_struct", .member = "pid" },
	[DLC_DDL_F_COMM] = { .type = "task_struct", .member = "comm" },
};

static struct ds_compat_type dlc_ddl_types[] = {
	{ .name = "task_struct" },
};

static struct ds_compat_layout dlc_ddl_layout_table = {
	.module = "droid_lkm_vendor",
	.fields = dlc_ddl_fields,
	.nfields = ARRAY_SIZE(dlc_ddl_fields),
	.types = dlc_ddl_types,
	.ntypes = ARRAY_SIZE(dlc_ddl_types),
};

static u32 dlc_ddl_pid_off;
static u32 dlc_ddl_comm_off;
static struct hk_redir dlc_ddl_hook;

static bool dlc_ddl_field_ok(u8 state)
{
	return state == DS_COMPAT_OK || state == DS_COMPAT_VERIFIED ||
	       state == DS_COMPAT_ANCHORED;
}

static bool dlc_ddl_layout_ready(void)
{
	ds_compat_layout_init(&dlc_ddl_layout_table);
	if (!dlc_ddl_field_ok(dlc_ddl_fields[DLC_DDL_F_PID].state) ||
	    !dlc_ddl_field_ok(dlc_ddl_fields[DLC_DDL_F_COMM].state))
		return false;

	dlc_ddl_pid_off = dlc_ddl_fields[DLC_DDL_F_PID].live;
	dlc_ddl_comm_off = dlc_ddl_fields[DLC_DDL_F_COMM].live;
	return true;
}

static DROID_LKM_ENTRY __nocfi noinline void dlc_ddl_update_wrap(struct task_struct *p)
{
	struct dlc_ddl_entry *entry;
	void *base = dlc_vendor_syms.ddl_sdata;
	const char *comm;
	pid_t pid;

	if (dlc_ddl_hook.how == HK_REDIR_KPROBE)
		hk_redir_leave(&dlc_ddl_hook);

	if (!p || !base)
		return;

	pid = *(const pid_t *)((const char *)p + dlc_ddl_pid_off);
	if (pid <= 0 || pid >= PID_MAX_DEFAULT)
		return;

	comm = (const char *)p + dlc_ddl_comm_off;
	entry = (struct dlc_ddl_entry *)base + pid;
	if (!entry->comm[0] ||
	    strncmp(comm, entry->comm, strnlen(comm, TASK_COMM_LEN))) {
		memset(entry, 0, sizeof(*entry));
		strscpy(entry->comm, comm, TASK_COMM_LEN);
	}
	entry->hit++;
}

int dlc_ddl_hit_init(void)
{
	struct hk_inline_probe probe;
	int ret;

	if (!dlc_vendor_syms.ddl_sdata || !dlc_vendor_syms.ddl_update)
		return 0;

	if (!dlc_ddl_layout_ready()) {
		pr_warn("[W] [droid_lkm_vendor] ddl: task_struct pid/comm offsets unavailable, hook skipped\n");
		return 0;
	}

	if (!hk_inline_probe("update_ddl_hit_history", &probe) &&
	    probe.state != HK_INLINE_PLAIN)
		pr_warn("[W] [droid_lkm_vendor] ddl: entry state %d (%s), text route skipped\n",
			probe.state, probe.reason ? probe.reason : "?");
	else {
		memset(&dlc_ddl_hook, 0, sizeof(dlc_ddl_hook));
		dlc_ddl_hook.ret_mode = HK_INLINE_RET_X17;
		ret = hk_redir_install(&dlc_ddl_hook, "update_ddl_hit_history",
				       "dlc_ddl_update_wrap", HK_REDIR_TEXT);
		if (!ret) {
			pr_info("[I] [droid_lkm_vendor] ddl: update_ddl_hit_history on the text route\n");
			return 0;
		}
		pr_warn("[W] [droid_lkm_vendor] ddl: text route refused %d, trying kprobe\n",
			ret);
	}

	memset(&dlc_ddl_hook, 0, sizeof(dlc_ddl_hook));
	dlc_ddl_hook.adjust = hk_kprobe_adjust_pad;
	ret = hk_redir_install_at(&dlc_ddl_hook,
				  (unsigned long)dlc_vendor_syms.ddl_update,
				  (unsigned long)dlc_ddl_update_wrap,
				  HK_REDIR_KPROBE);
	if (ret) {
		pr_warn("[W] [droid_lkm_vendor] ddl: no route took update_ddl_hit_history (%d)\n",
			ret);
		return 0;
	}
	pr_info("[I] [droid_lkm_vendor] ddl: update_ddl_hit_history on the kprobe route\n");
	return 0;
}

void dlc_ddl_hit_exit(void)
{
	if (!dlc_ddl_hook.live)
		return;

	hk_redir_remove(&dlc_ddl_hook);
	dlc_ddl_hook.live = false;
}
