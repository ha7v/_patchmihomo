// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Dere3046
 */

#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#include <linux/string.h>
#include <linux/preempt.h>
#include <linux/threads.h>
#include <linux/compiler.h>
#include <linux/mm.h>

#include "core.h"
#include "ds_compat.h"
#include "ds_hook.h"
#include "ghost.h"
#include "vendor_syms.h"

/* 6.18 builds with -Wmissing-prototypes */
DROID_LKM_ENTRY __nocfi noinline struct task_struct *dlc_ftbv_wrap(pid_t vnr);

#define DLC_GHOST_TASK_COMM	"ghost-task-sentinel"
#define DLC_GHOST_LOG_MAX	3
#define DLC_GHOST_SIZE_MAX	(64U * 1024U)

static bool dlc_ghost_enable = true;
module_param_named(ghost, dlc_ghost_enable, bool, 0444);
MODULE_PARM_DESC(ghost, "hand out a ghost task when find_task_by_vpid misses, default 1");

static char *dlc_ghost_match = "oplus_";
module_param_named(ghost_match, dlc_ghost_match, charp, 0444);
MODULE_PARM_DESC(ghost_match, "caller module name prefix, * matches all, default oplus_");

static typeof(&find_task_by_vpid) dlc_ftbv_orig;
static typeof(&__module_address) dlc_module_address;
static struct ds_hook dlc_ftbv_hook;
static struct task_struct *dlc_ghost_task;
static bool dlc_ghost_ready;
static atomic_t dlc_ghost_hits = ATOMIC_INIT(0);

/* Hot-path Midas fixed page & single-entry MRU for other vendor callers (16 bytes total) */
static unsigned long dlc_midas_page;
static unsigned long dlc_other_mru_page;

static bool dlc_ghost_match_module(const char *name)
{
	size_t n;

	if (!dlc_ghost_match || !*dlc_ghost_match)
		return false;
	if (dlc_ghost_match[0] == '*' && !dlc_ghost_match[1])
		return true;
	n = strlen(dlc_ghost_match);
	return strncmp(name, dlc_ghost_match, n) == 0;
}

static inline bool __nocfi dlc_ghost_is_vendor(unsigned long ret_ip)
{
	unsigned long page = ret_ip & PAGE_MASK;
	struct module *mod;
	bool match = false;

	if (unlikely(!page))
		return false;

	/* Fast path 1: midas dedicated page (100% hit in interrupt, zero thrashing) */
	if (likely(page == READ_ONCE(dlc_midas_page)))
		return true;

	/* Fast path 2: MRU page for other burst vendor callers */
	if (page == READ_ONCE(dlc_other_mru_page))
		return true;

	/* Slow path: parse kernel module tree */
	if (dlc_module_address) {
		bool is_midas = false;

		preempt_disable();
		mod = dlc_module_address(ret_ip);
		if (mod) {
			match = dlc_ghost_match_module(mod->name);
			if (match)
				is_midas = strcmp(mod->name, "oplus_bsp_midas") == 0;
		}
		preempt_enable();

		if (match) {
			/*
			 * Cross-device fallback:
			 * Bind to dlc_midas_page if not yet set or module is oplus_bsp_midas;
			 * otherwise store in the general MRU slot.
			 */
			if (!READ_ONCE(dlc_midas_page) || is_midas)
				WRITE_ONCE(dlc_midas_page, page);
			else
				WRITE_ONCE(dlc_other_mru_page, page);
			return true;
		}
	}
	return false;
}

// _RET_IP_ must be read before calling orig
DROID_LKM_ENTRY __nocfi noinline struct task_struct *dlc_ftbv_wrap(pid_t vnr)
{
	unsigned long ret_ip = (unsigned long)_RET_IP_;
	typeof(&find_task_by_vpid) orig;
	struct task_struct *task = NULL;
	bool is_vendor = false;

	orig = READ_ONCE(dlc_ftbv_orig);
	if (unlikely(!orig))
		orig = (typeof(orig))READ_ONCE(dlc_ftbv_hook.orig);
	if (likely(orig))
		task = orig(vnr);

	/* Always clean up hook guard state, even in the race-window where orig is NULL */
	ds_hook_leave(&dlc_ftbv_hook);

	if (likely(task))
		return task;

	/* If ghost fixups are disabled or task_struct template is not ready */
	if (!READ_ONCE(dlc_ghost_ready))
		return task;
	smp_rmb();

	/*
	 * Guard 1 (Container isolation / prevent Namespace Escape):
	 * Caller must be verified as an authorized vendor module before
	 * any cross-namespace fallback is permitted. Non-vendor callers
	 * maintain standard isolation and receive native NULL.
	 */
	is_vendor = dlc_ghost_is_vendor(ret_ip);
	if (!is_vendor)
		return task;

	/*
	 * Guard 2 (Root cause self-healing for vendor PID mismatches):
	 * Vendor drivers often supply host init_pid_ns TGIDs. In container
	 * child namespaces, find_task_by_vpid misses. Fall back to init_pid_ns
	 * under rcu_read_lock to retrieve the real task_struct.
	 */
	if (dlc_vendor_syms.find_task_by_pid_ns && dlc_vendor_syms.init_pid_ns) {
		struct pid_namespace *ns = task_active_pid_ns(current);
		if (ns && ns != dlc_vendor_syms.init_pid_ns) {
			rcu_read_lock();
			task = dlc_vendor_syms.find_task_by_pid_ns(vnr, dlc_vendor_syms.init_pid_ns);
			rcu_read_unlock();
			if (task)
				return task;
		}
	}

	/*
	 * Guard 3 (Airbag fallback: Ghost Task Sentinel):
	 * Task is dead or in !orig microsecond race window; hand out
	 * sentinel to avert vendor driver null dereference panic.
	 */
	task = READ_ONCE(dlc_ghost_task);
	if (!task)
		return NULL;
	if (atomic_read(&dlc_ghost_hits) < DLC_GHOST_LOG_MAX &&
	    atomic_inc_return(&dlc_ghost_hits) <= DLC_GHOST_LOG_MAX)
		pr_info("[I] [droid_lkm_vendor] ghost: pid=%d caller=%pS -> %s (orig=%s)\n",
			(int)vnr, (void *)ret_ip, DLC_GHOST_TASK_COMM,
			orig ? "miss" : "race-guard");
	return task;
}

enum {
	DLC_GHOST_F_PID,
	DLC_GHOST_F_TGID,
	DLC_GHOST_F_COMM,
	DLC_GHOST_F_USAGE,
	DLC_GHOST_F_TASKS,
	DLC_GHOST_F_CHILDREN,
	DLC_GHOST_F_SIBLING,
	DLC_GHOST_F_THREAD_NODE,
	DLC_GHOST_F_PTRACED,
	DLC_GHOST_F_PTRACE_ENTRY,
	/* the anchor writes these and counts a missing one as a failed scan,
	 * ghost itself only reads the fields above */
	DLC_GHOST_F_REAL_CRED,
	DLC_GHOST_F_CRED,
	DLC_GHOST_F_NSPROXY,
	DLC_GHOST_F_THREAD_PID,
	DLC_GHOST_F_MM,
	DLC_GHOST_F_FS,
	DLC_GHOST_F_SIGNAL,
	DLC_GHOST_F_SIGHAND,
	DLC_GHOST_F_FLAGS,
	DLC_GHOST_F_COUNT
};

static struct ds_compat_field dlc_ghost_fields[DLC_GHOST_F_COUNT] = {
	[DLC_GHOST_F_PID] = { .type = "task_struct", .member = "pid" },
	[DLC_GHOST_F_TGID] = { .type = "task_struct", .member = "tgid" },
	[DLC_GHOST_F_COMM] = { .type = "task_struct", .member = "comm" },
	[DLC_GHOST_F_USAGE] = { .type = "task_struct", .member = "usage" },
	[DLC_GHOST_F_TASKS] = { .type = "task_struct", .member = "tasks" },
	[DLC_GHOST_F_CHILDREN] = { .type = "task_struct", .member = "children" },
	[DLC_GHOST_F_SIBLING] = { .type = "task_struct", .member = "sibling" },
	[DLC_GHOST_F_THREAD_NODE] = { .type = "task_struct", .member = "thread_node" },
	[DLC_GHOST_F_PTRACED] = { .type = "task_struct", .member = "ptraced" },
	[DLC_GHOST_F_PTRACE_ENTRY] = { .type = "task_struct", .member = "ptrace_entry" },
	[DLC_GHOST_F_REAL_CRED] = { .type = "task_struct", .member = "real_cred" },
	[DLC_GHOST_F_CRED] = { .type = "task_struct", .member = "cred" },
	[DLC_GHOST_F_NSPROXY] = { .type = "task_struct", .member = "nsproxy" },
	[DLC_GHOST_F_THREAD_PID] = { .type = "task_struct", .member = "thread_pid" },
	[DLC_GHOST_F_MM] = { .type = "task_struct", .member = "mm" },
	[DLC_GHOST_F_FS] = { .type = "task_struct", .member = "fs" },
	[DLC_GHOST_F_SIGNAL] = { .type = "task_struct", .member = "signal" },
	[DLC_GHOST_F_SIGHAND] = { .type = "task_struct", .member = "sighand" },
	[DLC_GHOST_F_FLAGS] = { .type = "task_struct", .member = "flags" },
};

static struct ds_compat_type dlc_ghost_types[] = {
	{ .name = "task_struct" },
};

static struct ds_compat_layout dlc_ghost_layout_table = {
	.module = "droid_lkm_vendor",
	.fields = dlc_ghost_fields,
	.nfields = ARRAY_SIZE(dlc_ghost_fields),
	.types = dlc_ghost_types,
	.ntypes = ARRAY_SIZE(dlc_ghost_types),
};

static u32 dlc_ghost_size;

// offsets come from the running kernel BTF
// a build offset would write pid or comm into whatever the kernel keeps there
static int dlc_ghost_layout(void)
{
	if (!ds_compat_layout_init(&dlc_ghost_layout_table))
		return -ENODATA;

	dlc_ghost_size = dlc_ghost_types[0].live;
	/* the anchor backend does not size structs, the build size keeps every
	 * offset it located inside the copy */
	if (!dlc_ghost_size)
		dlc_ghost_size = sizeof(struct task_struct);
	return 0;
}

static bool dlc_ghost_field_fits(unsigned int field, u32 width, u32 alloc_sz)
{
	u8 st = dlc_ghost_fields[field].state;
	u32 off = dlc_ghost_fields[field].live;

	if (st != DS_COMPAT_OK && st != DS_COMPAT_VERIFIED &&
	    st != DS_COMPAT_ANCHORED)
		return false;
	return off <= alloc_sz && width <= alloc_sz - off;
}

static void *dlc_ghost_at(struct task_struct *ghost, unsigned int field)
{
	return (char *)ghost + dlc_ghost_fields[field].live;
}

// ghost is a shallow copy of init_task, list heads re-init to self
static int dlc_ghost_build(void)
{
	unsigned long init_task_addr = dlc_vendor_syms.init_task;
	struct task_struct *ghost;
	u32 alloc_sz, copy, i;
	int ret;

	if (!init_task_addr)
		return -ENOENT;

	ret = dlc_ghost_layout();
	if (ret) {
		pr_err("[E] [droid_lkm_vendor] ghost: no task_struct offsets for the running kernel (%d)\n",
		       ret);
		return ret;
	}

	/*
	 * OEM kernels routinely extend struct task_struct past the GKI build
	 * header size; allocate for the live size so both our field writes and
	 * vendor reads of trailing OEM fields stay in bounds
	 */
	alloc_sz = max_t(u32, sizeof(struct task_struct), dlc_ghost_size);
	if (alloc_sz > DLC_GHOST_SIZE_MAX) {
		pr_err("[E] [droid_lkm_vendor] ghost: implausible task_struct size %u\n",
		       alloc_sz);
		return -EINVAL;
	}

	if (!dlc_ghost_field_fits(DLC_GHOST_F_COMM, TASK_COMM_LEN, alloc_sz) ||
	    !dlc_ghost_field_fits(DLC_GHOST_F_PID, sizeof(pid_t), alloc_sz) ||
	    !dlc_ghost_field_fits(DLC_GHOST_F_TGID, sizeof(pid_t), alloc_sz) ||
	    !dlc_ghost_field_fits(DLC_GHOST_F_USAGE, sizeof(refcount_t), alloc_sz) ||
	    (dlc_ghost_fields[DLC_GHOST_F_TASKS].live &&
	     !dlc_ghost_field_fits(DLC_GHOST_F_TASKS, sizeof(struct list_head), alloc_sz))) {
		pr_err("[E] [droid_lkm_vendor] ghost: task_struct field offsets out of bounds (size=%u)\n",
		       alloc_sz);
		return -ERANGE;
	}

	ghost = kzalloc(alloc_sz, GFP_KERNEL);
	if (!ghost)
		return -ENOMEM;

	copy = min_t(u32, alloc_sz, dlc_ghost_size);
	memcpy(ghost, (void *)init_task_addr, copy);

	/*
	 * an empty list head in init_task points at itself, so every one of them
	 * can be repointed at this copy without knowing the member names; tasks
	 * is linked into the live task list, not self linked, and is reset below
	 */
	for (i = 0; i + 16 <= copy; i += 8) {
		unsigned long *p = (unsigned long *)((char *)ghost + i);

		if (p[0] != init_task_addr + i || p[1] != init_task_addr + i)
			continue;
		p[0] = (unsigned long)ghost + i;
		p[1] = p[0];
	}
	if (dlc_ghost_fields[DLC_GHOST_F_TASKS].live)
		INIT_LIST_HEAD(dlc_ghost_at(ghost, DLC_GHOST_F_TASKS));

	strscpy(dlc_ghost_at(ghost, DLC_GHOST_F_COMM), DLC_GHOST_TASK_COMM, TASK_COMM_LEN);
	// vendors index PID_MAX_DEFAULT sized arrays by p->pid
	// init_task.thread_pid is init_struct_pid nr 0 so the vnr helpers agree
	*(pid_t *)dlc_ghost_at(ghost, DLC_GHOST_F_PID) = 0;
	*(pid_t *)dlc_ghost_at(ghost, DLC_GHOST_F_TGID) = 0;
	refcount_set((refcount_t *)dlc_ghost_at(ghost, DLC_GHOST_F_USAGE), 0x40000000);
	WRITE_ONCE(dlc_ghost_task, ghost);
	smp_wmb();
	WRITE_ONCE(dlc_ghost_ready, true);
	return 0;
}

static void dlc_ghost_free_task(bool hooked)
{
	struct task_struct *ghost;

	WRITE_ONCE(dlc_ghost_ready, false);
	ghost = READ_ONCE(dlc_ghost_task);
	if (!ghost)
		return;
	WRITE_ONCE(dlc_ghost_task, NULL);
	if (hooked) {
		synchronize_rcu();
		if (refcount_read((refcount_t *)dlc_ghost_at(ghost, DLC_GHOST_F_USAGE)) !=
		    0x40000000) {
			pr_warn("[W] [droid_lkm_vendor] ghost: sentinel still referenced at exit, keeping allocation\n");
			return;
		}
	}
	kfree(ghost);
}

static void dlc_ghost_prewarm(void)
{
	unsigned long sym_addr;

	/*
	 * Cross-device fallback chain:
	 * Try known midas hook target symbols in descending specificity.
	 */
	sym_addr = ds_compat_sym("update_or_create_entry_locked");
	if (!sym_addr)
		sym_addr = ds_compat_sym("update_entry_locked");
	if (!sym_addr)
		sym_addr = ds_compat_sym("midas_record_task_times");

	if (sym_addr) {
		WRITE_ONCE(dlc_midas_page, sym_addr & PAGE_MASK);
		pr_info("[I] [droid_lkm_vendor] ghost: pre-warmed midas page (0x%lx)\n",
			sym_addr & PAGE_MASK);
	}
}

void dlc_ghost_exit(void)
{
	bool was_live = dlc_ftbv_hook.live;

	WRITE_ONCE(dlc_ghost_ready, false);
	if (was_live)
		ds_hook_remove(&dlc_ftbv_hook);
	WRITE_ONCE(dlc_ftbv_orig, NULL);
	dlc_ghost_free_task(was_live);
}

int dlc_ghost_init(void)
{
	int ret;

	if (!dlc_ghost_enable)
		return 0;

	ret = dlc_ghost_build();
	if (ret) {
		pr_err("[E] [droid_lkm_vendor] ghost: template build failed (%d)\n", ret);
		return ret;
	}

	dlc_ghost_prewarm();

	dlc_module_address = (typeof(dlc_module_address))dlc_vendor_syms.module_address;
	if (!dlc_module_address) {
		pr_err("[E] [droid_lkm_vendor] ghost: __module_address not found\n");
		dlc_ghost_free_task(false);
		return -ENOENT;
	}

	/*
	 * Hot-path single-instruction B hook first (safe on PAC/non-PAC; rejects
	 * LTO branch thunks and falls back cleanly to kprobe GUARD_CALLER).
	 */
	ret = ds_hook_install_guard(&dlc_ftbv_hook, "find_task_by_vpid",
				    "dlc_ftbv_wrap", HK_REDIR_GUARD_CALLER);
	if (ret) {
		pr_err("[E] [droid_lkm_vendor] ghost: hook find_task_by_vpid failed %d\n", ret);
		dlc_ghost_free_task(false);
		return ret;
	}
	smp_wmb();
	WRITE_ONCE(dlc_ftbv_orig, (typeof(dlc_ftbv_orig))dlc_ftbv_hook.orig);
	pr_info("[I] [droid_lkm_vendor] ghost: find_task_by_vpid hooked (%s), match=%s\n",
		ds_hook_route_name(dlc_ftbv_hook.route),
		dlc_ghost_match ? dlc_ghost_match : "");
	return 0;
}
