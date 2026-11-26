// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/barrier.h>
#include <asm/pgtable.h>

#include "core.h"
#include "btf.h"
#include "hint.h"
#include "ds_compat.h"
#include "hk_patch.h"
#include "type_info.h"

#define DS_COMPAT_NONGKI_SCAN_BACK	(8UL * 1024 * 1024)
#define DS_COMPAT_NONGKI_SCAN_FWD	(8UL * 1024 * 1024)

static const char *ds_compat_module = "droid_lkm";
static const char *ds_compat_own_prefix = "";

#define ds_compat_info(fmt, ...)                                               \
	pr_info("[I] [%s] " fmt, ds_compat_module, ##__VA_ARGS__)
#define ds_compat_warn(fmt, ...)                                               \
	pr_warn("[W] [%s] " fmt, ds_compat_module, ##__VA_ARGS__)

int ds_compat_init(const char *module, const char *own_prefix)
{
	if (module)
		ds_compat_module = module;
	if (own_prefix)
		ds_compat_own_prefix = own_prefix;

	find_kallsyms_base();
	if (!klnum_val || !kallrecon_klp) {
		enum kallrecon_fail reason = kallrecon_fail_reason();

		if (reason == KALLRECON_NO_OFFSETS ||
		    (reason == KALLRECON_OK && !kloffs_addr && kltable_addr)) {
			struct kallrecon_hint hint = {
				.scan_back = DS_COMPAT_NONGKI_SCAN_BACK,
				.scan_fwd = DS_COMPAT_NONGKI_SCAN_FWD,
			};

			ds_compat_warn("kallsyms default scan failed (reason=%d), suspect non-GKI kernel, widening scan window to 8MiB\n",
				       reason);
			kallrecon_supply(&hint);
			kallrecon_retry();
		}
	}
	if (!klnum_val || !kallrecon_klp) {
		ds_compat_warn("kallsyms recovery failed, nothing can be resolved\n");
		return -ENODATA;
	}

	ds_compat_info("kallsyms recovered, klnum=%u\n", klnum_val);
	return 0;
}

__nocfi noinline unsigned long ds_compat_sym(const char *name)
{
	unsigned long addr;

	if (!name || !kallrecon_klp)
		return 0;

	addr = kallrecon_klp(name);
	/*
	 * kallrecon_klp is the kernel's own kallsyms_lookup_name. a kernel that
	 * hides an address from it, _text being the image base, still has the
	 * symbol in its table, so the library's own walk answers that case
	 */
	if (!addr)
		addr = kallsyms_name_to_addr(name);
	/*
	 * the shims in a module are defined under the kernel's own names, and the
	 * lookup searches the module tables too, so a kernel that does not carry the
	 * name hands back the shim instead. that is not the kernel symbol: a shim
	 * whose body calls the resolved pointer calls itself. a wrapper carries the
	 * module prefix and is the one kind of symbol that is expected here
	 */
	if (addr && within_module(addr, THIS_MODULE) && ds_compat_own_prefix[0] &&
	    strncmp(name, ds_compat_own_prefix, strlen(ds_compat_own_prefix)))
		return 0;
	return addr;
}

int ds_compat_bind(const struct ds_compat_sym *tab, unsigned int count)
{
	unsigned int i, missing = 0;

	for (i = 0; i < count; i++) {
		unsigned long addr = ds_compat_sym(tab[i].name);

		*tab[i].slot = (void *)addr;
		if (!addr)
			missing++;
	}
	if (!missing)
		return 0;

	/*
	 * a name the kernel does not carry is the only way an entry stays empty,
	 * the features that need one stay off and the names are what says which
	 */
	ds_compat_info("%u/%u kernel symbols absent:", missing, count);
	for (i = 0; i < count; i++) {
		if (!*tab[i].slot)
			pr_cont(" %s", tab[i].name);
	}
	pr_cont("\n");
	return missing;
}

static typeof(&vmap) ds_compat_vmap_fn;
static typeof(&vunmap) ds_compat_vunmap_fn;
static long (*ds_compat_nofault_write_fn)(void *dst, const void *src,
					  size_t size);
static bool ds_compat_rodata_probed;

static void ds_compat_rodata_resolve(void)
{
	if (ds_compat_rodata_probed)
		return;
	ds_compat_vmap_fn = (typeof(&vmap))ds_compat_sym("vmap");
	ds_compat_vunmap_fn = (typeof(&vunmap))ds_compat_sym("vunmap");
	ds_compat_nofault_write_fn =
		(typeof(ds_compat_nofault_write_fn))ds_compat_sym(
			"copy_to_kernel_nofault");
	ds_compat_rodata_probed = true;
}

static __nocfi noinline void *ds_compat_call_vmap(struct page **pages,
						  unsigned int count,
						  unsigned long flags,
						  pgprot_t prot)
{
	if (!ds_compat_vmap_fn)
		return NULL;
	return ds_compat_vmap_fn(pages, count, flags, prot);
}

static __nocfi noinline void ds_compat_call_vunmap(const void *addr)
{
	if (ds_compat_vunmap_fn && addr)
		ds_compat_vunmap_fn(addr);
}

static __nocfi noinline long ds_compat_call_nofault_write(void *dst,
							  const void *src,
							  size_t size)
{
	if (!ds_compat_nofault_write_fn)
		return -EOPNOTSUPP;
	return ds_compat_nofault_write_fn(dst, src, size);
}

int ds_compat_rodata_map(void *dst, size_t len, struct ds_compat_rodata_map *m)
{
	unsigned long va, pa, pfn, off;
	struct page *page;
	void *base;

	if (!dst || !m || !len || len > PAGE_SIZE)
		return -EINVAL;
	memset(m, 0, sizeof(*m));

	va = (unsigned long)dst;
	off = va & ~PAGE_MASK;
	if (off + len > PAGE_SIZE)
		return -EINVAL;

	pa = hk_va_walk_pa(va);
	if (!pa)
		pa = hk_va_to_pa(va);
	if (!pa)
		return -ENOENT;
	pfn = pa >> PAGE_SHIFT;

	if (hk_va_writable(va)) {
		m->writable = dst;
		m->pfn = pfn;
		m->owned = false;
		return 0;
	}

	if (!pfn_valid(pfn))
		return -EFAULT;

	ds_compat_rodata_resolve();
	if (!ds_compat_vmap_fn || !ds_compat_vunmap_fn)
		return -ENOENT;

	page = pfn_to_page(pfn);
	base = ds_compat_call_vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!base)
		return -ENOMEM;

	m->vmap_base = base;
	m->writable = (char *)base + off;
	m->pfn = pfn;
	m->owned = true;
	return 0;
}

void ds_compat_rodata_unmap(struct ds_compat_rodata_map *m)
{
	if (!m)
		return;
	if (m->owned && m->vmap_base)
		ds_compat_call_vunmap(m->vmap_base);
	memset(m, 0, sizeof(*m));
}

int ds_compat_write(void *dst, unsigned long val)
{
	/*
	 * Private vmap writable alias first: avoids racing the kernel's
	 * FIX_TEXT_POKE0 slot (which is serialized by unexported patch_lock)
	 * and performs a single 64-bit atomic store on aligned pointers.
	 * Falls back to HooKern's private FIX_BTMAP_END library slot.
	 */
	struct hk_write w = {
		.slot = HK_SLOT_LIBRARY,
		.nofault = true,
		.verify = true,
	};

	if (!dst)
		return -EINVAL;

	if (IS_ALIGNED((unsigned long)dst, sizeof(val))) {
		struct ds_compat_rodata_map m;
		int ret;

		ret = ds_compat_rodata_map(dst, sizeof(val), &m);
		if (!ret) {
			long wret;

			ds_compat_rodata_resolve();
			if (ds_compat_nofault_write_fn)
				wret = ds_compat_call_nofault_write(
					m.writable, &val, sizeof(val));
			else {
				WRITE_ONCE(*(unsigned long *)m.writable, val);
				wret = 0;
			}
			dsb(ish);
			if (!wret && READ_ONCE(*(unsigned long *)dst) == val) {
				ds_compat_rodata_unmap(&m);
				return 0;
			}
			ds_compat_rodata_unmap(&m);
		}
	}

	return hk_write_run(dst, &val, sizeof(val), &w);
}

const char *ds_compat_state_name(u8 state)
{
	switch (state) {
	case DS_COMPAT_OK:
		return "ok";
	case DS_COMPAT_NO_TYPE:
		return "no-type";
	case DS_COMPAT_NO_MEMBER:
		return "no-member";
	case DS_COMPAT_DIFFERS:
		return "differs";
	case DS_COMPAT_UNVERIFIED:
		return "unverified";
	case DS_COMPAT_ANCHORED:
		return "anchored";
	case DS_COMPAT_VERIFIED:
		return "verified";
	case DS_COMPAT_MANUAL:
		return "manual";
	case DS_COMPAT_BUILD:
		return "build";
	default:
		return "?";
	}
}

/*
 * one place answers whether an offset may be dereferenced. DS_COMPAT_BUILD counts
 * only when the build was asked to fall back: an offset never checked against the
 * running kernel is a guess
 */
bool ds_compat_layout_verified(u8 state)
{
	if (state == DS_COMPAT_OK || state == DS_COMPAT_VERIFIED ||
	    state == DS_COMPAT_ANCHORED)
		return true;
#ifdef DROID_LKM_LAYOUT_MANUAL
	if (state == DS_COMPAT_MANUAL)
		return true;
#endif
#if defined(DROID_LKM_LAYOUT_FALLBACK) || defined(DROID_LKM_LAYOUT_FORCE_BUILD)
	return state == DS_COMPAT_BUILD;
#else
	return false;
#endif
}

/* the layout engine reads BTF through the type info reader */
static void ds_compat_layout_unverified(struct ds_compat_layout *l)
{
	unsigned int i;

	for (i = 0; i < l->nfields; i++) {
		l->fields[i].live = 0;
		l->fields[i].state = DS_COMPAT_UNVERIFIED;
	}
	for (i = 0; i < l->ntypes; i++) {
		l->types[i].live = 0;
		l->types[i].state = DS_COMPAT_UNVERIFIED;
	}
}

bool ds_compat_layout_init(struct ds_compat_layout *l)
{
	struct ti_resolver res = { .name_to_addr = ds_compat_sym };
	unsigned int ok = 0, missing = 0, differ = 0;
	unsigned int i;

	if (!l || !l->fields || !l->types)
		return false;

	ds_compat_layout_unverified(l);

	if (!ti_ready() && ti_init(&res)) {
		ds_compat_warn("layout: type info refused to start, every offset is refused\n");
		return false;
	}
	if (!ti_btf_available())
		return ds_compat_layout_anchor(l);

	for (i = 0; i < l->nfields; i++) {
		struct ds_compat_field *f = &l->fields[i];
		u32 type_id, member_type, bit_off, bit_sz;

		if (ti_type_by_name(ti_base(), f->type, BIT(BTF_KIND_STRUCT),
				    &type_id)) {
			f->state = DS_COMPAT_NO_TYPE;
			missing++;
			continue;
		}
		if (ti_member_info(ti_base(), type_id, f->member, &member_type,
				   &bit_off, &bit_sz)) {
			f->state = DS_COMPAT_NO_MEMBER;
			missing++;
			continue;
		}

		f->live = bit_off / 8;
		/*
		 * a bitfield is the only width btf carries, everything else
		 * comes from the member's type through its typedefs
		 */
		if (!bit_sz && !ti_follow(ti_base(), member_type, &member_type))
			f->live_size = ti_type_size(ti_base(), member_type);
		else
			f->live_size = bit_sz / 8;
		f->state = DS_COMPAT_OK;
		if (f->build_size && f->live_size != f->build_size) {
			f->state = DS_COMPAT_DIFFERS;
			differ++;
		}
		ok++;
	}

	for (i = 0; i < l->ntypes; i++) {
		struct ds_compat_type *t = &l->types[i];
		u32 type_id;

		if (ti_type_by_name(ti_base(), t->name, BIT(BTF_KIND_STRUCT),
				    &type_id)) {
			t->state = DS_COMPAT_NO_TYPE;
			missing++;
			continue;
		}
		t->live = ti_type_size(ti_base(), type_id);
		if (!t->live) {
			t->state = DS_COMPAT_NO_TYPE;
			missing++;
			continue;
		}
		t->state = DS_COMPAT_OK;
	}

	ds_compat_info("layout: BTF %u/%u fields live, %u not in BTF, %u differ\n",
		       ok, l->nfields, missing, differ);

	for (i = 0; i < l->nfields; i++) {
		struct ds_compat_field *f = &l->fields[i];

		if (f->state == DS_COMPAT_DIFFERS)
			ds_compat_warn("%s.%s width %u, this build uses %u\n",
				       f->type, f->member, f->live_size,
				       f->build_size);
	}

	return !missing;
}

void ds_compat_layout_exit(void)
{
	ti_exit();
}

void ds_compat_layout_fallback(struct ds_compat_layout *l)
{
	unsigned int i;

	if (!l)
		return;

	for (i = 0; i < l->nfields; i++) {
		struct ds_compat_field *f = &l->fields[i];

		if (f->state == DS_COMPAT_OK || f->state == DS_COMPAT_VERIFIED ||
		    f->state == DS_COMPAT_ANCHORED || f->state == DS_COMPAT_BUILD)
			continue;
		f->live = f->build;
		f->live_size = f->build_size;
		f->state = DS_COMPAT_BUILD;
		ds_compat_warn("layout fallback: %s.%s uses build %u\n",
			       f->type, f->member, f->build);
	}
	for (i = 0; i < l->ntypes; i++) {
		struct ds_compat_type *t = &l->types[i];

		if (t->state == DS_COMPAT_OK || t->state == DS_COMPAT_VERIFIED ||
		    t->state == DS_COMPAT_ANCHORED || t->state == DS_COMPAT_BUILD)
			continue;
		t->live = t->build;
		t->state = DS_COMPAT_BUILD;
		ds_compat_warn("layout fallback: sizeof(%s) uses build %u\n",
			       t->name, t->build);
	}
}

void ds_compat_layout_force_build(struct ds_compat_layout *l)
{
	unsigned int i;

	if (!l)
		return;

	for (i = 0; i < l->nfields; i++) {
		l->fields[i].live = l->fields[i].build;
		l->fields[i].live_size = l->fields[i].build_size;
		l->fields[i].state = DS_COMPAT_BUILD;
	}
	for (i = 0; i < l->ntypes; i++) {
		l->types[i].live = l->types[i].build;
		l->types[i].state = DS_COMPAT_BUILD;
	}
	ds_compat_warn("layout: forced to the build offsets for every field\n");
}

void ds_compat_layout_report(struct ds_compat_layout *l)
{
	unsigned int btf = 0, anchor = 0, manual = 0, build = 0, i;

	if (!l)
		return;

	for (i = 0; i < l->nfields; i++) {
		if (l->fields[i].state == DS_COMPAT_OK)
			btf++;
		else if (l->fields[i].state == DS_COMPAT_ANCHORED ||
			 l->fields[i].state == DS_COMPAT_VERIFIED)
			anchor++;
		else if (l->fields[i].state == DS_COMPAT_MANUAL)
			manual++;
		else if (l->fields[i].state == DS_COMPAT_BUILD)
			build++;
	}

	for (i = 0; i < l->ntypes; i++) {
		if (l->types[i].state == DS_COMPAT_DIFFERS)
			ds_compat_warn("sizeof(struct %s) is %u in the running kernel, this build uses %u\n",
				       l->types[i].name, l->types[i].live,
				       l->types[i].build);
	}

	ds_compat_info("layout: %u/%u offsets verified (%u btf, %u anchor, %u manual, %u build)\n",
		       btf + anchor + manual + build, l->nfields, btf, anchor,
		       manual, build);

	for (i = 0; i < l->nfields; i++) {
		const struct ds_compat_field *f = &l->fields[i];

		ds_compat_info("layout: %s.%s %s live=%u build=%u\n",
			       f->type, f->member,
			       ds_compat_state_name(f->state),
			       f->live, f->build);
	}
	for (i = 0; i < l->ntypes; i++) {
		const struct ds_compat_type *t = &l->types[i];

		ds_compat_info("layout: sizeof(%s) %s live=%u build=%u\n",
			       t->name, ds_compat_state_name(t->state),
			       t->live, t->build);
	}
}
