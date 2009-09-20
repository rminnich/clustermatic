/*-------------------------------------------------------------------------
 *  vmadump.c:  Virtual Memory Area dump/restore routines
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: vmadump_common.c,v 1.15 2004/10/27 15:49:38 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/sched.h>

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/binfmts.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/personality.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>	/* for mprotect, etc. */
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>

#define __VMADUMP_INTERNAL__
#include "vmadump.h"

static char vmad_magic[3] = VMAD_MAGIC;

MODULE_AUTHOR("Erik Hendriks <erik@hendriks.cx>");
MODULE_DESCRIPTION("VMADump - Virtual Memory Area Dumper");
MODULE_LICENSE("GPL");

/* A note about symbols...
 *
 * This module requires the following extra symbols from the kernel:
 *
 * sys_mprotect
 * do_exit
 * do_sigaction
 */

/*--------------------------------------------------------------------
 *  Some utility stuff for reading and writing and misc kernel syscalls.
 *------------------------------------------------------------------*/
static
ssize_t default_read_file(struct vmadump_map_ctx *ctx, struct file *file,
			  void *buf, size_t count) {
    return vfs_read(file, buf, count, &file->f_pos);
}

static
ssize_t read_user(struct vmadump_map_ctx *ctx,
		  struct file *file, void *buf, size_t count) {
    ssize_t r, bytes = count;
    ssize_t (*rfunc)(struct vmadump_map_ctx *ctx, struct file *file,
		     void *buf, size_t count);
    rfunc = (ctx && ctx->read_file) ? ctx->read_file : default_read_file;
    while (bytes) {
	r = rfunc(ctx, file, buf, bytes);
	if (r < 0)  return r;
	if (r == 0) return count - bytes;
	bytes -= r; buf += r;
    }
    return count;
}

ssize_t read_kern(struct vmadump_map_ctx *ctx,
		  struct file *file, void *buf, size_t count) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = read_user(ctx, file, buf, count);
    set_fs(oldfs);
    return err;
}

static
ssize_t default_write_file(struct vmadump_map_ctx *ctx, struct file *file,
			   const void *buf, size_t count) {
    return vfs_write(file, buf, count, &file->f_pos);
}

static
ssize_t write_user(struct vmadump_map_ctx *ctx, struct file *file,
		   const void *buf, size_t count) {
    ssize_t w, bytes = count;
    ssize_t (*wfunc)(struct vmadump_map_ctx *ctx, struct file *file,
		     const void *buf, size_t count);
    wfunc = (ctx && ctx->write_file) ? ctx->write_file : default_write_file;
    while (bytes) {
	w = wfunc(ctx, file, buf, bytes);
	if (w < 0)  return w;
	if (w == 0) return count - bytes;
	bytes -= w; buf += w;
    }
    return count;
}

ssize_t write_kern(struct vmadump_map_ctx *ctx, struct file *file,
		   const void *buf, size_t count) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = write_user(ctx, file, buf, count);
    set_fs(oldfs);
    return err;
}

/*--------------------------------------------------------------------
 *  Library list stuff.
 *------------------------------------------------------------------*/
/* XXX This should be more configurable than this - this is idea of
 *     figuring out what's a library  */
struct liblist_entry {
    struct list_head list;
    char libname[0];
};

static LIST_HEAD(liblist);

static
void liblist_clear(void) {
    struct liblist_entry *entry;
    while (!list_empty(&liblist)) {
	entry = list_entry(liblist.next, struct liblist_entry, list);
	list_del(liblist.next);
	kfree(entry);
    }
}

static
struct liblist_entry *
liblist_find(const char *filename) {
    struct list_head *p;
    struct liblist_entry *entry;
    p = liblist.next;
    while (p != &liblist) {
	entry = list_entry(p, struct liblist_entry, list);
	if (strcmp(entry->libname, filename) == 0)
	    return entry;
	p = p->next;
    }
    return 0;
}

static
int liblist_add(char *filename) {
    struct liblist_entry *entry;

    /* Don't add things twice */
    if (liblist_find(filename)) return 0;

    entry = kmalloc(sizeof(*entry)+strlen(filename)+1, GFP_KERNEL);
    if (!entry) return -ENOMEM;
    strcpy(entry->libname, filename);
    list_add(&entry->list, &liblist);
    return 0;
}

static
int liblist_del(char *filename) {
    struct liblist_entry *entry;
    entry = liblist_find(filename);
    if (entry) {
	list_del(&entry->list);
	kfree(entry);
	return 0;
    }
    return -ENOENT;
}

/* Returns the size of our library list converted to text */
static
int liblist_size(void) {
    int len;
    struct list_head *p;
    struct liblist_entry *entry;

    len = 0;
    p = liblist.next;
    while (p != &liblist) {
	entry = list_entry(p, struct liblist_entry, list);
	len += strlen(entry->libname)+1;
	p = p->next;
    }
    len++;			/* for trailing null. */
    return len;
}

static
int do_lib_op(int request, char *buf, int size) {
    int err, len;
    char *filename;
    struct list_head *p;
    struct liblist_entry *entry;

    switch(request) {
    case VMAD_LIB_CLEAR:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	liblist_clear();
	return 0;

    case VMAD_LIB_ADD:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	filename = getname(buf);
	if (IS_ERR(filename)) return PTR_ERR(filename);
	err = liblist_add(filename);
	putname(filename);
	return err;

    case VMAD_LIB_DEL:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	filename = getname(buf);
	if (IS_ERR(filename)) return PTR_ERR(filename);
	err = liblist_del(filename);
	putname(filename);
	return err;

    case VMAD_LIB_SIZE:
	return liblist_size();

    case VMAD_LIB_LIST:
	len = liblist_size();
	if (len > size) return -ENOSPC;
	size = len;
	/* Copy all those strings out to user space. */
	p = liblist.next;
	while (p != &liblist) {
	    entry = list_entry(p, struct liblist_entry, list);
	    len = strlen(entry->libname);
	    if (copy_to_user(buf, entry->libname, len)) return EFAULT;
	    buf += len;
	    put_user('\0', buf++);
	    p = p->next;
	}
	put_user('\0', buf);
	return size;

    default:
	return -EINVAL;
    }
}

static
char *default_map_name(struct file *f, char *buffer, int size) {
    return d_path(f->f_dentry, f->f_vfsmnt, buffer, PAGE_SIZE);
}


/* this is gonna be handled with contexts too */
static
int is_library(const char *filename) {
    return (liblist_find(filename) != 0);
}


static
struct file *default_map_open(const char *filename) {
    struct file *file;
    mm_segment_t user_fs;
    user_fs = get_fs(); set_fs(KERNEL_DS);
    file = filp_open(filename,O_RDONLY,0);
    set_fs(user_fs);
    return file;
}

/*--------------------------------------------------------------------
 *  Dump hook stuff.
 *------------------------------------------------------------------*/
struct hook_t {
    struct list_head list;
    struct vmadump_hook *hook;
};
struct vmadump_hook_handle {
    int rw;			/* for checking on the user */
    struct vmadump_map_ctx *ctx;
    struct file *file;
};

static struct rw_semaphore hook_lock;
static LIST_HEAD(hooks);

int vmadump_add_hook(struct vmadump_hook *hook) {
    struct hook_t *h, *new_h;
    struct list_head *l;

    new_h = kmalloc(sizeof(*new_h), GFP_KERNEL);
    new_h->hook = hook;

    down_write(&hook_lock);
    /* check to make sure that this hook isn't being added twice */
    for (l = hooks.next; l != &hooks; l = l->next) {
	h = list_entry(l, struct hook_t, list);
	if (h->hook == hook) {
	    up_write(&hook_lock);
	    kfree(new_h);
	    return -EEXIST;
	}
    }
    list_add_tail(&new_h->list, &hooks);
    up_write(&hook_lock);
    printk(KERN_INFO "vmadump: Registered hook \"%s\"\n", hook->tag);
    return 0;
}

int vmadump_del_hook(struct vmadump_hook *hook) {
    struct hook_t *h;
    struct list_head *l;

    down_write(&hook_lock);
    for (l = hooks.next; l != &hooks; l = l->next) {
	h = list_entry(l, struct hook_t, list);

	if (h->hook == hook) {
	    list_del(&h->list);
	    up_write(&hook_lock);
	    printk(KERN_INFO "vmadump: Unregistered hook \"%s\"\n", hook->tag);
	    kfree(h);
	    return 0;
	}
    }
    up_write(&hook_lock);
    return -ENOENT;
}

struct vmadump_callback_handle {
    int rw;
    struct vmadump_map_ctx *ctx;
    struct file *file;
};

/* Call every hook freeze function */
static
int do_freeze_hooks(struct vmadump_map_ctx *ctx, struct file *file,
		    struct pt_regs *regs, int flags) {
    long bytes = 0, r;
    struct hook_t *h;
    struct list_head *l;
    struct vmadump_hook_header hookhdr;
    struct vmadump_hook_handle hh = { 1, ctx, file};

    down_read(&hook_lock);
    for (l = hooks.next; l != &hooks; l = l->next) {
	h = list_entry(l, struct hook_t, list);
	r = h->hook->freeze(&hh, regs, flags);
	if (r < 0) {
	    up_read(&hook_lock);
	    return r;
	}
	bytes += r;
    }
    up_read(&hook_lock);

    /* Terminate the list of hooks */
    memset(&hookhdr, 0, sizeof(hookhdr));
    r = write_kern(ctx, file, &hookhdr, sizeof(hookhdr));
    if (r < 0) return r;
    if (r != sizeof(hookhdr)) return -EIO;
    bytes += r;

    return bytes;
}

static
long skip_data(struct vmadump_map_ctx *ctx, struct file *file, long len) {
    long r = 0;
    void *page;
    page = (void *) __get_free_page(GFP_KERNEL);
    if (!page)
	return -ENOMEM;

    while (len > 0) {
	r = read_kern(ctx, file, page, (len>PAGE_SIZE) ? PAGE_SIZE : len);
	if (r <= 0) break;
	len -= r;
    }
    free_page((long) page);

    if (r == 0) r = -EIO;	/* end of file.... */
    return 0;
}

static
int do_thaw_hooks(struct vmadump_map_ctx *ctx, struct file *file,
		  struct pt_regs *regs) {
    long r;
    struct hook_t *h;
    struct list_head *l;
    struct vmadump_hook_header hookhdr;
    struct vmadump_hook_handle hh = { 0, ctx, file};

    r = read_kern(ctx, file, &hookhdr, sizeof(hookhdr));
    if (r != sizeof(hookhdr)) goto err;
    while (hookhdr.tag[0]) {
	/* Do a bit of sanity checking on this dump header */
	hookhdr.tag[VMAD_HOOK_TAG_LEN-1] = 0; /* null terminate that string... */
	if (hookhdr.size <= 0) {
	    r = -EINVAL;
	    goto err;
	}

	/* See if we find a matching hook */
	down_read(&hook_lock);
	for (l = hooks.next; l != &hooks; l = l->next) {
	    h = list_entry(l, struct hook_t, list);
	    if (strcmp(hookhdr.tag, h->hook->tag) == 0) {
		r = h->hook->thaw(&hh, &hookhdr, regs);
		break;
	    }
	}
	if (l == &hooks)
	    r = skip_data(ctx, file, hookhdr.size);
	up_read(&hook_lock);
	if (r) goto err;

	r = read_kern(ctx, file, &hookhdr, sizeof(hookhdr));
	if (r != sizeof(hookhdr)) goto err;
    }
    return 0;

 err:
    if (r >= 0) r = -EIO;
    return r;
}

/* read/write calls for use by hooks */
ssize_t vmadump_read_u(struct vmadump_hook_handle *h, void *buf, size_t count){
    if (h->rw != 0) return -EINVAL;
    return read_user(h->ctx, h->file, buf, count);
}

ssize_t vmadump_read_k(struct vmadump_hook_handle *h, void *buf, size_t count){
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = vmadump_read_u(h, buf, count);
    set_fs(oldfs);
    return err;

}

ssize_t vmadump_write_u(struct vmadump_hook_handle *h,
			const void *buf, size_t count) {
    if (h->rw != 1) return -EINVAL;
    return write_user(h->ctx, h->file, buf, count);
}

ssize_t vmadump_write_k(struct vmadump_hook_handle *h,
			const void *buf, size_t count) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = vmadump_write_u(h, buf, count);
    set_fs(oldfs);
    return err;
}


/*--------------------------------------------------------------------
 *  Process "thawing" routines.
 *------------------------------------------------------------------*/
static
int mmap_file(struct vmadump_map_ctx *ctx,
	      struct vmadump_vma_header *head, char *filename,
	      unsigned long prot, unsigned long flags) {
    struct file *file;
    long mapaddr;

    /* This is a lot like open w/o a file descriptor */
    if (ctx && ctx->map_open)
	file = ctx->map_open(ctx, filename);
    else
	file = default_map_open(filename);
    if (IS_ERR(file))
	return PTR_ERR(file);

    down_write(&current->mm->mmap_sem);
    mapaddr = do_mmap(file, head->start, head->end - head->start,
		     prot, flags | MAP_FIXED, head->offset);
    up_write(&current->mm->mmap_sem);
    fput(file);
    if (mapaddr != head->start)
	printk("do_mmap(<file>, %p, %p, ...) failed: %p\n",
	       (void *) head->start, (void *) head->end-head->start,
	       (void *) mapaddr);
    return (mapaddr == head->start) ? 0 : mapaddr;
}

static
int load_map(struct vmadump_map_ctx *ctx,
	     struct file *file, struct vmadump_vma_header *head) {
    int r;
    unsigned long mmap_prot, mmap_flags, addr;
    struct vmadump_page_header page;

    mmap_prot  = 0;
    mmap_flags = MAP_FIXED|MAP_PRIVATE;
    if (head->flags & VM_READ)  mmap_prot |= PROT_READ;
    if (head->flags & VM_WRITE) mmap_prot |= PROT_WRITE;
    if (head->flags & VM_EXEC)  mmap_prot |= PROT_EXEC;
    if (head->flags & VM_GROWSDOWN) mmap_flags |= MAP_GROWSDOWN;
    if (head->flags & VM_EXECUTABLE) mmap_flags |= MAP_EXECUTABLE;
    if (head->flags & VM_DENYWRITE) mmap_flags |= MAP_DENYWRITE;

    if (head->namelen) {
	char *filename;
	if (head->namelen > PAGE_SIZE) {
	    printk("vmadump: thaw: bogus namelen %d\n", (int) head->namelen);
	    return -EINVAL;
	}
	filename = kmalloc(head->namelen+1,GFP_KERNEL);
	if (!filename) {
	    r = -ENOMEM;
	    goto err;
	}
	r = read_kern(ctx, file, filename, head->namelen);
	if (r != head->namelen) {
	    kfree(filename);
	    goto err;
	}
	filename[head->namelen] = 0;

	r = mmap_file(ctx, head, filename,
		      PROT_READ|PROT_WRITE|PROT_EXEC, mmap_flags);
	if (r) {
	    printk("vmadump: mmap failed: %s\n", filename);
	    kfree(filename);
	    return r;
	}
	kfree(filename);
    } else {
	/* Load the data from the dump file */
	down_write(&current->mm->mmap_sem);
	addr = do_mmap(0, head->start, head->end - head->start,
		       PROT_READ|PROT_WRITE|PROT_EXEC, mmap_flags, 0);
	up_write(&current->mm->mmap_sem);
	if (addr != head->start) {
	    printk("do_mmap(0, %08lx, %08lx, ...) = 0x%08lx (failed)\n",
		   head->start, head->end - head->start, addr);
	    return -EINVAL;
	}
    }

    /* Read in patched pages */
    r = read_kern(ctx, file, &page, sizeof(page));
    while (r == sizeof(page) && page.start != ~0UL) {
	r = read_user(ctx, file, (void *) page.start, PAGE_SIZE);
	if (r != PAGE_SIZE) goto err;
	if (mmap_prot & PROT_EXEC)
	    flush_icache_range(page.start, page.start + PAGE_SIZE);
	r = read_kern(ctx, file, &page, sizeof(page));
    }
    if (r != sizeof(page)) goto err;

    if (sys_mprotect(head->start,head->end - head->start, mmap_prot))
	printk("vmadump: thaw: mprotect failed. (ignoring)\n");
    return 0;

 err:
    if (r >= 0) r = -EIO;	/* map short reads to EIO */
    return r;
}

long vmadump_thaw_proc(struct vmadump_map_ctx *ctx,
		       struct file *file, struct pt_regs *regs) {
    int r;

    {
    struct vmadump_header header;

    /*--- First some sanity checking ---*/
    r = read_kern(ctx, file, &header, sizeof(header));
    if (r != sizeof(header)) {
	/*printk("vmadump: failed to read header: %d\n", r);*/
	return -EINVAL;
    }
    if (memcmp(header.magic, vmad_magic, sizeof(header.magic))) {
	/*printk("vmadump: invalid signature\n");*/
	return -EINVAL;
    }
    if (header.fmt_vers != VMAD_FMT_VERS) {
	printk(KERN_DEBUG "vmadump: dump version mistmatch. dump=%d; "
	       "kernel=%d\n", (int)header.fmt_vers, (int)VMAD_FMT_VERS);
	return -EINVAL;
    }
    if (header.arch != VMAD_ARCH) {
	printk(KERN_DEBUG "vmadump: architecture mismatch.\n");
	return -EINVAL;
    }

    if (header.major != ((LINUX_VERSION_CODE >> 16) & 0xFF) ||
	header.minor != ((LINUX_VERSION_CODE >> 8) & 0xFF)
#if STRICT_VERSION_CHECK
	||header.patch != (LINUX_VERSION_CODE & 0xFF)
#endif
	) {
	printk(KERN_DEBUG "vmadump: kernel version mismatch.\n");
	return -EINVAL;
    }
    }

    /* Ummm... Point of no-return is here.... maybe try to move this
     * down a bit? */

    /* Read our new comm */
    r = read_kern(ctx, file, current->comm, sizeof(current->comm));
    if (r != sizeof(current->comm)) goto bad_read;
    /*
     * CPU-specific register restore stuff
     *
     * Note that we're not presuming that our current regs pointer
     * points to anything even vaguely reasonable.  This is done to
     * support bproc type kernel threads that have never been user
     * processes before.
     */
    r = vmadump_restore_cpu(ctx, file, regs);
    if (r) goto bad_read;

    /*--- Signal information ---------------------------------------*/
    {
    int i;
    sigset_t             sig_blocked;
    struct k_sigaction   sig_action;

    /* Install set of blocked signals */
    r = read_kern(ctx, file, &sig_blocked, sizeof(sig_blocked));
    if (r != sizeof(sig_blocked)) goto bad_read;

    sigdelsetmask(&sig_blocked, sigmask(SIGKILL)|sigmask(SIGSTOP));
    spin_lock_irq(&current->sighand->siglock);
    memcpy(&current->blocked, &sig_blocked, sizeof(sig_blocked));
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);

    for (i=0; i < _NSIG; i++) {
	r = read_kern(ctx, file, &sig_action, sizeof(sig_action));
	if (r != sizeof(sig_action)) goto bad_read;

	if (i != SIGKILL-1 && i != SIGSTOP-1) {
	    r = do_sigaction(i+1, &sig_action, 0);
	    if (r) goto bad_read;
	}
    }
    }

    /*--- Misc other stuff -----------------------------------------*/
    {				/* our tid ptr */
    r = read_kern(ctx, file, &current->clear_child_tid,
		  sizeof(current->clear_child_tid));
    if (r != sizeof(current->clear_child_tid)) { goto bad_read; }
    }

    /*--- Memory map meta data -------------------------------------*/
    {
    struct mm_struct *mm;
    struct vm_area_struct *map;
    struct vmadump_mm_info mm_info;
    struct vmadump_vma_header mapheader;

    mm = current->mm;

    r = read_kern(ctx, file, &mm_info, sizeof(mm_info));
    if (r != sizeof(mm_info)) { goto bad_read; }

    /* Purge current maps - I'm sure there's a way to keep theses around
     * incase creation of the new ones fails in some unfortunate way... */
    while(mm->mmap) {
	map = mm->mmap;
	r = do_munmap(mm, map->vm_start, map->vm_end - map->vm_start);
	if (r) {
	    printk("do_munmap(%lu, %lu) = %d\n",
		   map->vm_start, map->vm_end-map->vm_start,r);
	}
    }

    /* Load new map data */
    r = read_kern(ctx, file, &mapheader, sizeof(mapheader));
    while (r == sizeof(mapheader) &&
	   (mapheader.start != ~0 || mapheader.end != ~0)) {
	if ((r = load_map(ctx, file, &mapheader))) goto bad_read;
	r = read_kern(ctx, file, &mapheader, sizeof(mapheader));
    }
    if (r != sizeof(mapheader)) goto bad_read;

    down_write(&current->mm->mmap_sem);
    mm->start_code = mm_info.start_code;
    mm->end_code   = mm_info.end_code;
    mm->start_data = mm_info.start_data;
    mm->end_data   = mm_info.end_data;
    mm->start_brk  = mm_info.start_brk;
    mm->brk        = mm_info.brk;
    mm->start_stack= mm_info.start_stack;
    /* FIX ME: validate these pointers */
    mm->arg_start  = mm_info.arg_start;
    mm->arg_end    = mm_info.arg_end;
    mm->env_start  = mm_info.env_start;
    mm->env_end    = mm_info.env_end;
    up_write(&current->mm->mmap_sem);
    }

    /*--- Call external thaw hooks ---------------------------------*/
    r = do_thaw_hooks(ctx, file, regs);
    if (r) goto bad_read;
    return 0;

 bad_read:
    if (r >= 0) r = -EIO;
    return r;
}

/*--------------------------------------------------------------------
 *  Process "freezing" routines
 *------------------------------------------------------------------*/
/* This routine checks if a page from a filemap has been copied via
 * copy on write.  Basically, this is just checking to see if the page
 * is still a member of the map or not.  Note this this should not end
 * up copying random things from VM_IO regions. */
static
int addr_copied(struct mm_struct *mm, unsigned long addr) {
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    struct page *pg;
    int ret;

    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd)) { ret = 0; goto out; }
    pmd = pmd_offset(pgd, addr);
    if (pmd_none(*pmd)) { ret = 0; goto out; }
    pte = pte_offset_map(pmd, addr);
    if (pte_present(*pte)) {
	pg  = pte_page(*pte);
	/*ret = test_bit(PG_anon, &pg->flags);*/
	ret = PageAnon(pg);
    } else
	/* pte_none is false for a swapped (written) page */
	ret = !pte_none(*pte);
    pte_unmap(pte);
 out:
    spin_unlock(&mm->page_table_lock);
    return ret;
}

/* This is the version for working on a region that is a file map.  In
 * this case we need to fault the page in to check for zero.  This
 * isn't a big deal since we'll be faulting in for sending anyway if
 * it's not.  */
static
int addr_nonzero_file(struct mm_struct *mm, unsigned long addr) {
    int i;
    unsigned long val = 0;

    /* Simple zero check */
    for (i=0; i < (PAGE_SIZE/sizeof(long)); i++) {
	/* We ignore EFAULT and presume that it's zero here */
	get_user(val, (((long*)addr)+i));
	if (val) return 1;
    }
    return 0;
}

/* This version is for use on regions which are *NOT* file maps.  Here
 * we look at the page tables to see if a page is zero.  If it's never
 * been faulted in, we know it's zero - and we don't fault it in while
 * checking for this. */
static
int addr_nonzero(struct mm_struct *mm, unsigned long addr) {
    int i;
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long val;

    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd)) goto out_zero;
    pmd = pmd_offset(pgd, addr);
    if (pmd_none(*pmd)) goto out_zero;
    pte = pte_offset_map(pmd, addr);
    if (pte_none(*pte)) {
	pte_unmap(pte);
	goto out_zero;
    }
    pte_unmap(pte);
    spin_unlock(&mm->page_table_lock);

    /* Ok, the page could be non-zero - check it... */
    for (i=0; i < (PAGE_SIZE/sizeof(long)); i++) {
	get_user(val, (((long*)addr)+i));
	if (val) return 1;
    }
    return 0;

 out_zero:
    spin_unlock(&mm->page_table_lock);
    return 0;
}

static
int store_page_list_eof(struct vmadump_map_ctx *ctx, struct file *file) {
    int r;
    struct vmadump_page_header header;
    header.start = ~0UL;
    r = write_kern(ctx, file, &header, sizeof(header));
    if (r != sizeof(header)) r = -EIO;
    return r;
}

static
int store_page_list(struct vmadump_map_ctx *ctx, struct file *file,
		    unsigned long start, unsigned long end,
		    int (*pfunc)(struct mm_struct *mm, unsigned long)) {
    int r, bytes = 0;
    unsigned long addr;
    struct vmadump_page_header header;
    for (addr = start; addr < end; addr += PAGE_SIZE) {
	if (pfunc(current->mm, addr)) {
	    header.start = addr;
	    r = write_kern(ctx, file, &header, sizeof(header));
	    if (r != sizeof(header)) { r = -EIO; return r; }
	    bytes += r;
	    r = write_user(ctx, file, (void *)addr, PAGE_SIZE);
	    if (r != PAGE_SIZE) { r = -EIO; return r; }
	    bytes += r;
	}
    }
    r = store_page_list_eof(ctx, file);
    if (r < 0) return r;
    bytes += r;
    return bytes;
}

static
int store_map(struct vmadump_map_ctx *ctx, struct file *file,
	      struct vm_area_struct *map, int flags) {
    int bytes;
    struct vmadump_vma_header head;
    char *filename=0;
    char *buffer = 0;
    int r;
    unsigned long start, end;
    int isfilemap;

    head.start   = map->vm_start;
    head.end     = map->vm_end;
    head.flags   = map->vm_flags;
    head.namelen = 0;
    head.offset  = map->vm_pgoff << PAGE_SHIFT; /* XXX LFS! */

    /* Decide Whether or not we're gonna store the map's contents or
     * a reference to the file they came from */
    if (map->vm_file) {
	buffer = (char *) __get_free_page(GFP_KERNEL);
	if (!buffer) { return -ENOMEM; }
	if (ctx && ctx->map_name)
	    filename = ctx->map_name(ctx, map->vm_file, buffer, PAGE_SIZE);
	else
	    filename = default_map_name(map->vm_file, buffer, PAGE_SIZE);
	head.namelen = strlen(filename);

	if (map->vm_flags & VM_IO) {
	    /* Region is an IO map. */

	    /* Never store the contents of a VM_IO region */
	} else if (map->vm_flags & VM_EXECUTABLE) {
	    /* Region is an executable */
	    if (flags & VMAD_DUMP_EXEC)
		head.namelen = 0;
	} else if (is_library(filename)) {
	    /* Region is a library */
	    if (flags & VMAD_DUMP_LIBS)
		head.namelen = 0;
	} else {
	    /* Region is something else */
	    if (flags & VMAD_DUMP_OTHER)
		head.namelen=0;
	}
    }

    start     = map->vm_start;
    end       = map->vm_end;
    isfilemap = (map->vm_file != 0);
    /* Release the mm_sem here to avoid deadlocks with page faults and
     * write locks that may happen during the writes.  (We can't use
     * the "map" pointer beyond this point. */
    up_read(&current->mm->mmap_sem);

    /* Spit out the section header */
    r = write_kern(ctx, file, &head, sizeof(head));
    if (r != sizeof(head)) goto err;
    bytes = r;

    if (head.namelen) {
	/* Store the filename */
	r = write_kern(ctx, file, filename, head.namelen);
	if (r != head.namelen) goto err;
	bytes += r;
	r = store_page_list(ctx, file, start, end, addr_copied);
	if (r < 0) goto err;
	bytes += r;
    } else {
	/* Store the contents of the VMA as defined by start, end */
	r = store_page_list(ctx, file, start, end,
			    isfilemap ? addr_nonzero_file : addr_nonzero);
	if (r < 0) goto err;
	bytes += r;
    }
    if (buffer)   free_page((long)buffer);
    down_read(&current->mm->mmap_sem);
    return bytes;

 err:
    if (r >= 0) r = -EIO;	/* Map short writes to EIO */
    if (buffer)   free_page((long)buffer);
    down_read(&current->mm->mmap_sem);
    return r;
}

long vmadump_freeze_proc(struct vmadump_map_ctx *ctx, struct file *file,
			struct pt_regs *regs, int flags) {
    long r, bytes=0;
    static struct vmadump_header header ={VMAD_MAGIC, VMAD_FMT_VERS, VMAD_ARCH,
					  (LINUX_VERSION_CODE >> 16) & 0xFF,
					  (LINUX_VERSION_CODE >> 8) & 0xFF,
					  LINUX_VERSION_CODE & 0xFF };

    /*--- Write out the file header ---*/
    r = write_kern(ctx, file, &header, sizeof(header));
    if (r != sizeof(header)) goto err;
    bytes += r;

    r = write_kern(ctx, file, current->comm, sizeof(current->comm));
    if (r != sizeof(current->comm)) goto err;
    bytes += r;

    /*--- CPU State Information ------------------------------------*/
    r = vmadump_store_cpu(ctx, file, regs);
    if (r < 0) goto err;
    bytes += r;

    /*--- Signal information ---------------------------------------*/
    {
    int i;
    sigset_t             sig_blocked;
    struct k_sigaction   sig_action;

    spin_lock_irq(&current->sighand->siglock);
    memcpy(&sig_blocked, &current->blocked, sizeof(sig_blocked));
    spin_unlock_irq(&current->sighand->siglock);

    r = write_kern(ctx, file, &sig_blocked, sizeof(sig_blocked));
    if (r != sizeof(sig_blocked)) goto err;
    bytes += r;

    for (i=0; i < _NSIG; i++) {
	spin_lock_irq(&current->sighand->siglock);
	memcpy(&sig_action, &current->sighand->action[i], sizeof(sig_action));
	spin_unlock_irq(&current->sighand->siglock);

	r = write_kern(ctx, file, &sig_action, sizeof(sig_action));
	if (r != sizeof(sig_action)) goto err;
	bytes += r;
    }
    }

    /*--- Misc other stuff -----------------------------------------*/
    r = write_kern(ctx, file, &current->clear_child_tid,
		   sizeof(current->clear_child_tid));
    if (r != sizeof(current->clear_child_tid)) goto err;
    bytes += r;

    /* XXX Will we need FUTEX related stuff here as well? */

    /*--- Memory Information ---------------------------------------*/
    {
    struct vm_area_struct     *map, *next_map;
    struct vmadump_mm_info     mm_info;
    struct mm_struct          *mm = current->mm;
    struct vmadump_vma_header  term;

    down_read(&mm->mmap_sem);
    mm_info.start_code  = mm->start_code;
    mm_info.end_code    = mm->end_code;
    mm_info.start_data  = mm->start_data;
    mm_info.end_data    = mm->end_data;
    mm_info.start_brk   = mm->start_brk;
    mm_info.brk         = mm->brk;
    mm_info.start_stack = mm->start_stack;
    mm_info.arg_start   = mm->arg_start;
    mm_info.arg_end     = mm->arg_end;
    mm_info.env_start   = mm->env_start;
    mm_info.env_end     = mm->env_end;
    up_read(&mm->mmap_sem);

    r = write_kern(ctx, file, &mm_info, sizeof(mm_info));
    if (r != sizeof(mm_info)) goto err;
    bytes += r;

    down_read(&mm->mmap_sem);
    next_map = mm->mmap;
    while (next_map) {
	/* Scan forward till we find the map we're looking for.  We
	 * have to do it this way because store_map needs to release
	 * the mmap_sem. */
	for (map = mm->mmap; map && map != next_map; map = map->vm_next);
	if (!map) break;
	next_map = map->vm_next;
	r = store_map(ctx, file, map, flags);
	if (r < 0) {
	    up_read(&mm->mmap_sem);
	    goto err;
	}
	bytes += r;
    }
    up_read(&mm->mmap_sem);

    /* Terminate maps list */
    term.start = term.end = ~0L;
    r = write_kern(ctx, file, &term, sizeof(term));
    if (r != sizeof(term)) goto err;
    bytes += r;
    }

    /*--- Call freeze hooks ----------------------------------------*/
    r = do_freeze_hooks(ctx, file, regs, flags);
    if (r < 0) goto err;
    bytes += r;

    return bytes;

 err:
    if (r >= 0) r = -EIO;	/* Map short writes to EIO */
    return r;
}

/*--------------------------------------------------------------------
 * syscall interface
 *------------------------------------------------------------------*/
long do_vmadump(long op, long arg0, long arg1, struct pt_regs *regs) {
    long retval;
    struct file *file;

    switch (op) {
    case VMAD_DO_DUMP:
	if (arg1 & ~VMAD_FLAG_USER_MASK) {
	    retval = -EINVAL;
	    break;
	}
	if ((file = fget(arg0))) {
	    retval = vmadump_freeze_proc(0, file, regs, arg1);
	    fput(file);
	} else
	    retval = -EBADF;
	break;
    case VMAD_DO_UNDUMP:
	if ((file = fget(arg0))) {
	    retval = vmadump_thaw_proc(0, file, regs);
	    fput(file);
	} else
	    retval = -EBADF;

	/* Un-dump is a whole lot like exec() */
	if (retval == 0) {
	    if (current->euid == current->uid && current->egid == current->gid)
		current->mm->dumpable = 1;
	    current->did_exec = 1;
	    current->self_exec_id++;
	    if (current->ptrace & PT_PTRACED)
                send_sig(SIGTRAP, current, 0);
	}
	break;
    case VMAD_DO_EXECDUMP: {
	struct vmadump_execdump_args args;
	char * filename;

	if (copy_from_user(&args, (void *) arg0, sizeof(args))) {
	    retval = -EFAULT;
	    break;
	}

	if (args.flags & ~VMAD_FLAG_USER_MASK) {
	    retval = -EINVAL;
	    break;
	}

	filename = getname(args.arg0);
	retval = PTR_ERR(filename);
	if (IS_ERR(filename)) break;

	file = fget(args.fd);
	if (!file) {
	    retval = -EBADF;
	    putname(filename);
	    break;
	}

	retval = do_execve(filename, (char **)args.argv,
			   (char **)args.envp, regs);
	putname(filename);
	if (retval) {
	    fput(file);
	    break;
	}

	/* Check to make sure we're actually allowed to dump :) */
	if (!current->mm->dumpable) { 
	    fput(file);
	    do_exit(-EPERM);
	}

	retval = vmadump_freeze_proc(0, file, regs, args.flags);
	fput(file);
	if (retval > 0) retval = 0;
	do_exit(retval);		/* Ok, we're done... */
	/* NOT REACHED */
    } break;

    case VMAD_LIB_CLEAR:
    case VMAD_LIB_ADD:
    case VMAD_LIB_DEL:
    case VMAD_LIB_LIST:
    case VMAD_LIB_SIZE:
	lock_kernel();		/* very very lazy... */
	retval = do_lib_op(op, (char *) arg0, arg1);
	unlock_kernel();
	break;

    default:
	retval = -EINVAL;
    }
    return retval;
}

/*--------------------------------------------------------------------
 *  New binary format code
 *------------------------------------------------------------------*/
#ifdef HAVE_BINFMT_VMADUMP

static
int load_vmadump(struct linux_binprm *bprm, struct pt_regs *regs) {
    int retval;
    struct vmadump_header *header;

    header = (struct vmadump_header *) bprm->buf;
    if (memcmp(header->magic, vmad_magic, sizeof(header->magic)) != 0  ||
	header->fmt_vers != VMAD_FMT_VERS ||
	header->major != ((LINUX_VERSION_CODE >> 16) & 0xFF) ||
	header->minor != ((LINUX_VERSION_CODE >> 8) & 0xFF)
#if STRICT_VERSION_CHECK
	|| header->patch != (LINUX_VERSION_CODE & 0xFF)
#endif
	)
	return -ENOEXEC;

    if (!bprm->file->f_op || !bprm->file->f_op->mmap)
	return -ENOEXEC;

    retval = vmadump_thaw_proc(0, bprm->file, regs);
    if (retval == 0) {
	if (current->euid == current->uid && current->egid == current->gid)
	    current->mm->dumpable = 1;
	current->did_exec = 1;
	current->self_exec_id++;
#if 0
        if (current->exec_domain && current->exec_domain->module)
	    __MOD_DEC_USE_COUNT(current->exec_domain->module);
        if (current->binfmt && current->binfmt->module)
	    __MOD_DEC_USE_COUNT(current->binfmt->module);
	current->exec_domain = 0;
#endif
	current->binfmt = 0;
    }
    return retval;
}

struct linux_binfmt vmadump_fmt = {
    0,THIS_MODULE,load_vmadump,0,0,0
};
#endif



/* This is some stuff that allows vmadump to latch onto the BProc
 * syscall for testing purposes. */
#ifdef CONFIG_BPROC
static int syscall = 0;
MODULE_PARM(syscall, "i");
MODULE_PARM_DESC(syscall,
"Syscall number to allow calling VMADump directly.  The default (0) means "
"no VMADump syscall.  There is no bounds check on the syscall number so "
"be careful with this option.");
#endif

int init_module(void) {
    printk(KERN_INFO "vmadump: %s Erik Hendriks "
	   "<erik@hendriks.cx>\n", __stringify(PACKAGE_VERSION));
    init_rwsem(&hook_lock);
#ifdef CONFIG_BPROC
    {
	/*extern struct rw_semaphore do_bproc_lock;*/
	extern long (*do_bproc_ptr)(long,long,long,struct pt_regs *);
	/*down_write(&do_bproc_lock);*/
	do_bproc_ptr = 0;
	if (syscall) {
	    if (do_bproc_ptr)
		printk("vmadump: BProc syscall hook is occupied. "
		       "Can't attach to BProc syscall.\n");
	    else {
		do_bproc_ptr = do_vmadump;
		printk("vmadump: Attached to BProc syscall.\n");
	    }
	}
	/*up_write(&do_bproc_lock);*/
    }
#endif
#ifdef HAVE_BINFMT_VMADUMP
    register_binfmt(&vmadump_fmt);
#endif
    return 0;
}

void cleanup_module(void) {
    liblist_clear();
#ifdef HAVE_BINFMT_VMADUMP
    unregister_binfmt(&vmadump_fmt);
#endif

#ifdef CONFIG_BPROC
    {
	/*extern struct rw_semaphore do_bproc_lock;*/
	extern long (*do_bproc_ptr)(long,long,long,struct pt_regs *);
	if (syscall) {
	    /*down_write(&do_bproc_lock);*/
	    if (do_bproc_ptr == do_vmadump)
		do_bproc_ptr = 0;
	    /*up_write(&do_bproc_lock);*/
	}
    }
#endif
}

EXPORT_SYMBOL(vmadump_freeze_proc);
EXPORT_SYMBOL(vmadump_thaw_proc);
EXPORT_SYMBOL(do_vmadump);

EXPORT_SYMBOL(vmadump_add_hook);
EXPORT_SYMBOL(vmadump_del_hook);
EXPORT_SYMBOL(vmadump_read_u);
EXPORT_SYMBOL(vmadump_read_k);
EXPORT_SYMBOL(vmadump_write_u);
EXPORT_SYMBOL(vmadump_write_k);

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
