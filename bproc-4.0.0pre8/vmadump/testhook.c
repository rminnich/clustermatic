#include <linux/config.h>
#if defined(CONFIG_SMP) && ! defined(__SMP__)
#define __SMP__
#endif
#if defined(CONFIG_MODVERSIONS) && ! defined(MODVERSIONS)
#define MODVERSIONS
#endif
#if defined(MODVERSIONS)
#include <linux/modversions.h>
#endif

#include <linux/kernel.h>
#include <linux/module.h>
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
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>

#ifdef __i386__
#include <asm/i387.h>
#endif
#ifdef __sparc__
#include <asm/cprefix.h>
#endif

#include "vmadump.h"

#define HNAME "pwd"

/* Get the chdir syscall */
extern void *sys_call_table[];
#define k_sys_call1(rt,sys,t1,arg1) \
            (((rt (*)(t1)) \
               sys_call_table[(sys)])((arg1)))
int k_chdir(const char *path) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS); 
    err = k_sys_call1(int,__NR_chdir,const char *,(path));
    set_fs(oldfs);
    return err;
}

static
long freeze(struct vmadump_hook_handle *h, struct pt_regs *regs) {
    void *pg;
    char *ptr;
    struct vmadump_hook_header hh = { HNAME, 0};
    
    printk("In freeze %s!\n", HNAME);

    if (!current->fs || !current->fs->pwd) return 0;

    pg = (void *) get_free_page(GFP_KERNEL);
    if (!pg) return -ENOMEM;

    ptr = d_path(current->fs->pwd, current->fs->pwdmnt, pg, PAGE_SIZE);

    hh.size = strlen(ptr)+1;
    if (vmadump_write_k(h, &hh, sizeof(hh)) != sizeof(hh)) {
	free_page((long)pg);
	return -EIO;
    }

    if (vmadump_write_k(h, ptr, hh.size) != hh.size) {
	free_page((long)pg);
	return -EIO;
    }

    free_page((long)pg);
    return sizeof(hh) + hh.size;
}

static
int thaw(struct vmadump_hook_handle *h, struct vmadump_hook_header *hh,
	 struct pt_regs *regs) {
    char *pg;
    
    printk("In Thaw %s! (%ld)\n", HNAME, hh->size);

    if (hh->size > PAGE_SIZE)
	return -EINVAL;

    pg = (char *)get_free_page(GFP_KERNEL);
    if (vmadump_read_k(h, (void *) pg, hh->size) != hh->size) {
	free_page((long)pg);
	return -EIO;
    }
    pg[hh->size - 1] = 0;	/* make sure it's null terminated */
    printk("chdir(\"%s\") = %d\n", pg, k_chdir(pg));

    free_page((long)pg);
    printk("returning zero from thaw hook.\n");
    return 0;
}

static
struct vmadump_hook hook = {
    HNAME,
    freeze,
    thaw
};

/* Example of how to make vmadump optional...  NOTE: Even if vmadump
   is present, weakening these symbols will cause modprobe to NOT
   automatically load vmadump before this module.  Note that a request
   module call will not solve this problem since this is a linker hack
   and the module will already be linked.  This hack is of dubious
   value. */
asm(".weak vmadump_add_hook");
asm(".weak vmadump_del_hook");
asm(".weak vmadump_read_k");
asm(".weak vmadump_write_k");

int init_module(void) {
    if (vmadump_add_hook && vmadump_add_hook(&hook)) {
	printk("vmadump_add_hook failed.\n");
	return -EINVAL;
    }
    return 0;
}

void cleanup_module(void) {
    if (vmadump_del_hook) vmadump_del_hook(&hook);
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
