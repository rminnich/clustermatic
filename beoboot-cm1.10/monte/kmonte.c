/*------------------------------------------------------------ -*- C -*-
 *  2 Kernel Monte a.k.a. Linux loading Linux on x86
 *
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *  This version is a derivative of the original two kernel monte
 *  which is (C) 2000 Scyld.
 *
 *  Copyright (C) 2000 Scyld Computing Corporation
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Portions related to the alpha architecture are:
 *
 *  Copyright(C) 2001 University of California.  LA-CC Number 01-67.
 *  This software has been authored by an employee or employees of the
 *  University of California, operator of the Los Alamos National
 *  Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 *  Department of Energy.  The U.S. Government has rights to use,
 *  reproduce, and distribute this software. If the software is
 *  modified to produce derivative works, such modified software should
 *  be clearly marked, so as not to confuse it with the version
 *  available from LANL.
 *
 *  This software may be used and distributed according to the terms
 *  of the GNU General Public License, incorporated herein by
 *  reference to http://www.gnu.org/licenses/gpl.html.
 *
 *  This software is provided by the author(s) "as is" and any express
 *  or implied warranties, including, but not limited to, the implied
 *  warranties of merchantability and fitness for a particular purpose
 *  are disclaimed.  In no event shall the author(s) be liable for any
 *  direct, indirect, incidental, special, exemplary, or consequential
 *  damages (including, but not limited to, procurement of substitute
 *  goods or services; loss of use, data, or profits; or business
 *  interruption) however caused and on any theory of liability,
 *  whether in contract, strict liability, or tort (including
 *  negligence or otherwise) arising in any way out of the use of this
 *  software, even if advised of the possibility of such damage.
 *
 *  $Id: kmonte.c,v 1.16 2004/08/09 18:46:08 mkdist Exp $
 *--------------------------------------------------------------------*/

#define KBUILD_BASENAME kmonte
#define KBUILD_MODNAME  kmonte

#include <linux/config.h>
#if defined(CONFIG_SMP) && ! defined(__SMP__)
#define __SMP__
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/reboot.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include "monte.h"		/* For user interface stuff.... */

/* Supporting SMP is complicated.  Stopping the processors doesn't
 * seem too bad.  Fooling with the APICs looks like it will be a major
 * pain unless the kernel exports a few more symbols.  */
#ifdef __SMP__
#warning "2 Kernel Monte doesn't work with SMP!"
#endif

MODULE_AUTHOR("Erik Arjan Hendriks <hendriks@lanl.gov>");
MODULE_DESCRIPTION("Two Kernel Monte: Loads new Linux kernels from Linux.");
MODULE_LICENSE("GPL");

/*--------------------------------------------------------------------
 * Monte memory management
 *--------------------------------------------------------------------
 *
 * TODO: explain in excruciating detail wtf is going on here.
 *------------------------------------------------------------------*/
struct monte_reloc_t {
    unsigned long dest;
    unsigned long src;
};
#define MONTE_RELOCS_PER_PAGE ((PAGE_SIZE-(sizeof(long)*2))/sizeof(struct monte_reloc_t))
struct monte_reloc_page_t {
    struct monte_reloc_t       relocs[MONTE_RELOCS_PER_PAGE];
    struct monte_reloc_page_t *next;
    unsigned long _pad;
};

static struct monte_reloc_page_t *m_pg_list = 0;

static
void m_pg_list_free(void) {
    struct monte_reloc_page_t *tmp;
    while (m_pg_list) {
	tmp = m_pg_list->next;
	free_page((unsigned long) m_pg_list);
	m_pg_list = tmp;
    }
}

/* This function borrowed from the /proc file system. */
static
unsigned long get_phys_addr_(pgd_t *pgd, unsigned long ptr) {
    pgd_t *page_dir;
    pmd_t *page_middle;
    pte_t *pte;
    unsigned long addr;

    page_dir = pgd + pgd_index(ptr);
    if (pgd_none(*page_dir))
	return 0;
    if (pgd_bad(*page_dir)) {
	printk("bad page directory entry %08lx\n", (long) pgd_val(*page_dir));
	pgd_clear(page_dir);
	return 0;
    }
    page_middle = pmd_offset(page_dir,ptr);
    if (pmd_none(*page_middle))
	return 0;
    if (pmd_bad(*page_middle)) {
	printk("bad page middle entry %08lx\n", (long) pmd_val(*page_middle));
	pmd_clear(page_middle);
	return 0;
    }
    pte = pte_offset_map(page_middle,ptr);
    if (!pte_present(*pte)) {
	pte_unmap(pte);
	return 0;
    }
    /* This will probably break with DISCONTIGMEM */
    addr = (pte_val(*pte) & PAGE_MASK) | (ptr & ~PAGE_MASK);
    pte_unmap(pte);
    return addr;
}

static
unsigned long get_phys_addr(unsigned long ptr) {
    if (!current->mm || ptr >= TASK_SIZE)
	return 0;
    /* Check for NULL pgd .. shouldn't happen! */
    if (!current->mm->pgd) {
	printk("get_phys_addr: pid %d has NULL pgd!\n", current->pid);
	return 0;
    }

    return get_phys_addr_(current->mm->pgd, ptr);
}


static
int m_setup_page_list(struct monte_region_t *regions, int nregions) {
    int i, npages, pg_idx;
    unsigned long j;
    struct monte_reloc_page_t *pg;

    npages = 0;
    for (i=0; i < nregions; i++)
	npages += (regions[i].size + PAGE_SIZE-1) >> PAGE_SHIFT;
    if (npages == 0) return -EINVAL;

    /* Allocate all the pages we're going to need. */
    m_pg_list = 0;
    for (i = 0; i < npages; i+= MONTE_RELOCS_PER_PAGE) {
	/* grab a new page and make entries on this page. */
	if (!(pg = (struct monte_reloc_page_t *) __get_free_page(GFP_KERNEL)))
	    return -ENOMEM;
	memset(pg, 0, sizeof(*pg));
	pg->next = m_pg_list;
	m_pg_list = pg;
    }

    /* Load up the page list.  Here we go through the regions that the
     * user provided us and find the physical addresses of those
     * pages.  XXX Should we also go through and lock these pages at
     * this time ? */
    pg = m_pg_list;
    pg_idx = 0;
    for (i=0; i < nregions; i++) {
	for (j=0; j < regions[i].size; j += PAGE_SIZE) {
	    pg->relocs[pg_idx].dest = ((unsigned long)regions[i].destaddr)+j;
	    pg->relocs[pg_idx].src  = get_phys_addr(((unsigned long)
						     regions[i].addr)+j);
	    if (pg->relocs[pg_idx].src == 0) {
		printk("monte: page not present in page list load!\n");
		return -ENOMEM;
	    }
	    pg_idx++;
	    if (pg_idx == MONTE_RELOCS_PER_PAGE) {
		pg_idx = 0;
		pg = pg->next;
	    }
	}
    }
    return 0;
}

static
int m_check_page_list(void) {
    int pg1i, pg2i;
    void *tmp_page, *src;
    unsigned long tmp;
    struct monte_reloc_page_t *pg1, *pg2, *last;

    if (!(tmp_page = (void *) __get_free_page(GFP_KERNEL)))
	return -ENOMEM;
    
    printk("monte: sorting pages: ");
    pg1=m_pg_list; pg1i=0;
    while (pg1) {
	if (pg1->relocs[pg1i].dest) {
	    /* check if there are any pages which will be placed on
	     * this page in the end. */
	    pg2 = pg1; pg2i = pg1i+1;
	    if (pg2i == MONTE_RELOCS_PER_PAGE) { pg2 = pg2->next; pg2i = 0; }
	    while (pg2) {
		/* We have a winner, swap these two pages. */
		if (pg2->relocs[pg2i].src == pg1->relocs[pg1i].dest) {
		    /* Swap page contents */
		    memcpy(tmp_page, phys_to_virt(pg1->relocs[pg1i].src),
			   PAGE_SIZE);
		    memcpy(phys_to_virt(pg1->relocs[pg1i].src),
			   phys_to_virt(pg2->relocs[pg2i].src), PAGE_SIZE);
		    memcpy(phys_to_virt(pg2->relocs[pg2i].src),
			   tmp_page, PAGE_SIZE);
		    /* Swap "src" pointers */
		    tmp = pg1->relocs[pg1i].src;
		    pg1->relocs[pg1i].src = pg2->relocs[pg2i].src;
		    pg2->relocs[pg2i].src = tmp;
		    break;
		}
		pg2i++;
		if (pg2i == MONTE_RELOCS_PER_PAGE) {
		    pg2 = pg2->next;
		    pg2i = 0;
		}
	    }
	    if (!pg2) {
		/* Also check on the pages used as indirect pages. */
		last = 0;
		for (pg2 = m_pg_list; pg2; pg2 = pg2->next) {
		    if (virt_to_phys(pg2) == pg1->relocs[pg1i].dest) {
			src = phys_to_virt(pg1->relocs[pg1i].src);
			/* Swap page contents */
			memcpy(tmp_page, src, PAGE_SIZE);
			memcpy(src, pg2, PAGE_SIZE);
			memcpy(pg2, tmp_page, PAGE_SIZE);
			/* Swap the pointers */
			if (last)
			    last->next = src;
			else
   			    m_pg_list = src;
			if (pg1 == pg2) pg1 = src;
			pg1->relocs[pg1i].src = virt_to_phys(pg2);
			break;
		    }
		    last = pg2;
		}
	    }
	}
	pg1i++; if (pg1i == MONTE_RELOCS_PER_PAGE) { pg1=pg1->next; pg1i=0;}
    }
    printk("done\n");
    free_page((unsigned long) tmp_page);
    return 0;
}

/* Allocate a free page that we can count on not getting clobbered
 * during our relocation step. */
static unsigned long m_get_free_page(void) __attribute__((unused));
static
unsigned long m_get_free_page(void) {
    int i;
    struct monte_reloc_page_t *pg;
    unsigned long page;

    if (!(page = __get_free_page(GFP_KERNEL)))
	return 0;

    pg = m_pg_list;
    while (pg) {
	for (i=0; i < MONTE_RELOCS_PER_PAGE; i++) {
	    if (virt_to_phys((void*)page) == pg->relocs[i].dest) {
		/* Found a collision */
		printk("c");
		/* move the data */
		memcpy((void*)page,phys_to_virt(pg->relocs[i].src),PAGE_SIZE);

		/* Update page pointers */
		page = (unsigned long)phys_to_virt(pg->relocs[i].src);
		pg->relocs[i].src = pg->relocs[i].dest;
		goto found_hit;
	    }
	}
	pg = pg->next;
    }
 found_hit:
    return page;
}

static void m_make_phys(void) __attribute__((unused));
static
void m_make_phys(void) {
    struct  monte_reloc_page_t *pg;
    /* Convert all the pointers in our relocation list to physical
     * addresses.  Most of them already are.  We just need to fix the
     * "next" pointers. */
    pg = m_pg_list;
    m_pg_list = (void *) virt_to_phys(m_pg_list);
    while (pg->next) {
	pg->next = (void *) virt_to_phys(pg->next);
	pg = phys_to_virt((unsigned long)pg->next);
    }
}

static void m_make_virt(void) __attribute__((unused));
static
void m_make_virt(void) {
    int i;
    struct  monte_reloc_page_t *pg;
    /* Convert all the pointers to virtual addresses.  The next
     * pointers will be ok but the page addresses are all physical. */
    pg = m_pg_list;
    while (pg) {
	for (i=0; i < MONTE_RELOCS_PER_PAGE; i++) {
	    if (pg->relocs[i].src) {
		pg->relocs[i].src  = (long)phys_to_virt(pg->relocs[i].src);
		pg->relocs[i].dest = (long)phys_to_virt(pg->relocs[i].dest);
	    }
	}
	pg = pg->next;
    }
}

/*--------------------------------------------------------------------
 *  Syscall interface
 *------------------------------------------------------------------*/
static int monte_restart(unsigned long entry_addr, unsigned long flags);
int (*real_reboot)(int, int, int, void *);

#if defined(__i386__)
#include <asm/setup.h>
#endif

static struct semaphore monte_sem;
asmlinkage int sys_monte(int magic1, int magic2, int cmd, void *arg) {
    int err;
    struct monte_param_t  param;
    struct monte_region_t *regions=0;

    if (magic1 != MONTE_MAGIC_1 || magic2 != MONTE_MAGIC_2) {
	err = real_reboot(magic1, magic2, cmd, arg);
	return err;
    }

    if (!capable(CAP_SYS_BOOT)) {
	return -EPERM;
    }

#if defined(__i386__)
    /* Magic bit to get real mode configuration data.  If we didn't
     * suck so much we might be able to synthesize this for user
     * space... */
    if (cmd == 1) {
	if (copy_to_user(arg, boot_params, PARAM_SIZE))
	    return -EFAULT;
	return 0;
    }
#endif

    if (cmd != 0)
	return -EINVAL;

    down(&monte_sem);		/* one process only please... */
    /* Get the user's parameters */
    if (copy_from_user(&param, arg, sizeof(param))) {
	err = -EFAULT;
	goto out;
    }
    if (!(regions = kmalloc(sizeof(struct monte_region_t)*param.nregions,
			    GFP_KERNEL))) {
	err = -ENOMEM;
	goto out;
    }
    if (copy_from_user(regions, param.regions,
		       sizeof(*regions)*param.nregions)) {
	err = -EFAULT;
	goto out;
    }
    down_write(&current->mm->mmap_sem);
    if ((err = m_setup_page_list(regions, param.nregions))) goto out1;
    if ((err = m_check_page_list())) goto out1;

    
    if (param.flags & MONTE_NOT_REALLY) { err = 0; goto out1; }

    printk("monte: restarting system...\n");
#if 0
    {unsigned long now=jiffies;while(jiffies<(now+2*HZ))schedule();}
#endif
    err = monte_restart(param.entrypoint, param.flags);
    printk("monte: failure (errno = %d)\n", -err);

 out1:
    up_write(&current->mm->mmap_sem);
 out:
    if (regions) kfree(regions);
    m_pg_list_free();
    up(&monte_sem);
    return err;
}

#if defined(__i386__)
/*-------------------------------------------------------------------------
 * Machine restart code - x86
 *-----------------------------------------------------------------------*/
static unsigned long long
real_mode_gdt_entries [] = {
        0x0000000000000000ULL,  /* 00h: Null descriptor */
	0x0000000000000000ULL,  /* 08h: Unused... */
	0x00cf9a000000ffffULL,	/* 10h: 32-bit 4GB code at 0x00000000 */
	0x00cf92000000ffffULL,	/* 18h: 32-bit 4GB data at 0x00000000 */
        0x00009a000000ffffULL,  /* 20h: 16-bit 64k code at 0x00000000 */
        0x000092000000ffffULL,	/* 28h: 16-bit 64k data at 0x00000000 */
	0,			/* 30h */
	0,			/* 38h */
	0,			/* 40h */
	0,			/* 48h */
	0,			/* 50h */
	0,			/* 58h */
        0x00cf9a000000ffffULL,  /* 0x60 kernel 4GB code at 0x00000000 */
        0x00cf92000000ffffULL,  /* 0x68 kernel 4GB data at 0x00000000 */
        0x00cffa000000ffffULL,	/* 0x73 user 4GB code at 0x00000000 */
        0x00cff2000000ffffULL,	/* 0x7b user 4GB data at 0x00000000 */
};

static struct {
        unsigned short       size __attribute__ ((packed));
        unsigned long long * base __attribute__ ((packed));
}
real_mode_gdt = { sizeof (real_mode_gdt_entries)-1, 0 },
real_mode_idt = { 0x3ff, 0 };

/*
  Registers:
  eax - scratch
  ebx - memory list pointer
  ecx - counter
  edx - entry point
  esi - scratch memcpy pointer
  edi - scratch memcpy pointer
  ebp - flags
 */
/* The address arguments to this function are PHYSICAL ADDRESSES */ 
static void real_mode_switch(struct monte_reloc_page_t *mem_list,
			     void *entry,
			     unsigned long flags) {
  __asm__ __volatile__
      (/* Grab the args for our memcpy off the stack now while we still
	* have page tables. */
       "    movl %0, %%ebx           \n" /* Arg storage: memlist -> EBX */
       "    movl %1, %%edx           \n" /* Arg storage: entry   -> EDX */
       "    movl %2, %%ebp           \n" /* Arg storage: flags   -> EBP */

       /* Turn off paging, leave protected mode turned on. */
       "    movl %%cr0, %%eax        \n" /* Turn off paging (bit 31 in CR0) */
       "    andl $0x7FFFFFFF, %%eax  \n"
       "    movl %%eax, %%cr0        \n"
       "    xorl %%eax, %%eax        \n" /* Flush the TLB (write 0 to CR3) */
       "    movl %%eax, %%cr3        \n"

       /* Memory setup code */
       /* We need to memcpy all the bits of code and data reload to
	* the right places now We can do this safely now that we don't
	* have to worry about overwriting our own page tables.  */
       "    mov  $0x18, %%ax         \n" /* 32-bit, 4GB data from GDT */
       "    mov  %%ax, %%ds          \n"
       "    mov  %%ax, %%es          \n"

       "    cld                      \n"
       "1:                           \n"
       "    orl  %%ebx, %%ebx        \n" /* ebx = addr of chunk descriptor */
       "    jz   3f                  \n"
       "    movl  (%%ebx), %%edi     \n" /* Destination */
       "    movl 4(%%ebx), %%esi     \n" /* Source */
       "    movl $0x1000, %%ecx      \n" /* Size = PAGE_SIZE */
       "    cmpl %%edi, %%esi        \n" /* skip if dest == src  */
       "    je   2f                  \n"
       "    rep; movsb               \n" /* Do it. */
       "2:                           \n"
       "    addl $8, %%ebx           \n" /* move ebx to the next item. */
       "    movl %%ebx, %%edi        \n" /* Check if we're at the end    */
       "    andl $0xfff, %%edi       \n" /* of the page and actually     */
       "    cmpl $0xff8, %%edi       \n" /* looking at the next page ptr.*/
       "    jne  1b                  \n" /* If not, next iteration */
       "        movl (%%ebx), %%ebx  \n" /* Follow the pointer here */
       "    jmp  1b                  \n" /* ... next iteration */
       "3:                           \n"

       /* Option here...  If we want to skip the setup section, stay
	* in protected mode and jump to the new kernel now.
	*
	* bit 0 of EBP: 1 = stay in protected mode start; skip the setup
	*                   portion of the kernel.  (Jump to the kernel
	*                   from here.)
	*               0 = continue on to real mode; start kernel at
	*                   setup code.
	*/
       "    movl $0x90000, %%esi     \n" /* pointer to setup block */
       "    andl $0x1, %%ebp         \n"
       "    jz  1f                   \n"
       "        xor %%bx, %%bx       \n" /* bx==0 means boot */
       "        jmp *%%edx           \n" /* Jump to our entry point */
       "1:                           \n"

       /* Now that our memcpy is done we can get to 16 bit code
	* segment.  This configures CS properly for real mode. */
       "    ljmp $0x20, $0x1000-(real_mode_switch_end - __rms_16bit) \n"
       "__rms_16bit:                 \n"
       ".code16                      \n" /* 16 bit code from here on... */

       /* Load the segment registers w/ properly configured segment
	* descriptors.  They will retain these configurations (limits,
	* writability, etc.) once protected mode is turned off. */
       "    mov  $0x28, %%ax         \n"
       "    mov  %%ax, %%ds          \n"
       "    mov  %%ax, %%es          \n"
       "    mov  %%ax, %%fs          \n"
       "    mov  %%ax, %%gs          \n"
       "    mov  %%ax, %%ss          \n"

       /* Turn off protection (bit 0 in CR0) */
       "    movl %%cr0, %%eax        \n"
       "    andl $0xFFFFFFFE, %%eax  \n"
       "    movl %%eax, %%cr0        \n"

       /* Now really going into real mode */
       "    ljmp $0, $0x1000-(real_mode_switch_end - __rms_real) \n"
       "__rms_real:                  \n"

       /* Setup a stack */
       "    mov  $0x9000, %%ax       \n"
       "    mov  %%ax, %%ss          \n"
       "    mov  $0xAFFE, %%ax       \n"
       "    mov  %%ax, %%sp          \n"

       /* Dump zeros in the other segregs */
       "    xor  %%ax, %%ax          \n"
       "    mov  %%ax, %%ds          \n"
       "    mov  %%ax, %%es          \n"
       "    mov  %%ax, %%fs          \n"
       "    mov  %%ax, %%gs          \n"

       "    sti                      \n" /* Enable interrupts */

       /* Try and sanitize the video hardware state. */
       "    mov  $0x0003, %%ax       \n"	/* Ask for 80x25 */
       "    int  $0x10               \n"
       
       "    push %%edx               \n" /* Kludge to do far jump */
       "    lret                     \n"

       /*"    jmp *%%edx               \n"*/
       /*"    ljmp $0x9020, $0x0000    \n"*/
#if 0
       /* Debugging tools... */
       "    .byte 0xcc               \n" /* XXX DEBUG triple fault XXXX */
       "    .byte 0xeb, 0xfe         \n" /* XXX DEBUG wedge XXXXX */
#endif
       ".code32                      \n" /* Restore mode for rest of file */
       : : "m" (mem_list), "m" (entry), "m" (flags));
}
__asm__ (".text\n""real_mode_switch_end:\n");
extern char real_mode_switch_end[];


static
void restore_xt_pic(void) {
    /* These following is taken from arch/i386/boot/setup.S
     *
     *     I hope. Now we have to reprogram the interrupts :-( we put
     *     them right after the intel-reserved hardware interrupts, at
     *     int 0x20-0x2F. There they won't mess up anything. Sadly IBM
     *     really messed this up with the original PC, and they
     *     haven't been able to rectify it afterwards. Thus the bios
     *     puts interrupts at 0x08-0x0f, which is used for the
     *     internal hardware interrupts as well. We just have to
     *     reprogram the 8259's, and it isn't fun.
     *
     * This tidbit puts the interrupts back where the BIOS likes them. */

    outb(0x11, 0x20);		/* 8259A-1 Start initialization sequence */
    outb(0x11, 0xA0);		/* 8259A-2 Start initialization sequence */

    outb(0x08, 0x21);		/* 1: start hw interrupts at 0x08 */
    outb(0x70, 0xA1);		/* 2: start hw interrupts at 0x70 */

    outb(0x04, 0x21);		/* 1: this PIC is master */
    outb(0x02, 0xA1);		/* 2: this PIC is slave */

    outb(0x01, 0x21);		/* 1: 8086 mode */
    outb(0x01, 0xA1);		/* 2: 8086 mode */

    outb(0x00, 0xA1);		/* unmask all interrupts */
    outb(0x00, 0x21);
}

static
int monte_restart(unsigned long entry_addr, unsigned long flags) {
    void * ptr;

    /* Step 1: get an identity mapped page.  The code that will turn
     * off paging later needs to run out of an identity mapped page.
     * For simplicity we'll use page zero.  This page is normally not
     * mapped at all. */
    if (remap_page_range(current->mm->mmap,0,0,PAGE_SIZE,PAGE_KERNEL)) {
	printk("Failed to remap page range\n");
	return -EAGAIN;
    }
    local_irq_disable();

    /*----- POINT OF NO RETURN IS HERE --------------------------------------*/
    /* Step 2: Copy the real_mode_switch code and our GDT into the
     * page we just setup.  We stick this stuff right at the end to
     * avoid clobbering BIOS variables and stuff in the beginning. */
#define RMS_SIZE ((unsigned long)real_mode_switch_end - (unsigned long) real_mode_switch)
    /* Copy our GDT down there. */
    ptr = (void *) ((0x1000 - RMS_SIZE - sizeof(real_mode_gdt_entries)) & ~7);
    memcpy(ptr, real_mode_gdt_entries, sizeof(real_mode_gdt_entries));
    real_mode_gdt.base = ptr;

    /* Copy the real_mode_switch function down there. */
    memcpy((void *)(0x1000-RMS_SIZE), real_mode_switch, RMS_SIZE);

    m_make_phys();		/* Prep our memory to-do list. */

    /* Prep the hardware to restart */
    if (!(flags & MONTE_PROTECTED)) restore_xt_pic();
    
    /* Ok, now the real monkey business begins.... Please keep hands
     * and feet inside the memory space and remain seated until the
     * ride comes to a complete stop. */
    __asm__ __volatile__
	(/* Install the IDT and GDT we copied to page zero. */
	 "lidt  %0             \n"
	 "lgdt  %1             \n"
	 
	 /* Function call with args... sort of */
	 "pushl %4             \n"
	 "pushl %3             \n"
	 "pushl %2             \n" /* Push args on the stack */
	 "sub $4, %%esp        \n" /* bogo return address */
	 "ljmp $0x10, $0x1000-(real_mode_switch_end-real_mode_switch) \n" : :
	 "m" (real_mode_idt), "m" (real_mode_gdt),
	 "r" (m_pg_list), "r" (entry_addr), "r" (flags)
	 : "memory");
    /* NOT REACHED */
    while(1);			/* Shut up gcc. */
}
#endif /* defined(__i386__) */
/*-------------------------------------------------------------------------
 * Machine restart code - Alpha
 *-----------------------------------------------------------------------*/
#if defined(__alpha__)
#include <asm/hwrpb.h>
/*#include <asm/mmu_context.h>*/
/*#include <asm/irq.h>*/

static
int map_page(struct pcb_struct *pcb, unsigned long virt, unsigned long phys) {
    pgd_t *pgd_table;
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;

    if (!pcb->ptbr) {
	pgd_table = (void *)m_get_free_page();
	memset(pgd_table, 0, PAGE_SIZE);
	pcb->ptbr = virt_to_phys(pgd_table) >> PAGE_SHIFT;
	pcb->flags = 1;		/*  1 = FEN (floating point enable) */
    }
    pgd_table = phys_to_virt(pcb->ptbr << PAGE_SHIFT);
    pgd = pgd_table + pgd_index(virt);
    if (pgd_none(*pgd)) {
	/* allocate middle */
	pmd = (void*) m_get_free_page();
	memset(pmd, 0, PAGE_SIZE);
	pgd_set(pgd, pmd);
    }
    pmd = pmd_offset(pgd, virt);

    if (pmd_none(*pmd)) {
	/* Allocate pte table */
	pte = (void *) m_get_free_page();
	memset(pte, 0, PAGE_SIZE);
	pmd_set(pmd, pte);
    }
    pte = pte_offset(pmd, virt);
    *pte = mk_pte_phys(phys, PAGE_KERNEL);
    return 0;
}

#if 0
/* Note: This POST tidbit (which is only for debugging) won't work on
 * all alpha boards.  Stupid DEC can't even design an architecture
 * where "outb" is consistent. *sigh* This stuff works on tsunami type
 * boards and I think it requires an EV6 or better... */
#define STR(x) #x
#define POST(x) \
	 /* POST */            \
	 "    lda     $23, "STR(x)"($31) \n" \
	 "    lda     $24, 0x80($31) \n" \
	 "    ldah    $22,-1($31)    \n" /* generate tsunami IO base */ \
	 "    lda     $22,16511($22) \n" \
	 "    sll     $22,0x1a,$22   \n" \
	 "    addq    $24,$22,$24    \n" /* add it to arg */ \
	 "    stb     $23, 0($24)    \n" \
	 "    mb                     \n"
#else
#define POST(x) 
#endif

/* Alpha page relocation code */
__asm__
(/* memcpy everything in the relocation list */
 ".text                       \n"
 ".align 4                    \n"
 "relocate_start:             \n"

 POST(0xf1)
 "    mov     $16, $9         \n" /* save arguments */
 "    mov     $17, $10        \n"
 "    mov     $18, $16        \n" /* PAL_swpctx */
 "    call_pal 48             \n"
 POST(0xf2)
 "    lda     $16, -2         \n" /* tbia(); */
 "    call_pal 51             \n"
 POST(0xf3)
 "1:                          \n"
 "    beq     $9, 4f          \n"
 /* memcpy 1 page a0 ($9) contains address of monte_reloc_t */
 "    ldq     $2, 8($9)       \n" /* src */
 "    ldq     $3, 0($9)       \n" /* dest */
 "    beq     $2, 3f          \n" /* skip if src == 0    */
 "    beq     $3, 3f          \n" /* skip if dest == 0   */
 "    cmpeq   $2, $3, $4      \n" /* skip if src == dest */
 "    bne     $4, 3f          \n"
 "    lda     $4, 8192($31)   \n" /* page size (aka loop counter) */
 "2:                          \n"
 "    beq     $4, 3f          \n" /* check if finished */
 "    ldq     $5, 0($2)       \n" /* copy word */
 "    stq     $5, 0($3)       \n"
 "    addq    $2, 8, $2       \n" /* update pointers */
 "    addq    $3, 8, $3       \n"
 "    subq    $4, 8, $4       \n"
 "    br      2b              \n"
 "3:                          \n"

 "    lda     $9, 16($9)      \n" /* move pointer to next record */
 "    lda     $2, 0x1fff($31) \n" /* check if we're at the end */
 "    and     $9, $2, $3      \n" /* mask off offset within page */
 "    lda     $2, 8176        \n" 
 "    cmpeq   $2, $3, $4      \n" /* are we at end of page ? */
 "    beq     $4, 1b          \n" /* no: do next relocation */
 "     ldq    $9, 0($9)       \n" /* yes: follow next pointer */
 "     br     1b              \n"

 /* Relocation finished, do jump */
 "4:                          \n"
 POST(0xff)
 "    mov     $10, $27        \n" /* call in the ELF approved way  */
 "    jmp     $26,($27)       \n"

 /* This is the dummy SRM fixup function */
 "do_fixup:                   \n"
 POST(0xAA)
 "    mov     $31, $0         \n" /* return zero */
 "    ret     $31,($26),1     \n"
 "relocate_end:               \n"
 ".previous                   \n");
extern void relocate_start;
extern void relocate_end;
extern void do_fixup;

static
int monte_restart(unsigned long entry_addr, unsigned long flags) {
    /*int err;*/
    long i, j;
    void *code;
    struct pcb_struct *pcb;
    struct crb_struct *crb;

    /* This page holds PCB, code relocator, dummy PCB. */
    code = (void *) m_get_free_page();
    if (!code) return -ENOMEM;

    pcb = code;
    code += sizeof(*pcb);
    memcpy(code, &relocate_start, &relocate_end - &relocate_start);

    memset(pcb, 0, sizeof(*pcb)); /* initialize PCB */
    printk("monte: Mapping HWRPB at %p\n", INIT_HWRPB);
    for (i=0; i < (hwrpb->size + PAGE_SIZE-1) / PAGE_SIZE; i++)
	map_page(pcb, (unsigned long) INIT_HWRPB + PAGE_SIZE*i,
		 hwrpb->phys_addr + PAGE_SIZE * i);
    printk("monte: Mapping CRB.\n");
    crb = ((void *)hwrpb) + hwrpb->crb_offset;
    for (i=0; i < crb->map_entries; i++) {
	for (j=0; j < crb->map[i].count; j++)
	    map_page(pcb, crb->map[i].va + PAGE_SIZE*j,
		     crb->map[i].pa + PAGE_SIZE*j);
    }
    /* This is a big hack...  srm_fixup just doesn't seem to work so
     * we replace the call address with a dummy function provided by
     * us.  This *should* be ok as long as we're booting Linux and
     * that kernel wants to map it in the same place as us.
     */
    printk("monte: inserting wrench into CRB.\n");
    crb->fixup_va->address = (long)code + (&do_fixup - &relocate_start);

    map_page(pcb, 0xfffffffe00000000, pcb->ptbr << PAGE_SHIFT);	/*necessary?*/

    /* Prep the hardware to restart */
#ifdef CONFIG_PCI
    if (flags & MONTE_PCI_DISABLE)
	monte_pci_disable();	/* Turn off PCI bus masters */
#endif

    /* The alpha kernel uses an odd identy mapping starting at
     * IDENT_ADDR which is not dependent on page tables.  This is
     * convenient since we can use kernel virtual addresses in our
     * relocation code without having to worry at all about clobbering
     * our page tables. */
    m_make_virt();	/* convert our lists to all virtual addresses */
    cli();		/* interrupts are bad while re-arranging */

    /* clean up hardware state */
    if (alpha_mv.kill_arch)
	alpha_mv.kill_arch(LINUX_REBOOT_CMD_RESTART);

    pcb->ksp = ((long)pcb)+(PAGE_SIZE&~7); /* to keep swpctx happy... */
    ((void(*)(void *, long, long))code)(m_pg_list, entry_addr,
					virt_to_phys(pcb));
    /* NOT REACHED */
    while(1);			/* shut-up, gcc */
}
#endif

/*--------------------------------------------------------------------
 *  Module mechanics
 *------------------------------------------------------------------*/
extern void *sys_call_table[];
int init_module(void) {
    printk("monte: 2 Kernel Monte Version %s\n"
	   "monte: Erik Arjan Hendriks <hendriks@lanl.gov>\n",
	   __stringify(PACKAGE_VERSION));
    init_MUTEX(&monte_sem);

    real_reboot = sys_call_table[__NR_reboot];
    sys_call_table[__NR_reboot] = sys_monte;
    return 0;
}

void cleanup_module(void) {
    sys_call_table[__NR_reboot] = real_reboot;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
