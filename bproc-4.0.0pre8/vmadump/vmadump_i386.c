/*-------------------------------------------------------------------------
 *  vmadump_i386.c:  i386 specific dumping/undumping routines
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
 * $Id: vmadump_i386.c,v 1.7 2004/10/09 01:08:00 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <asm/i387.h>
#include <asm/desc.h>

#define __VMADUMP_INTERNAL__
#include "vmadump.h"

extern
ssize_t write_kern(struct vmadump_map_ctx *ctx, struct file *file,
		   const void *buf, size_t count);

long vmadump_store_cpu(struct vmadump_map_ctx *ctx, struct file *file,
		       struct pt_regs *regs) {
    struct user_i387_struct dummy;
    union i387_union i387tmp;
    char flag;
    long bytes = 0, r;
    

    /* Store struct pt_regs */
    r = write_kern(ctx, file, regs, sizeof(*regs));
    if (r != sizeof(*regs)) goto err;
    bytes += r;

    /* The i386's FPU state isn't included in struct pt_regs, so
     * save it seperately here. */

    /* Explanation of flags:
     * used_math  =  1 iff process has used FPU
     * PF_USEDFPU =  1 iff process has used math since last context switch
     * TS         =  1 iff task switched, i.e. fpu ops will cause trap
     */

    /* If we haven't touched the FPU, make like we have so that we
     * have something to save.  First initialize it and then store
     * it in our thread (unlazy does this.) */
    if (current->used_math) {
	/* If the FPU has been used, try to save the state */
	flag = 1;
	r = write_kern(ctx, file, &flag, sizeof(flag));
	if (r != sizeof(flag)) goto err;
	bytes += r;

	if (current->flags & TS_USEDFPU) {
	    /* hack here, unlazy in not available from to modules
	     * so call dump_fpu which has unlazy as a side effect.
	     * *sigh* */
	    dump_fpu(0, &dummy);
	}
	memcpy(&i387tmp, &current->thread.i387, sizeof(i387tmp));
	r = write_kern(ctx, file, &i387tmp, sizeof(i387tmp));
	if (r != sizeof(i387tmp)) goto err;
	bytes += r;
    } else {
	/* No math used */
	flag = 0;
	r = write_kern(ctx, file, &flag, sizeof(flag));
	if (r != sizeof(flag)) goto err;
	bytes += r;
    }

    /* Store debugging state */
    r = write_kern(ctx, file, &current->thread.debugreg,
		   sizeof(current->thread.debugreg));
    if (r != sizeof(current->thread.debugreg)) goto err;
    bytes += r;

    /* Store TLS (segment) information */
    r = write_kern(ctx, file, &current->thread.tls_array,
		   sizeof(current->thread.tls_array));
    if (r != sizeof(current->thread.tls_array)) goto err;
    bytes += r;

    savesegment(fs,current->thread.fs);
    savesegment(gs,current->thread.gs);

    r = write_kern(ctx, file, &current->thread.fs, sizeof(current->thread.fs));
    if (r != sizeof(current->thread.fs)) goto err;
    bytes += r;

    r = write_kern(ctx, file, &current->thread.gs, sizeof(current->thread.gs));
    if (r != sizeof(current->thread.gs)) goto err;
    bytes += r;

    return bytes;

 err:
    if (r >= 0) r = -EIO;
    return r;
}

int vmadump_restore_cpu(struct vmadump_map_ctx *ctx, struct file *file,
			struct pt_regs *regs) {
    union i387_union     i387tmp;
    struct thread_struct threadtmp;
    struct pt_regs regtmp;
    char flag;
    int r;

    r = read_kern(ctx, file, &regtmp, sizeof(regtmp));
    if (r != sizeof(regtmp)) goto bad_read;

    /* Don't let the user pick bogo-segregs.  Restoring other values
     * will either lead us to fault while restoring or worse it might
     * allow users to do bad(tm) things in kernel space. */
    regtmp.xcs = __USER_CS;
    regtmp.xds = __USER_DS;
    regtmp.xes = __USER_DS;
    regtmp.xss = __USER_DS;
    /* fs and gs aren't represented in struct pt_regs... *hrm* */

    /* Only restore bottom 9 bits of eflags.  Restoring anything else
     * is bad bad mojo for security. (0x200 = interrupt enable) */
    regtmp.eflags = 0x200 | (regtmp.eflags & 0x000000FF);
    memcpy(regs, &regtmp, sizeof(regtmp));

    r = read_kern(ctx, file, &flag, sizeof(flag));
    if (r != sizeof(flag)) goto bad_read;

    if (flag) {
	/* Restore i386 FPU.
	 * - Clear TS so that we can do FPU ops.
	 * - Set PF_USEDFPU so the kernel knows that what's in the fpu right
	 *   now is of interest to us.
	 * - Read our dump data into the tss.
	 * - Manually restore from tss.
	 * - If the restore causes a GPF:
	 *     - Set TS so that FPU ops will trap.
	 *     - Clear used_math and PF_USEDFPU so the kernel will
	 *       give us a clean FPU when we trap.
	 */
	r = read_kern(ctx, file, &i387tmp, sizeof(i387tmp));
	if (r != sizeof(current->thread.i387)) goto bad_read;
	memcpy(&current->thread.i387, &i387tmp, sizeof(i387tmp));
	clts();
	current->used_math  = 1;
	current->thread_info->status |= TS_USEDFPU;

	/* Invalid FPU states can blow us out of the water so we will do
	 * the restore here in such a way that we trap the fault if the
	 * restore fails.  This modeled after get_user and put_user. */
	if (cpu_has_fxsr) {
	    asm volatile
		("1: fxrstor %1               \n"
		 "2:                          \n"
		 ".section .fixup,\"ax\"      \n"
		 "3:  movl %2, %0             \n"
		 "    jmp 2b                  \n"
		 ".previous                   \n"
		 ".section __ex_table,\"a\"   \n"
		 "    .align 4                \n"
		 "    .long 1b, 3b            \n"
		 ".previous                   \n"
		 : "=r"(r)
		 : "m" (current->thread.i387.fxsave), "i"(-EFAULT));
	} else {
	    asm volatile
		("1: frstor %1                \n"
		 "2:                          \n"
		 ".section .fixup,\"ax\"      \n"
		 "3:  movl %2, %0             \n"
		 "    jmp 2b                  \n"
		 ".previous                   \n"
		 ".section __ex_table,\"a\"   \n"
		 "    .align 4                \n"
		 "    .long 1b, 3b            \n"
		 ".previous                   \n"
		 : "=r"(r)
		 : "m" (current->thread.i387.fsave), "i"(-EFAULT));
	}

	if (r == -EFAULT) {
	    /* Check for restore failure and bitch about it */
	    printk("vmadump: %d: FPU restore failure.\n", current->pid);
	    current->used_math  = 0;
	    current->thread_info->status &= ~TS_USEDFPU;
	    stts();
	}
    } else {
	/* No FPU state for this process - setup for a clean FPU */
	current->used_math  = 0;
	current->thread_info->status &= ~TS_USEDFPU;
	stts();
    }

    r = read_kern(ctx, file, threadtmp.debugreg, sizeof(threadtmp.debugreg));
    if (r != sizeof(threadtmp.debugreg)) goto bad_read;

    /* XXX FIX ME: RESTORE DEBUG INFORMATION ?? */

    /* Restore TLS information */
    {
	unsigned long fs, gs;
	int i, idx, cpu;
	struct desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];
	
	r = read_kern(ctx, file, tls_array, sizeof(tls_array));
	if (r != sizeof(tls_array)) goto bad_read;

	r = read_kern(ctx, file, &fs, sizeof(fs));
	if (r != sizeof(fs)) goto bad_read;

	r = read_kern(ctx, file, &gs, sizeof(gs));
	if (r != sizeof(gs)) goto bad_read;

	/* Sanitize the TLS entries...
	 * Make sure the following bits are set/not set:
         *  bit 12   : S    =  1    (code/data - not system)
	 *  bit 13-14: DPL  = 11    (priv level = 3 (user))
	 *  bit 21   :      =  0    (reserved)
	 *
	 * If the entry isn't valid, zero the whole descriptor.
	 */
	for (i=0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
	    if ((tls_array[i].b & 0x00207000) != 0x00007000)
		tls_array[i].a = tls_array[i].b = 0;
	}

	/* Sanitize fs, gs.  These segment descriptors should load one
	 * of the TLS entries and have DPL = 3.  If somebody is doing
	 * some other LDT monkey business, I'm currently not
	 * supporting that here.  Also, I'm presuming that the offsets
	 * to the GDT_ENTRY_TLS_MIN is the same in both kernels. */
	idx = fs >> 3;
	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX || (fs&7) != 3)
	    fs = 0;
	idx = gs >> 3;
	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX || (gs&7) != 3)
	    gs = 0;
	
	/* Load the freshly sanitized entries */
	memcpy(current->thread.tls_array, tls_array,
	       sizeof(current->thread.tls_array));

	/* load_TLS can't get pre-empted */
	cpu = get_cpu();
	load_TLS(&current->thread, cpu);
	put_cpu();

	/* this stuff will get stored in thread->fs,gs at the next
	 * context switch. */
	loadsegment(fs, fs);
	loadsegment(gs, gs);
    }
    
    return 0;

 bad_read:
    if (r >= 0) return -EIO;
    return r;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
