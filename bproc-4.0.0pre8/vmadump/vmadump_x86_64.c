/*-------------------------------------------------------------------------
 *  vmadump_x86_64.c:  x86-64 specific dumping/undumping routines
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
 * $Id: vmadump_x86_64.c,v 1.9 2004/10/09 01:08:00 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/config.h>
#if defined(CONFIG_SMP) && ! defined(__SMP__)
#define __SMP__
#endif

#define __FRAME_OFFSETS		/* frame offset macros from ptrace.h */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/config.h>

#include <asm/offset.h>
#include <asm/i387.h>
#include <asm/desc.h>

#define __VMADUMP_INTERNAL__
#include "vmadump.h"

extern
ssize_t write_kern(struct vmadump_map_ctx *ctx, struct file *file,
		   const void *buf, size_t count);




/* dump_fpu is a bit confused so replicate it here */
static
int x_dump_fpu(struct pt_regs *regs, struct user_i387_struct *fpu) {
    struct task_struct *tsk = current;

    if (!tsk->used_math) 
	return 0;

    unlazy_fpu(tsk);
    memcpy(fpu, &tsk->thread.i387.fxsave, sizeof(struct user_i387_struct)); 
    return 1; 
}

#define savesegment(seg, value) \
        asm volatile("movl %%" #seg ",%0":"=m" (*(int *)&(value)))

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
	    
	    x_dump_fpu(0, &dummy);
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

    /* Store all weird segmenty crap */

    /* 64-bit offsets for FS and GS */
    r = write_kern(ctx, file, &current->thread.fs,
		   sizeof(current->thread.fs));
    if (r != sizeof(current->thread.fs)) goto err;
    bytes += r;
    
    r = write_kern(ctx, file, &current->thread.gs,
		   sizeof(current->thread.gs));
    if (r != sizeof(current->thread.gs)) goto err;
    bytes += r;

    savesegment(fs,current->thread.fsindex);
    savesegment(gs,current->thread.gsindex);

    /* 32-bit segment descriptors for FS and GS */
    r = write_kern(ctx, file, &current->thread.fsindex,
		   sizeof(current->thread.fsindex));
    if (r != sizeof(current->thread.fsindex)) goto err;
    bytes += r;
    
    r = write_kern(ctx, file, &current->thread.gsindex,
		   sizeof(current->thread.gsindex));
    if (r != sizeof(current->thread.gsindex)) goto err;
    bytes += r;

    /* TLS segment descriptors */
    r = write_kern(ctx, file, &current->thread.tls_array,
		   sizeof(current->thread.tls_array));
    if (r != sizeof(current->thread.tls_array)) goto err;
    bytes += r;

    /* Store debugging state */
    r = write_kern(ctx, file, &current->thread.debugreg0,
		   sizeof(current->thread.debugreg0));
    if (r != sizeof(current->thread.debugreg0)) goto err;
    bytes += r;
    r = write_kern(ctx, file, &current->thread.debugreg1,
		   sizeof(current->thread.debugreg1));
    if (r != sizeof(current->thread.debugreg1)) goto err;
    bytes += r;
    r = write_kern(ctx, file, &current->thread.debugreg2,
		   sizeof(current->thread.debugreg2));
    if (r != sizeof(current->thread.debugreg2)) goto err;
    bytes += r;
    r = write_kern(ctx, file, &current->thread.debugreg3,
		   sizeof(current->thread.debugreg3));
    if (r != sizeof(current->thread.debugreg3)) goto err;
    bytes += r;
    r = write_kern(ctx, file, &current->thread.debugreg6,
		   sizeof(current->thread.debugreg6));
    if (r != sizeof(current->thread.debugreg6)) goto err;
    bytes += r;
    r = write_kern(ctx, file, &current->thread.debugreg7,
		   sizeof(current->thread.debugreg7));
    if (r != sizeof(current->thread.debugreg7)) goto err;
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
    int idx, i, cpu;
    uint16_t fsindex, gsindex;
    struct n_desc_struct tls_array[GDT_ENTRY_TLS_ENTRIES];

    r = read_kern(ctx, file, &regtmp, sizeof(regtmp));
    if (r != sizeof(regtmp)) goto bad_read;

    /* Don't let the user pick funky segments */
    if ((regtmp.cs != __USER_CS && regtmp.cs != __USER32_CS) &&
	(regtmp.ss != __USER_DS && regtmp.ss != __USER32_DS)) {
	r = -EINVAL;
	goto bad_read;
    }

    /* Set our process type */
    if (regtmp.cs == __USER32_CS)
	set_thread_flag(TIF_IA32);
    else
	clear_thread_flag(TIF_IA32);	

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
	current->thread_info->flags |= TS_USEDFPU;

	/* Invalid FPU states can blow us out of the water so we will do
	 * the restore here in such a way that we trap the fault if the
	 * restore fails.  This modeled after get_user and put_user. */
	asm volatile
	    ("1: fxrstor %1               \n"
	     "2:                          \n"
	     ".section .fixup,\"ax\"      \n"
	     "3:  movl %2, %0             \n"
	     "    jmp 2b                  \n"
	     ".previous                   \n"
	     ".section __ex_table,\"a\"   \n"
	     "    .align 8                \n"
	     "    .quad 1b, 3b            \n"
	     ".previous                   \n"
	     : "=r"(r)
	     : "m" (current->thread.i387.fxsave), "i"(-EFAULT));

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

    /*-- restore segmentation related stuff */

    /* Restore FS_BASE MSR */
    r = read_kern(ctx, file, &threadtmp.fs, sizeof(threadtmp.fs));
    if (r != sizeof(threadtmp.fs)) goto bad_read;
    if (threadtmp.fs >= TASK_SIZE) {
	r = -EINVAL;
	goto bad_read;
    }
    current->thread.fs = threadtmp.fs;
    if ((r = checking_wrmsrl(MSR_FS_BASE, threadtmp.fs)))
	goto bad_read;
	
    /* Restore GS_KERNEL_BASE MSR */
    r = read_kern(ctx, file, &threadtmp.gs, sizeof(threadtmp.gs));
    if (r != sizeof(threadtmp.gs)) goto bad_read;
    if (threadtmp.gs >= TASK_SIZE) {
	r = -EINVAL;
	goto bad_read;
    }
	
    current->thread.gs = threadtmp.gs;
    if ((r = checking_wrmsrl(MSR_KERNEL_GS_BASE, threadtmp.gs)))
	goto bad_read;

    /* Restore 32 bit segment stuff */
    r = read_kern(ctx, file, &fsindex, sizeof(fsindex));
    if (r != sizeof(fsindex)) goto bad_read;

    r = read_kern(ctx, file, &gsindex, sizeof(gsindex));
    if (r != sizeof(gsindex)) goto bad_read;

    r = read_kern(ctx, file, tls_array, sizeof(tls_array));
    if (r != sizeof(tls_array)) goto bad_read;

    /* Sanitize fs, gs.  These segment descriptors should load one
     * of the TLS entries and have DPL = 3.  If somebody is doing
     * some other LDT monkey business, I'm currently not
     * supporting that here.  Also, I'm presuming that the offsets
     * to the GDT_ENTRY_TLS_MIN is the same in both kernels. */
    idx = fsindex >> 3;
    if (idx<GDT_ENTRY_TLS_MIN || idx>GDT_ENTRY_TLS_MAX || (fsindex&7) != 3)
	fsindex = 0;
    idx = gsindex >> 3;
    if (idx<GDT_ENTRY_TLS_MIN || idx>GDT_ENTRY_TLS_MAX || (gsindex&7) != 3)
	gsindex = 0;

    /* Sanitize the TLS entries...
     * Make sure the following bits are set/not set:
     *  bit 12   : S    =  1    (code/data - not system)
     *  bit 13-14: DPL  = 11    (priv level = 3 (user))
     *  bit 21   :      =  0    (reserved)
     *
     * If the entry isn't valid, zero the whole descriptor.
     */
    for (i=0; i < GDT_ENTRY_TLS_ENTRIES; i++) {
	if (tls_array[i].b != 0 && 
	    (tls_array[i].b & 0x00207000) != 0x00007000) {
	    r = -EINVAL;
	    goto bad_read;
	}
    }

    /* Ok load this crap */
    cpu = get_cpu();	/* load_TLS can't get pre-empted. */
    memcpy(current->thread.tls_array, tls_array,
	   sizeof(current->thread.tls_array));
    current->thread.fsindex = fsindex;
    current->thread.gsindex = gsindex;
    load_TLS(&current->thread, cpu);

    loadsegment(fs, current->thread.fsindex);
    load_gs_index(current->thread.gsindex);
    put_cpu();

    /* 32 bit procs need this... */
    if (regtmp.cs == __USER32_CS) {
	loadsegment(ds, __USER32_DS);
	loadsegment(es, __USER32_DS);
    }
	
    /* XXX FIX ME: RESTORE DEBUG INFORMATION ?? */
    /* Here we read it but ignore it. */
    r = read_kern(ctx, file, &threadtmp.debugreg0,sizeof(threadtmp.debugreg0));
    if (r != sizeof(threadtmp.debugreg0)) goto bad_read;
    r = read_kern(ctx, file, &threadtmp.debugreg1,sizeof(threadtmp.debugreg1));
    if (r != sizeof(threadtmp.debugreg1)) goto bad_read;
    r = read_kern(ctx, file, &threadtmp.debugreg1,sizeof(threadtmp.debugreg2));
    if (r != sizeof(threadtmp.debugreg2)) goto bad_read;
    r = read_kern(ctx, file, &threadtmp.debugreg1,sizeof(threadtmp.debugreg3));
    if (r != sizeof(threadtmp.debugreg3)) goto bad_read;
    r = read_kern(ctx, file, &threadtmp.debugreg1,sizeof(threadtmp.debugreg6));
    if (r != sizeof(threadtmp.debugreg6)) goto bad_read;
    r = read_kern(ctx, file, &threadtmp.debugreg1,sizeof(threadtmp.debugreg7));
    if (r != sizeof(threadtmp.debugreg7)) goto bad_read;
    return 0;

 bad_read:
    if (r >= 0) r = -EIO;
    return r;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
