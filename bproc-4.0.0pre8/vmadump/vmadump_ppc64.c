/*-------------------------------------------------------------------------
 *  vmadump_powerpc.c:  powerpc specific dumping/undumping routines
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
 * $Id: vmadump_ppc64.c,v 1.1 2004/10/09 01:08:00 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/processor.h>

#define __VMADUMP_INTERNAL__
#include "vmadump.h"

extern
ssize_t write_kern(struct vmadump_map_ctx *ctx, struct file *file,
		   const void *buf, size_t count);

long vmadump_store_cpu(struct vmadump_map_ctx *ctx, struct file *file,
		       struct pt_regs *regs) {
    long bytes = 0, r;

    /* Store struct pt_regs */
    r = write_kern(ctx, file, regs, sizeof(*regs));
    if (r != sizeof(*regs)) goto err;
    bytes += r;

    /* Floating point regs */
    if (regs->msr & MSR_FP)
	giveup_fpu(current);
    r = write_kern(ctx, file, &current->thread.fpr,
		   sizeof(current->thread.fpr));
    if (r != sizeof(current->thread.fpr)) goto err;
    bytes += r;

    r = write_kern(ctx, file, &current->thread.fpscr,
		   sizeof(current->thread.fpscr));
    if (r != sizeof(current->thread.fpscr)) goto err;
    bytes += r;
#ifdef CONFIG_ALTIVEC
    /* XXX I really need to find out if this is right */
    if (regs->msr & MSR_VEC)
	giveup_altivec(current);
    r = write_kern(ctx, file, &current->thread.vr,
		   sizeof(current->thread.vr));
    if (r != sizeof(current->thread.vr)) goto err;
    bytes += r;

    r = write_kern(ctx, file, &current->thread.vscr,
		   sizeof(current->thread.vscr));
    if (r != sizeof(current->thread.vscr)) goto err;
    bytes += r;
#endif
    return bytes;

 err:
    if (r >= 0) r = -EIO;
    return r;
}


int vmadump_restore_cpu(struct vmadump_map_ctx *ctx, struct file *file,
			struct pt_regs *regs) {
    struct pt_regs regtmp;
    int r;

    r = read_kern(ctx, file, &regtmp, sizeof(regtmp));
    if (r != sizeof(regtmp)) goto bad_read;

    /* Don't restore machine state register since this is
     * unpriviledged user space stuff we're restoring. */
    if (regtmp.msr & MSR_SF) {
	regtmp.msr = MSR_USER64;
	clear_thread_flag(TIF_32BIT);
    } else {
	regtmp.msr = MSR_USER32;
	set_thread_flag(TIF_32BIT);
    }
    memcpy(regs, &regtmp, sizeof(regtmp));

    /* Floating point regs */
    r = read_kern(ctx, file, &current->thread.fpr,
		  sizeof(current->thread.fpr));
    if (r != sizeof(current->thread.fpr)) goto bad_read;

    r = read_kern(ctx, file, &current->thread.fpscr,
		  sizeof(current->thread.fpscr));
    if (r != sizeof(current->thread.fpscr)) goto bad_read;

#ifdef CONFIG_ALTIVEC
    /* Restore Altivec */
    r = read_kern(ctx, file, &current->thread.vr,
		  sizeof(current->thread.vr));
    if (r != sizeof(current->thread.vr)) goto bad_read;

    r = read_kern(ctx, file, &current->thread.vscr,
		  sizeof(current->thread.vscr));
    if (r != sizeof(current->thread.vscr)) goto bad_read;
#endif

    current->thread.regs = regs;
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
