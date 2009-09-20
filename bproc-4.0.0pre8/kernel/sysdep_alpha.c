/*-------------------------------------------------------------------------
 *  sysdep_alpha.c: system dependencies for alpha
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: sysdep_alpha.c,v 1.3 2004/04/28 17:21:46 mkdist Exp $
 *-----------------------------------------------------------------------*/
#define __NO_VERSION__

#include <linux/config.h>
#if defined(CONFIG_SMP) && ! defined(__SMP__)
#define __SMP__
#endif

#include <linux/sched.h>

#include "bproc.h"
#include "bproc_internal.h"

/* This is a version of kernel_thread() with three differences.
 * 1 - it does not force a CLONE_VM on you
 * 2 - it simulates syscall entry on the child by setting
 *     aside room for a struct pt_regs.  A pointer to this is
 *     the first argument to the child.  This way, the child can
 *     fill in the regs and "return" to user space if it wants to.
 * 3 - it doesn't throw away USP.
 */
int bproc_kernel_thread(int (*fn)(struct pt_regs *, void *),
			void *arg, unsigned long flags);
__asm__(
".align 3                   \n"
".ent   bproc_kernel_thread \n"
".globl bproc_kernel_thread \n"
"bproc_kernel_thread:       \n"
"        ldgp $29, 0($27)   \n"
"        .frame $30, 3*8, $26 \n"
"        subq $30,3*8,$30   \n"
"        stq  $26, 0($30)   \n"
"        stq  $9,  8($30)   \n"
"        stq  $10, 16($30)  \n"
"        .prologue 1        \n"
"        mov $16, $9        \n"
"        mov $17, $10       \n"
"        mov $18, $16       \n"
"        mov $31, $17       \n"	/* zero out the USP argument so that we preserve USP */
"        jsr $26, kernel_clone \n"
"        ldgp $29, 0($26)   \n"
"        bne $0,  1f        \n"

/* Child... */
/* Setup the stack */
"        lda $8, 0x3fff     \n" /* get current */
"        bic $30,$8,$8      \n"
"        lda $30, 15832($8) \n" /* 15832 = 16k-(sizeof(ptregs)+sizeof(switchstack)) */

/* Call fn */
"        lda  $16, 320($30) \n" /* a0 = pt_reg pointer */
"        mov  $10, $17      \n" /* a1 = arg */
"        mov   $9, $27      \n" /* Procs are only happy if called with t12 ($27) */
"        jsr  $26, ($27)    \n" /* jump to procedure */
"        ldgp $29, 0($26)   \n" /* Restore GP */

/* Return to user space */
"        jmp ret_to_user_space \n"

/* Parent */
"        1:                 \n"
"        ldq $26, 0($30)    \n"
"        ldq $9,  8($30)    \n"
"        ldq $10, 16($30)   \n"
"        addq $30,3*8,$30   \n"
"        ret $31,($26)      \n"

".end   bproc_kernel_thread \n"
);

#define SWITCH_STACK_SIZE "320"

asm(
".align 3                             \n"
".globl  sys_bproc                    \n"
".ent    sys_bproc                    \n"
"sys_bproc:                           \n"
"        ldgp    $29,0($27)           \n"
"        jsr     $1,do_switch_stack   \n" /*Won't disturb GP*/
"        lda     $16, 320($30)        \n" /*320 = sizeof(struct switch_stack)*/
"        jsr     $26,do_bproc         \n"
"        ldgp    $29,0($26)           \n"
"        jsr     $1,undo_switch_stack \n"
"        ret     $31,($26),1          \n"
".end    sys_bproc                    \n"
);

void store_return_value(struct pt_regs *regs, int value) {
    /* This steps on the special return mechanism that ptrace() uses
     * but it's ok since we're not trying to return an error. */
    regs->r0  = value;		/* v0       <= return value */
    regs->r19 = 0;		/* a3 == 0  <= no error */
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
