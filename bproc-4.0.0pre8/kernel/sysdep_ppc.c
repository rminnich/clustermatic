/*-------------------------------------------------------------------------
 *  sysdep_ppc.c: system dependencies for PowerPC (32 bit)
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
 * $Id: sysdep_ppc.c,v 1.5 2004/10/15 21:20:04 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <asm/uaccess.h>

/* Header clashes... Ugh... */
#undef TRAP
#undef CLONE_VM
#undef CLONE_UNTRACED
#include <asm/offsets.h>

#include "bproc.h"
#include "bproc_internal.h"

/* This is a lot like the system kernel thread except that it does not
 * force a CLONE_VM on you and it leaves space on the stack for a
 * struct pt_regs so that the */
int bproc_kernel_thread(int (*fn)(struct pt_regs *, void *),
			void *arg, unsigned long flags) {
    long register retval __asm__("r3");
    __asm__ __volatile__
	(
	 "    stwu    1,-%[sfo](1)  \n"
	 "    stw     30,8(1)       \n"
	 "    stw     31,12(1)      \n"

	 "    mr      30,3          \n"	/* function */
	 "    mr      31,4          \n"	/* argument */
	 "    mr      3,5           \n"	/* flags */

	 "    li      4,0           \n" /* new sp == 0 (unused) */
	 "    li      0,%[NRclone]  \n"	/* r0 = NR_clone */
	 "    sc                    \n"

	 "    cmpi    0,3,0         \n"  /* parent or child? */
	 "    bne     1f            \n"  /* return if parent */

	 "    li      0,0           \n" /* make top-level stack frame */
	 "    stwu    0,-%[sfo]-%[ptr](1) \n"

	 /* Call user function */
	 "    mtlr    30            \n"  /* fn addr in lr */
	 "    addi    3,1,%[sfo]    \n"  /* arg0 = ptr to regs */
	 "    mr      4,31          \n"  /* arg1 = user arg (saved) */
	 "    blrl                  \n"

	 /* ret_from_syscall isn't gonna restore this stuff... */
	 "    lwz     13,"__stringify(GPR13)"(1) \n" /* REST_NVGPRS */
	 "    lwz     14,"__stringify(GPR14)"(1) \n"
	 "    lwz     15,"__stringify(GPR15)"(1) \n"
	 "    lwz     16,"__stringify(GPR16)"(1) \n"
	 "    lwz     17,"__stringify(GPR17)"(1) \n"
	 "    lwz     18,"__stringify(GPR18)"(1) \n"
	 "    lwz     19,"__stringify(GPR19)"(1) \n"
	 "    lwz     20,"__stringify(GPR20)"(1) \n"
	 "    lwz     21,"__stringify(GPR21)"(1) \n"
	 "    lwz     22,"__stringify(GPR22)"(1) \n"
	 "    lwz     23,"__stringify(GPR23)"(1) \n"
	 "    lwz     24,"__stringify(GPR24)"(1) \n"
	 "    lwz     25,"__stringify(GPR25)"(1) \n"
	 "    lwz     26,"__stringify(GPR26)"(1) \n"
	 "    lwz     27,"__stringify(GPR27)"(1) \n"
	 "    lwz     28,"__stringify(GPR28)"(1) \n"
	 "    lwz     29,"__stringify(GPR29)"(1) \n"
	 "    lwz     30,"__stringify(GPR30)"(1) \n"
	 "    lwz     31,"__stringify(GPR31)"(1) \n"

	 /* Return to user space */
	 "    b       ret_from_syscall \n"

	 "1:  lwz     30,8(1)       \n"
	 "    lwz     31,12(1)      \n"
	 "    addi    1,1,%[sfo]    \n"
	 "    blr                   \n"

	 : "=r" (retval)
	 : [NRclone] "i" (__NR_clone),
	   [ptr]     "i" (sizeof(struct pt_regs)),
	   [sfo]     "i" (STACK_FRAME_OVERHEAD)
	 : "memory");

    return retval;
}

/*--------------------------------------------------------------------
 *  ptrace stuff
 */
int sysdep_ptrace_store_req(struct bproc_ptrace_msg_t *pt_req, 
			    long request, long pid, long addr, long data) {
    WARNING("Way more ptrace request types to deal with");
    switch (request) {
    case PTRACE_SETSIGINFO:
	WARNING("SETSIGINFO not implemented.");
	break;
    }
    return 0;
}

int sysdep_ptrace_store_user(struct bproc_ptrace_msg_t *pt_resp,
			     long request, long pid, long addr, long data) {
    switch (request) {
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKUSR:
	if (put_user(pt_resp->data.data[0], (long*)data))
	    return -EFAULT;
	break;
    }
    return 0;
}

void sysdep_ptrace_syscall_trace_exit(struct pt_regs *regs) {
    extern void do_syscall_trace(struct pt_regs *, int);
    do_syscall_trace(regs, 1);
}

asmlinkage int sys_ptrace(long request, long pid, long addr, long data);
long sysdep_ptrace_kcall(struct bproc_ptrace_msg_t *pt_resp,
			 long req, long pid, long addr, long data) {
    long result;
    mm_segment_t oldfs;

    oldfs = get_fs(); set_fs(KERNEL_DS);
    result = sys_ptrace(req, pid, addr, data);
    if ((req == PTRACE_PEEKTEXT || req == PTRACE_PEEKDATA) && result == 0)
	pt_resp->bytes += sizeof(long);
    set_fs(oldfs);
    return result;
}

void sysdep_store_return_value(struct pt_regs *regs, int value) {
    regs->gpr[3] = value;
}

int sysdep_get_user_args(struct bproc_move_t *args, struct bproc_move_t *user){
    return generic_get_user_args(args, user);
}

int sysdep_do_execve(char *filename, char **argv, char **envp,
		     struct pt_regs *regs) {
    return do_execve(filename, argv, envp, regs);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
