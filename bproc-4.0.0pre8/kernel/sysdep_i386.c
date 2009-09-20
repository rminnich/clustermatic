/*-------------------------------------------------------------------------
 *  sysdep_i386.c: system dependencies for x86
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
 * $Id: sysdep_i386.c,v 1.11 2004/10/15 21:20:04 mkdist Exp $
 *-----------------------------------------------------------------------*/
/* required to get the sys_ptrace prototype */
#define __KERNEL_SYSCALLS__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>

#include "bproc.h"
#include "bproc_internal.h"

/* This kernel thread function is a modified version of the one
 * contained in the Linux kernel.  Just the helper portion is
 * modified. */

/*
 * 1 - it does not force a CLONE_VM on you
 * 2 - it simulates syscall entry on the child by setting
 *     aside room for a struct pt_regs.  A pointer to this is
 *     the first argument to the child.  This way, the child can
 *     fill in the regs and "return" to user space if it wants to.
 */

/*
 * This gets run with %ebx containing the
 * function to call, and %edx containing
 * the "args".
 */
void bproc_kernel_thread_helper(void) {
__asm__(
/* Move our stack pointer so that we have a struct pt_regs on the
 * stack and nothing else.
 *
 * 8132 = 8k (stack size) - 60 (struct pt_regs size)
 */
"    movl  %%esp, %%eax       \n"
"    andl  %1, %%eax          \n" /* 1= -THREAD_SIZE */
"    addl  %2, %%eax          \n" /* 2= THREAD_SIZE-60 */
"    movl  %%eax, %%esp       \n"

"    pushl %%edx              \n" /* arg2 = user pointer */
"    pushl %%eax              \n" /* arg1 = pointer to regs */
"    call *%%ebx              \n" /* call func */
"    addl  $8, %%esp          \n" /* pop args */

"    movl  %%esp, %%ebx       \n" /* Store EAX to return to user space */
"    movl  %%eax, 0x18(%%ebx) \n" /* Set EAX to return to process */

/* syscall_exit requires thread_info pointer in ebp */
"    movl  %%esp, %%ebp       \n"
"    andl  %1, %%ebp          \n" /* 1= -THREAD_SIZE */
"    jmp syscall_exit         \n"

/* Magic compiler generated constants and stuff... */
: : "i" THREAD_SIZE,
    "i" (-THREAD_SIZE),
    "i" (THREAD_SIZE - sizeof(struct pt_regs)));
}

/*
 * Create a kernel thread
 */
int bproc_kernel_thread(int (*fn)(struct pt_regs *, void *),
			void * arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.ebx = (unsigned long) fn;
	regs.edx = (unsigned long) arg;
	regs.ecx = flags;

	regs.xds = __USER_DS;
	regs.xes = __USER_DS;
	regs.orig_eax = -1;
	regs.eip = (unsigned long) bproc_kernel_thread_helper;
	regs.xcs = __KERNEL_CS;
	regs.eflags = 0x286;

	/* Ok, create the new process.. */
	return do_fork(flags, 0, &regs, 0, NULL, NULL);
}

void sysdep_store_return_value(struct pt_regs *regs, int value) {
    regs->eax = value;
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
    case PTRACE_SETREGS:
	if (copy_from_user(pt_req->data.regs, (void *)data,
			   sizeof(pt_req->data.regs))) {
	    return -EFAULT;
	}
	break;
    case PTRACE_SETFPREGS:
	if (copy_from_user(pt_req->data.fpregs, (void *)data,
			   sizeof(pt_req->data.fpregs))) {
	    return -EFAULT;
	}
    case PTRACE_SETFPXREGS:
	WARNING("SETFPXREGS not implemented.");
	break;
    case PTRACE_SET_THREAD_AREA:
	WARNING("SET_THREAD_AREA not implemented.");
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
    case PTRACE_GETREGS:
	if (copy_to_user((void *)data, pt_resp->data.regs,
			 sizeof(pt_resp->data.regs)))
	    return -EFAULT;
	break;
    case PTRACE_GETFPREGS:
	if (copy_to_user((void *)data, pt_resp->data.fpregs,
			 sizeof(pt_resp->data.fpregs)))
	    return -EFAULT;
	break;
    case PTRACE_GETFPXREGS:
	WARNING("FPXREGS not implemented.");
	break;
    }
    return 0;
}

void sysdep_ptrace_syscall_trace_exit(struct pt_regs *regs) {
    extern void do_syscall_trace(struct pt_regs *, int);
    do_syscall_trace(regs, 1);
}

int sysdep_get_user_args(struct bproc_move_t *args, struct bproc_move_t *user){
    return generic_get_user_args(args, user);
}

int sysdep_do_execve(char *filename, char **argv, char **envp,
		     struct pt_regs *regs) {
    return do_execve(filename, argv, envp, regs);
}

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

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
