/*-------------------------------------------------------------------------
 *  sysdep_x86_64.c: system dependencies for AMD64/Opteron/k8/x86_64
 *
 *  Erik Hendriks <erik@hendriks.cx>
 *
 *
 *  $Id: sysdep_x86_64.c,v 1.14 2004/10/15 21:20:04 mkdist Exp $
 *-----------------------------------------------------------------------*/
#define __FRAME_OFFSETS		/* Define this one early so we get all
				 * the magical offset values from
				 * ptrace.h and offset.h */

#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/unistd.h>	/* for sys_ptrace()... */
#include <asm/offset.h>
#include <asm/uaccess.h>
#include "bproc.h"
#include "bproc_internal.h"

/* We have to do our own restore on the callee-saveds and also the top
 * of stack stuff before going to ret_from_sys_call */
__asm__(
"       .text                      \n"
"	.globl bproc_kernel_thread \n"
"bproc_kernel_thread:              \n"

/* These first three sections put something that looks like a fork
 * syscall on our stack - a full 'struct ptregs'.  rip is set so that
 * the process restoring these registers will go to bproc_child_rip in
 * the kernel segment. */

/* All this is a modified version of kernel_thread from the linux kernel */

/* FAKE_STACK_FRAME - sets up a bogus "TOP_OF_STACK" This is the first
 * part of the 'struct pt_regs' */
"	xorl %eax,%eax			 \n"
"	subq $6*8,%rsp			 \n"
"	movq %rax,5*8(%rsp)		 \n" /* ss */
"	movq %rax,4*8(%rsp)		 \n" /* rsp */
"	movq $(1<<9),3*8(%rsp)		 \n" /* eflags - enable interrupts */
"	movq $"__stringify(__KERNEL_CS)",2*8(%rsp) \n" /* cs */
"	movq $bproc_child_rip,1*8(%rsp)	 \n" /* rip */
"	movq %rax,(%rsp)		 \n" /* orig_rax */

/* SAVE_ARGS + SAVE_REST = SAVE_ALL */
/* SAVE_ARGS - store the commonly saved registers */
"	subq  $9*8,%rsp		\n"
"	movq  %rdi,8*8(%rsp)	\n"
"	movq  %rsi,7*8(%rsp)	\n"
"	movq  %rdx,6*8(%rsp)	\n"
"	movq  %rcx,5*8(%rsp)	\n"
"	movq  %rax,4*8(%rsp)	\n"
"	movq  %r8,3*8(%rsp)	\n"
"	movq  %r9,2*8(%rsp)	\n"
"	movq  %r10,1*8(%rsp)	\n"
"	movq  %r11,(%rsp)	\n"

/* SAVE_REST */
"	subq $6*8,%rsp		\n"
"	movq %rbx,5*8(%rsp)	\n"
"	movq %rbp,4*8(%rsp)	\n"
"	movq %r12,3*8(%rsp)	\n"
"	movq %r13,2*8(%rsp)	\n"
"	movq %r14,1*8(%rsp)	\n"
"	movq %r15,(%rsp)	\n"

/* Setup clone arguments */
"	movq %rdx, %rdi		\n" /* clone flags */
"	movq $-1, %rsi		\n" /* new SP, -1 is special in copy_thread) */
"	movq %rsp, %rdx		\n" /* pointer to pt_regs */
"       xorq %r8, %r8           \n" /* stack_size */
"       xorq %r9, %r9           \n" /* parent_tidptr   XXX must become arg? */
"       pushq %r9               \n" /* child_tidptr    XXX must become arg? */

"	call "__stringify(do_fork)" \n"

"	addq $22*8, %rsp	\n" /* Ditch stack frame + child_tidptr */
"	ret			\n"

"bproc_child_rip:		\n" /* child - regs are same as at the */

/* move stack pointer so that we room for a pt_regs (21*8) */
"       movq %rsp, %rdx         \n"
"       andq $-8192, %rdx       \n"
"       addq $8192-21*8, %rdx   \n"
"       movq %rdx, %rsp         \n" /* set stack pointer w/ room for ptregs */

"	movq %rdi, %rax		\n" /* Func pointer in ARG1 */
"	movq %rsp, %rdi		\n" /* ARG1 = pointer to pt_regs */
"	call *%rax		\n" /* ARG2 is still in rsi for call. */
"	movq %rax,"__stringify(RAX)"(%rsp)\n" /* save retval; it will get popped later */

/* RESTORE_TOP_OF_STACK - restores funky bits like eflags...*/
"	movq   "__stringify(RSP)"(%rsp),%r11	\n"
"	movq   %r11,%gs:"__stringify(pda_oldrsp)" \n"
"	movq   "__stringify(EFLAGS)"(%rsp),%r11	\n"
"	movq   %r11,"__stringify(R11)"(%rsp)	\n"

/* RESTORE_REST - restore the callee-saved registers */
"	movq (%rsp),%r15	\n"
"	movq 1*8(%rsp),%r14	\n"
"	movq 2*8(%rsp),%r13	\n"
"	movq 3*8(%rsp),%r12	\n"
"	movq 4*8(%rsp),%rbp	\n"
"	movq 5*8(%rsp),%rbx	\n"
"	addq $6*8,%rsp		\n"

/* ret_from_sys_call will do "RESTORE_ARGS" */
"	jmp int_ret_from_sys_call \n"
"       .previous               \n"
);

void sysdep_store_return_value(struct pt_regs *regs, int value) {
    regs->rax = value;
}


/* ptrace stuff */
int sysdep_ptrace_store_req(struct bproc_ptrace_msg_t *pt_req, 
			    long request, long pid, long addr, long data) {
#if defined(CONFIG_IA32_EMULATION)
    if (test_thread_flag(TIF_IA32)) {
	switch(request) {
	case PTRACE_SETREGS:
	    if (copy_from_user(pt_req->data.regs, (void *)data, 16 * 4))
		return -EFAULT;
	    return 0;
	}
	/* Fall thru to 64 bit */
    }
#endif
    /* 64 bit process */
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
	break;
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
#if defined(CONFIG_IA32_EMULATION)
    if (test_thread_flag(TIF_IA32)) {
	switch(request) {
	case PTRACE_PEEKDATA:
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKUSR:
	    /* this works because we're little endian...*/
	    if (put_user(pt_resp->data.data[0], (int*)data))
		return -EFAULT;
	    return 0;
	case PTRACE_GETREGS:
	    if (copy_to_user((void *)data, pt_resp->data.regs, 16 * 4))
		return -EFAULT;
	    return 0;
	}

	/* Fall thru to 64 bit (FPREGS are the same...) */
    }
#endif
    /* 64 bit process case */
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
    extern void syscall_trace_leave(struct pt_regs *);
    syscall_trace_leave(regs);
}


long sysdep_ptrace_kcall(struct bproc_ptrace_msg_t *pt_resp,
			 long req, long pid, long addr, long data) {
    long result;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);

#if defined(CONFIG_IA32_EMULATION)
    if (test_bit(TIF_IA32, &pt_resp->flags)) {
	long sys32_ptrace(long,long,long,long);
	result = sys32_ptrace(req, pid, addr, data);

	if ((req == PTRACE_PEEKTEXT || req == PTRACE_PEEKDATA) && result == 0)
	    pt_resp->bytes += sizeof(u32);
    }
    else
#endif
    {
	result = sys_ptrace(req, pid, addr, data);
	if ((req == PTRACE_PEEKTEXT || req == PTRACE_PEEKDATA) && result == 0)
	    pt_resp->bytes += sizeof(long);
    }
    set_fs(oldfs);
    return result;
}


#ifdef CONFIG_IA32_EMULATION
#include <linux/compat.h>
#include <asm/uaccess.h>
struct bproc_compat_move_t {
    u32 arg0;			/* pointer */
    u32 argv;			/* pointer */
    u32 envp;			/* pointer */
    u32 flags;
    u32 clone_flags; /* not supported yet... */
    u32 iolen;
    u32 io;			/* pointer */
    /* For vrfork, vexecmove */
    u32 nodeslen;
    u32 nodes;			/* pointer */
    u32 pids;			/* pointer */
};

struct bproc_compat_io_t {
    u32 fd;
    u16 type;
    u16 flags;
    union {
	struct sockaddr addr;
	struct {
	    u32 flags;
	    u32 mode;
	    u32 offset;
	    char  name[256];
	} file;
	/* memfile isn't allowed from user space anyway...
	struct {
	    void *base;
	    long  size;
        } mem; 
	*/
    } d;
};

int compat_get_user_args_(struct bproc_move_t *args,
			  struct bproc_move_t *user) {
    int i;
    struct bproc_compat_move_t mvtmp;
    struct bproc_compat_io_t   iotmp;

    if (copy_from_user(&mvtmp, user, sizeof(mvtmp)))
	return -EFAULT;

    args->arg0        = (char *)  (long) mvtmp.arg0;
    args->argv        = (char **) (long) mvtmp.argv;
    args->envp        = (char **) (long) mvtmp.envp;
    args->flags       = mvtmp.flags;
    args->clone_flags = mvtmp.clone_flags;
    args->iolen       = mvtmp.iolen;
    args->io          = (struct bproc_io_t *)(long) mvtmp.io;
    args->nodeslen    = mvtmp.nodeslen;
    args->nodes       = (int *) (long) mvtmp.nodes;
    args->pids        = (int *) (long) mvtmp.pids;

#if 0
    printk("args: arg0:  %p\n", args->arg0);
    printk("args: argv:  %p\n", args->argv);
    printk("args: envp:  %p\n", args->envp);
    printk("args: flags: 0x%x\n", args->flags);
    printk("args: iolen: %d\n", args->iolen);
    printk("args: io:    %p\n", args->io);
#endif

    if (args->iolen > BPROC_IO_MAX_LEN)
	return -EINVAL;

    if (args->iolen > 0) {
	struct bproc_compat_io_t *userio;
	userio = (struct bproc_compat_io_t *) args->io;

	args->io = kmalloc(args->iolen * sizeof(*args->io), GFP_KERNEL);
	if (!args->io) return -ENOMEM;

	for (i=0; i < args->iolen; i++) {
	    if (copy_from_user(&iotmp, &userio[i], sizeof(iotmp))) {
		kfree(args->io);
		return -EFAULT;
	    }

	    args->io[i].fd    = iotmp.fd;
	    args->io[i].type  = iotmp.type;
	    args->io[i].flags = iotmp.flags;
	    switch (args->io[i].type) {
	    case BPROC_IO_SOCKET:
		memcpy(&args->io[i].d.addr,&iotmp.d.addr,sizeof(iotmp.d.addr));
		break;
	    case BPROC_IO_FILE:
		args->io[i].d.file.flags  = iotmp.d.file.flags;
		args->io[i].d.file.mode   = iotmp.d.file.mode;
		args->io[i].d.file.offset = iotmp.d.file.offset;
		break;
	    default:		/* ignore... catch it later. */
		break;
	    }
	}
    }

    return 0;
}

int sysdep_get_user_args(struct bproc_move_t *args,
			 struct bproc_move_t *user) {
    if (test_thread_flag(TIF_IA32)) {
	return compat_get_user_args_(args, user);
    } else {
	/* 64bit is normal. */
	return generic_get_user_args(args, user);
    }
}

int sysdep_do_execve(char *filename, char **argv, char **envp,
		     struct pt_regs *regs) {
    if (test_thread_flag(TIF_IA32)) {
	return compat_do_execve(filename, (void *)argv, (void *) envp, regs);
    } else {
	return do_execve(filename, argv, envp, regs);
    }
}
#else
int sysdep_get_user_args(struct bproc_move_t *args, struct bproc_move_t *user){
    return generic_get_user_args(args, user);
}

int sysdep_do_execve(char *filename, char **argv, char **envp,
		     struct pt_regs *regs) {
    return do_execve(filename, argv, envp, regs);
}
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
