/*-------------------------------------------------------------------------
 *  sysdep_ppc64.c: system dependencies for PowerPC (64 bit)
 *
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
 * $Id: sysdep_ppc64.c,v 1.3 2004/10/18 19:51:47 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <asm/uaccess.h>

/* Header clashes... Ugh... */
#undef TRAP
#undef CLONE_VM
#undef CLONE_UNTRACED
#undef THREAD_SHIFT
#undef THREAD_SIZE
#include <asm/offsets.h>

#include "bproc.h"
#include "bproc_internal.h"


/* This is a lot like the system kernel thread except that it does not
 * force a CLONE_VM on you and it leaves space on the stack for a
 * struct pt_regs so that the */

/* Also for ppc64:
 *
 * This one will make sure that the TIF_32BIT flag is preserved.  This
 * is important because the children sometimes do memory space related
 * things before returning to user space.
 */
void restore_32bit(long flags) {
    if (flags & _TIF_32BIT) {
	set_thread_flag(TIF_32BIT);
    } else {
	clear_thread_flag(TIF_32BIT);
    }
}

int bproc_kernel_thread(int (*fn)(struct pt_regs *, void *),
			void *arg, unsigned long flags) {
    long register retval __asm__("r3");
    __asm__ __volatile__
	(
	 /* Make a TOC entry for the func descriptor we need to get
	  * out of here. */
	 "    .section \".toc\",\"aw\"\n"
	 ".RFSC:                      \n"
	 "    .tc ret_from_sys_call[TC],ret_from_sys_call \n"
	 "    .previous               \n"

	 "    stdu    1,-%[sfo](1)    \n"
	 "    std     29,%[sfo]-24(1) \n"
	 "    std     30,%[sfo]-16(1) \n"
	 "    std     31,%[sfo]-8 (1) \n"

	 "    clrrdi  29,1,%[thrsft]  \n" /* current->thread */
	 "    ld      29,%[tflgs](29) \n" /* store flags */

	 "    mr      30,3            \n" /* function */
	 "    mr      31,4            \n" /* argument */

	 "    mr      3,5             \n" /* flags */
	 "    li      4,0             \n" /* new sp == 0 (unused) */
	 "    li      0,%[NRclone]    \n" /* r0 = NR_clone */
	 "    sc                      \n"

	 "    cmpi    0,3,0           \n" /* parent or child? */
	 "    bne     1f              \n" /* return if parent */

	 "    li      0,0             \n" /* make top-level stack frame */
	 "    stdu    0,-%[sfo]-%[ptr](1) \n"

	 "    mr      3, 29           \n" /* restore TIF_32BIT */
	 "    bl      .restore_32bit  \n"

	 /* Call user function (load func descriptor first) */
	 "    ld      2,8(30)         \n" /* load global ptr from descriptor*/
	 "    ld      30,0(30)        \n" /* load function addr */
	 "    mtlr    30              \n" /* fn addr in lr */

	 "    addi    3,1,%[sfo]      \n" /* arg0 = ptr to regs */
	 "    mr      4,31            \n" /* arg1 = user arg (saved) */
	 "    blrl                    \n" /* call! */

	 /* Load function descriptor crap to get back.. */
	 "    ld      31, .RFSC@toc(2)\n" /* get symbol address */
	 "    ld      2,  8(31)       \n" /* global ptr */
	 "    ld      31, 0(31)       \n" /* func ptr*/
	 "    mtlr    31              \n"

	 /* ret_from_syscall isn't gonna restore this stuff... */
#define LOAD_REG(n) "    ld      " n ", %[gpr0]+8*" n "(1) \n"
	                                 LOAD_REG("14")	 LOAD_REG("15")
	 LOAD_REG("16")	 LOAD_REG("17")	 LOAD_REG("18")	 LOAD_REG("19")
	 LOAD_REG("20")	 LOAD_REG("21")	 LOAD_REG("22")	 LOAD_REG("23")
	 LOAD_REG("24")	 LOAD_REG("25")	 LOAD_REG("26")	 LOAD_REG("27")
	 LOAD_REG("28")	 LOAD_REG("29")	 LOAD_REG("30")	 LOAD_REG("31")

	 /* Return to user space */
	 "    blr                    \n"

	 /* Parent return */
	 "1:  ld      29,%[sfo]-24(1) \n"
	 "    ld      30,%[sfo]-16(1) \n"
	 "    ld      31,%[sfo]-8(1)  \n"
	 "    addi    1,1,%[sfo]      \n"
	 "    blr                     \n"

	 : "=r" (retval)
	 /* Constants that this chunk wants to use */
	 : [NRclone] "i" (__NR_clone),
	   [sfo]     "i" (STACK_FRAME_OVERHEAD),
	   [ptr]     "i" (sizeof(struct pt_regs)),
	   [gpr0]    "i" (STACK_FRAME_OVERHEAD + 
			  offsetof(struct pt_regs,gpr[0])),
	   [thrsft]  "i" (THREAD_SHIFT),
	   [tflgs]   "i" (offsetof(struct thread_info,flags))
	 : "memory");

    return retval;
}

/*--------------------------------------------------------------------
 *  ptrace stuff
 */
/* store req stores user data in the ptrace request */
int sysdep_ptrace_store_req(struct bproc_ptrace_msg_t *pt_req, 
			    long request, long pid, long addr, long data) {
    if (test_thread_flag(TIF_32BIT)) {
	switch (request) {
	case PPC_PTRACE_SETREGS:
	    if (copy_from_user(pt_req->data.regs, (void *)data, 32 * 4))
		return -EFAULT;
	    return 0;
	}
	/* Fall thru to 64 bit default */
    }
    WARNING("Way more ptrace request types to deal with");

    /* 64-bit process defaults */
    switch (request) {
    case PTRACE_SETSIGINFO:
	WARNING("PTRACE_SETSIGINFO not implemented.");
	break;
    case PPC_PTRACE_SETREGS:
	if (copy_from_user(pt_req->data.regs, (void *)data,
			   sizeof(pt_req->data.regs))) {
	    return -EFAULT;
	}
	break;
    case PPC_PTRACE_SETFPREGS:
	if (copy_from_user(pt_req->data.fpregs, (void *)data,
			   sizeof(pt_req->data.fpregs))) {
	    return -EFAULT;
	}
	break;
    }
    return 0;
}

int sysdep_ptrace_store_user(struct bproc_ptrace_msg_t *pt_resp,
			     long request, long pid, long addr, long data) {
    if (test_thread_flag(TIF_32BIT)) {
	switch(request) {
	case PTRACE_PEEKDATA:
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKUSR:
	    if (copy_to_user((int *)data, &pt_resp->data.data[0], sizeof(int)))
		return -EFAULT;
	    break;
	case PPC_PTRACE_GETREGS:
	    if (copy_to_user((void *)data, pt_resp->data.regs, 32 * 4))
		return -EFAULT;
	    break;
	}
    }

    switch (request) {
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKUSR:
	if (put_user(pt_resp->data.data[0], (long*)data))
	    return -EFAULT;
	break;
    case PPC_PTRACE_GETREGS:
	if (copy_to_user((void *)data, pt_resp->data.regs,
			 sizeof(pt_resp->data.regs)))
	    return -EFAULT;
	break;
    case PPC_PTRACE_GETFPREGS:
	if (copy_to_user((void *)data, pt_resp->data.fpregs,
			 sizeof(pt_resp->data.fpregs)))
	    return -EFAULT;
	break;
    }
    return 0;
}

void sysdep_ptrace_syscall_trace_exit(struct pt_regs *regs) {
    extern void do_syscall_trace_leave(struct pt_regs *, int);
    do_syscall_trace_leave(regs, 1);
}

long sysdep_ptrace_kcall(struct bproc_ptrace_msg_t *pt_resp,
			 long req, long pid, long addr, long data) {
    long result;
    mm_segment_t oldfs;

    oldfs = get_fs(); set_fs(KERNEL_DS);
    if (test_bit(TIF_32BIT, &pt_resp->flags)) {
	/* 32-bit compat case */
	int sys32_ptrace(long,long,long,long);
	result = sys32_ptrace(req, pid, addr, data);
	if ((req == PTRACE_PEEKTEXT || req == PTRACE_PEEKDATA) && result == 0)
	    pt_resp->bytes += sizeof(u32);
    } else {
	/* 64-bit normal case */
	result = sys_ptrace(req, pid, addr, data);
	if ((req == PTRACE_PEEKTEXT || req == PTRACE_PEEKDATA) && result == 0)
	    pt_resp->bytes += sizeof(long);
    }
    set_fs(oldfs);
    return result;
}


void sysdep_store_return_value(struct pt_regs *regs, int value) {
    regs->gpr[3] = value;
}


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

static
int compat_get_user_args(struct bproc_move_t *args,
			 struct bproc_move_t *user) {
    int i;
    struct bproc_compat_move_t mvtmp;
    struct bproc_compat_io_t   iotmp;

    if (copy_from_user(&mvtmp, user, sizeof(mvtmp)))
	return -EFAULT;

    args->arg0        = compat_ptr(mvtmp.arg0);
    args->argv        = compat_ptr(mvtmp.argv);
    args->envp        = compat_ptr(mvtmp.envp);
    args->flags       = mvtmp.flags;
    args->clone_flags = mvtmp.clone_flags;
    args->iolen       = mvtmp.iolen;
    args->io          = compat_ptr(mvtmp.io);
    args->nodeslen    = mvtmp.nodeslen;
    args->nodes       = compat_ptr(mvtmp.nodes);
    args->pids        = compat_ptr(mvtmp.pids);

#if 0
    printk("\n");
    printk("args: arg0:  %p\n", args->arg0);
    printk("args: argv:  %p\n", args->argv);
    printk("args: envp:  %p\n", args->envp);
    printk("args: flags: 0x%x\n", args->flags);
    printk("args: iolen: %d\n", args->iolen);
    printk("args: io:    %p\n", args->io);
    printk("args: nodeslen = %d\n", args->nodeslen);
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

int sysdep_get_user_args(struct bproc_move_t *args, struct bproc_move_t *user){
    if (test_thread_flag(TIF_32BIT)) {
	return compat_get_user_args(args, user);
    } else {
	/* 64bit is normal. */
	return generic_get_user_args(args, user);
    }
}

int sysdep_do_execve(char *filename, char **argv, char **envp,
		     struct pt_regs *regs) {
    if (test_thread_flag(TIF_32BIT)) {
	/* The prototype for compat_do_execve is screwed up... we'll
	 * just play along here */
	return compat_do_execve(filename, (void *)argv, (void *) envp, regs);
    } else {
	return do_execve(filename, argv, envp, regs);
    }
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
