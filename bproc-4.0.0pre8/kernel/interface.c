/*-------------------------------------------------------------------------
 *  interface.c:  userland interface code
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
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
 * $Id: interface.c,v 1.117 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/mman.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/completion.h>
#include <linux/sysctl.h>
#include <linux/ptrace.h>
#include <linux/compat.h>
#include <linux/bproc.h>
#include <asm/uaccess.h>

#include "vmadump.h"
#include "bproc.h"
#include "bproc_internal.h"

MODULE_AUTHOR("Erik Hendriks <erik@hendriks.cx>");
MODULE_DESCRIPTION("bproc: Beowulf Distributed Process Space Version "
		   __stringify(PACKAGE_VERSION));
MODULE_LICENSE("GPL");

/**------------------------------------------------------------------------
 ** Memory file interface
 **----------------------------------------------------------------------*/
static
int memfile_open(struct inode *ino, struct file *filp) {
    return 0;
}

static
int memfile_release(struct inode *ino, struct file *filp) {
    return 0;
}

static
ssize_t memfile_read(struct file *filp, char *buff, size_t rsize, loff_t *l) {
    void *tmpbuf;
    int chunk;
    size_t left;
    loff_t pos;
    void * base;
    long   size;

    base = filp->f_dentry->d_inode->u.generic_ip;
    size = filp->f_dentry->d_inode->i_size;

    if (!base) return 0;	/* file not configured */
    if (!(tmpbuf = (void *)__get_free_page(GFP_KERNEL)))
	return -ENOMEM;

    pos = *l;
    if (pos + rsize > size)
	rsize = size - pos; /* restrict to file size. */

    left = rsize;
    while (left > 0) {
	chunk = left > PAGE_SIZE ? PAGE_SIZE : left;
	/* XXX is there some easy way to do a user->user copy? */
	if (copy_from_user(tmpbuf, base + pos, chunk) ||
	    copy_to_user(buff, tmpbuf, chunk)) {
	    free_page((long)tmpbuf);
	    return -EFAULT;
	}
	left -= chunk;
	pos  += chunk;
	buff += chunk;
    }
    *l = pos;

    free_page((long)tmpbuf);
    return rsize;
}

/* XXX might need mmap here.... */

struct file_operations bproc_memfile_fops = {
    open:    memfile_open,
    release: memfile_release,
    read:    memfile_read,
};

/**------------------------------------------------------------------------
 ** Syscall interface for application programs.
 **----------------------------------------------------------------------*/

#ifdef ENABLE_DEBUG
/* XXX THESE ARE THE DEBUG INTERFACES FOR PEOPLE HACKING ON BPROC.  IF
 * XXX YOU ARE ANYTHING OTHER THAN A TEST PROGRAM THESE INTERFACES ARE
 * XXX NOT FOR YOU.  THESE INTERFACES WILL CHANGE OR GO AWAY AT ANY
 * XXX POINT.  */

struct debug_kt_struct {
    struct completion compl;
    struct pt_regs *regs;
};

struct debug_ptbl {
    long addr;
    long pgd;
    long pmd;
    long pte;
};

#if 0
static int debug_kt_stub(struct pt_regs *regs, void *arg) {
    struct debug_kt_struct *dbkts = arg;


    /*printk("ARG2 = %p", arg);
    printk("dbkts->regs = %p", dbkts->regs);
    printk(", NIP = %p\n", (void *)dbkts->regs->nip);
    printk("MSR=%lx\n", dbkts->regs->msr);

    printk("current=%p current->thread=%p regs=%p\n",
    current, current->thread_info, regs);*/
    

    printk("current=%p current->thread=%p regs=%p (%lx)\n",
	   current, current->thread_info, regs,
	   ((long)regs) - ((long)current->thread_info));
    memcpy(regs, dbkts->regs, sizeof(*regs)); /* copy regs from the parent */
    /*reg_dump(regs);*/

    complete(&dbkts->compl);
    printk("debug_kt_stub1 %d %x %lx\n", current->pid,
	   test_thread_flag(TIF_SYSCALL_TRACE), current->ptrace);
    return 0;
}
#endif

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
static
long do_debug(struct pt_regs *regs, long arg1, long arg2) {
    switch(arg1) {
    case 0: {			/* Return number of children */
	int ct;
	struct list_head *l;
	read_lock(&tasklist_lock);
	ct = 0;
	for (l = current->children.next; l != &current->children; l = l->next)
	    ct++;
	for (l = current->ptrace_children.next;
	     l != &current->ptrace_children; l = l->next)
	    ct++;
	if (BPROC_ISMASQ(current)) ct += current->bproc.nlchild;
	read_unlock(&tasklist_lock);
	return ct;
    }
    case 2:			/* return the value of nlchild */
	if (BPROC_ISMASQ(current))
	    return current->bproc.nlchild;
	else
	    return 0;
    case 1: {			/* return whether or not wait will be handled locally */
	struct task_struct *task;
	if (!BPROC_ISMASQ(current)) return 1;
	if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag)) {
	    printk("bproc flag kcall set for masq proc in user space.\n");
	    return 1;
	}
	if (arg2 > 0) {
	    read_lock(&tasklist_lock);
	    task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), arg2);
	    read_unlock(&tasklist_lock);
	    if (task) return 1;
	}
	if (current->bproc.nlchild == 0) return 1;
	return 0;
    }
    case 3: {			/* local process ID sanity check */
	struct {
	    u32 mppid, moppid;
	    u32 rppid, roppid;
	} tmp;
	struct task_struct *task;
	read_lock(&tasklist_lock);
	if (BPROC_ISMASQ(current)) {
	    tmp.mppid  = current->bproc.ppid;
	    tmp.moppid = current->bproc.oppid;
	    if (BPROC_ISMASQ(current->parent))
		tmp.rppid = current->parent->bproc.pid;
	    else {
		tmp.rppid = -1;	/* parent is not masq... */
		/* check if it's on this machine or not (and not dead) */
		if ((task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current),
						  current->bproc.ppid)))
		    if (task->state < TASK_ZOMBIE)
			tmp.rppid = -2; /* error this should be our parent */
	    }
	    if (BPROC_ISMASQ(current->real_parent))
		tmp.roppid = current->real_parent->bproc.pid;
	    else {
		tmp.roppid = -1;
		if ((task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current),
						  current->bproc.oppid)))
		    if (task->state < TASK_ZOMBIE)
			tmp.roppid = -2; /* error this should be our parent */
	    }
	} else {
	    tmp.mppid = tmp.rppid = current->parent->pid;
	    tmp.moppid= tmp.roppid= current->real_parent->pid;
	}
	read_unlock(&tasklist_lock);
	if (copy_to_user((void *)arg2, &tmp, sizeof(tmp)))
	    return -EFAULT;
	return 0;
    }
    case 4: {			/* Test the kernel thread  */
#if 0
	int pid;
	struct debug_kt_struct dbkts;
	init_completion(&dbkts.compl);
	dbkts.regs = regs;

	printk("current=%p current->thread=%p regs=%p (%lx)\n",
	       current, current->thread_info, regs,
	       ((long)regs) - ((long)current->thread_info));
	
	printk("ARG1 = %p,", &dbkts);
	printk("dbkts->regs = %p,", dbkts.regs);
	printk("NIP = %p\n", (void*)regs->nip);
	printk("MSR=%lx\n", dbkts.regs->msr);
	printk("MSR1=%lx\n", dbkts.regs->msr);
	pid = bproc_kernel_thread(debug_kt_stub, &dbkts, arg2);
	printk("MSR2=%lx\n", dbkts.regs->msr);
	wait_for_completion(&dbkts.compl);
	printk("MSR3=%lx\n", dbkts.regs->msr);
	printk("got it.\n");
	return pid;
#else
	return -ENOSYS;
#endif
    }
#if 0
    case 5: {			/* get a single pte */
	pgd_t *pgd, pgdval;
	pmd_t *pmd, pmdval;
	pte_t *pte, pteval;
	long addr;
	struct mm_struct *mm = current->mm;

	struct debug_ptbl *ptbl = (struct debug_ptbl *) arg2;
	if (get_user(addr, (long *) arg2))
	    return -EFAULT;

	pgdval.pgd = pmdval.pmd = pteval.pte_low = 0;
	spin_lock(&mm->page_table_lock);
	pgd = pgd_offset(mm, addr);
	if (!pgd_none(*pgd)) {
	    pgdval = *pgd;
	    pmd = pmd_offset(pgd, addr);
	    if (!pmd_none(*pmd)) {
		pmdval = *pmd;
		if (!pmd_large(*pmd)) {
		    pte = pte_offset_map(pmd, addr);
		    if (!pte_none(*pte)) {
			pteval = *pte;
		    }
		    pte_unmap(pte);
		}
	    }
	}
	spin_unlock(&mm->page_table_lock);

	if (put_user(pgdval.pgd, &ptbl->pgd))     return -EFAULT;
	if (put_user(pmdval.pmd, &ptbl->pmd))     return -EFAULT;
	if (put_user(pteval.pte_low, &ptbl->pte)) return -EFAULT;
	return 0;
    }
#endif
    case 6: {			/* get a single pte */
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	long pfn;
	long addr = arg2;
	struct mm_struct *mm = current->mm;

	pfn = 0;
	spin_lock(&mm->page_table_lock);
	pgd = pgd_offset(mm, addr);
	if (!pgd_none(*pgd)) {
	    pmd = pmd_offset(pgd, addr);
	    if (!pmd_none(*pmd)) {
		pte = pte_offset_map(pmd, addr);
		pfn = pte_pfn(*pte);
		pte_unmap(pte);
	    }
	}
	spin_unlock(&mm->page_table_lock);
	return pfn;
    }
    }
    return -EINVAL;
}
#endif


static
int do_control_async(int cmd, int node) {
    int ret;
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;

    if (BPROC_ISMASQ(current)) return -ENOSYS;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    ret = nodeset_nodeup(node);	/* Check that the node is available to us */
    if (ret) return ret;

    req = bproc_new_req(cmd, sizeof(*msg), GFP_KERNEL);
    if (!req) return -ENOMEM;
    msg = bproc_msg(req);
    bpr_to_node(msg, node);
    bpr_from_real(msg, BPROC_MASQ_PID(current));
    ret = bproc_send_req(&bproc_ghost_reqs, req);
    bproc_put_req(req);
    return ret;
}

/* Little functions to do random things */

static
int do_control(int cmd, int node, void *arg) {
    int ret;
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;

    if (BPROC_ISMASQ(current))   return -ENOSYS;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    /* Special cases for request data packing */
    switch(cmd) {
    case BPROC_NODE_CHROOT: {
	char *path;
	struct bproc_chroot_msg_t *msg;

	/* Get the pathname from user space */
	path = getname((char *)arg);
	if (IS_ERR(path)) return PTR_ERR(path);

	req = bproc_new_req(cmd, sizeof(*msg) + strlen(path)+1, GFP_KERNEL);
	if (!req) {
	    putname(path);
	    return -ENOMEM;
	}
	msg = bproc_msg(req);
	strcpy(msg->path, path);
	putname(path);
	} break;
    case BPROC_NODE_RECONNECT: {
	struct bproc_connect_t *c = (struct bproc_connect_t*)arg;
	struct bproc_reconnect_msg_t *msg;

	req = bproc_new_req(cmd, sizeof(*msg), GFP_KERNEL);
	if (!req) 
	    return -ENOMEM;
	msg = bproc_msg(req);
	
	if (copy_from_user(&msg->conn, c, sizeof(msg->conn))) {
	    bproc_put_req(req);
	    return -EFAULT;
	}
	} break;
    default:
	return -EINVAL;
    }

    msg = bproc_msg(req);
    bpr_to_node(msg, node);
    bpr_from_real(msg, BPROC_MASQ_PID(current));

    /* Synchronous request - wait for response but be interruptible */
    req->flags |= BPROC_REQ_WANT_RESP;
    ret = bproc_send_req(&bproc_ghost_reqs, req);
    if (ret == 0) {
	ret = bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, 1);
	if (ret == 0) {
	    msg = bproc_msg(req->response);
	    ret = msg->hdr.result;
	}
    }
    bproc_put_req(req);
    return ret;
}

/*--------------------------------------------------------------------
 *
 */
int generic_get_user_args(struct bproc_move_t *args,
			  struct bproc_move_t *user) {
    if (copy_from_user(args, user, sizeof(*args)))
	return -EFAULT;

    if (args->iolen > BPROC_IO_MAX_LEN)
	return -EINVAL;

    if (args->iolen > 0) {
	struct bproc_io_t *userio;
	userio = args->io;

	args->io = kmalloc(args->iolen * sizeof(*args->io),GFP_KERNEL);
	if (!args->io) return -ENOMEM;

	if (copy_from_user(args->io, userio,
			   args->iolen * sizeof(*userio))) {
	    kfree(args->io);
	    return -EFAULT;
	}
    } else {
	args->io = 0;
    }
    return 0;
}

static
int get_move_args(struct bproc_kmove_t *args, struct bproc_move_t *user) {
    int i, r;

    memset(args, 0, sizeof(*args));
    r = sysdep_get_user_args(&args->user, user);
    if (r) return r;

    /* sanity checking - the user is not allowed to specify MEMFILE */
    for (i=0; i < args->user.iolen; i++) {
	if (args->user.io[i].type == BPROC_IO_MEMFILE) {
	    kfree(args->user.io);
	    return -EPERM;
	}
    }
    if (args->user.nodeslen < 0) {
	if (args->user.iolen > 0) kfree(args->user.io);
	return -EINVAL;
    }

    /* The nodes and pids arrays are left in user space */
    args->creds = kmalloc(creds_size(current), GFP_KERNEL);
    if (!args->creds) {
	if (args->user.iolen > 0) kfree(args->user.io);
	return -ENOMEM;
    }
    creds_store(args->creds);
    return 0;
}

static
void put_move_args(struct bproc_kmove_t *args) {
    if (args->user.iolen > 0)
	kfree(args->user.io);
    kfree(args->creds);
}

/*-------------------------------------------------------------------------
 * rfork
 */
struct rfork_info {
    struct completion    *compl;
    int                   node;
    struct bproc_kmove_t *req;
    struct pt_regs       *regs;
    int                   status;
};

static
int do_execmove_execve(struct bproc_kmove_t *move, struct pt_regs *regs);
static int suid_execmove = 1;



static
int rfork_stub(struct pt_regs *regs, struct rfork_info *info) {
    int pid;

    memcpy(regs, info->regs, sizeof(*regs));
#if defined(__alpha__)
    /* We also need to copy the "switch_stack" part that lives before
     * struct pt_regs on alpha. */
    memcpy(((struct switch_stack *)regs)-1,
	   ((struct switch_stack *)(info->regs))-1,
	   sizeof(struct switch_stack));
#endif


    /* Debugging: execmove is a series of system calls jammed
     * together.  If we're being debugged at this point it's possible
     * that we'll confuse the debuggers by providing an execve event
     * before we actually stop from the fork.
     *
     * Therefore we'll eat any SIGSTOP here and stop.
     */
    if (current->ptrace) {
	spin_lock_irq(&current->sighand->siglock);
	if (sigismember(&current->pending.signal, SIGSTOP)) {
	    /* Newly exported kernel func */
	    void ptrace_stop(int exit_code, siginfo_t *info);
	    /* Eat the SIGSTOP. */
	    
	    /* XXX maybe use the normal signal delivery path here? */

	    sigdelset(&current->pending.signal, SIGSTOP);
	    recalc_sigpending();
	    spin_unlock_irq(&current->sighand->siglock);

	    ptrace_stop(SIGSTOP, 0);
	} else {
	    spin_unlock_irq(&current->sighand->siglock);
	}
    }

    /* For VEXECMOVE, we have do the execve step here.  This is a bit
     * of a kludge right now.... */
    if (info->req->type == BPROC_SYS_VEXECMOVE && info->req->data_addr == 0) {
	info->status = do_execmove_execve(info->req, regs);
	if (info->status) goto error_out;

	/* Squash suid execmoves if necessary. */
	if (!suid_execmove && !current->mm->dumpable) {
	    info->status = -EPERM;
	    goto error_out;
	}
    }

    /* moving will un-masq so make note of our pid now... */
    pid = BPROC_MASQ_PID(current);
    info->status = send_process(info->node, info->req, regs);
    if (info->status != 0)
	goto error_out;

    info->status = pid;

    /* XXX we should probably reparent ourself *BEFORE* returning a
     * response here.  Otherwise the parent has a window where it
     * might see this process. */

    complete(info->compl);
    if (BPROC_ISGHOST(current)) {
	return ghost_thread(regs, 0);
    } else {
	/* process is moved to another node, get rid of the
	 * process here */
	silent_exit();
    }
    /* NOT REACHED */

 error_out:
    /* Error - notify and clean myself up */
    complete(info->compl);
    if (BPROC_ISMASQ(current)) {
	/* We need to silent exit but still notify the ghost in
	 * this case. */
	masq_exit_notify(current, BPROC_SILENT_EXIT);
    }
    silent_exit();
    /* NOT REACHED */
}

static
int do_rfork_async(int node, struct bproc_kmove_t *move, struct pt_regs *regs,
		   struct rfork_info *info) {
    info->node   = node;
    info->req    = move;
    info->regs   = regs;
    info->status = 0;

    /* This will *not* be treated like a kernel call */
    return bproc_kernel_thread((bproc_kthread_func *)rfork_stub,
			      (void *)info, CLONE_VM | SIGCHLD);
}

#if 0
static
int do_rfork_sync(int node, struct bproc_kmove_t *move, struct pt_regs *regs) {
    int pid;
    struct rfork_info info;
    struct completion compl;

    info.compl = &compl;
    init_completion(&compl);

    pid = do_rfork_async(node, move, regs, &info);
    if (pid < 0) return pid;
    wait_for_completion(&compl);
    /* The child process will clean itself up in the case of failure -
     * no need to do a wait() here */
    return info.status;
}

static
int do_rfork(int node, struct bproc_kmove_t *args, struct pt_regs *regs) {
    int pid, r;
    struct bproc_kmove_t move;

    /* not really race-safe */
    if (ghost_master == 0 && !BPROC_ISMASQ(current))
	return -ENOSYS;

    if ((r = get_move_args(&move, (void *) bp_reg_arg2(regs))))
	return r;
    move.type = BPROC_SYS_RFORK;
    pid = do_rfork_sync(node, &move, regs);
    put_move_args(&move);
    return pid;
}
#endif

/*-------------------------------------------------------------------------
 * vrfork    (and vexecmove)
 */
/* Start the child processes for one node in the tree */

/* Vector rfork. */
struct vmove_t {
    struct list_head     list;
    struct vmove_t      *parent;
    struct bproc_kmove_t move;
    struct rfork_info    info;
};

struct vrfork_context {
    int idx;			/* current index */
    struct list_head ready;	/* nodes ready to act as re-senders */
    struct list_head mip;	/* moves in progress */
    struct list_head ready_nr;	/* ones that can't resend for some reason */
};

static
int vrfork_init_user(struct vrfork_context *ctx,
		     struct bproc_kmove_t *move) {
    int i, node;

    for (i=0; i < move->user.nodeslen; i++) {
	if (get_user(node, &move->user.nodes[i]))
	    return -EFAULT;

	/* Clear out the result array... */
	if (put_user(0, &move->user.pids[i]))
	    return -EFAULT;
    }
    return 0;
}

static
int vrfork_start_process(struct vrfork_context *ctx, struct vmove_t *parent,
			 struct pt_regs *regs) {
    int r, node;
    struct vmove_t *mv;

    /* XXX We're not worrying about node-duplicates right now */

    if (get_user(node, &parent->move.user.nodes[ctx->idx]))
	return -EFAULT;

    mv = kmalloc(sizeof(*mv), GFP_KERNEL);
    if (!mv) return -ENOMEM;
    memcpy(mv, parent, sizeof(*mv));
    mv->parent      = parent;
    mv->move.index  = ctx->idx++;

    /*printk("SP: me=%d id=%d parent->id=%d\n", current->pid,
      mv->move.index, mv->parent->move.index);*/
    r = do_rfork_async(node, &mv->move, regs, &mv->info);
    if (r < 0) {
	kfree(mv);
	return r;
    }
    list_add_tail(&mv->list, &ctx->mip);
    return 0;
}

/* This looks like rfork_stub except that I/O setup is done here.  It has */
static
int fork_local_stub(struct pt_regs *regs, struct rfork_info *info) {
    int i, retval;

    memcpy(regs, info->regs, sizeof(*regs));
#if defined(__alpha__)
    /* We also need to copy the "switch_stack" part that lives before
     * struct pt_regs on alpha. */
    memcpy(((struct switch_stack *)regs)-1,
	   ((struct switch_stack *)(info->regs))-1,
	   sizeof(struct switch_stack));
#endif

    /* Perform I/O setup - important to do this before execve for
     * security reasons... */
    for (i=0; i < info->req->user.iolen; i++) {
	info->status = setup_io_fd(&info->req->user.io[i]);
	if (info->status)
	    goto error_out;
    }

    /* For VEXECMOVE, we have do the execve step here.  This is a bit
     * of a kludge right now.... */
    if (info->req->type == BPROC_SYS_VEXECMOVE && info->req->data_addr == 0) {
	info->status = do_execmove_execve(info->req, regs);
	if (info->status) goto error_out;

	/* Squash suid execmoves if necessary. */
	if (!suid_execmove && !current->mm->dumpable) {
	    info->status = -EPERM;
	    goto error_out;
	}
    }

    /* Ok, return to user space and let 'er rip. */
    info->status = BPROC_MASQ_PID(current);
    retval = info->req->index;
    complete(info->compl);
    return retval;

 error_out:
    complete(info->compl);
    if (BPROC_ISMASQ(current)) {
	masq_exit_notify(current, BPROC_SILENT_EXIT);
    }
    silent_exit();
}

static
int vrfork_start_process_local(struct vrfork_context *ctx,
			       struct vmove_t *mv, struct pt_regs *regs) {
    int r;
    mv->info.status    = 0;	/* reset status for another try */
    mv->move.data_addr = 0;	/* this one will not be a resender */
    mv->move.data_port = 0;

    r = bproc_kernel_thread((bproc_kthread_func *)fork_local_stub,
			    (void *)&mv->info, SIGCHLD);
    if (r < 0)
	return r;

    list_add_tail(&mv->list, &ctx->mip);
    return 0;
}

static inline
struct vmove_t *vrfork_find_finished(struct list_head *mip) {
    struct list_head *l;
    struct vmove_t *mv;
    for (l = mip->next; l != mip; l=l->next) {
	mv = list_entry(l, struct vmove_t, list);
	if (mv->info.status != 0) {
	    list_del(&mv->list);
	    return mv;
	}
    }
    return 0;
}

static
void vrfork_stop_resends(struct vmove_t *mv) {
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;

    req = bproc_new_req(BPROC_RESPONSE(BPROC_MOVE_COMPLETE),
			sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk(KERN_CRIT "bproc: Out of memory stopping resends.\n");
	return;
    }
    msg = bproc_msg(req);
    bpr_to_real(msg, mv->info.status);
    bpr_from_real(msg, BPROC_MASQ_PID(current));
    msg->hdr.id = mv->move.msg_id;
    bproc_send_req(bproc_msgdest(), req);
    bproc_put_req(req);
}

static
int do_vrfork(int move_type, struct bproc_kmove_t *move, struct pt_regs *regs){
    int r;
    struct vmove_t *mv, top;
    struct vrfork_context ctx;
    struct completion cmpl;

    if (ghost_master == 0 && !BPROC_ISMASQ(current))
	return -ENOSYS;

    /* Move related args from the user */
    memcpy(&top.move, move, sizeof(top.move));
    if (top.move.user.nodeslen <= 0) {
	r = -EINVAL;
	goto out_quick;
    }

    init_completion(&cmpl);

    /* Initialize our context */
    ctx.idx = 0;
    INIT_LIST_HEAD(&ctx.mip);
    INIT_LIST_HEAD(&ctx.ready);
    INIT_LIST_HEAD(&ctx.ready_nr);

    /* Initialize the user's view of the world */
    if ((r = vrfork_init_user(&ctx, &top.move)) < 0)
	goto out;

    /* Initialize the rest of our "top" move information */
    top.move.index  = -1;
    top.info.compl  = &cmpl;
    top.move.type   = move_type;

    /* XXX FIX ME:  If the first move fails, we're hosed in here */
    /*SPEW2("%p starting vrfork/vexecmove", &ctx);*/

    /* XXX FIX ME: There's no mechanism here for automagic
     * notification if the parent of a move should go away during a
     * migrate.  */
    r = vrfork_start_process(&ctx, &top, regs);
    /* If vrfork_start process fails in a local way, we won't end up
     * with a move in progress.  If that happens we'll just fall
     * through and leave here. */
 out:
    while (!list_empty(&ctx.mip)) {
	wait_for_completion(&cmpl);

	/* Clean up completed moves.... */
	mv = vrfork_find_finished(&ctx.mip);
	if (mv) {
	    /* Add this one to the list of ready senders */
	    /*SPEW2("%p id=%d stat=%d",&ctx,mv->move.index,mv->info.status);*/

	    /* Store this move result */
	    if (put_user(mv->info.status, &top.move.user.pids[mv->move.index]))
		r = -EFAULT;

	    if (mv->info.status > 0) {
		/* Add the parent back to the list of ready senders */
		if (mv->parent && mv->parent != &top)
		    list_add_tail(&mv->parent->list, &ctx.ready);
		/* Only add this to our resender list if it's setup
		 * for resending... */
		/* XXX We shouldn't have more than one sender per machine. */
		if (mv->move.data_addr && mv->move.data_port) {
		    /*SPEW2("%p Add %d to ready list.",&ctx,mv->move.index);*/
		    list_add_tail(&mv->list, &ctx.ready);
		} else {
		    if (!mv->parent) {
			/* Local starts have a null parent, don't send
			 * them a MOVE_COMPLETE */
			kfree(mv);
		    } else {
			/*SPEW2("%p Discarding %d due to zero addr/port.",
			  &ctx, mv->move.index);*/
			list_add_tail(&mv->list, &ctx.ready_nr);
		    }
		}
	    } else if (mv->info.status == -BE_SAMENODE) {
		/* If we're trying to move to the same node we catch it
		 * here and do a local process creation instead. */
		mv->parent = 0;
		r = vrfork_start_process_local(&ctx, mv, regs);
		if (r) kfree(mv);
	    } else {
		/* XXX We need to try to classify some errors here so
		 * that we can re-try creation of a child process if
		 * the sender is deemed bogus or whether the child is
		 * just bogus. */
		if (mv->parent != &top) {
		    /* There was a failure involving this sender.  We
		     * have no idea what state it's in at this point.
		     * Sending it a stop message should kick it out of
		     * the send if it's not already out.
		     *
		     * We should be able to send a stop message that
		     * kept it in the resend loop but it would still
		     * be tricky to re-synchronize with the sender in
		     * that case.  (or would it? - think about this)
		     */
		    vrfork_stop_resends(mv->parent);
		    kfree(mv->parent);
		}
		/* XXX We need to try and determine if the error was
		 * caused by the sender here.  If so, we need should
		 * retry this transfer to this slave node.  Note that
		 * we're not currently detecting sender errors. */
		kfree(mv);
	    }
	}

	/* Don't start anything new if we are ready to bail out */
	if (r || signal_pending(current)) continue;

	/* Try to start a new child for all the ready senders */
	while (ctx.idx < top.move.user.nodeslen && !list_empty(&ctx.ready)){
	    mv = list_entry(ctx.ready.next, struct vmove_t, list);
	    list_del(&mv->list);
	    /*printk("Got %d from the ready list.\n", mv->move.index);*/
	    r = vrfork_start_process(&ctx, mv, regs);
	    if (r != 0) {
		/* In case of failure, put the parent back so that
		 * it doesn't get lost. */
		list_add_tail(&mv->list, &ctx.ready);
	    }
	}

	/* If we don't have anything running, try to start another
	 * one from the front end. */
	if (r == 0 && ctx.idx < top.move.user.nodeslen &&
	    list_empty(&ctx.mip)) {
	    /*printk("Starting %d from the front end.\n", ctx.idx);*/
	    r = vrfork_start_process(&ctx, &top, regs);
	}
    }

    /*SPEW2("%p flushing out senders", &ctx);*/

    /* Flush out the ready senders moves */
    /* printk("Flushing out senders.\n");*/
    while (!list_empty(&ctx.ready)) {
	/* Grab the next ready sender off the list, and turn it off */
	mv = list_entry(ctx.ready.next, struct vmove_t, list);
	list_del(&mv->list);
	vrfork_stop_resends(mv);
	kfree(mv);
    }

    /* ... and the others as well */
    while (!list_empty(&ctx.ready_nr)) {
	mv = list_entry(ctx.ready_nr.next, struct vmove_t, list);
	list_del(&mv->list);
	vrfork_stop_resends(mv);
	kfree(mv);
    }

    /* We need to start killing things if any of this has gone
     * south.... but that's tough because we're only storing PIDs in
     * user memory (which we can't trust) right now. */
 out_quick:
    if (r < 0) return r;
    return top.move.user.nodeslen;
}
/*-------------------------------------------------------------------------
 */
int execmove_load_script(const char *filename,
			 void ** base, unsigned long * size) {
    int err = 0;
    struct file *filp;

    filp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(filp)) return PTR_ERR(filp);
    if (!S_ISREG(filp->f_dentry->d_inode->i_mode)) {
	fput(filp);
	return -EINVAL;
    }
    *size = filp->f_dentry->d_inode->i_size;
    *base = (void*) do_mmap(filp, 0, *size, PROT_READ, MAP_PRIVATE, 0);
    if (IS_ERR(*base)) {
	err = PTR_ERR(*base);
	*base = 0;
    }
    fput(filp);
    return err;
}

static
int do_execmove_execve(struct bproc_kmove_t *move, struct pt_regs *regs) {
    int r;
    char *filename;

    extern int bproc_hook_sys_execve(struct pt_regs *regs, char *arg0,
				     char **argv, char **envp);

    filename = getname(move->user.arg0);
    r = PTR_ERR(filename);
    if (IS_ERR(filename))
	return r;

    /* kludge - set flags for the script hooks. */
    clear_bit(BPROC_FLAG_SCRIPT,   &current->bproc.flag);
    set_bit  (BPROC_FLAG_EXECMOVE, &current->bproc.flag);
    r = sysdep_do_execve(filename, move->user.argv, move->user.envp, regs);
    if (r == -ENOENT && BPROC_ISMASQ(current)) {
	/* Try the grab the remote binary trick... */
	r = bproc_hook_sys_execve(regs, move->user.arg0,
				  move->user.argv, move->user.envp);
    }
    clear_bit(BPROC_FLAG_EXECMOVE, &current->bproc.flag);
    if (r == 0) {
	current->ptrace &= ~PT_DTRACE; /* sys_execve does this */
	if (current->ptrace & PT_PTRACED) {
	    /* If we're traced, we just got a SIGTRAP from do_execve.
	     * Having a pending signal will reliably nuke the move
	     * step we're about to do so suppress it and we'll generate
	     * a new signal on the far end after we're done with the
	     * move. */
	    sigset_t sigset;
	    struct siginfo info;
	    sigfillset(&sigset);
	    sigdelset(&sigset, SIGTRAP);
	    spin_lock_irq(&current->sighand->siglock);
	    dequeue_signal(current, &sigset, &info);
	    spin_unlock_irq(&current->sighand->siglock);
	}

	if (test_bit(BPROC_FLAG_SCRIPT, &current->bproc.flag))
	    execmove_load_script(filename,
				 &move->script_base, &move->script_size);
    }

    putname(filename);

    return r;
}

static
int do_execmove(int node, struct bproc_kmove_t *args, struct pt_regs *regs) {
    int r;

    /* Set this up here because exec() might change euids on us... */
    args->type = BPROC_SYS_EXECMOVE;
    r = do_execmove_execve(args, regs);
    if (r != 0) 
	return r;

    if (!suid_execmove && !current->mm->dumpable) {
	/* XXX An error here is great but we need to make sure we don't
	 * run by accident. */
	if (r) do_exit((-EPERM)<<8); /* Dont run locally by accident.... */
    }

    /* Ok... exec complete. Now move.*/
    r = send_process(node, args, regs);
    
    if (r) do_exit((-r)<<8); /* Dont run locally by accident.... */

    if (BPROC_ISMASQ(current))
	silent_exit();
    else
	return ghost_thread(regs,0);
}

#if 0
static
int do_exec(struct pt_regs *regs) {
    int r;
    struct bproc_kmove_t move;

    if (!BPROC_ISMASQ(current))
	return -EINVAL;
    if ((r = get_move_args(&move, (void *) bp_reg_arg1(regs))))
	return r;
    move.type = BPROC_SYS_EXEC;
    move.user.iolen = 0;	/* no IO setup allowed */

    r = send_recv_process(&move, regs);

    put_move_args(&move);
    return r;
}
#endif

static
int bproc_get_fd(int ino, char *name) {
    int fd;
    struct file *filp;

    fd = get_unused_fd();
    if (fd < 0) return -ENFILE;

    filp = bpfs_get_file(ino, name);
    if (IS_ERR(filp)) {
	put_unused_fd(fd);
	return PTR_ERR(filp);
    }
    fd_install(fd, filp);
    return fd;
}

static
int bproc_version_check(struct bproc_version_t *uvers) {
    static struct bproc_version_t vers = { BPROC_MAGIC, BPROC_ARCH,
					   PACKAGE_MAGIC,
					   __stringify(PACKAGE_VERSION) };

    if (copy_to_user(uvers, &vers, sizeof(struct bproc_version_t)))
	return -EFAULT;
    return 0;
}

long do_bproc(long op, long arg1, long arg2, struct pt_regs *regs) {
    int r;
    struct bproc_kmove_t move;

    switch(op) {
    case BPROC_SYS_VERSION:
	return bproc_version_check((struct bproc_version_t *)arg1);
/*--- Debug interface ---------------------------------------------------*/
#ifdef ENABLE_DEBUG
    case BPROC_SYS_DEBUG:
	return do_debug(regs, arg1, arg2);
#endif
/*--- File descriptor interfaces ----------------------------------------*/
    case BPROC_SYS_MASTER:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	return bproc_get_fd(BPFS_MASTER_INO, "master");
    case BPROC_SYS_SLAVE:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	return bproc_get_fd(BPFS_SLAVE_INO, "slave");
    case BPROC_SYS_IOD:
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	return bproc_get_fd(BPFS_IOD_INO, "iod");
/*--- Migration interfaces ----------------------------------------------*/
    case BPROC_SYS_REXEC: /*--------------------------------------------*/
    case BPROC_SYS_MOVE:
	/* not really race-safe */
	if (ghost_master == 0 && !BPROC_ISMASQ(current))
	    return -ENOSYS;
	if ((r = get_move_args(&move, (struct bproc_move_t *) arg2)))
	    return r;
	move.type = op;
	r = send_process(arg1, &move, regs);
	put_move_args(&move);
	if (r) return r;

	if (BPROC_ISGHOST(current))
	    return ghost_thread(regs,0);
	else
	    silent_exit();
	/* NOT REACHED */

#if 0
    case BPROC_SYS_RFORK: /*--------------------------------------------*/
	if (ghost_master == 0 && !BPROC_ISMASQ(current))
	    return -ENOSYS;
	if ((r = get_move_args(&move, (struct bproc_move_t *) arg2)))
	    return r;
	r = do_rfork(arg1, arg2, regs);
	put_move_args(&move);
	return r;
#endif
    case BPROC_SYS_EXECMOVE: /*-----------------------------------------*/
	if (ghost_master == 0 && !BPROC_ISMASQ(current))
	    return -ENOSYS;
	if ((r = get_move_args(&move, (struct bproc_move_t *) arg2)))
	    return r;
	r = do_execmove(arg1, &move, regs);
	put_move_args(&move);
	return r;

    case BPROC_SYS_VRFORK: /*-------------------------------------------*/
    case BPROC_SYS_VEXECMOVE:
	if (ghost_master == 0 && !BPROC_ISMASQ(current))
	    return -ENOSYS;
	if ((r = get_move_args(&move, (struct bproc_move_t *) arg1)))
	    return r;
	r = do_vrfork(op, &move, regs);
	put_move_args(&move);
	return r;

#if 0
	/* This is a testing interface */
    case BPROC_SYS_EXEC:
	return do_exec(regs);
#endif


/*--- Node control interfaces ------------------------------------------*/
    case BPROC_SYS_REBOOT:
	return do_control_async(BPROC_NODE_REBOOT, arg1);
    case BPROC_SYS_HALT:
	return do_control_async(BPROC_NODE_HALT,   arg1);
    case BPROC_SYS_PWROFF:
	return do_control_async(BPROC_NODE_PWROFF, arg1);

    case BPROC_SYS_CHROOT:
	return do_control(BPROC_NODE_CHROOT,    arg1, (void *)arg2);
    case BPROC_SYS_RECONNECT:
	return do_control(BPROC_NODE_RECONNECT, arg1, (void *)arg2);

	/* Provide VMADump interface here... */
    case BPROC_SYS_VMADUMP + VMAD_DO_DUMP:
    case BPROC_SYS_VMADUMP + VMAD_DO_UNDUMP:
    case BPROC_SYS_VMADUMP + VMAD_DO_EXECDUMP:
    case BPROC_SYS_VMADUMP + VMAD_LIB_CLEAR:
    case BPROC_SYS_VMADUMP + VMAD_LIB_ADD:
    case BPROC_SYS_VMADUMP + VMAD_LIB_DEL:
    case BPROC_SYS_VMADUMP + VMAD_LIB_SIZE:
    case BPROC_SYS_VMADUMP + VMAD_LIB_LIST:
	return do_vmadump(op - BPROC_SYS_VMADUMP, arg1, arg2, regs);
    }
    return -EINVAL;
}

/**------------------------------------------------------------------------
 ** sysctl interface
 **----------------------------------------------------------------------*/


#ifdef ENABLE_DEBUG
extern atomic_t msg_counters[];
#endif

extern int execve_hook;
extern int shell_script_hack;
extern int proc_pid_map;

static int yesno_min = 0;
static int yesno_max = 1;
static int pid_map_min = 0;
static int pid_map_max = 2;
static
struct ctl_table bproc_sysctl1[] = {
    {1, "messages", &msg_count, sizeof(atomic_t), 0444, 0,
     proc_dointvec, sysctl_intvec },
    {4, "execve_hook", &execve_hook, sizeof(int), 0644, 0,
     proc_dointvec_minmax, sysctl_intvec, 0, &yesno_min, &yesno_max},
    {5, "proc_pid_map", &proc_pid_map, sizeof(int), 0644, 0,
     proc_dointvec_minmax, sysctl_intvec, 0, &pid_map_min, &pid_map_max},
    {6, "shell_hack", &shell_script_hack, sizeof(int), 0644, 0,
     proc_dointvec_minmax, sysctl_intvec, 0, &yesno_min, &yesno_max},
    {7, "suid_execmove", &suid_execmove, sizeof(int), 0644, 0,
     proc_dointvec_minmax, sysctl_intvec, 0, &yesno_min, &yesno_max},
#ifdef ENABLE_DEBUG
    {100, "dbg_msgcount", msg_counters, sizeof(atomic_t)*MSG_COUNTER_MAX,
     0444, 0, proc_dointvec, sysctl_intvec },
#endif
    {0}
};

static
struct ctl_table bproc_sysctl[] = {
    {222, "bproc", 0, 0, 0555, bproc_sysctl1, 0, 0},
    {0}
};

#ifdef CONFIG_SYSCTL
struct ctl_table_header *sysctl_header;
#endif
int init_module(void) {
    int err;
#ifdef ENABLE_DEBUG
    void msg_counter_init(void);
    msg_counter_init();
#endif

    atomic_set(&msg_count, 0);
    printk(KERN_INFO "bproc: Beowulf Distributed Process Space Version %s\n"
	   KERN_INFO "bproc: (C) 1999-2003 Erik Hendriks <erik@hendriks.cx>\n",
	   __stringify(PACKAGE_VERSION));
    bproc_init_request_queue(&bproc_ghost_reqs);
    bproc_close_request_queue(&bproc_ghost_reqs); /* Until we get a master. */

    if ((err = register_filesystem(&bprocfs_type)))
	goto bail;

    ghost_refresh_init();

#ifdef CONFIG_SYSCTL
    if (!(sysctl_header = register_sysctl_table(bproc_sysctl, 0))) {
	printk(KERN_ERR "bproc: failed register bproc sysctl table.\n");
    }
#endif
    set_hooks();

    /* Set the pointer in the kernel do me */
#if 0
    down_write(&do_bproc_lock);
    do_bproc_ptr = do_bproc;
    up_write(&do_bproc_lock);
#else
    do_bproc_ptr = do_bproc;
#endif
    return 0;

    unregister_filesystem(&bprocfs_type);
 bail:
    return err;
}

void cleanup_module(void) {
#if 0
    down_write(&do_bproc_lock);
    do_bproc_ptr = 0;
    up_write(&do_bproc_lock);
#else
    do_bproc_ptr = 0;
#endif

    unset_hooks();

    unregister_filesystem(&bprocfs_type);
#ifdef CONFIG_SYSCTL
    if (sysctl_header)
	unregister_sysctl_table(sysctl_header);
#endif
    nodeset_cleanup();
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
