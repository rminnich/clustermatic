/*-------------------------------------------------------------------------
 *  ghost.c:  Beowulf distributed process space ghost process code
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
 * $Id: ghost.c,v 1.128 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/bproc.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <asm/mmu_context.h>

#include "bproc.h"
#include "bproc_internal.h"

#include <asm/unistd.h>

int ghost_status_timeout = BPROC_GHOST_DEFAULT_STATUS_TIMEOUT;

spinlock_t ghost_lock   = SPIN_LOCK_UNLOCKED;
int        ghost_master = 0;
LIST_HEAD(ghost_list);
DECLARE_WAIT_QUEUE_HEAD(ghost_wait);

struct bproc_request_queue_t bproc_ghost_reqs;

int
ghost_deliver_msg(pid_t pid, struct bproc_krequest_t *req) {
    int r;
    struct task_struct *p;

    read_lock(&tasklist_lock);
    p = find_task_by_pid(pid);
    if (!p || !p->bproc.ghost) {
	read_unlock(&tasklist_lock);
	return -ESRCH;
    }
    r = bproc_send_req(&p->bproc.ghost->req, req);
    read_unlock(&tasklist_lock);
    return r;
}

/*--------------------------------------------------------------------
 *  Ghost management
 *------------------------------------------------------------------*/

struct bproc_ghost_proc_t *ghost_alloc(int node) {
    struct bproc_ghost_proc_t *ghost;

    ghost = (struct bproc_ghost_proc_t *) kmalloc(sizeof(*ghost), GFP_KERNEL);
    if (!ghost) {
	printk(KERN_NOTICE "bproc: add_ghost: out of memory\n");
	return 0;
    }
    memset(ghost, 0, sizeof(*ghost));

    /* Initialize this ghost structure */
    ghost->count = (atomic_t) ATOMIC_INIT(1);
    ghost->lock  = SPIN_LOCK_UNLOCKED;
    bproc_init_request_queue(&ghost->req);
    ghost->wait=(wait_queue_head_t)__WAIT_QUEUE_HEAD_INITIALIZER(ghost->wait);
    ghost->state = TASK_RUNNING;
    ghost->node  = node;

    return ghost;
}

/* you are expected to have tasklist_lock (write) */
int ghost_add(struct bproc_ghost_proc_t *ghost) {
    spin_lock(&ghost_lock);
    if (ghost_master == 0) {
	spin_unlock(&ghost_lock);
	return -EBUSY;
    }
    current->bproc.ghost = ghost;
    list_add_tail(&ghost->list, &ghost_list);
    spin_unlock(&ghost_lock);
    wake_up(&ghost_wait);	/* safe here? */
    return 0;
}

/*
 * ghost_drop - dispose of a ghost structure after it's been removed
 * from a process.
 *
 */
void ghost_drop(struct bproc_ghost_proc_t *g) {
    /* Kick anyone that might have been waiting for status */
    g->last_response = jiffies;	/* Wake up those waiting on status. */
    wake_up(&g->wait);

    bproc_purge_requests(&g->req);
    ghost_put(g);
}

int add_ghost(int node) {
    int ret;
    struct bproc_ghost_proc_t *ghost;

    ghost = ghost_alloc(node);
    if (!ghost) return -ENOMEM;

    write_lock_irq(&tasklist_lock);
    ret = ghost_add(ghost);
    write_unlock_irq(&tasklist_lock);
    if (ret < 0)
	kfree(ghost);
    return ret;
}

struct bproc_ghost_proc_t *
ghost_get(struct task_struct *task) {
    struct bproc_ghost_proc_t *g;

    read_lock(&tasklist_lock);
    g = task->bproc.ghost;
    if (g)
	atomic_inc(&g->count);
    read_unlock(&tasklist_lock);
    return g;
}

void ghost_put(struct bproc_ghost_proc_t *g) {
    if (atomic_dec_and_test(&g->count)) {
	/* Remove this ghost from the lists.. */
	if (g->proc.exe) fput(g->proc.exe); /* no lock since ref ct is zero */
	spin_lock(&ghost_lock);
	list_del(&g->list);
	spin_unlock(&ghost_lock);
	kfree(g);
	wake_up(&ghost_wait);
    }
}

void bproc_ghost_unghost(void) {
    struct bproc_ghost_proc_t *g;
    g = current->bproc.ghost;

    /* Un-ghost remove self from list */
    write_lock_irq(&tasklist_lock);
    current->bproc.ghost = 0;
    write_unlock_irq(&tasklist_lock);

    ghost_drop(g);
}

int ghost_thread(struct pt_regs *regs, struct bproc_krequest_t *fork_req);

/*-------------------------------------------------------------------------
 *  Ghost remote syscalls
 *-----------------------------------------------------------------------*/
static
void ghost_setup_proc(void) {
    int i;
    struct bproc_ghost_proc_t *g = current->bproc.ghost;

    spin_lock_irq(&current->sighand->siglock);
    sigemptyset(&current->blocked);
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);

    /* Get rid of any user space memory we've got on the front end. */
    current->clear_child_tid = 0;

    if (current->mm) {
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	/* Keep track of any exe pointer we might have now. */
	spin_lock(&g->lock);
	if (g->proc.exe) {
	    fput(g->proc.exe);
	    g->proc.exe = 0;
	}
	spin_unlock(&g->lock);

	vma = mm->mmap;
	while (vma) {
	    if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file) {
		spin_lock(&g->lock);
		g->proc.exe = vma->vm_file;
		get_file(g->proc.exe);
		spin_unlock(&g->lock);
		break;
	    }
	    vma = vma->vm_next;
	}
	up_read(&mm->mmap_sem);
	g->proc.dumpable = mm->dumpable;

#if defined(powerpc) || defined(__powerpc64__)
	current->thread.regs = 0;
#endif
	exit_mm(current);
    }
    /* Exit files but keep our file structure around since we might
     * want to open files again at some point.  FIX ME: we should be
     * able to get rid of this and create a new file table somewhere
     * down the road. */
    for (i=0; i < current->files->max_fds; i++)
	if (current->files->fd[i])
	    sys_close(i);

    /* We don't get rid of our file system context.  Recreating this
     * is non-trivial and could present a security issue. */
    k_chdir("/");
}

static
void ghost_sys_setup(struct bproc_rsyscall_msg_t *msg) {
    /* setup the ghost signal handler state to do a remote syscall */
    spin_lock_irq(&current->sighand->siglock);
    memcpy(&current->blocked, &msg->blocked, sizeof(sigset_t));
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);
}

static
void ghost_sys_restore(void) {
    /* Restore the ghost's signal handler state */
    spin_lock_irq(&current->sighand->siglock);
    sigemptyset(&current->blocked);
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);
}

static
void ghost_sys_fork(struct bproc_krequest_t *req) {
    int result;
    struct bproc_ghost_proc_t *g = current->bproc.ghost;
    struct bproc_rsyscall_msg_t *msg;

    msg = bproc_msg(req);
    bproc_get_req(req); /* Up the count for the child proc.... */
    ghost_sys_setup(msg);

    /* Hack, we store some stuff in the request so that the child will
     * have access to it. */
    msg->arg[3] = g->proc.dumpable;
    if (g->proc.exe) get_file(g->proc.exe);
    msg->arg[4] = (long) g->proc.exe;
    msg->arg[5] = current->bproc.ghost->node;

    /* Only certain flags will make sense for a ghost.  Strip out
     * stuff that doesn't make sense that might trip us up. */
    msg->arg[0] &= ~(CLONE_VFORK |
		     CLONE_SETTLS |
		     CLONE_PARENT_SETTID |
		     CLONE_CHILD_CLEARTID |
		     CLONE_CHILD_SETTID |
		     CLONE_STOPPED);

    result = bproc_kernel_thread((bproc_kthread_func *)ghost_thread,
				 (void *)req, msg->arg[0]);
    ghost_sys_restore();
    if (result < 0) {
        /* Error occurred so we'll have to respond to the message
         * instead of the child. */
	struct bproc_krequest_t *resp;
	struct bproc_fork_resp_t *msg; /* use null since no data? */
	if (g->proc.exe) fput(g->proc.exe);
        bproc_put_req(req);     /* ... since child never got started. */

	resp = bproc_new_resp(req, sizeof(*msg), GFP_KERNEL);
	if (!resp) {
	    printk(KERN_CRIT "bproc: Out of memory in fork response.\n");
	    return;
	}
	msg = bproc_msg(resp);
	msg->hdr.result = result;
	bproc_send_req(&bproc_ghost_reqs, resp);
	bproc_put_req(resp);
    }
}

static
void ghost_sys_wait(struct bproc_krequest_t *req) {
    int status;
    struct rusage ru;
    struct bproc_rsyscall_msg_t *req_msg;
    struct bproc_krequest_t *resp;
    struct bproc_wait_resp_t *resp_msg;

    req_msg = bproc_msg(req);

    resp = bproc_new_resp(req, sizeof(*resp_msg), GFP_KERNEL);
    if (!resp) {
	printk(KERN_CRIT "bproc: out of memory in sys_wait\n");
	return;
    }
    resp_msg = bproc_msg(resp);
    
    ghost_sys_setup(req_msg);
    resp_msg->hdr.result = k_wait4(req_msg->arg[0], req_msg->arg[1],
				   NULL, &status, &ru);
    ghost_sys_restore();

    /* Only a few elements of the rusage structure are provided by
     * Linux.  Also, convert the times back to the HZ representation. */
    resp_msg->status = status;
    resp_msg->utime  = ((ru.ru_utime.tv_sec*HZ) + 
			(ru.ru_utime.tv_usec/(1000000/HZ)));
    resp_msg->stime  = ((ru.ru_stime.tv_sec*HZ) + 
			(ru.ru_stime.tv_usec/(1000000/HZ)));
    resp_msg->minflt = ru.ru_minflt;
    resp_msg->majflt = ru.ru_majflt;
    resp_msg->nswap  = ru.ru_nswap;
    bproc_send_req(&bproc_ghost_reqs, resp);
    bproc_put_req(resp);
}

static
void ghost_sys_kill(struct bproc_krequest_t *req) {
    struct siginfo info;
    int kill_something_info(int sig, struct siginfo *info, int pid);
    struct bproc_signal_msg_t *msg;
    struct bproc_krequest_t *resp;
    struct bproc_null_msg_t *resp_msg;

    msg = bproc_msg(req);
    resp = bproc_new_resp(req, sizeof(*resp_msg), GFP_KERNEL);
    if (!resp) {
	printk(KERN_CRIT "bproc: out of memory doing sys_kill\n");
	return;
    }
    resp_msg = bproc_msg(resp);

    bproc_unpack_siginfo(&msg->info, &info);
    resp_msg->hdr.result = kill_something_info(info.si_signo, &info, msg->pid);

    bproc_send_req(&bproc_ghost_reqs, resp);
    bproc_put_req(resp);
}

/* This is more or less copied from the new mm creation code from
 * exec_mmap() in linux/fs/exec.c */
int bproc_get_new_mm(void) {
    struct mm_struct *mm, *active_mm;

    if (current->mm) {
	printk(KERN_ERR "bproc: bproc_get_new_mm called with existing mm!\n");
	return -ENOMEM;
    }

    mm = mm_alloc();
    if (!mm) return -ENOMEM;

    if (init_new_context(current, mm)) {
	mmdrop(mm);
	return -ENOMEM;
    }

    /* Add it to the list of mm's */
    spin_lock(&mmlist_lock);
    list_add(&mm->mmlist, &init_mm.mmlist);
    mmlist_nr++;
    spin_unlock(&mmlist_lock);

    task_lock(current);
    active_mm = current->active_mm;
    current->mm = mm;
    current->active_mm = mm;
    activate_mm(active_mm, mm);
    task_unlock(current);
    arch_pick_mmap_layout(mm);
    mmdrop(active_mm);
    return 0;
}

static
int ghost_handle_request(struct pt_regs *regs, struct bproc_krequest_t *req) {
    int pid, retval = 0;
    long exit_code;
    struct bproc_ghost_proc_t *g = current->bproc.ghost;
    struct bproc_message_hdr_t *hdr;

    hdr = bproc_msg(req);

    switch (hdr->req) {
    case BPROC_MOVE: {
	struct bproc_move_msg_t *msg = (struct bproc_move_msg_t *)hdr;
	retval = msg->index; /* save move index for returing to user space */

	if (bproc_get_new_mm()) {
	    struct bproc_krequest_t *resp;
	    struct bproc_move_msg_t *resp_msg;
	    printk(KERN_ERR "bproc: ghost: bproc_get_new_mm failed.\n");

	    resp = bproc_new_resp(req, sizeof(*resp_msg), GFP_KERNEL);
	    if (!resp) {
		printk(KERN_CRIT "bproc: ghost: out of memory.\n");
		/* do_exit(SIGKILL); ? */
		break;
	    }
	    resp_msg = bproc_msg(resp);
	    /* clone the move request */
	    memcpy(resp_msg, hdr, sizeof (*resp_msg));
	    resp_msg->hdr.result = -ENOMEM;
	    bproc_send_req(&bproc_ghost_reqs, resp);
	    bproc_put_req(resp);
	    break;
	}

	/* Make this process fit the move request + unghost */
	move2process(req, 0);
	if (recv_process(req, regs) != 0) {
	    ghost_setup_proc();	/* cleanup any mess that was made... */
	}

	/* recv_process normally handles un-ghosting for us if the
	 * receive was successful.  We don't just check the return
	 * value from recv_process because in the case of REXECMOVE,
	 * the receive is successful but we will probably still want
	 * to be a ghost.  */
	} break;
    case BPROC_EXEC:
#if 0
	/* NOTE: We don't have an mm but doing the execve will
	 * allocate a new one for us. */

	/* Some rate limiting would be good here */
	req->req.result = recv_send_process(req, regs);
	if (req->req.result)
	    bproc_respond(&bproc_ghost_reqs, req);

	/* Cleanup ghost state since we just used our mm */
	ghost_setup_proc();
#else
	WARNING("BPROC_EXEC not implemented!");
#endif
	break;
    case BPROC_EXIT: {
	struct bproc_status_msg_t *msg = (struct bproc_status_msg_t *)hdr;
	exit_code = msg->hdr.result;
	/* Store the final time information for this process. */
	current->utime   = msg->utime;
	current->stime   = msg->stime;
	spin_lock_irq(&current->sighand->siglock);
	current->signal->cutime = msg->cutime;
	current->signal->cstime = msg->cstime;
	spin_unlock_irq(&current->sighand->siglock);
	
	current->min_flt = msg->minflt;
	current->maj_flt = msg->majflt;
	/*current->nswap   = msg->nswap;*/

	/* XXX REALLY NEED TO MERGE CHILD TIMES TO BE CORRECT HERE... */
	bproc_put_req(req);

	if (exit_code & BPROC_SILENT_EXIT) {
	    silent_exit();
	} else {
	    do_exit(exit_code);
	}
        }
	/* Not reached */
    case BPROC_WAIT: {
	struct bproc_wait_msg_t *msg = (struct bproc_wait_msg_t *)hdr;
	/* We add __WALL here so that we don't have to worry about the
	 * child process's exit signal. */
	pid = k_wait4(msg->pid, msg->options | __WALL, NULL, NULL, NULL);
	if (pid != msg->pid) {
	    if (pid == -ERESTARTSYS)
		/* If we got interrupted this go-round.  Put this guy
		 * on our queue and try it again later.  (It's not
		 * important that we instantly clean up our process
		 * tree here.)  */
		bproc_send_req(&g->req, req);
	    else
		printk(KERN_ERR "bproc: ghost(%d): failed to wait on %d."
		       "options=0x%x  err=%d\n", current->pid,
		       msg->pid, (int) msg->options, pid);
	}
	} break;

	/*--- Remote System Calls ---------------------------------------*/
    case BPROC_SYS_FORK:
	ghost_sys_fork(req);
	break;
    case BPROC_SYS_WAIT:
	ghost_sys_wait(req);
	break;
    case BPROC_SYS_KILL:
	/* XXX Do we still have to worry about uids with siginfo? */
	ghost_sys_kill(req);
	break;
    case BPROC_SYS_SETSID:
	bproc_null_response(&bproc_ghost_reqs, req, sys_setsid());
	break;
    case BPROC_SYS_GETSID: {
	struct bproc_rsyscall_msg_t *msg = (struct bproc_rsyscall_msg_t *)hdr;
	bproc_null_response(&bproc_ghost_reqs, req, sys_getsid(msg->arg[0]));
	} break;
    case BPROC_SYS_GETPGID: {
	struct bproc_rsyscall_msg_t *msg = (struct bproc_rsyscall_msg_t *)hdr;
	bproc_null_response(&bproc_ghost_reqs, req, sys_getpgid(msg->arg[0]));
	} break;
    case BPROC_SYS_SETPGID: {
	struct bproc_rsyscall_msg_t *msg = (struct bproc_rsyscall_msg_t *)hdr;
	bproc_null_response(&bproc_ghost_reqs, req, 
			    sys_setpgid(msg->arg[0], msg->arg[1]));
	} break;
    case BPROC_SET_CREDS: {
	struct bproc_creds_msg_t *msg = (struct bproc_creds_msg_t *)hdr;
	struct bproc_credentials_t *creds = creds_ptr(msg, sizeof(*msg));
	memcpy(current->comm, msg->comm, 16);
	creds_restore(creds, 1);
	if (msg->new_exec) {
	    spin_lock(&g->lock);
	    if (g->proc.exe) fput(g->proc.exe);
	    g->proc.exe = 0;
	    spin_unlock(&g->lock);
	}
	g->proc.dumpable = creds->dumpable;
	} break;

    default:
	printk(KERN_ERR "bproc: ghost: [%d] unhandled request type: %d\n",
	       (int)current->pid, hdr->req);
    }
	return retval;
    
}


static
void ghost_handle_signal(void) {
    int signr;
    struct siginfo info;
    struct bproc_krequest_t *req;
    struct bproc_signal_msg_t *msg;

    spin_lock_irq(&current->sighand->siglock);
    signr = dequeue_signal(current, &current->blocked, &info);
    spin_unlock_irq(&current->sighand->siglock);

    if (!signr) {
	printk(KERN_ERR "bproc: ghost: signal: signr == 0\n");
	return;
    }

    req = bproc_new_req(BPROC_FWD_SIG, sizeof(*msg), GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "bproc: ghost %d: signal forwarding: Out of memory\n",
               (int)current->pid);
        return;
    }
    msg = bproc_msg(req);
    bpr_to_real(msg,    current->pid);
    bpr_from_ghost(msg, current->pid);
    bproc_pack_siginfo(&msg->info, &info);
    bproc_send_req(&bproc_ghost_reqs, req);
    bproc_put_req(req);
}

int ghost_thread(struct pt_regs *regs, struct bproc_krequest_t *fork_req) {
    struct bproc_krequest_t *req;

    ghost_setup_proc();

    /**-----------------------------------------------------------------------
     ** Let remote entities know about our existence.
     **---------------------------------------------------------------------*/
    if (fork_req) {
	struct bproc_rsyscall_msg_t *msg;
	struct bproc_krequest_t *fork_resp;
	struct bproc_fork_resp_t *resp_msg;

	msg = (struct bproc_rsyscall_msg_t *)bproc_msg(fork_req);

	/* Since the remote entity that initiated this fork will be
	 * waiting for a response, it's ok to wait till this point to
	 * add ourselves to the list of ghosts. */
	if (add_ghost(msg->arg[5]) < 0) {
	    printk(KERN_ERR "bproc: ghost: unhandled error case:"
		   " add_ghost flailed!!!\n");
	    do_exit(SIGKILL);
	}
	if (msg->arg[4]) {
	    struct bproc_ghost_proc_t *g = current->bproc.ghost;
	    spin_lock(&g->lock);
	    g->proc.dumpable = msg->arg[3];
	    g->proc.exe = (struct file *) msg->arg[4];
	    spin_unlock(&g->lock);
	}

	fork_resp = bproc_new_resp(fork_req, sizeof(*resp_msg), GFP_KERNEL);
	if (!fork_resp) {
	    printk(KERN_CRIT "bproc: ghost %d: out of memory.\n",
		   current->pid);
	}
	resp_msg = bproc_msg(fork_resp);
	
	/*--- Formulate and send reply to the fork request. -----*/
	/* Add parent information so the remote process will know
	 * exactly where to place itself in the process tree. */
	read_lock(&tasklist_lock);
	resp_msg->hdr.result = current->pid;
	resp_msg->tgid       = current->tgid;
	resp_msg->ppid       = current->parent->pid;
	resp_msg->oppid      = current->real_parent->pid;
	resp_msg->pgrp       = process_group(current);
	resp_msg->session    = current->signal->session;
	read_unlock(&tasklist_lock);

	bproc_send_req(&bproc_ghost_reqs, fork_resp);
	bproc_put_req(fork_req);
	bproc_put_req(fork_resp);
    }

    /**-----------------------------------------------------------------------
     ** Ok wait for stuff to happen now.
     **---------------------------------------------------------------------*/
    while(1) {
	DECLARE_WAITQUEUE(wait, current);
	struct bproc_request_queue_t *reqlist = &current->bproc.ghost->req;

	/**-------------------------------------------------------------------
	 ** This looks like bproc_next_req except that it does the signal
	 ** bypass around the schedule step.
	 ** ----------------------------------------------------------------*/
	add_wait_queue(&reqlist->wait, &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock(&reqlist->lock);
	if (list_empty(&reqlist->list) && !reqlist->closing &&
	    !signal_pending(current)){
	    spin_unlock(&reqlist->lock);
	    schedule();
	    spin_lock(&reqlist->lock);
	}
	set_current_state(TASK_RUNNING);

	if (!list_empty(&reqlist->list)) {
	    req = list_entry(reqlist->list.next,struct bproc_krequest_t,list);
	    list_del(&req->list);
	} else
	    req = 0;
    	spin_unlock(&reqlist->lock);
	remove_wait_queue(&reqlist->wait, &wait);
	/*----------------------------------------------------------*/
	if (req) {
	    int ret;
	    ret = ghost_handle_request(regs, req);
	    bproc_put_req(req);
	    /* Return to user space if we're no longer a ghost. */
	    if (!BPROC_ISGHOST(current)) {
		/* XXX I think syscall tracing will be broken if we
		 * attach remotely and then move here with tracing
		 * attached.  We really need to know what syscall path
		 * we came in on. */
		return ret;
	    }
	} else {
	    /* This is the 'violent death' case.  i.e. master or
	     * slave daemon disappears for some reason. */
	    if (current->bproc.ghost->req.closing) {
		do_exit(SIGKILL);
	    }
	}

	if (signal_pending(current))
	    ghost_handle_signal();
    }
    /* NOT REACHED */
}

/*--------------------------------------------------------------------
 *  /proc ps helpers.
 *------------------------------------------------------------------*/
/*  Before doing PS:
 *  If last_global_update + data_timeout < jiffies then
 *      update_all()
 *  If ghost.response_time < last_global_update &&
 *     last_global_update + response_timeout < jiffies then
 *      wait w/ timeout for response
 *      if got response
 *
 *  use cached info.
 *
 * data_timeout >> response_timeout
 *
 * response_timeout controls how long you want 'ps' to block.            (~1s?)
 * data_timeout     controls how frequently you want to re-query nodes.  (5-10s?)
 */

/* FIX ME: These should be tunables. */
int ghost_data_timeout     = 5*HZ;
int ghost_response_timeout = 1*HZ;
static unsigned long last_request = 0, last_request2 = 0;

int ghost_update_status(struct bproc_krequest_t *req) {
    struct task_struct *tsk;
    struct bproc_ghost_proc_t *g = 0;
    struct bproc_status_msg_t *msg;

    /* newly exported kernel func w/o prototype */
    void do_notify_parent_cldstop(struct task_struct *tsk,
				  struct task_struct *parent,
				  int why);

    msg = bproc_msg(req);

    read_lock(&tasklist_lock);
    tsk = find_task_by_pid(msg->hdr.from);
    if (tsk) {
	g = tsk->bproc.ghost;
	if (g) {
	    g->last_response = jiffies;

	    /* state update */
	    if (msg->state >= TASK_ZOMBIE) {
		/*SPEW2("squashing %d state %d -> %d", tsk->pid, msg->state,
		  TASK_RUNNING);*/
		/* Squash since the FE clearly hasn't exited yet and
		 * having a Z in the ghost status structure will mess
		 * up wait.  The exit message should be on its way to
		 * sync up the front end.*/
		msg->state = TASK_RUNNING;
	    }

	    tsk->utime     = msg->utime;
	    tsk->stime     = msg->stime;
	    /* child times are kinda fucked here. */
	    spin_lock_irq(&tsk->sighand->siglock);
	    tsk->signal->cutime = msg->cutime;
	    tsk->signal->cstime = msg->cstime;
	    spin_unlock_irq(&tsk->sighand->siglock);
	    tsk->min_flt   = msg->minflt;
	    tsk->maj_flt   = msg->majflt;

	    if (msg->vm.statm.size > 0)	{/* vm stuff may not be valid... */
		memcpy(&g->vm, &msg->vm, sizeof(g->vm));
	    }
	    wake_up(&g->wait);

	    /* We only update process state if it's a STOP,CONT or if
	     * the STOPPED flag isn't set.  This keeps the lazy update
	     * messages from stomping on the immediate STOP/CONT
	     * updates. */
	    switch (msg->hdr.req) {
	    case BPROC_STOP:
		/* Sanity checks. */
		if (test_bit(BPROC_FLAG_STOPPED, &tsk->bproc.flag))
		    SPEW1("Huh? Stop already set.");

		set_bit(BPROC_FLAG_STOPPED, &tsk->bproc.flag);
		tsk->exit_code = msg->exit_code;
		spin_lock(&g->lock);
		g->state = msg->state;
		spin_unlock(&g->lock);

		switch (g->state) {
		case TASK_TRACED:
		    do_notify_parent_cldstop(tsk, tsk->parent, CLD_TRAPPED);
		    break;		    
		case TASK_STOPPED:
		    do_notify_parent_cldstop(tsk, tsk->parent, CLD_STOPPED);
		    break;
		default:
		    SPEW2("Unknown state in BPROC_STOP 0x%x", g->state);
		}
		break;
	    case BPROC_CONT:
		if (!test_bit(BPROC_FLAG_STOPPED, &tsk->bproc.flag))
		    SPEW1("Huh? Stop not set set.");

		clear_bit(BPROC_FLAG_STOPPED, &tsk->bproc.flag);
		spin_lock(&g->lock);
		g->state = msg->state;
		g->ptrace.bytes = 0; /* invalidate ptrace read ahead data */
		spin_unlock(&g->lock);
		tsk->exit_code = msg->exit_code;
		break;
	    default:
		if (!test_bit(BPROC_FLAG_STOPPED, &tsk->bproc.flag)) {
		    spin_lock(&g->lock);
		    tsk->exit_code = msg->exit_code;
		    g->state = msg->state;
		    spin_unlock(&g->lock);
		}
		break;
	    }
	}
    }
    read_unlock(&tasklist_lock);
    if (!g) return -ESRCH;
    return 0;
}



void ghost_refresh_init(void) {
    last_request  = jiffies - ghost_data_timeout;
    last_request2 = jiffies - ghost_data_timeout*2;
}

void ghost_refresh_status(struct task_struct *p) {
    DECLARE_WAITQUEUE(wait, current);
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;
    struct bproc_ghost_proc_t *g;
    long timeout;

    if (!(g = ghost_get(p))) return;

    /* See if we've waited long enough to do another global update */
    if (jiffies - last_request > ghost_data_timeout) {
	/* Send out a request to update all process status */
	req = bproc_new_req(BPROC_GET_STATUS, sizeof(*msg), GFP_KERNEL);
	if (!req) {
	    printk(KERN_ERR "bproc: ghost_update_status: out of memory\n");
	    ghost_put(g);
	    return;
	}
	msg = bproc_msg(req);
	bpr_to_node(msg, -1);
	bpr_from_node(msg, -1);
	bproc_send_req(&bproc_ghost_reqs, req);
	bproc_put_req(req);

	last_request2 = last_request;
	last_request = jiffies;
    } else {
	/* Else, if this is a new ghost, ask right away. */
	if (g->last_response == 0) {
	    g->last_response = last_request2-1;	/* set a reasonable value? */
	    req = bproc_new_req(BPROC_GET_STATUS, sizeof(*msg), GFP_KERNEL);
	    if (!req) {
		printk(KERN_ERR "bproc: ghost_update_status: out of memory\n");
		ghost_put(g);
		return;
	    }
	    msg = bproc_msg(req);
	    bpr_to_real(msg, p->pid);
	    bpr_from_node(msg, -1);
	    bproc_send_req(&bproc_ghost_reqs, req);
	    bproc_put_req(req);
	}
    }

    if (g->last_response < last_request) {
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&g->wait, &wait);
	timeout = last_request + ghost_response_timeout - jiffies;
	/* while
	 *   - there's no response to the last request
	 *   - we did get a response to the one before it
	 *   - and we're still willing to wait a little longer.
	 */
	while (g->last_response <  last_request  &&
	       g->last_response >= last_request2 &&
	       timeout > 0 && !signal_pending(current)) {
	    timeout = schedule_timeout(timeout);
	    set_current_state(TASK_INTERRUPTIBLE);
	}
	remove_wait_queue(&g->wait, &wait);
	set_current_state(TASK_RUNNING);
    }
    ghost_put(g);
}

int ghost_set_location(int pid, int loc) {
    int ret = -ESRCH;
    struct task_struct *t;
    struct bproc_ghost_proc_t *g;

    read_lock(&tasklist_lock);
    t = find_task_by_pid(pid);
    if (t) {
	g = t->bproc.ghost;
	if (g) {
	    g->node = loc;
	    ret = 0;
	}
    }
    read_unlock(&tasklist_lock);
    return ret;
}


/*--------------------------------------------------------------------
 *
 *
 *
 */
void ghost_ptrace_cache(struct bproc_ptrace_msg_t *pt_resp) {
    struct task_struct *p;
    struct bproc_ghost_proc_t *g;

    p = find_task_by_pid(pt_resp->hdr.from);
    if (p) {
	if ((g = ghost_get(p))) {
	    spin_lock(&g->lock);
	    if (g->state != TASK_STOPPED && g->state != TASK_TRACED) {
		printk(KERN_ERR "bproc: ptrace data but ghost not "
		       "stopped state=%d pid=%d flags=%lx\n",
		       g->state, pt_resp->hdr.from, p->bproc.flag);
	    }

	    /* Sanity check */
	    if (pt_resp->bytes > BPROC_PTRACE_RA_BYTES)
		pt_resp->bytes = 0;

	    /* Copy the data */
	    g->ptrace.addr  = pt_resp->addr;
	    g->ptrace.bytes = pt_resp->bytes;
	    memcpy(g->ptrace.data, pt_resp->data.data, pt_resp->bytes);

	    spin_unlock(&g->lock);
	    ghost_put(g);
	}
    }
}

/*--------------------------------------------------------------------
 *  reparent_process()
 *
 *  This reparents a process on the front end.  This notification is
 *  sent when a ptrace attach succeeds on a remote node.
 */
void reparent_process(struct bproc_krequest_t *req) {
    struct task_struct *child, *parent;
    struct bproc_reparent_msg_t *msg;

    msg = bproc_msg(req);

    spin_lock(&bproc_ptrace_attach_lock); /* might not be necessary */
    write_lock_irq(&tasklist_lock);
    child = find_task_by_pid(msg->hdr.from);
    if (!child) {
	printk(KERN_ERR "bproc: reparent_process: failed to find child (%d)\n",
	       msg->hdr.from);
	goto out;
    }
    if (!BPROC_ISGHOST(child)) {
	printk(KERN_ERR "bproc: reparent_process: expecting a ghost (%d)\n",
	       msg->hdr.from);
	goto out;
    }

    switch (msg->new_parent) {
    case 0:
	parent = 0;		/* unlink/detach case. */
	break;
    default:
	parent = find_task_by_pid(msg->new_parent);
	break;
    }

    /* We check to make sure the parent is alive here.  In the TRACEME
     * case, it's possible that the parent exits while the child is
     * doing a TRACEME.  If the parent has exited, the reparent is
     * ignored. */
    if (parent && parent->state < TASK_ZOMBIE) {
	child->ptrace = msg->ptrace;
	ptrace_link(child, parent);
    } else {
	ptrace_unlink(child);	/* clears ptrace flag */
    }
 out:
    write_unlock_irq(&tasklist_lock);
    spin_unlock(&bproc_ptrace_attach_lock); /* might not be necessary */
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
