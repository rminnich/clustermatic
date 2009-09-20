/*-------------------------------------------------------------------------
 *  masq.c: Beowulf distributed process space PID masquerading routines
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
 * $Id: masq.c,v 1.94 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/signal.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/bproc.h>
#include <linux/hugetlb.h>
#include <asm/uaccess.h>

#include "bproc.h"
#include "bproc_internal.h"

/*-------------------------------------------------------------------------
 *  process list management functions
 */
struct task_struct *masq_find_task_by_pid(struct bproc_masq_master_t *m,
					  pid_t pid) {
    struct list_head *l;
    struct task_struct *p;

    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	p = list_entry(l, struct task_struct, bproc.list);
	if (p->bproc.pid == pid) return p;
    }
    return 0;
}

void set_parents(struct task_struct *task,
		 struct task_struct *real_parent, struct task_struct *parent) {
    /*SPEW2("Reparenting %d gets %d and %d as parents.",
      task->pid, real_parent->pid, parent->pid);*/
    if (task == real_parent || task == parent)
	BUG();

    list_del_init(&task->ptrace_list); /* always safe... */

    task->real_parent = real_parent;
    REMOVE_LINKS(task);
    task->parent = parent;
    SET_LINKS(task);

    if (real_parent != parent) {
	if (!task->ptrace) /* Sanity check */
	    printk(KERN_ERR "bproc: different parent but no ptrace! (sps)\n");
	list_add(&task->ptrace_list, &real_parent->ptrace_children);
    }
}

int masq_find_id_mapping(struct bproc_masq_master_t *m, int id,
			 struct task_struct *ignore) {
    struct list_head *l;
    struct task_struct *p;

    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	p = list_entry(l, struct task_struct, bproc.list);
	if (p != ignore) {
	    if (p->bproc.pid  == id) return p->pid;
	    if (p->bproc.tgid == id) return p->tgid;
	    if (p->signal->bproc.pgrp == id)
		return process_group(p);
	    if (p->signal->bproc.session == id)
		return p->signal->session;
	}
    }
    return 0;
}

/* masq process IDs are mapped to local process IDs.  */

/* The arrival of a new process might change a pid mapping on this
 * node.  Update any other processes which might be using that mapping
 * for something */
static
void masq_update_mappings(struct bproc_masq_master_t *m,
			  struct task_struct *proc) {
    struct list_head *l;
    struct task_struct *task;
    int /*id,*/ masq_id, real_id;

    /* Step 1: Our real/masq pid pair defines one masq->real mapping.
     * Any other processes in the system that have our masq pid in
     * their pgrp or session id might have to be updated.  */

    /* TGID: Since we're not allowing thread groups to span multiple
     * nodes, we should never end up with a situation where they're
     * out of sync.  (with multithreaded migration this might be
     * different some day.) */
    masq_id = proc->bproc.pid;
    real_id = proc->pid;
    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	task = list_entry(l, struct task_struct, bproc.list);

	/* tgid shouldn't be necessary since we're not going to allow
	 * thread groups to span nodes. */

	if (task->signal->bproc.pgrp == masq_id &&
	    task->signal->pgrp       != real_id) {
	    detach_pid(task, PIDTYPE_PGID);
	    task->signal->pgrp = real_id;
	    attach_pid(task, PIDTYPE_PGID, real_id);
	}

	if (task->signal->bproc.session == masq_id &&
	    task->signal->session       != real_id) {
	    detach_pid(task, PIDTYPE_SID);
	    task->signal->session = real_id;
	    attach_pid(task, PIDTYPE_SID, real_id);
	}
    }
#if 0
    /* Step 2: Our pgrp and session ID might exist in the system on
     * some other process.  If so, make sure that ours is uptodate as
     * well. */
    if (proc->signal->bproc.pgrp != proc->bproc.pid) {
	id = masq_find_id_mapping(m, proc->signal->bproc.pgrp, proc);
	if (!id)
	    id = alloc_pidmap();
	if (!id)
	    printk(KERN_EMERG "bproc: failed to allocate pid.\n");

	if (proc->signal->pgrp != id) {
	    detach_pid(proc, PIDTYPE_PGID);
	    proc->signal->pgrp = id;
	    attach_pid(proc, PIDTYPE_PGID, id);
	}
    }
    if (proc->signal->bproc.session != proc->bproc.pid) {
	id = masq_find_id_mapping(m, proc->signal->bproc.session, proc);
	if (!id)
	    id = alloc_pidmap();
	if (!id)
	    printk(KERN_EMERG "bproc: failed to allocate pid.\n");

	if (proc->signal->session != id) {
	    detach_pid(proc, PIDTYPE_SID);
	    proc->signal->session = id;
	    attach_pid(proc, PIDTYPE_SID, id);
	}
    }
#endif
}


/* masq_select_parents: This function finds and links up parent
 * processes for a masqueraded process.  This is used for adding and
 * removing processes from a process space.
 *
 * THIS MUST BE CALLED WITH tasklist_lock write-held !
 */
static
void masq_select_parents(struct bproc_masq_master_t *m,
			 struct task_struct *newp) {
    struct task_struct *pp, *rpp;

    /* Step 1: Insert this process into the process tree.  Look for
     * the processes that this one wants as its parents.  If no
     * suitable parents available, make init the parent.  In the case
     * of traced processes, the parent is set to the slave daemon. */
    rpp = masq_find_task_by_pid(m, newp->bproc.oppid);
    pp  = masq_find_task_by_pid(m, newp->bproc.ppid);

    /* check to make sure that we don't end up giving children back to
     * zombies. */
    if (rpp && rpp->state >= TASK_ZOMBIE) rpp = 0;
    if (pp  && pp->state  >= TASK_ZOMBIE) pp  = 0;

    /* Update book keeping on the parent(s) */
    if (rpp && rpp != newp->real_parent)         rpp->bproc.nlchild--;
    if (pp  && pp  != newp->parent && rpp != pp) pp ->bproc.nlchild--;

    /* If any parents are missing, select appropriate local parent processes */
    if (!rpp) rpp = child_reaper;
    if (!pp)  pp  = child_reaper;
    set_parents(newp, rpp, pp);	/* ... and do it. */
}

/* masq_add_proc: this is the function that takes a new process and
 * inserts it into our masqueraded process space.
 *
 * THIS MUST BE CALLED WITH tasklist_lock write-held !
 */
void masq_add_proc(struct bproc_masq_master_t *m,
		   struct task_struct *newp, int sp) {
    struct list_head *l;
    struct task_struct *p, *pp, *rpp;

    if (newp->bproc.master) {
	printk(KERN_ERR "bproc: we're already a managed process (%d)\n",
	       newp->bproc.pid);
	return;
    }

    /* Step 0: Sanity check.  Make sure that this process ID doesn't
     * already exist on this node. */
    if (masq_find_task_by_pid(m, newp->bproc.pid)) {
	printk(KERN_CRIT "bproc: masq: process ID %d already exists on "
	       "this node!\n", newp->bproc.pid);
    }

    masq_select_parents(m, newp);

    /* This next bit is conditional because we don't want to do it
     * when handling clone() with CLONE_PARENT */
    if (sp) {
	/* Step 2: look for processes that really want this one as its
	 * parent */
	for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	    p = list_entry(l, struct task_struct, bproc.list);

	    if (p->bproc.oppid != newp->bproc.pid &&
		p->bproc.ppid != newp->bproc.pid)
		continue;

	    rpp = p->real_parent;
	    pp  = p->parent;

	    if (p->bproc.oppid == newp->bproc.pid)
		rpp = newp;
	    if (p->bproc.ppid  == newp->bproc.pid)
		pp = newp;

	    set_parents(p, rpp, pp);
	    if (rpp == newp) newp->bproc.nlchild--;
	    if (pp  == newp && rpp != newp) newp->bproc.nlchild--;
	}
    }

    /* Setup our IDs (tgid, pgrp, session) so that they mesh with
     * whatever is already on this system. */
    masq_update_mappings(m, newp);

    /* bproc_clear_kcall */
    clear_bit(BPROC_FLAG_KCALL,    &newp->bproc.flag);
    clear_bit(BPROC_FLAG_NO_KCALL, &newp->bproc.flag);

    /* Add new masq'ed process */
    newp->bproc.master = m;
    list_add_tail(&newp->bproc.list, &m->proc_list);
    atomic_inc(&m->count);
}

/*-------------------------------------------------------------------------
 *  pid mapping functions
 */
pid_t masq_masq2real(struct bproc_masq_master_t *m, pid_t masq) {
    pid_t pid;
    struct list_head *l;
    struct task_struct *p;

    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	p = list_entry(l, struct task_struct, bproc.list);
	if (p->bproc.pid == masq) {
	    pid = p->pid;
	    return pid;
	}
    }
    return -ESRCH;
}

extern struct task_struct *child_reaper;


/* This one is copied directly from the kernel (kernel/signal.c) */
/*
 * Joy. Or not. Pthread wants us to wake up every thread
 * in our parent group.
 */
static void __wake_up_parent(struct task_struct *p,
				    struct task_struct *parent)
{
	struct task_struct *tsk = parent;

	/*
	 * Fortunately this is not necessary for thread groups:
	 */
	if (p->tgid == tsk->tgid) {
		wake_up_interruptible_sync(&tsk->wait_chldexit);
		return;
	}

	do {
		wake_up_interruptible_sync(&tsk->wait_chldexit);
		tsk = next_thread(tsk);
		if (tsk->signal != parent->signal)
			BUG();
	} while (tsk != parent);
}

void silent_exit(void) {
    struct task_struct *parent;

    write_lock_irq(&tasklist_lock);
    parent = current->parent;
    if (BPROC_ISMASQ(current)) {
	/* unmasq includes a re-parent step */
	masq_remove_proc(current, 0);
    } else {
	/* Reparent self to init */
	current->exit_signal = SIGCHLD;
	set_parents(current, child_reaper, child_reaper);
    }
    __wake_up_parent(current,parent);
    write_unlock_irq(&tasklist_lock);
    do_exit(0);
}



/*
 * Determine whether a signal should be posted or not.
 *
 * Signals with SIG_IGN can be ignored, except for the
 * special case of a SIGCHLD.
 *
 * Some signals with SIG_DFL default to a non-action.
 *
 * (This function stolen from Linux)
 */

#if SIGRTMIN > BITS_PER_LONG
#define M(sig) (1ULL << ((sig)-1))
#else
#define M(sig) (1UL << ((sig)-1))
#endif
#define T(sig, mask) (M(sig) & (mask))

#define sig_kernel_ignore(sig) \
                (((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_IGNORE_MASK))
#define SIG_KERNEL_IGNORE_MASK (\
        M(SIGCONT)   |  M(SIGCHLD)   |  M(SIGWINCH)  |  M(SIGURG)    )
static inline int sig_ignored(struct task_struct *t, int sig)
{
        void * handler;

        /*
         * Tracers always want to know about signals..
         */
        if (t->ptrace & PT_PTRACED)
                return 0;

        /*
         * Blocked signals are never ignored, since the
         * signal handler may change by the time it is
         * unblocked.
         */
        if (sigismember(&t->blocked, sig))
                return 0;

        /* Is it explicitly or implicitly ignored? */
        handler = t->sighand->action[sig-1].sa.sa_handler;
        return   handler == SIG_IGN ||
                (handler == SIG_DFL && sig_kernel_ignore(sig));
}


/*-------------------------------------------------------------------------
 *  bpr_rsyscall - Generic remote syscall code.
 *
 *  rsyscall1 - create a remote syscall message.
 *  rsyscall2 - send the message and wait while forwarding any signals...
 */
static
struct bproc_krequest_t *bpr_rsyscall1(int type) {
    int i;
    struct bproc_krequest_t *req;
    struct bproc_rsyscall_msg_t *msg;

    req = bproc_new_req(type, sizeof(*msg), GFP_KERNEL);
    if (!req) return 0;
    msg = (struct bproc_rsyscall_msg_t *)bproc_msg(req);

    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    req->flags = BPROC_REQ_WANT_RESP;

    spin_lock_irq(&current->sighand->siglock);
    /* Store my signal handler information */
    sigemptyset((sigset_t*)msg->blocked);
    for (i=1; i <= _NSIG; i++) {
	if (sig_ignored(current, i))
	    sigaddset((sigset_t*)msg->blocked, i);
	else
	    sigdelset((sigset_t*)msg->blocked, i);
    }
    spin_unlock_irq(&current->sighand->siglock);
    return req;
}

static
void masq_forward_signal(struct bproc_masq_master_t *m) {
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
	printk(KERN_ERR "bproc: masq: [%d] signal forwarding: Out of memory\n",
	       (int)current->bproc.pid);
	return;
    }
    msg = (struct bproc_signal_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg,  current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    bproc_pack_siginfo(&msg->info, &info);
    bproc_send_req(&m->req, req);
    bproc_put_req(req);
}

static
int bpr_rsyscall2(struct bproc_masq_master_t *m,
		  struct bproc_krequest_t *req, int interruptible) {
    int r;
    req->flags |= BPROC_REQ_WANT_RESP;
    if ((r = bproc_send_req(&m->req, req)) != 0) return r;
    r = bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, interruptible);
    while (r == -EINTR && bproc_pending(req)) {
	/* Deal with a signal */
	masq_forward_signal(m);
	r = bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, interruptible);
    }
    /* XXX TO DO: Deal with signal response w/ EINTR */
    return r;
}

/*-------------------------------------------------------------------------
 *  bproc_masq_new_pid
 *
 *  This is called by fork() to allocate a new masqueraded PID for a new
 *  child process.
 */
int masq_new_pid(struct task_struct *child, int flags) {
    int r;
    struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);
    struct bproc_krequest_t    *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_fork_resp_t   *resp;

    /* We already have a child thread at this point.  All new
     * processes are re-parented to init so that we can take care of
     * all the parent child relationships on the front end. */

    /* Setup a new request */
    req = bpr_rsyscall1(BPROC_SYS_FORK);
    if (!req) return -ENOMEM;
    msg = (struct bproc_rsyscall_msg_t *) bproc_msg(req);
    msg->arg[0] = flags;

    r = bpr_rsyscall2(m, req, 1);
    if (r != 0) {
	bproc_put_req(req);
	return r;
    }

    resp = bproc_msg(req->response);
    if (resp->hdr.result > 0) {
	/* Everything is ok... Setup all the masq stuff for this
	 * process. */
	child->bproc.pid             = resp->hdr.result;
	child->bproc.tgid            = resp->tgid;
	child->bproc.ppid            = resp->ppid;
	child->bproc.oppid           = resp->oppid;
	child->signal->bproc.pgrp    = resp->pgrp;
	child->signal->bproc.session = resp->session;

	/* Other local book keeping */
	child->bproc.nlchild = 0;
	child->bproc.last_update = 0;

	/* masq_add_proc(m, child, 0); Done later... */
    }
    r = resp->hdr.result;

    bproc_put_req(req);
    return r;
}

/*-------------------------------------------------------------------------
 *  bproc_masq_wait
 */
int masq_wait(pid_t pid, int options, struct siginfo *infop,
	      unsigned int * stat_addr, struct rusage * ru) {
    int result, lpid, status;
    struct bproc_krequest_t *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_wait_resp_t *resp_msg;
    struct task_struct *child;

    /* XXX to be 100% semantically correct, we need to verify_area
     * here on stat_addr and ru here... */
    req = bpr_rsyscall1(BPROC_SYS_WAIT);
    if (!req){
	printk("bproc: masq: sys_wait: out of memory.\n");
	return -ENOMEM;
    }
    msg = (struct bproc_rsyscall_msg_t *) bproc_msg(req);
    msg->arg[0] = pid;
    msg->arg[1] = options;

    if (bpr_rsyscall2(BPROC_MASQ_MASTER(current), req, 1) != 0) {
	bproc_put_req(req);
	return -EIO;
    }

    resp_msg = bproc_msg(req->response);

    result = resp_msg->hdr.result;
    status = resp_msg->status;
    if (stat_addr) put_user(status, stat_addr);
    if (ru) {
	/* Only a few elements of the rusage structure are provided by
	 * Linux.  Also, convert the times back to the HZ
	 * representation. */
	struct rusage ru_tmp;
	memset(&ru_tmp, 0, sizeof(ru_tmp));
	ru_tmp.ru_utime.tv_sec  =  resp_msg->utime/HZ;
	ru_tmp.ru_utime.tv_usec = (resp_msg->utime*(1000000/HZ))%1000000;
	ru_tmp.ru_stime.tv_sec  =  resp_msg->stime/HZ;
	ru_tmp.ru_stime.tv_usec = (resp_msg->stime*(1000000/HZ))%1000000;
	ru_tmp.ru_minflt        =  resp_msg->minflt;
	ru_tmp.ru_majflt        =  resp_msg->majflt;
	ru_tmp.ru_nswap         =  resp_msg->nswap;
	copy_to_user(ru, &ru_tmp, sizeof(ru_tmp));
    }
    bproc_put_req(req);

    if (result > 0 && (status & 0xff) != 0x7f) {
	/* It's possible that the process we waited on was actually
	 * local.  We need to make sure and get it out of this process
	 * tree too.  If it's not, we need to down the non local child
	 * count by one... */
	write_lock_irq(&tasklist_lock);
	child = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), result);
	if (child)
	    lpid = child->pid;
	else {
	    lpid = 0;
	    current->bproc.nlchild--;
	}
	write_unlock_irq(&tasklist_lock);
	if (lpid) {
	    /* Do all of this as a kernel call to avoid re-entering
	     * this whole mess... */
	    set_bit(BPROC_FLAG_KCALL, &current->bproc.flag);
	    if (k_wait4(lpid, options & ~WNOHANG, NULL, NULL, NULL) == -1) {
		printk(KERN_ERR "bproc: masq: local wait failed on %d (%d)\n",
		       lpid, result);
#if 0
		/* This probably isn't correct.  If we fail to wait,
		 * that probably means that somebody else picked it
		 * up. */
		write_lock_irq(&tasklist_lock);
		current->bproc.nlchild--;
		write_unlock_irq(&tasklist_lock);
#endif
	    }
	}
    }
    return result;
}


/*-------------------------------------------------------------------------
 *  bproc_masq_send_sig
 *
 *  Forward a signal to a remote process.  This process just formulates
 *  a request for user space daemon and queues it up.
 */
int masq_send_sig(int sig, struct siginfo *info, pid_t pid) {
    int result;
    struct bproc_request_queue_t *master = &(BPROC_MASQ_MASTER(current)->req);
    struct bproc_krequest_t      *req;
    struct bproc_signal_msg_t    *msg;
    struct siginfo                tmpinfo;
    struct bproc_null_msg_t      *resp_msg;

    /* If info is 0 or 1 we need to cook up an info structure... */
    switch ((unsigned long) info) {
    case 0:
	tmpinfo.si_signo = sig;
	tmpinfo.si_errno = 0;
	tmpinfo.si_code = SI_USER;
	tmpinfo.si_pid = current->pid;
	tmpinfo.si_uid = current->uid;
	info = &tmpinfo;
	break;
    case 1:
	tmpinfo.si_signo = sig;
	tmpinfo.si_errno = 0;
	tmpinfo.si_code = SI_KERNEL;
	tmpinfo.si_pid = 0;
	tmpinfo.si_uid = 0;
	info = &tmpinfo;
	break;
    }

    req = bproc_new_req(BPROC_SYS_KILL, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk("bproc: masq: forward signal failed.\n");
	return -ENOMEM;		/* XXX not a valid error for kill() */
    }
    msg = (struct bproc_signal_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    msg->pid = pid;
    bproc_pack_siginfo(&msg->info, info);

    if (bproc_send_req_wait(master, req) != 0) {
	printk("bproc: masq: BPROC_SYS_KILL failed!\n");
	bproc_put_req(req);
	return -ESRCH;		/* reasonable ? */
    }
    resp_msg = bproc_msg(req->response);
    result = resp_msg->hdr.result;
    bproc_put_req(req);
    return result;
}


/*-------------------------------------------------------------------------
 * masq_set_creds
 */
void masq_set_creds(int new_exec) {
    struct bproc_request_queue_t *master;
    struct bproc_krequest_t *req;
    struct bproc_creds_msg_t *msg;

    /* Notify our ghost of a change in our credentials.  */
    req = bproc_new_req(BPROC_SET_CREDS,
			sizeof(*msg) + creds_size(current), GFP_KERNEL);
    if (!req) {
	printk("Out of mmemory on BPROC_SET_CREDS");
	return;
    }
    msg = (struct bproc_creds_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);

    memcpy(msg->comm, current->comm, 16);
    creds_store(creds_ptr(msg, sizeof(*msg)));
    msg->new_exec = new_exec;

    master = &(BPROC_MASQ_MASTER(current)->req);
    bproc_send_req(master, req);
    bproc_put_req(req);
}

/*-------------------------------------------------------------------------
 *  bproc_masq_exit_notify
 *  note that tsk == current (always, I think)...
 */

static
void pack_process_mm_stats(struct bproc_status_msg_t *msg,
			   struct mm_struct *mm) {
    	struct vm_area_struct *vma;
	memset(&msg->vm, 0, sizeof(msg->vm));

	msg->vm.statm.resident   = mm->rss;

	msg->vm.status.total_vm  = mm->total_vm;
	msg->vm.status.locked_vm = mm->locked_vm;
	msg->vm.status.rss       = mm->rss;

	/* This code is stolen from the Linux kernel (fs/proc/task_mmu.c) */
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
	    {			/* CODE FOR statm */
		int pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

		msg->vm.statm.size += pages;
		if (is_vm_hugetlb_page(vma)) {
			if (!(vma->vm_flags & VM_DONTCOPY))
				msg->vm.statm.shared += pages;
			continue;
		}
		if (vma->vm_file)
			msg->vm.statm.shared += pages;
		if (vma->vm_flags & VM_EXECUTABLE)
			msg->vm.statm.text += pages;
		else
			msg->vm.statm.data += pages;
	    }
	    {			/* CODE FOR status */
		unsigned long len = (vma->vm_end - vma->vm_start) >> 10;
		if (!vma->vm_file) {
			msg->vm.status.data += len;
			if (vma->vm_flags & VM_GROWSDOWN)
				msg->vm.status.stack += len;
			continue;
		}
		if (vma->vm_flags & VM_WRITE)
			continue;
		if (vma->vm_flags & VM_EXEC) {
			msg->vm.status.exec += len;
			if (vma->vm_flags & VM_EXECUTABLE)
				continue;
			msg->vm.status.lib += len;
		}
	    }
	}
}

static
void pack_process_status(struct bproc_status_msg_t *msg,
			 struct task_struct *tsk, int pack_mm) {
    msg->state     = tsk->state;
    msg->exit_code = tsk->exit_code;

    msg->utime     = tsk->utime;
    msg->stime     = tsk->stime;

    spin_lock_irq(&current->sighand->siglock);
    /* XXX FIX ME:  there's utime and stime in here too */
    msg->cutime    = tsk->signal->cutime;
    msg->cstime    = tsk->signal->cstime;
    spin_unlock_irq(&current->sighand->siglock);

    msg->minflt    = tsk->min_flt;
    msg->majflt    = tsk->maj_flt;
    /*msg->nswap     = tsk->nswap;*/

    if (pack_mm) {
	struct mm_struct *mm;
	mm = get_task_mm(tsk);
	if (mm) {
	    down_read(&mm->mmap_sem);
	    pack_process_mm_stats(msg, mm);
	    up_read(&mm->mmap_sem);
	    mmput(mm);
	}
    } else {
	msg->vm.statm.size = 0;
    }
}

void masq_exit_notify(struct task_struct *tsk, long code) {
    struct bproc_krequest_t   *req;
    struct bproc_status_msg_t *msg;
    req = bproc_new_req(BPROC_EXIT, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk(KERN_CRIT "bproc: out of memory doing exit notify.\n");
	return;
    }
    msg = (struct bproc_status_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg, tsk->bproc.pid);
    bpr_from_real(msg, tsk->bproc.pid);
    msg->hdr.result = code;
    pack_process_status(msg, tsk, 1);
    bproc_send_req(&(BPROC_MASQ_MASTER(tsk)->req), req);
    bproc_put_req(req);
}

/*-------------------------------------------------------------------------
 *  masq state notifications
 */
void masq_stop_notify(void) {
    struct bproc_krequest_t   *req;
    struct bproc_status_msg_t *msg;

    /* weirdness here...  we come in here with our state set to
     * STOPPED.  kmalloc could schedule for us, instead  */

    req = bproc_new_req(BPROC_STOP, sizeof(*msg), GFP_ATOMIC);
    if (!req) {
	printk("bproc: STOP notification failed - out of memory.\n");
	clear_bit(BPROC_FLAG_STOPPED, &current->bproc.flag);
	return;
    }
    msg = (struct bproc_status_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    pack_process_status(msg, current, 0);

    /* A note about the process exit_code: This can be cleared by a
     * waiting parent before we even get into schedule.
     *
     * We only want to notify the front end about our stop if:
     *  Our parent is NOT local - that is remote notification is necessary NOW.
     *  Our exit status has not been sucked up already.
     *  We haven't already notified about our stop.
     */

    /* We need to block out wait here for a second while we check
     * whether or not we want to emit this message. */
    read_lock(&tasklist_lock);
    if (/*!BPROC_ISMASQ(current->parent) &&*/
	current->exit_code != 0) {
	bproc_send_req(&current->bproc.master->req, req);
    } else {
	clear_bit(BPROC_FLAG_STOPPED, &current->bproc.flag);
    }
    read_unlock(&tasklist_lock);
    bproc_put_req(req);
}

void masq_cont_notify(void) {
    struct bproc_krequest_t *req;
    struct bproc_status_msg_t *msg;

    req = bproc_new_req(BPROC_CONT, sizeof(*msg), GFP_KERNEL);
    if (!req) return;
    msg = (struct bproc_status_msg_t *) bproc_msg(req);
    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    pack_process_status(msg, current, 1);

    bproc_send_req(&current->bproc.master->req, req);
    bproc_put_req(req);
}

/*-------------------------------------------------------------------------
 *  masq_remove_proc
 *
 *  This removes a process from a pid space master's list of processes.
 *  This is called by sys_wait4 when a process is actually released from
 *  the system's task list.
 *
 *  This is the special case where it's safe to modify another task's
 *  BProc pointers... This is because we know the other task in
 *  question is a ZOMBIE and therefore not using the pointers.
 *
 * THIS MUST BE CALLED WITH tasklist_lock write-held.
 */

void masq_remove_proc(struct task_struct *tsk, int update_nlchild) {
    struct bproc_masq_master_t *m;

    /* update the child counts on the parent process(es) but only if
     * we're going away in a silent exit.  (i.e. tsk == current and
     * we're running, not from wait->release->unmasq in which case tsk
     * is some other process and a zombie.) */
    if (update_nlchild) {
	if (BPROC_ISMASQ(tsk->real_parent)) {
	    tsk->real_parent->bproc.nlchild++;
	    wake_up_interruptible(&tsk->real_parent->wait_chldexit);
	}
	if (tsk->parent != tsk->real_parent && BPROC_ISMASQ(tsk->parent)) {
	    tsk->parent->bproc.nlchild++;
	    wake_up_interruptible(&tsk->parent->wait_chldexit);
	}
    }

    /* Remove this process from the list of processes for this master.
     * If this was the last reference to it, free the master structure
     * as well. */
    m = tsk->bproc.master;
    list_del(&tsk->bproc.list);
    tsk->bproc.master = 0;
    if (atomic_dec_and_test(&m->count))
	kfree(m);

    /*ptrace_disable ? */
    if (tsk->state < TASK_ZOMBIE) {
	/* Since we're trying to disappear silently, we should
	 * reparent ourselves to init which will do the wait() on
	 * us. */
	ptrace_unlink(tsk);
	tsk->exit_signal = SIGCHLD;
	set_parents(tsk, child_reaper, child_reaper);
    }

#if 0
    /* Shed child processes - we just have them re-select parents.  If
     * this is being called from release() we shouldn't have any
     * children...  */
    while (!list_empty(&tsk->children)) {
	struct task_struct *child;
	child = list_entry(tsk->children.next, struct task_struct, sibling);

	if (!BPROC_ISMASQ(child) || child->bproc.master != m)
	    printk(KERN_ERR "bproc: masq_remove_proc: child isn't in my"
		   " process space!\n");

	masq_select_parents(child->bproc.master, child);

	if (child->parent == tsk || child->real_parent == tsk) {
	    printk(KERN_CRIT "bproc: masq: child is still mine! me=%d child=%d\n",
		   tsk->pid, child->pid);
	}
    }
    while (!list_empty(&tsk->ptrace_children)) {
	struct task_struct *child;
	child = list_entry(tsk->ptrace_children.next, struct task_struct,
			   ptrace_list);

	if (!BPROC_ISMASQ(child) || child->bproc.master != m)
	    printk(KERN_ERR "bproc: masq_remove_proc: child isn't in my"
		   " process space!\n");

	masq_select_parents(child->bproc.master, child);

	if (child->parent == tsk || child->real_parent == tsk) {
	    printk(KERN_CRIT "bproc: masq: child is still mine! me=%d child=%d\n",
		   tsk->pid, child->pid);
	}
    }
#endif
}

/*-------------------------------------------------------------------------
 * Session ID helpers
 *-----------------------------------------------------------------------*/
int masq_getsid(pid_t pid) {
    int result;
    struct bproc_krequest_t *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_null_msg_t *resp_msg;

    /* The check for local PIDs (including our own) is done in the
     * hook code. */
    req = bpr_rsyscall1(BPROC_SYS_GETSID);
    if (!req)
	return -ENOMEM;
    msg = (struct bproc_rsyscall_msg_t *) bproc_msg(req);
    msg->arg[0] = pid;
    if (bpr_rsyscall2(BPROC_MASQ_MASTER(current), req, 0)) {
	bproc_put_req(req);
	return -EIO;
    }
    resp_msg = bproc_msg(req->response);
    result = resp_msg->hdr.result;
    bproc_put_req(req);
    return result;
}

int masq_setsid(void) {
    int result;
    struct bproc_krequest_t *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_null_msg_t *resp_msg;

    req = bpr_rsyscall1(BPROC_SYS_SETSID);
    if (!req) return -ENOMEM;
    msg = (struct bproc_rsyscall_msg_t *)bproc_msg(req);
    if (bpr_rsyscall2(BPROC_MASQ_MASTER(current), req, 0)) {
	bproc_put_req(req);
	return -EIO;
    }
    resp_msg = bproc_msg(req->response);
    result = resp_msg->hdr.result;
    bproc_put_req(req);
    if (result >= 0) {
	/* Doing it here might not be technically race-safe... */
	write_lock_irq(&tasklist_lock);
	current->signal->bproc.pgrp    = result;
	current->signal->bproc.session = result;
	masq_update_mappings(current->bproc.master, current);

	/* more stuff that setsid does on the front end */
	current->signal->leader = 1;
	current->signal->tty = NULL;
	current->signal->tty_old_pgrp = 0;
	write_unlock_irq(&tasklist_lock);
    }
    return result;
}

/*-------------------------------------------------------------------------
 * Process Group Helpers
 *-----------------------------------------------------------------------*/
int masq_is_orphaned_pgrp(int pgrp) {
    int result;
    struct bproc_request_queue_t *master;
    struct bproc_krequest_t *req;
    struct bproc_pgrp_msg_t *msg;

    /* XXXX FIX ME #warning "This is almost certainly busted."*/

    /* We show up here holding the tasklist lock */

    read_unlock(&tasklist_lock);

    /* PRESUMPTION:
     * This will only ever get called with pgrp == current->pgrp so
     * that we can safely substitute our masq'ed pgrp in here.
     */
    req = bproc_new_req(BPROC_ISORPHANEDPGRP, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	read_lock(&tasklist_lock);
	return -ENOMEM;
    }
    msg = (struct bproc_pgrp_msg_t *)bproc_msg(req);
    bpr_to_node(msg, -1);
    bpr_from_real(msg, current->bproc.pid);
    msg->pgid = current->signal->bproc.pgrp;

    master = &(BPROC_MASQ_MASTER(current)->req);
    if (bproc_send_req_wait(master, req)) {
	bproc_put_req(req);
	read_lock(&tasklist_lock);
	return -EIO;
    }
    result = msg->hdr.result;
    bproc_put_req(req);

    read_lock(&tasklist_lock);
    return result;
}

int masq_getpgid(pid_t pid) {
    int result;
    struct bproc_krequest_t     *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_null_msg_t     *resp_msg;
    
    /* The check for local PIDs (including our own) is done in the
     * hook code. */
    req = bpr_rsyscall1(BPROC_SYS_GETPGID);
    if (!req) return -ENOMEM;
    msg = (struct bproc_rsyscall_msg_t *)bproc_msg(req);
    msg->arg[0] = pid;
    if (bpr_rsyscall2(BPROC_MASQ_MASTER(current), req, 0)) {
	bproc_put_req(req);
	return -EIO;
    }
    resp_msg = bproc_msg(req->response);
    result = resp_msg->hdr.result;
    bproc_put_req(req);
    return result;
}

int masq_setpgid(pid_t pid, pid_t pgid) {
    int result;
    struct bproc_krequest_t *req;
    struct bproc_rsyscall_msg_t *msg;
    struct bproc_null_msg_t *resp_msg;

    /* XXX Possible optimization: See if this can be handled entirely
     * locally and turn this rsyscall into a notification */

    req = bpr_rsyscall1(BPROC_SYS_SETPGID);
    if (!req) return -ENOMEM;
    msg = (struct bproc_rsyscall_msg_t *) bproc_msg(req);
    msg->arg[0] = pid;
    msg->arg[1] = pgid;
    if (bpr_rsyscall2(BPROC_MASQ_MASTER(current), req, 0)) {
	bproc_put_req(req);
	return -EIO;
    }
    resp_msg = bproc_msg(req->response);
    result = resp_msg->hdr.result;
    bproc_put_req(req);
    /* Our actual process group change (if we're operating on
     * ourselves) will happen via the pgrp change message which will
     * be ahead of us... */
    return result;
}

/*-------------------------------------------------------------------------
 *
 */
int deliver_signal(struct bproc_masq_master_t *m, struct bproc_signal_msg_t *msg) {
    int realpid, r;
    struct siginfo info;

    /* FIX ME: If we're doing pid mapping we should deliver the signal
     * before letting go of the tasklist_lock */

    if (m) {
	read_lock(&tasklist_lock);
	realpid = masq_masq2real(m, msg->hdr.to);
	read_unlock(&tasklist_lock);
	if (realpid < 0) {
	    /* This case can happen when exit messages and fwd_sig
	     * messages cross each other.  I'm not sure whether allowing
	     * this to happen is technically "incorrect". */
	    return -ESRCH;
	}
    } else
	realpid = msg->hdr.to;

    if (realpid == 1) {
	/* XXXX DEBUG PARANOIA */
	BUG();
    }

    /* We know we're signalling a process here since this signal was
     * forwarded from a ghost */
    bproc_unpack_siginfo(&msg->info, &info);
    r = kill_proc_info(msg->info.si_signo, &info, realpid);
    return r;
}

/*-------------------------------------------------------------------------
 *  masq_parent_exit
 *
 */
int masq_parent_exit(struct bproc_masq_master_t *m, int ppid) {
    struct task_struct *task, *rpp, *pp;
    struct list_head *l;

    /* Check all our tasks for this parent process ID */
    write_lock_irq(&tasklist_lock);
    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	task = list_entry(l, struct task_struct, bproc.list);

	if (ppid != task->bproc.oppid && ppid != task->bproc.ppid)
	    continue;

	rpp = task->real_parent;
	pp  = task->parent;

	if (ppid == task->bproc.oppid) {
	    task->bproc.oppid = 1;
	    rpp = child_reaper;
	    task->exit_signal = SIGCHLD;
	    task->self_exec_id++;
	    /* The pdeath signal will probably get handled on the front
	     * end by our ghost */
	}
	if (ppid == task->bproc.ppid) {
	    task->bproc.ppid = task->bproc.oppid;
	    pp = rpp;
	    ptrace_unlink(task);
#if 0
	    SPEW2("task state after parent exit = %d\n", task->state);

	    /* DEBUGGING:  this *should* be done by TASK_TRACED */
	    if (task->state == TASK_TRACED) {
		/* FIX ME:  Do we want to bother updating the front end? */
		SPEW2("task %d pid needed update.", task->bproc.pid);
		task->state = TASK_STOPPED;
	    }
#endif
	}
	set_parents(task, rpp, pp);
    }
    write_unlock_irq(&tasklist_lock);
    return 0;
}

int masq_modify_nlchild(struct bproc_masq_master_t *m, int pid, int adj) {
    struct task_struct *task;
    write_lock_irq(&tasklist_lock);
    task = masq_find_task_by_pid(m, pid);
    if (!task) {
	write_unlock_irq(&tasklist_lock);
	return -ESRCH;
    }
    task->bproc.nlchild += adj;
    /*printk("%dm%d: nlchild %d (%d)\n", mp->task->pid, mp->pid, adj,
      mp->task->bproc.masq->nlchild);*/
    /* Sanity checks */
    if (task->bproc.nlchild < 0) {
	printk(KERN_ERR "%dm%d: nlchild < 0!  nlchild=%d",
	       task->bproc.pid, task->pid, task->bproc.nlchild);
    }
    if (adj > 0)
	wake_up_interruptible(&task->parent->wait_chldexit);
    write_unlock_irq(&tasklist_lock);
    return 0;
}

int masq_pgrp_change(struct bproc_masq_master_t *m,
		     struct bproc_pgrp_msg_t *msg) {
    struct task_struct *task;
    write_lock_irq(&tasklist_lock);
    task = masq_find_task_by_pid(m, msg->hdr.to);
    if (task) {
	task->signal->bproc.pgrp = msg->pgid;
	masq_update_mappings(m, task);
    }
    write_unlock_irq(&tasklist_lock);
    return task ? 0 : -ESRCH;
}

/*-------------------------------------------------------------------------
 *  masq_get_state_single
 *
 *  Kernel assist for [hopefully] more efficient grabbing of process
 *  state information.
 */
int masq_get_state_single(struct bproc_masq_master_t *m, int pid) {

    struct task_struct *p;

    struct bproc_krequest_t *req;
    struct bproc_status_msg_t *msg;

    req = bproc_new_req(BPROC_RESPONSE(BPROC_GET_STATUS),
			sizeof(*msg), GFP_KERNEL);
    if (!req)
	return -ENOMEM;
    msg = (struct bproc_status_msg_t *) bproc_msg(req);

    read_lock(&tasklist_lock);
    p = masq_find_task_by_pid(m, pid);
    if (p) get_task_struct(p);
    read_unlock(&tasklist_lock);
    if (p) {
	p->bproc.last_update = jiffies;

	bpr_to_node(msg, -1);
	bpr_from_real(msg, p->bproc.pid);
	msg->hdr.result = 0;
	pack_process_status(msg, p, 1);
	put_task_struct(p);
	bproc_send_req(&m->req, req);
    }
    bproc_put_req(req);
    return p ? 0 : -ESRCH;
}

void masq_get_state_all(struct bproc_masq_master_t *m) {
    long this_update;
    struct task_struct *p = 0;
    struct list_head *l;
    struct bproc_krequest_t *req;
    struct bproc_status_msg_t *msg;

    this_update = jiffies;

    do {
	req = bproc_new_req(BPROC_RESPONSE(BPROC_GET_STATUS),
			    sizeof(*msg), GFP_KERNEL);
	if (!req) {
	    printk("bproc: masq_get_state_all: out of memory.\n");
	    return;
	}
	msg = (struct bproc_status_msg_t *)bproc_msg(req);

	/* This could be made more efficient by moving the head of the
	 * list after each one... */

	read_lock(&tasklist_lock);

	for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	    p = list_entry(l, struct task_struct, bproc.list);
	    if (p->bproc.last_update < this_update) {
		p->bproc.last_update = this_update;
		get_task_struct(p);
		break;
	    }
	    p = 0;
	}
	read_unlock(&tasklist_lock);

	if (p) {
	    bpr_to_node(msg, -1);
	    bpr_from_real(msg, p->bproc.pid);
	    msg->hdr.result = 0;
	    pack_process_status(msg, p, 1);
	    bproc_send_req(&m->req, req);

	    put_task_struct(p);
	}
	bproc_put_req(req);
    } while (p);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
