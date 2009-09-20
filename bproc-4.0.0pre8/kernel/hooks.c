/*-------------------------------------------------------------------------
 *  bproc_hook.c: Beowulf distributed PID space (bproc) definitions
 *
 *  Copyright (C) 2000-2002 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: hooks.c,v 1.79 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>
#include <linux/unistd.h>
#include <linux/bproc.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <asm/uaccess.h>

#include "bproc.h"
#include "bproc_internal.h"

/*#define hookdef(ret,func,args) extern ret (* func ## _hook) args; ret func args*/
#define sethook1(func)         bproc_hook_ ## func ## _hook = bproc_hook_ ## func
#define sethook2(func,func2)   bproc_hook_ ## func ## _hook = func2
#define unsethook(func)        bproc_hook_ ## func ## _hook = 0

/*----- generic/reused hook functions -----------------------------------*/

/*
 * bproc_hook_find_task
 *
 * This hook performs the function of find_task_by_pid with process ID
 * mapping for the slave node.
 *
 * You must hold the tasklist_lock on entry (read or write) and you
 * must be masq process.
 */
static
struct task_struct *bproc_hook_find_task(int pid) {
    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag)) {
	return find_task_by_pid(pid);
    } else if (current->bproc.context) {
	return masq_find_task_by_pid(current->bproc.context, pid);
    } else if (BPROC_ISMASQ(current)) {
	return masq_find_task_by_pid(BPROC_MASQ_MASTER(current), pid);
    } else {
	return find_task_by_pid(pid);
    }
}

static
int bproc_hook_masq_pid(struct task_struct *tsk) {
    return tsk->bproc.pid;
}

static
int bproc_hook_masq_tgid(struct task_struct *tsk) {
    return tsk->bproc.tgid;
}

static
long bproc_hook_task_state(struct task_struct *tsk) {
    /* the tasklist lock must be held at this point (read or write) */
    if (BPROC_ISGHOST(tsk)) {
	long state;
	spin_lock(&tsk->bproc.ghost->lock);
	state = tsk->bproc.ghost->state;
	spin_unlock(&tsk->bproc.ghost->lock);
	return state;
    } else
	return tsk->state;
}

static
int bproc_hook_localpid(int pid) {
    struct task_struct *task;

    read_lock(&tasklist_lock);
    task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), pid);
    if (task)
	pid = task->pid;
    read_unlock(&tasklist_lock);
    return(pid);
}

static
int bproc_hook_masqpid(int pid) {
    struct task_struct *p;

    read_lock(&tasklist_lock);
    p = find_task_by_pid(pid);
    if(p)
	pid = p->bproc.pid;
    read_unlock(&tasklist_lock);
    return(pid);
}


/*----- kernel/sched.c --------------------------------------------------*/
static
int bproc_hook_sys_getppid(struct task_struct *parent) {
    if (!BPROC_ISMASQ(current->group_leader)) {
	printk(KERN_ERR "bproc: huh? group_leader is not masq.\n");
    }
    return current->group_leader->bproc.oppid;
}

/*----- kernel/exit.c ---------------------------------------------------*/
static
void bproc_hook_release(struct task_struct *p) {
    if (BPROC_ISMASQ(p)) {
	write_lock_irq(&tasklist_lock);
	masq_remove_proc(p, 0);
	write_unlock_irq(&tasklist_lock);
    }
}

static
void bproc_hook_do_exit(struct task_struct *tsk, long code) {
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;

    current->bproc.arg = 0;

    if (BPROC_ISMASQ(tsk)) {
	masq_exit_notify(tsk, code);
	return;
    }

    if (BPROC_ISGHOST(tsk))
	bproc_ghost_unghost();

    /* This is a huge terrible hack....
     *
     * Basically we get to burp up a message later on when it's
     * difficult and awkward to burp up a message.  Therefore we
     * allocate a message here because we might need it.
     *
     * Do this for any process that might have a ghost as a child -
     * that is any which is not masq.
     */
    req = bproc_new_req(BPROC_PARENT_EXIT, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk(KERN_ERR "bproc: Out of memory sending pexit.\n");
	return;
    }
    msg = bproc_msg(req);
    bpr_from_real(msg, tsk->pid);
    bpr_to_node  (msg, -1);

    current->bproc.arg = (long) req;
}

static
void bproc_hook_forget_parent(int send_pexit) {
    struct bproc_krequest_t *req;

    /* Here we pick up + use the message we allocated above... */
    req = (struct bproc_krequest_t *) current->bproc.arg;
    if (req) {
	if (send_pexit)
	    bproc_send_req(&bproc_ghost_reqs, req);
	bproc_put_req(req);
    }
}

static
int bproc_hook_sys_wait4_1(pid_t *pid, int options,  struct siginfo *infop,
			   unsigned int * stat_addr,
			   struct rusage * ru, int *result) {
    /* !!! NOTE: We are holding the readlock on the task list when we
     * come in here !!! */
    struct task_struct *task;

    /* let normal kernel calls run their course... */
    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag)) return 0;

    /* If asking for a specific PID, see if we can handle it locally. */
    if (*pid > 0) {
	/* Waiting on a particular process ID */
	task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), *pid);
	if (task) {
	    *pid = task->pid;
	    return 0;
	}
    }

    /* If asking for any pid, see if we can handle it locally. */
    if (current->bproc.nlchild == 0) return 0;

    /* Else do the remote syscall */
    read_unlock(&tasklist_lock);
    *result = masq_wait(*pid, options, infop, stat_addr, ru);
    /* wait() will presume we have unlocked the lock if we handle the call */
    return 1;
}


static
int bproc_hook_sys_wait4_3(struct task_struct *tsk) {
    /* SMP Ok - task list read lock is held at this point */
    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag))
	return tsk->pid;
    else
	return tsk->bproc.pid;
}

static
void bproc_hook_sys_wait4_4(pid_t pid, int options) {
    struct bproc_krequest_t *req;
    struct bproc_wait_msg_t *msg;

    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag)) return;

    /* This only gets called for local waits on the slave side */
    req = bproc_new_req(BPROC_WAIT, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk(KERN_ERR "bproc: out of memory.\n");
	return;
    }
    msg = bproc_msg(req);
    bpr_to_ghost(msg, current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    msg->pid = pid;
    msg->options = options & (~WNOHANG);
    bproc_send_req(&BPROC_MASQ_MASTER(current)->req, req);
    bproc_put_req(req);
}

/*----- kernel/fork.c ---------------------------------------------------*/
static
void send_child_add(struct bproc_request_queue_t *dest,
		    int dest_pid, int child_pid) {
    /* Note: this should be called by real processes to modify parents */
    struct bproc_krequest_t *req;
    struct bproc_null_msg_t *msg;

    req = bproc_new_req(BPROC_CHILD_ADD, sizeof(*msg), GFP_KERNEL);
    if (!req) {
	printk("bproc: child_add: Out of memory.\n");
	return;
    }
    msg = bproc_msg(req);
    bpr_to_real  (msg, dest_pid);
    /* Ok, this is a bit of a hack.  We use the child as the sender
     * here.  We have to do this in case current is a ghost.  We can't
     * send a request with which requires a response from a ghost.
     * Them's the rules for error recovery to work in the master.
     * Therefore, we use the PID of the child we're in the process of
     * creating as the sender. */
    bpr_from_real(msg, child_pid);
    bproc_send_req_wait(dest, req);
    bproc_put_req(req);
}

static
int bproc_hook_copy_process(struct task_struct *p, unsigned long flags) {
    int retval = p->pid;
    struct bproc_masq_master_t *m;

    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag))
	return retval;

    retval = masq_new_pid(p, flags);

    if (retval < 0) return retval;

    /* This modifies nlchild values on the parents of this process.
     * This is either done locally or by sending CHILD_ADD messages.
     * When this child actually gets added with masq_add_proc(..,1),
     * those values will be decremented again if the process is local.
     * This will allow for parent processes moving around during the
     * fork.  Note that we can safely use p->bproc.masq without
     * holding locks here since p isn't on any process lists yet and p
     * is therefore also no running yet. */
    m = BPROC_MASQ_MASTER(current);
    if (masq_modify_nlchild(m, p->bproc.oppid, 1))
	send_child_add(&m->req, p->bproc.oppid, p->bproc.pid);
    if (p->bproc.oppid != p->bproc.ppid &&
	masq_modify_nlchild(m, p->bproc.ppid, 1)) {
	send_child_add(&m->req, p->bproc.ppid, p->bproc.pid);
    }
    return retval;
}

static
void bproc_hook_copy_process_2(struct task_struct *p) {
    int pid, pid1=0, pid2=0;
    /* We are holding a write_lock_irq on the task list lock */
    if (BPROC_ISMASQ(current)) {
	if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag))
	    return;

	/* On the slave side, we just need to finish the fork by
	 * adding this process to the local task list */

	set_parents(p, child_reaper, child_reaper); /* let masq_add_proc place it */
	masq_add_proc(current->bproc.master, p, 0);
	return;
    }

    /* If the fork caller is a ghost, sending child add messages will
     * be handled on the remote machine where fork/clone was called. */
    if (BPROC_ISGHOST(current))
	return;

    /* On the front end we need to check our parent to see if we need
     * to send out a nlchild update to some remote box. */
    if (BPROC_ISGHOST(p->real_parent)) {
	pid1 = p->real_parent->pid;
    }

    if (p->parent != p->real_parent && BPROC_ISGHOST(p->parent)) {
	/* This might be dicey if it races with a detach... */
	pid2 = p->parent->pid;
    }

    if (pid1 || pid2) {
	pid = p->pid;
	/* Release the lock to do our message traffic.  This is ok
	 * since fork is basically done. */
	write_unlock_irq(&tasklist_lock);
	if (pid1) send_child_add(&bproc_ghost_reqs, pid1, pid);
	if (pid2) send_child_add(&bproc_ghost_reqs, pid2, pid);
	write_lock_irq(&tasklist_lock);
    }
}

static
void bproc_hook_copy_process_cleanup(struct task_struct *p) {
    masq_exit_notify(p, BPROC_SILENT_EXIT);
}

static
int bproc_hook_do_fork(struct task_struct *p) {
    if (test_bit(BPROC_FLAG_KCALL, &current->bproc.flag))
	return p->pid;
    else
	return p->bproc.pid;
}

/*----- kernel/signal.c -------------------------------------------------*/
#if 0
/* This is the signalbypass delivery function for ghosts.  It's
 * essentially the same as ghost's own signal forwarding function but
 * it doesn't require the ghost to wake up to forward the signal. */
static
int  bproc_hook_send_sig_info(int sig, struct siginfo *info,
			      struct task_struct *t) {
    /* We get here holding the following locks:
     * tasklist_lock
     * t->sigmask */
    struct bproc_krequest_t *req;
    struct bproc_signal_msg_t *msg;
    struct siginfo           tmpinfo;

    return 0;			/* XXX disable sigbypass for now.
				 * There seems to be something busted or
				 * unsafe about this code... */

    if (!BPROC_ISGHOST(t) || !t->bproc.ghost->sigbypass)
	return 0;

    req = bproc_new_req(BPROC_FWD_SIG, GFP_ATOMIC);
    if (!req) {
	/* Might not want to bitch here...  since we really have to be
           prepared to run out of RAM w/ GFP_ATOMIC and we can safely
           fall back on non-bypass signal forwarding. */
        printk(KERN_ERR "bproc: ghost: [%d] signal forwarding:"
	       " Out of memory\n", (int)t->pid);
        return 0;
    }
    msg = bproc_msg(req);

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
    /*printk("delivering sig %d via bypass\n", sig);*/
    bpr_to_real(msg,    t->pid);
    bpr_from_ghost(msg, t->pid);
    bproc_pack_siginfo(&msg->info, info);
    bproc_send_req(&bproc_ghost_reqs, req);
    bproc_put_req(req);
    return 1;			/* indicate signal delivery handled */
}
#endif

int bproc_hook_kill_pg_info(int sig, struct siginfo *info, pid_t pid) {
    int id, result = 0, error;

    /* Deliver to this process group locally. */
    read_lock(&tasklist_lock);
    id = masq_find_id_mapping(current->bproc.master, pid, 0);
    if (id)
	result = __kill_pg_info(sig, info, id);
    read_unlock(&tasklist_lock);

    /* Since we have no way of knowing if the entire process group is
     * on this node, try to do this as a remote signal */
    error = masq_send_sig(sig, info, -pid);
    if (!result)
	result = error;
    return result;
}



int bproc_hook_kill_proc_info(int sig, struct siginfo *info, pid_t pid) {
    int err = 0;
    struct task_struct *p;

    read_lock(&tasklist_lock);
    p = masq_find_task_by_pid(current->bproc.master, pid);
    if (p)
	err = group_send_sig_info(sig, info, p);
    read_unlock(&tasklist_lock);
    if (p) return err;

    return masq_send_sig(sig, info, pid);
}

/*----- kernel/sys.c ---------------------------------------------------*/

static
int bproc_hook_sys_setpgid_m(pid_t pid, pid_t pgid) {
    return masq_setpgid(pid, pgid);
}

static
void bproc_hook_sys_setpgid_g(struct task_struct *p) {
    struct bproc_krequest_t *req;
    struct bproc_pgrp_msg_t *msg;

    /* We come in here holding the tasklist lock so no sleeping */
    req = bproc_new_req(BPROC_PGRP_CHANGE, sizeof(*msg), GFP_ATOMIC);
    if (!req) {
	printk(KERN_ERR "bproc: setpgid2: out of memory.\n");
	return;
    }
    msg = bproc_msg(req);
    bpr_from_real(msg, current->pid);
    bpr_to_real(msg, p->pid);
    msg->pgid = process_group(p);
    bproc_send_req(&bproc_ghost_reqs, req);
    bproc_put_req(req);
}

static
int bproc_hook_sys_getpgid(pid_t pid) {
    int ret;
    struct task_struct *task;
    if (!pid)
	return current->signal->bproc.pgrp;
    else {
	read_lock(&tasklist_lock);
	task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), pid);
	if (task) {
	    ret = task->signal->bproc.pgrp;
	    read_unlock(&tasklist_lock);
	    return ret;
	}
	read_unlock(&tasklist_lock);
	return masq_getpgid(pid);
    }
}

/* session */

static
int bproc_hook_sys_getsid(pid_t pid) {
    int ret;
    struct task_struct *task;
    if (!pid)
	return current->signal->bproc.session;
    else {
	read_lock(&tasklist_lock);
	task = masq_find_task_by_pid(BPROC_MASQ_MASTER(current), pid);
	if (task) {
	    ret = task->signal->bproc.session;
	    read_unlock(&tasklist_lock);
	    return ret;
	}
	read_unlock(&tasklist_lock);
	return masq_getsid(pid);
    }
}

int bproc_hook_sys_setsid(void) {
    return masq_setsid();
}

/*--------------------------------------------------------------------
 * P T R A C E
 *------------------------------------------------------------------*/

/* This checks for the special case of a 3rdparty ptrace call.  In
 * that case a daemon is performing a ptrace call on behalf of another
 * process.  In that case child->parent may not point to current.  We
 * know what process we're doing to the call for so we check to make
 * sure that:
 *
 * - This is a master/slave daemon doing a call for another process.
 * - The caller has attached to the child.
 */
static
int bproc_hook_ptrace_check_attach(struct task_struct *child) {
    int attached = 1;
    int caller_pid;
    struct bproc_ptrace_info_t *pt_info;

    if (!test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag))
	return 0;

    pt_info = (struct bproc_ptrace_info_t *) current->bproc.arg;

    /* 3rd party ptrace places a pointer to the ptrace request in arg */
    caller_pid = pt_info->from;

    /* This checks to see if we're attached for a 3rd party call. */
    read_lock(&tasklist_lock);	/* protects child->bproc.* */
    if (current->bproc.context) {
	/* Check to make sure this process is still a masq process.
	 * There's a chance that it decided to leave here... */
	if (child->bproc.master) {
	    /* We don't actually check that we're the correct master
	     * daemon.  If we're looking at this process at all, we
	     * must have looked it up in the right context. */
	    if (child->bproc.ppid != caller_pid) {
		SPEW2("attach check failed: %d %d",
		      child->bproc.ppid, caller_pid);
		attached = 0;
	    }
	} else {
	    WARNING("ESRCH needs to become ELOOP in this case...");
	    attached = 0;
	}
    } else {
	if (child->parent->pid != caller_pid) {
	    SPEW2("attach check failed: %d %d",
		  child->parent->pid, caller_pid);
	    attached = 0;
	}
    }
    read_unlock(&tasklist_lock);
    return attached;
}

/*-------------------------------------------------------------------------
 * bproc_hook_ptrace_request
 *
 * This function creates a remote ptrace request.  The resulting
 * request will be handled by a daemon whereever the process exists.
 */
void ptrace_3rd_party(struct bproc_krequest_t *req,
		      struct bproc_masq_master_t *context) {
    int uid,gid,dumpable;
    long data;
    kernel_cap_t cap_effective;
    struct bproc_ptrace_msg_t *pt_req;

    struct bproc_krequest_t *resp;
    struct bproc_ptrace_msg_t *pt_resp;
    struct bproc_ptrace_info_t pt_info;

    pt_req = bproc_msg(req);
    resp = bproc_new_resp(req, sizeof(*pt_resp), GFP_KERNEL);
    if (!resp) {
	printk(KERN_CRIT "bproc: ptrace_3rd_party: Out of memory.\n");
	return;
    }
    pt_resp = bproc_msg(resp);
    pt_resp->request = pt_req->request;
    pt_resp->addr    = pt_req->addr;
    pt_resp->bytes   = 0;
    pt_resp->flags   = pt_req->flags;

    /* This is a bit of magical goop which will let the rest of the
     * ptrace code know that we're doing a call on behalf of a 3rd
     * party and who the 3rd party is. */
    set_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag);
    pt_info.from          = pt_req->hdr.from;
    current->bproc.arg     = (long) &pt_info;
    current->bproc.context = context;

    /* Swap credentials to those of the remote caller.  This is only
     * necessary for attach.  Also, only a few of the credentials are
     * relevant.  (this is ignoring the security extensions...) */
    /* These assignments are outside just to avoid a gcc warning... */
    dumpable      = current->mm->dumpable;
    uid           = current->uid;
    gid           = current->gid;
    cap_effective = current->cap_effective;
    if (pt_req->request == PTRACE_ATTACH) {
	task_lock(current);
	current->mm->dumpable  = 0;
	current->uid           = pt_req->uid;
	current->gid           = pt_req->gid;
	current->cap_effective = pt_req->cap_effective;
	task_unlock(current);
    }

    switch (pt_req->request) {
    /* If we're doing a peek of some kind, update the address */
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKUSR:
    case PTRACE_GETSIGINFO:
    case PTRACE_GETEVENTMSG:
#if defined(__i386__) || defined(__x86_64__)
    case PTRACE_GETREGS:
    case PTRACE_GETFPREGS:
    case PTRACE_GETFPXREGS:
    case PTRACE_GET_THREAD_AREA:
#endif
	data = (long) &pt_resp->data;
	break;

    /* POKE where a pointer is involved... */
    case PTRACE_SETSIGINFO:
#if defined(__i386__) || defined(__x86_64__)
    case PTRACE_SETREGS:
    case PTRACE_SETFPREGS:
    case PTRACE_SETFPXREGS:
    case PTRACE_SET_THREAD_AREA:
#endif
	data = (long) &pt_req->data;
	break;
    default:
	data = pt_req->data.data[0];
	break;
    }

    pt_resp->hdr.result = sysdep_ptrace_kcall(pt_resp, pt_req->request,
					      pt_req->hdr.to, pt_req->addr,
					      data);
    /* PEEK read-ahead */
    if ((pt_req->request == PTRACE_PEEKTEXT ||
	 pt_req->request == PTRACE_PEEKDATA)) {
	long result = pt_resp->hdr.result;

	while (result == 0 && pt_resp->bytes < BPROC_PTRACE_RA_BYTES) {
	    /* ptrace_kcall updates the number of bytes in the response */
	    result = sysdep_ptrace_kcall(pt_resp, pt_req->request,
					 pt_req->hdr.to,
					 pt_req->addr + pt_resp->bytes,
					 data + pt_resp->bytes);
	}
    }

    switch(pt_req->request) {
    case PTRACE_ATTACH:
    case PTRACE_DETACH:
	pt_resp->data.data[0] = pt_info.child;
	break;
    }
    
    clear_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag);
    current->bproc.arg     = 0;
    current->bproc.context = 0;

    /* Restore credentials */
    if (pt_req->request == PTRACE_ATTACH) {
	task_lock(current);
	current->mm->dumpable = dumpable;
	current->uid = uid;
	current->gid = gid;
	current->cap_effective = cap_effective;
	task_unlock(current);
    }

    if (pt_resp->hdr.result == ELOOP) {
	/* ELOOP indicatest that we can't service this request here. */
	bproc_send_req(context ? &context->req : &bproc_ghost_reqs, req);
    } else {
	bproc_send_req(context ? &context->req : &bproc_ghost_reqs, resp);
    }
    bproc_put_req(resp);
}

/*--------------------------------------------------------------------
 * bproc_hook_ptrace_attach
 *
 * This hook performs the following functions:
 *   For 3rd party attach calls, it returns an appropriate parent.
 *   For slave attach calls, it emits a reparent message.
 *   For slave attach calls, it updates the masq structure on the child.
 *
 * *** tasklist_lock is write-held on entry ***
 */
struct task_struct *bproc_hook_ptrace_attach(struct task_struct *child) {
    int ppid;
    struct task_struct *parent;
    struct bproc_masq_master_t *ctx;

    /* Find the parent process to use */
    if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag)) {
	struct bproc_ptrace_info_t *pt_info;
	pt_info = (struct bproc_ptrace_info_t *)current->bproc.arg;
	ppid = pt_info->from;
    } else if (BPROC_ISMASQ(current)) {
	ppid = current->bproc.pid;
    } else {
	ppid = current->pid;
    }

    /* ... and the right context to look it up in. */
    ctx = current->bproc.master ? current->bproc.master :
	current->bproc.context;

    if (ctx) {
	/* Slave node case (with a context) */
	struct bproc_krequest_t  *reparent;
	struct bproc_reparent_msg_t *msg;
	
	parent = masq_find_task_by_pid(ctx, ppid);
	if (!parent || parent->state >= TASK_ZOMBIE) parent = child_reaper;

	/* Update the ppid entry in the masq structure */
	child->bproc.ppid = ppid;

	/* In the case of a 3rd party ptrace, we need to */
	if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag)) {
	    struct bproc_ptrace_info_t *pt_info;
	    pt_info = (struct bproc_ptrace_info_t *)current->bproc.arg;
	    pt_info->child=(child->bproc.ppid!=child->bproc.oppid);
	}

	/* Send a reparent message to the front end. */
	/* FIX ME: do this in such a way that we're not holding too many
	 * damned locks.  If this fails, it's BAD but we need to emit this
	 * message before releasing the tasklist_lock. */
	reparent = bproc_new_req(BPROC_REPARENT, sizeof(*msg), GFP_ATOMIC);
	if (!reparent) {
	    printk(KERN_CRIT "bproc: out of memory sending reparent.\n");
	    return parent;
	}
	msg = bproc_msg(reparent);
	bpr_to_ghost(msg,  child->bproc.pid);
	bpr_from_real(msg, child->bproc.pid);
	msg->ptrace     = child->ptrace;
	msg->new_parent = ppid;
	bproc_send_req(&ctx->req, reparent);
	bproc_put_req(reparent);
    } else {
	/* Master node case (without a context) */
	parent = find_task_by_pid(ppid);
	if (!parent || parent->state >= TASK_ZOMBIE) {
	    printk(KERN_CRIT "Failed to find parent process (%d) for "
		   "ptrace attach.\n", ppid);
	    parent = child_reaper;
	}

	if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag)) {
	    struct bproc_ptrace_info_t *pt_info;
	    pt_info = (struct bproc_ptrace_info_t *)current->bproc.arg;
	    pt_info->child = (child->parent != child->real_parent);
	}
    }
    return parent;
}

/*--------------------------------------------------------------------
 * bproc_hook_ptrace_detach
 *
 * This hook performs the following:
 *   For 3rd party attach calls, it returns an appropriate parent.
 *   For slave attach calls, it emits a reparent message.
 *
 * *** tasklist_lock is write-held on entry ***
 */
void bproc_hook_ptrace_detach(struct task_struct *child) {
    if (bproc_ismasq(child)) {
	struct bproc_krequest_t *reparent;
	struct bproc_reparent_msg_t *msg;

	/* Check to see if a remote nlchild is going to have to change */
	if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag)) {
	    struct bproc_ptrace_info_t *pt_info;
	    pt_info = (struct bproc_ptrace_info_t *)current->bproc.arg;
	    pt_info->child=(child->bproc.ppid!=child->bproc.oppid);
	}

	child->bproc.ppid = child->bproc.oppid;
	
	/* FIX ME: do this in such a way that we're not holding too
	 * many damned locks.  If this fails, it's BAD but we need to
	 * emit this message before releasing the tasklist_lock. */
	reparent = bproc_new_req(BPROC_REPARENT, sizeof(*msg), GFP_ATOMIC);
	if (!reparent) {
	    printk(KERN_CRIT "bproc: out of memory sending reparent.\n");
	    return;
	}
	msg = bproc_msg(reparent);
	bpr_to_ghost(msg,  child->bproc.pid);
	bpr_from_real(msg, child->bproc.pid);
	msg->ptrace     = child->ptrace;
	msg->new_parent = 0;
	bproc_send_req(&child->bproc.master->req, reparent);
	bproc_put_req(reparent);
    } else {
	/* Check to see if a remote nlchild is going to have to change */
	if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag)) {
	    struct bproc_ptrace_info_t *pt_info;
	    pt_info = (struct bproc_ptrace_info_t *)current->bproc.arg;
	    pt_info->child = (child->parent != child->real_parent);
	}
    }
}

/*--------------------------------------------------------------------
 * bproc_hook_ptrace_traceme
 *
 * No locks held (except mondo kernel lock) at this point.
 */
static
void bproc_hook_ptrace_traceme(void) {
    struct bproc_krequest_t *reparent;
    struct bproc_reparent_msg_t *msg;

    reparent = bproc_new_req(BPROC_REPARENT, sizeof(*msg), GFP_KERNEL);
    if (!reparent) {
	printk(KERN_CRIT "bproc: out of memory sending reparent.\n");
	return;
    }
    msg = bproc_msg(reparent);
    bpr_to_ghost(msg,  current->bproc.pid);
    bpr_from_real(msg, current->bproc.pid);
    
    read_lock(&tasklist_lock);
    /* This is an attempt to deal with the fact that TRACEME can race
     * with an exit message and we might end up with a discrepancy
     * with who's attached to who.
     *
     * I think we might still have some kind of race involving detach
     * here...
     */

    /* It's possible that we've already been detached or our parent
     * has exited - so check again just to be sure.  (the ptrace flag
     * is cleared under a tasklist write lock) */
    if (current->ptrace) {
	msg->ptrace     = current->ptrace;
	msg->new_parent = current->bproc.ppid;
	bproc_send_req(&current->bproc.master->req, reparent);
    }
    read_unlock(&tasklist_lock);
    bproc_put_req(reparent);
}

/*-------------------------------------------------------------------------
 * bproc_hook_ptrace_request
 *
 * This function creates a remote ptrace request.  The resulting
 * request will be handled by a daemon whereever the process exists.
 */
static
long ptrace_request_remote(long request, long pid, long addr, long data) {
    long retval;
    struct bproc_krequest_t *req;
    struct bproc_ptrace_msg_t *pt_req, *pt_resp;

    req = bproc_new_req(BPROC_PTRACE, sizeof(*pt_req), GFP_KERNEL);
    if (!req) {
	return -ENOMEM;
    }
    pt_req = bproc_msg(req);
    bpr_to_real(pt_req, pid);
    bpr_from_real(pt_req, BPROC_MASQ_PID(current));

    /* ptrace request basics */
    pt_req->uid           = current->uid;
    pt_req->gid           = current->gid;
    pt_req->cap_effective = current->cap_effective;
    pt_req->request       = request;
    pt_req->addr          = addr;
    pt_req->data.data[0]  = data;
    
    /* This is required on AMD64, ppc64 to distinguish 32 bit ptrace
     * requests from 64 bit ptrace requests. */
    pt_req->flags = current_thread_info()->flags;

    /* Special cases where we need to get information from user space. */
    WARNING("Way more ptrace request types to deal with");
    switch (request) {
    case PTRACE_SETSIGINFO:
	
	break;
    default:
	retval = sysdep_ptrace_store_req(pt_req, request, pid, addr, data);
	if (retval)
	    goto out;
    }

    /* 3rd party calls never get in here */
    retval = bproc_send_req_wait(bproc_msgdest(), req);
    if (retval)
	goto out;
    pt_resp = bproc_msg(req->response);
    retval = pt_resp->hdr.result;

    switch(request) {
	/* ATTACH/DETACH might have to adjust nlchild. */
    case PTRACE_ATTACH:
	if (BPROC_ISMASQ(current) && 
	    pt_resp->hdr.result == 0 && pt_resp->data.data[0]) { 
	    write_lock_irq(&tasklist_lock);
	    current->bproc.nlchild++;
	    write_unlock_irq(&tasklist_lock);
	}	
	break;
    case PTRACE_DETACH:
	if (BPROC_ISMASQ(current) &&
	    pt_resp->hdr.result == 0 && pt_resp->data.data[0]) { 
	    write_lock_irq(&tasklist_lock);
	    current->bproc.nlchild--;
	    write_unlock_irq(&tasklist_lock);
	}	
	break;
    default:
	/* Store the result into user space. */
	if (retval == 0)
	    retval = sysdep_ptrace_store_user(pt_resp,request,pid,addr,data);
	break;
    }

 out:
    bproc_put_req(req);
    return retval;
}

/*-------------------------------------------------------------------------
 * bproc_hook_ptrace_no_proc
 *

 * This hook gets called when process lookup fails.
 */

static
long bproc_hook_ptrace_no_proc(long request,long pid,long addr,long data) {
    
    if (BPROC_ISMASQ(current))	/* forward to remote */
	return ptrace_request_remote(request, pid, addr, data);
    
    /* This is kinda like ISMASQ() for the 3rd party caller */ 
    if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag) &&
	current->bproc.context)
	return -ELOOP;		/* look elsewhere */

    return -ESRCH;
}


/*-------------------------------------------------------------------------
 * bproc_hook_ptrace_ghost
 */
static
long bproc_hook_ptrace_ghost(long request,long pid,long addr,long data) {
    struct task_struct *p;
    struct bproc_ghost_proc_t *g;

    /* Check if there's cached ptrace data */
    if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) {
	long offset;
	struct bproc_ptrace_msg_t pt_resp; /* using this as a temp is gross. */

	p = find_task_by_pid(pid);
	if (p) {
	    if ((g = ghost_get(p))) {
		spin_lock(&g->lock);
		/* XXX 32 bit compat bug: we presume the sizeof of
		 * thing we're grabbing is sizeof(long)... the
		 * practical outcome of this should just be that the
		 * last word in the cache is never used. */
		offset = addr - g->ptrace.addr;
		if (offset >= 0 &&
		    offset + sizeof(long) <= g->ptrace.bytes) {
		    if (g->state != TASK_TRACED && g->state != TASK_STOPPED) {
			printk(KERN_ERR "bproc: ptrace_ghost - cache valid but"
			       " task not stopped.  pid=%d state=%d\n",
			       p->pid, g->state);
		    }
		    /* memcpy to avoid alignment funnies */
		    memcpy(&pt_resp.data.data[0],
			   ((void *)g->ptrace.data) + offset, sizeof(long));
		    spin_unlock(&g->lock);
		    ghost_put(g);

		    return sysdep_ptrace_store_user(&pt_resp, request,
						    pid, addr, data);
		}
		spin_unlock(&g->lock);
		ghost_put(g);
	    }
	}
    }

    /* If we're going to modify this ghost at all, invalidate cached
     * data. */
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) {
	p = find_task_by_pid(pid);
	if (p) {
	    if ((g = ghost_get(p))) {
		spin_lock(&g->lock);
		g->ptrace.bytes = 0;
		spin_unlock(&g->lock);
		ghost_put(g);
	    }
	}
    }

    if (test_bit(BPROC_FLAG_PTRACE_3RD_PARTY, &current->bproc.flag))
	return -ELOOP;

    return ptrace_request_remote(request, pid, addr, data);
}

/*-------------------------------------------------------------------------
*/


int proc_pid_map = 2;		/* Default to map for all */
static inline
int do_pid_mapping(void) {
    if (capable(CAP_SYS_ADMIN))
	return proc_pid_map >= 2;
    else
	return proc_pid_map >= 1;
}

static
int bproc_hook_proc_pid(struct task_struct *p) {
    if (!do_pid_mapping()) return p->pid;
    /* Due to the fact that readdir and opening/reading the process
       files is not an atomic operation, possibility that p will no
       longer be a masqueraded process by the time we get here.  If
       that's the case, just return 0 for the pid. */
    if (!BPROC_ISMASQ(p)) return 0;
    return p->bproc.pid;
}

static
int bproc_hook_proc_tgid(struct task_struct *p) {
    if (!do_pid_mapping()) return p->pid;
    /* Due to the fact that readdir and opening/reading the process
       files is not an atomic operation, possibility that p will no
       longer be a masqueraded process by the time we get here.  If
       that's the case, just return 0 for the pid. */
    if (!BPROC_ISMASQ(p)) return 0;

    /* We're not doing anything with thread groups at this point.
     * Therefore we're just returning the pid at this point. */
    return p->bproc.pid;
}

static
int bproc_hook_proc_ppid(struct task_struct *p) {
    if (!do_pid_mapping()) return p->pid ? p->real_parent->pid : 0;
    /* See the note in bproc_hook_proc_pid... */
    if (!BPROC_ISMASQ(p))  return 0;
    return p->bproc.ppid;
}

static
int bproc_hook_proc_masq_only(struct task_struct *p) {
    /* Ignore processes not in our process space */
    if (!do_pid_mapping()) return p->pid;
    if (!p->bproc.master || p->bproc.master != current->bproc.master)
	return 0;
    return p->bproc.pid;
}

static
int bproc_hook_proc_lookup(int pid) {
    if (do_pid_mapping()) {
	int r;
	read_lock(&tasklist_lock);
	r = masq_masq2real(current->bproc.master, pid);
	read_unlock(&tasklist_lock);
	return r;
    } else
	return pid;
}

static
int bproc_hook_proc_self(void) {
    return do_pid_mapping() ? current->bproc.pid : current->pid;
}

static
int bproc_hook_proc_nodeid(struct task_struct *p) {
    int node = -1;
    struct bproc_ghost_proc_t *g;
    if ((g = ghost_get(p))) {
	node = g->node;
	ghost_put(g);
    }
    return node;
}

static
int bproc_hook_proc_exe(struct task_struct *p,
			struct dentry **dentry, struct vfsmount **mnt) {
    int result = -ENOENT;
    struct file *f;
    struct bproc_ghost_proc_t *g;
    
    if ((g = ghost_get(p))) {
	spin_lock(&g->lock);
	if ((f = g->proc.exe)) {
	    *mnt = mntget(f->f_vfsmnt);
	    *dentry = dget(f->f_dentry);
	    result = 0;
	}
	spin_unlock(&g->lock);
	ghost_put(g);
    }
    return result;
}

static
int bproc_hook_proc_dumpable(struct task_struct *p) {
    int dumpable = 0;
    struct bproc_ghost_proc_t *g;
    if ((g = ghost_get(p))) {
	spin_lock(&g->lock);
	dumpable = g->proc.dumpable;
	spin_unlock(&g->lock);
	ghost_put(g);
    }
    return dumpable;
}

static
char *bproc_hook_proc_task_mem(struct task_struct *task, char *buffer) {
    struct bproc_ghost_proc_t *g;
    if ((g = ghost_get(task))) {
	ghost_refresh_status(task);
	buffer += sprintf(buffer,
			  "VmSize:\t%8lu kB\n"
			  "VmLck:\t%8lu kB\n"
			  "VmRSS:\t%8lu kB\n"
			  "VmData:\t%8lu kB\n"
			  "VmStk:\t%8lu kB\n"
			  "VmExe:\t%8lu kB\n"
			  "VmLib:\t%8lu kB\n",
			  g->vm.status.total_vm << (PAGE_SHIFT-10),
			  g->vm.status.locked_vm << (PAGE_SHIFT-10),
			  g->vm.status.rss << (PAGE_SHIFT-10),
			  g->vm.status.data - g->vm.status.stack,
			  g->vm.status.stack,
			  g->vm.status.exec - g->vm.status.lib,
			  g->vm.status.lib);
	ghost_put(g);
    }
    return buffer;
}

static
int bproc_hook_proc_task_statm(struct task_struct *task, int *shared,
			       int *text, int *data, int *resident) {
    int size = 0;
    struct bproc_ghost_proc_t *g;

    if ((g = ghost_get(task))) {
	ghost_refresh_status(task);
	size      = g->vm.statm.size;
	*shared   = g->vm.statm.shared;
	*text     = g->vm.statm.text;
	*data     = g->vm.statm.data;
	*resident = g->vm.statm.resident;
	ghost_put(g);
    }
    return size;
}

int shell_script_hack = 1;
static
char **bproc_hook_load_script(char **script_name) {
    static char * argv[] = { "/proc/self/fd/3", 0};
    if (shell_script_hack &&
	test_bit(BPROC_FLAG_EXECMOVE, &current->bproc.flag)) {
	set_bit(BPROC_FLAG_SCRIPT, &current->bproc.flag);
	return argv;
    } else {
	return script_name;
    }
}

int execve_hook = 1;
/* This one is referenced by interface.c... */
int bproc_hook_sys_execve(struct pt_regs *regs, char *arg0,
			  char **argv, char **envp) {
    int err;
    struct bproc_kmove_t move;
    if (!execve_hook) return -ENOENT;

    memset(&move, 0, sizeof(move));
    move.type = BPROC_SYS_EXEC;
    move.user.arg0 = arg0;
    move.user.argv = argv;
    move.user.envp = envp;

    move.creds = kmalloc(creds_size(current), GFP_KERNEL);
    if (!move.creds)
	return -ENOMEM;
    creds_store(move.creds);

#if defined(__alpha__)
    /* Ok this is nasty.  The execve stack build-up on syscall entry
     * is the "light" variety.  This is not ok for vmadump since it
     * expects the full stack build-up used by fork, context switch
     * and the BProc syscalls.  We have to simulate the full build-up
     * here so that we won't end up clobbering our stack during
     * undump.  We should still be able to undump ok since we'll be
     * undumping a freshly exec()ed process image which shouldn't care
     * about the values saved in the registers we're not restoring. */
    {
    struct {		/* This is what the full stack build-up looks like */
	struct switch_stack ss;
	struct pt_regs      pt;
    } regtmp;
    memcpy(&regtmp.pt, regs, sizeof(*regs));
    err = send_recv_process(&move, &regtmp.pt);
    memcpy(regs, &regtmp.pt, sizeof(*regs));
    }
#else
    err = send_recv_process(&move, regs);
#endif

    /* Clean up our move structure */
    if (move.user.iolen > 0)
	kfree(move.user.io);

    /* Any errors here get turned back into ENOENT */
    return err ? -ENOENT : 0;
}

static
void bproc_hook_do_execve(void) {
    masq_set_creds(1);
}

static
void bproc_hook_refresh_status(struct task_struct *tsk) {
    ghost_refresh_status(tsk);
}

static
int bproc_hook_is_orphaned_pgrp(int pgrp) {
    return masq_is_orphaned_pgrp(pgrp);
}

static
void bproc_hook_set_creds(void) {
    masq_set_creds(0);
}

static
void bproc_hook_schedule_in(void) {
    /* Explanation: We want to emit a stop message when we stop but we
     * don't want to do it until we're REALLY going to stop.  It's
     * possible that we will set our process state to STOPPED and then
     * get preempted.  In this case we're actually going to call
     * schedule on our own.
     */
    if ((current->state == TASK_TRACED || current->state == TASK_STOPPED) &&
	!(preempt_count() & PREEMPT_ACTIVE) &&
	!test_and_set_bit(BPROC_FLAG_STOPPED, &current->bproc.flag)) {
	masq_stop_notify();
    }
}

static
void bproc_hook_schedule_out(void) {
    if (test_and_clear_bit(BPROC_FLAG_STOPPED, &current->bproc.flag)) {
	if (current->state == TASK_TRACED || current->state == TASK_STOPPED){
	    SPEW2("exiting schedule state=0x%lx", current->state);
	    dump_stack();
	}
	masq_cont_notify();
    }
}

void set_hooks(void) {
#define bprocdeclhook(ret,func,args)  \
    bproc_hook_ ## func ## _hook = bproc_hook_ ## func;
#include <linux/bproc_hooks.h>
#undef  bprocdeclhook
}

void unset_hooks(void) {
#define bprocdeclhook(ret,func,args)  \
    bproc_hook_ ## func ## _hook = 0;
#include <linux/bproc_hooks.h>
#undef  bprocdeclhook
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
