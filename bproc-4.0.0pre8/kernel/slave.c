/*-------------------------------------------------------------------------
 *  slave.c:  Beowulf distributed process space slave side code.
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
 * $Id: slave.c,v 1.68 2004/10/15 21:20:04 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/smp_lock.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <asm/uaccess.h>

#include "vmadump.h"
#include "bproc.h"
#include "bproc_internal.h"

/**------------------------------------------------------------------------
 ** Process receive code for use on slave nodes.  This stuff mostly
 ** makes sure that a process is created (and the pids in question
 ** exist) before allowing the slave daemon to continue.
 **/
struct recv_proc_info {
    struct bproc_masq_master_t *master;
    struct bproc_krequest_t    *req;
};

extern struct task_struct *child_reaper;

static
int do_recv_proc_stub(struct pt_regs *regs, struct recv_proc_info *arg) {
    int r, i, retval;
    struct bproc_krequest_t *req = arg->req;
    struct bproc_masq_master_t *master = arg->master;
    struct bproc_move_msg_t *move_req;

    bproc_get_req(req);
    move_req = bproc_msg(req);

    /* Throw off open files from the slave daemon. */
    for (i=0; i < current->files->max_fds; i++)
        if (current->files->fd[i])
	    sys_close(i);

    {    /* Restore scheduling policy to NORMAL... */
	struct sched_param p;
	mm_segment_t oldfs;
	p.sched_priority = 0;
	oldfs = get_fs(); set_fs(KERNEL_DS);
	retval = sys_sched_setscheduler(current->pid, SCHED_NORMAL, &p);
	set_fs(oldfs);
	if (retval != 0) {
	    printk("setscheduler failure: %d\n", retval);
	    goto out_compl;
	}
    }

    /* Get a new memory space for ourselves.  This is step one since
     * some of the process credentials we're about to restore relate
     * to this memory space. */
    exit_mm(current);
    retval = bproc_get_new_mm();
    if (retval != 0)
	goto out_compl;

    /* Do a set-sid on this thing */
    write_lock_irq(&tasklist_lock);
    if (current->signal->session != current->pid) {
	detach_pid(current, PIDTYPE_SID);
	current->signal->session = current->pid;
	attach_pid(current, PIDTYPE_SID, current->pid);
    }
    if (process_group(current) != current->pid) {
	detach_pid(current, PIDTYPE_PGID);
	current->signal->pgrp = current->pid;
	attach_pid(current, PIDTYPE_PGID, current->pid);
    }
    current->signal->leader = 1;
    current->signal->tty = NULL;
    current->signal->tty_old_pgrp = 0;
    write_unlock_irq(&tasklist_lock);

    /* Process priority should be set as part of move2process */
    retval = move2process(req, master);
    if (retval != 0)
	goto out_compl;

    /* Let the slave daemon continue now that we've camped on
     * these pid's and it's safe to go on doing other things
     * now. */
    complete(&master->done);

    /* Save this now since recv_process will overwrite the request */
    retval = move_req->index;

    /* recv_process sends the move response... */
    r = recv_process(req, regs);
    bproc_put_req(req);

    /* It's very important to not return unless we've
     * successfully restored something.  Otherwise our registers
     * will be completely bogus and anything can happen. */
    if (r != 0) silent_exit();

    /* This extra tid-bit helps deal with PF_TRACESYS.  A process is
     * expecting to stop there on the way out of the syscall.  Since
     * we will be returning via the standard return mechanism, we'll
     * have to do the standard tracesys step here.
     *
     * Before we call tracesys we need to make the process's register
     * state looks like it's right at the point of coming back from
     * the syscall.  Poke the return values into the right places to
     * accomplish this.
     */
    if (test_thread_flag(TIF_SYSCALL_TRACE)) {
	sysdep_store_return_value(regs, retval);
	sysdep_ptrace_syscall_trace_exit(regs);
    }
    return retval; /* return to user space to start this process again. */

 out_compl:
    {
	struct bproc_krequest_t *resp;
	struct bproc_null_msg_t *move_resp;
	/* We have an error that we need to respond to */
	
	/* using move_req->size is just laziness */

	resp = bproc_new_resp(req, sizeof(*move_resp), GFP_KERNEL);
	if (!resp) {
	    printk(KERN_CRIT "bproc: Out of memory responding"
		   " to move request.\n");
	    /* blow chunks?  We're gonna in a second anyway... */
	}
	move_resp = bproc_msg(resp);
	move_resp->hdr.result = retval;
	bproc_send_req(&master->req, resp);
	bproc_put_req(resp);
    }
    bproc_put_req(req);
    complete(&master->done);	/* let daemon know we're done here... */
    silent_exit();
}

static
void do_recv_proc(struct bproc_masq_master_t *master,
		 struct bproc_krequest_t *req) {
    int pid;
    struct recv_proc_info info;

    info.master = master;
    info.req    = req;
    init_completion(&master->done);

    /* We have to clear out PF_TRACESYS temporarily here since kernel
     * thread uses the system call entry/exit path.  (on x86
     * anyway...)
     *
     * This would be a non-issue since the slave daemon is the caller
     * and not some random process which might be traced.  On the
     * other hand, who knows....  We might be debugging the slave
     * daemon itself.
     */
    pid = bproc_kernel_thread((bproc_kthread_func *)do_recv_proc_stub,
			      (void *)&info, CLONE_VM | SIGCHLD);
    if (pid < 0) {
#if 0
	req->req.result = pid;
	bproc_respond(&master->req, req);
#endif
	/* Child process creation failed, we have to respond to the
	 * move message manually. */
	struct bproc_krequest_t *resp;
	struct bproc_move_msg_t *move_req, *move_resp;

	move_req = bproc_msg(req);
	resp = bproc_new_resp(req, sizeof(*move_resp), GFP_KERNEL);
	if (!resp) {
	    printk(KERN_CRIT "bproc: Out of memory responding to move request.\n");
	}
	move_resp = bproc_msg(req);
	move_resp->hdr.result = pid;
	bproc_send_req(&master->req, resp);
	bproc_put_req(resp);
	return;
    }

    /* Waiting for completion here serves two purposes:
     * - We know that the child is done using "info" and we can safely
     *   return from this stack frame.
     * - The child thread has been created and the PIDs that are
     *   supposed to exist on this node exist now.  This is important
     *   before processing more messages.
     */
    wait_for_completion(&master->done);

    /* The child will take care of responses to the move message if it
     * is successfully created. */
}

/**------------------------------------------------------------------------
 ** bproc device interface for slave daemons.
 **/
static
ssize_t bproc_slave_read(struct file *filp, char *buff, size_t size, loff_t *l) {
    struct bproc_krequest_t *r;
    struct bproc_message_hdr_t *hdr;
    struct bproc_masq_master_t *m = filp->private_data;

    r = bproc_next_req_wait(&m->req, filp->f_flags & O_NONBLOCK ?
			    0 : MAX_SCHEDULE_TIMEOUT);
    if (!r) {
	if (m->req.closing)
	    return 0;
	if (signal_pending(current))
	    return -EINTR;
	return -EAGAIN;
    }
    hdr = bproc_msg(r);

    /* Check to make sure the read request has the right size */
    if (hdr->size != size) {
	bproc_put_back_req(&m->req, r);
	return -EINVAL;
    }

    if (copy_to_user(buff, hdr, size)) {
	bproc_put_back_req(&m->req, r);
	return -EFAULT;
    }
    bproc_put_req(r);		/* Ok, we're done with this... */
    return size;
}

static
ssize_t bproc_slave_write(struct file *filp, const char *buff,
			  size_t size, loff_t *l) {
    int ret=0;
    struct bproc_krequest_t *req;
    struct bproc_message_hdr_t *hdr;
    struct bproc_masq_master_t *m = filp->private_data;

    /* Make sure we get at least a complete message header */
    if (size < sizeof(*hdr) || size > BPROC_MAX_MESSAGE_SIZE)
	return -EINVAL;

    /* Get the message from user space */
    req = bproc_new_req(0, size, GFP_KERNEL);
    if (!req)
	return -ENOMEM;
    hdr = bproc_msg(req);
    if (copy_from_user(hdr, buff, size)) {
	bproc_put_req(req);
	return -EFAULT;
    }
    if (hdr->size != size) {	/* Sanity check */
	bproc_put_req(req);
	return -EINVAL;
    }

#ifdef ENABLE_DEBUG
    msg_xfer(0, BPROC_REQUEST(hdr->req));
#endif
    if (BPROC_ISRESPONSE(hdr->req)) {
	if (hdr->req == BPROC_RESPONSE(BPROC_MOVE) && hdr->result != 0) {
	    /* This is a special case.  Unsuccessful move responses,
	     * like move requests can cause processes to appear or
	     * disappear.  Therefore we want to wait for the move
	     * response to get eaten before we go on and process more
	     * messages.  This will prevent some messages getting
	     * ping-ponged back and forth while we wait for  */
	    init_completion(&m->done);
	    ret = bproc_deliver_response(&m->req, req);
	    if (ret == 0)
		wait_for_completion(&m->done);
	} else {
	    ret = bproc_deliver_response(&m->req, req);
	}
	if (ret != 0) {
	    SPEW2("No pending request for response. (%d)"
		  " id=%p req=%d to=%d,%d",
		  ret, hdr->id, BPROC_REQUEST(hdr->req), hdr->to, hdr->totype);
	    /* Responses should never be chasing a process so squash it here */
	    ret = 0;
	}
    } else {
	switch (hdr->totype) {
	case BPROC_ROUTE_REAL:
	    switch(hdr->req) {
	    case BPROC_FWD_SIG:
		ret = deliver_signal(m, (struct bproc_signal_msg_t *) hdr);
		break;
	    case BPROC_PGRP_CHANGE:
		ret = masq_pgrp_change(m, (struct bproc_pgrp_msg_t *) hdr);
		break;
	    case BPROC_GET_STATUS:
		ret = masq_get_state_single(m, hdr->to);
		break;
	    case BPROC_CHILD_ADD:
		ret = masq_modify_nlchild(m, hdr->to, 1);
		if (ret == 0) {
		    struct bproc_krequest_t *resp;
		    struct bproc_null_msg_t *msg;
		    resp = bproc_new_resp(req, sizeof(*msg), GFP_KERNEL);
		    if (!resp) {
			printk(KERN_CRIT "bproc: Out of memory responding to "
			       "CHILD_ADD.\n");
			ret = -ENOMEM;
			goto barf;
		    }
		    msg = bproc_msg(resp);
		    msg->hdr.result = 0;
		    bproc_send_req(&m->req, resp);
		    bproc_put_req(resp);
		}
		break;
	    case BPROC_PTRACE:
		ptrace_3rd_party(req, m);
		ret = 0;
		break;
	    default:
		printk("slave: received ROUTE_REAL of type %d\n", hdr->req);
		ret = -EINVAL;
		break;
	    }
	    break;
	case BPROC_ROUTE_NODE:
	    switch(hdr->req) {
	    case BPROC_MOVE:
		/* This will block until the process gets created. */
		do_recv_proc(m, req);
		ret = 0;
		break;
	    case BPROC_GET_STATUS:
		masq_get_state_all(m);
		ret = 0;
		break;
	    case BPROC_PARENT_EXIT:
		ret = masq_parent_exit(m, hdr->from);
		break;
	    default:
		printk("slave: unhandled request sent to node: %d\n",hdr->req);
		ret = -EINVAL;
		break;
	    }
	    break;
	case BPROC_ROUTE_GHOST:
	    printk("slave: received message routed to ghost: %d\n", hdr->req);
	    ret = -EINVAL;
	    break;
	default:
	    printk("Unknown totype %d; reqtype = %d\n", hdr->totype, hdr->req);
	    ret = -EINVAL;
	    break;
	}
    }
 barf:
    bproc_put_req(req);
    return ret ? ret : size;
}

static
int bproc_slave_ioctl(struct inode *ino, struct file * filp,
		     unsigned int cmd, unsigned long arg) {
    struct bproc_masq_master_t *m = filp->private_data;

    switch (cmd) {
    case BPROC_MASQ_SET_MYADDR:
	if (copy_from_user(&m->my_addr,(void *)arg,sizeof(m->my_addr)))
	    return -EFAULT;
	return 0;
    case BPROC_MASQ_SET_MASTERADDR:
	if (copy_from_user(&m->master_addr,(void *)arg,sizeof(m->master_addr)))
	    return -EFAULT;
	return 0;
    case BPROC_MASQ_SET_NODENUM:
	m->node_number = arg;
	return 0;
    case BPROC_MSG_SIZE: {	/* return the size of the next message
				 * on the queue */
	int size;
	struct bproc_request_queue_t *queue = &m->req;
	struct bproc_krequest_t *req;
	struct bproc_message_hdr_t *hdr;

	/* Peek at the first message to get the size */
	size = 0;
	spin_lock(&queue->lock);
	if (!list_empty(&queue->list)) {
	    req = list_entry(queue->list.next, struct bproc_krequest_t, list);
	    hdr = bproc_msg(req);
	    size = hdr->size;
	}
	spin_unlock(&queue->lock);
	return size;
    }
    default:
	return -EINVAL;
    }
}

static
int bproc_slave_open(struct inode *ino, struct file *filp) {
    struct bproc_masq_master_t *m;
    m = kmalloc(sizeof(*m), GFP_KERNEL);
    if (!m) {
	printk("Out of memory in pid_masq_open\n");
	return -ENOMEM;
    }
    atomic_set(&m->count, 1);	/* open file counts for 1... */
    INIT_LIST_HEAD(&m->proc_list);
    m->req    = EMPTY_BPROC_REQUEST_QUEUE(m->req);
    init_completion(&m->done);
    filp->private_data = m;
    return 0;
}

static
int bproc_slave_release(struct inode *ino, struct file *filp) {
    struct list_head *l;
    struct task_struct *p;
    struct bproc_masq_master_t *m = filp->private_data;

    write_lock_irq(&tasklist_lock);
    for (l = m->proc_list.next; l != &m->proc_list; l = l->next) {
	p = list_entry(l, struct task_struct, bproc.list);

	/* Untrace so that we can cleanly shoot in the head */
	ptrace_unlink(p);

	force_sig(SIGKILL, p);
    }
    write_unlock_irq(&tasklist_lock);

    /* throw out all existing requests and clean up */
    write_lock_irq(&tasklist_lock);
    bproc_purge_requests(&m->req);

    /* Down the reference count on this thing and free it if we're the
     * last one.  If we're not, then one of the other exiting
     * processes should get rid of it. */
    if (atomic_dec_and_test(&m->count))
	kfree(m);
    write_unlock_irq(&tasklist_lock);
    return 0;
}

static
unsigned int bproc_slave_poll(struct file * filp, poll_table * wait) {
    unsigned int mask=0;
    struct bproc_masq_master_t *m = filp->private_data;

    poll_wait(filp,&m->req.wait,wait);
    if (!list_empty(&m->req.list)) mask |= POLLIN | POLLRDNORM;
    mask |= POLLOUT | POLLWRNORM; /* Always ready for writes... */
    return mask;
}

struct file_operations bproc_slave_fops = {
    open:    bproc_slave_open,
    release: bproc_slave_release,
    read:    bproc_slave_read,
    write:   bproc_slave_write,
    poll:    bproc_slave_poll,
    ioctl:   bproc_slave_ioctl
};

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
