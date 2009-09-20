/*-------------------------------------------------------------------------
 *  master.c:  Beowulf distributed process space ghost process code
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
 * $Id: master.c,v 1.42 2004/09/01 19:48:40 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/tty.h>		/* for is_orphaned_pgrp() */
#include <linux/ptrace.h>
#include <asm/uaccess.h>

#include "bproc.h"
#include "bproc_internal.h"

/**------------------------------------------------------------------------
 **  bproc device interface for PID space masters.
 **----------------------------------------------------------------------*/
static
ssize_t bproc_master_read(struct file *filp, char *buff,
			  size_t size, loff_t *l) {
    struct bproc_krequest_t *req;
    struct bproc_message_hdr_t *hdr;

    req = bproc_next_req_wait(&bproc_ghost_reqs,filp->f_flags & O_NONBLOCK ?
			      0 : MAX_SCHEDULE_TIMEOUT);
    if (!req) {
	if (bproc_ghost_reqs.closing)
	    return 0;
	if (signal_pending(current))
	    return -EINTR;
	return -EAGAIN;
    }
    hdr = bproc_msg(req);

    if (hdr->size != size) {
	bproc_put_back_req(&bproc_ghost_reqs, req);
	return -EINVAL;
    }

    if (copy_to_user(buff, hdr, size)) {
	bproc_put_back_req(&bproc_ghost_reqs, req);
	return -EFAULT;
    }

    /* XXX WACKY DEBUG */
    if (req->count.counter == 0) {
	printk(KERN_CRIT "bproc: FUCK!  ZERO REF COUNT ON LIST! 0x%x\n",
	       hdr->req);
	return size;
    }

    bproc_put_req(req);
    return size;
}

static
ssize_t bproc_master_write(struct file *filp, const char *buff, size_t size, loff_t *l) {
    int ret = 0;
    struct bproc_krequest_t *req;
    struct bproc_message_hdr_t *hdr;

    if (size < sizeof (*hdr) || size > BPROC_MAX_MESSAGE_SIZE)
	return -EINVAL;

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
	switch (hdr->req) {
	case BPROC_RESPONSE(BPROC_GET_STATUS):
	    /* get status is a special weird message which doesn't
	     * necessarily have a receiver waiting for a response.
	     * Updating the ghosts is done here. */
	    ghost_update_status(req);
	    break;
	case BPROC_RESPONSE(BPROC_PTRACE): {
	    struct bproc_ptrace_msg_t *pt_resp=(struct bproc_ptrace_msg_t*)hdr;
	    if (pt_resp->request == PTRACE_PEEKDATA ||
		pt_resp->request == PTRACE_PEEKTEXT)
		ghost_ptrace_cache(pt_resp);

	    ret = bproc_deliver_response(&bproc_ghost_reqs, req);
	    } break;
	default:
	    ret = bproc_deliver_response(&bproc_ghost_reqs, req);
	    /* Squash errors on this one... */
	    if (ret != 0 &&
		hdr->req == BPROC_RESPONSE(BPROC_MOVE_COMPLETE))
		ret = 0;
	}
    } else {
	switch (hdr->totype) {
	case BPROC_ROUTE_REAL:
	    switch(hdr->req) {
	    case BPROC_FWD_SIG:
		deliver_signal(0, (struct bproc_signal_msg_t *)hdr);
		ret = 0;	/* Ignore errors here. */
		break;
	    case BPROC_CHILD_ADD: {
		struct task_struct *task;
		read_lock(&tasklist_lock);
		task = find_task_by_pid(hdr->to);
		if (task && BPROC_ISGHOST(task)) {
		    /* Stick this message back on the outgoing queue
		     * if the process is remote or moving.  If it's
		     * not we can safely discard it. */
		    bproc_send_req(&bproc_ghost_reqs, req);
		    read_unlock(&tasklist_lock);
		} else {
		    struct bproc_krequest_t *resp;
		    struct bproc_null_msg_t *msg;
		    read_unlock(&tasklist_lock);

		    resp = bproc_new_resp(req, sizeof(*msg), GFP_KERNEL);
		    if (!resp) {
			printk(KERN_CRIT "CHILD_ADD out of memory.\n");
		    }
		    msg = bproc_msg(resp);
		    msg->hdr.result = 0;
		    bproc_send_req(&bproc_ghost_reqs, resp);
		    bproc_put_req(resp);
		}
		ret = 0;
		} break;
	    case BPROC_GET_STATUS:
	    case BPROC_PARENT_EXIT:
		ret = 0;	/* silently discard these messages ... */
		break;
	    case BPROC_PTRACE:
		ptrace_3rd_party(req, 0);
		ret = 0;
		break;

	    default:
		/* Leave this in for paranoia for now */
		printk(KERN_ERR "master: received ROUTE_REAL of type %d"
		       " (id=%p)\n", hdr->req, hdr->id);
		ret = 0;		/* eat it? */
		break;
	    }
	    break;
	case BPROC_ROUTE_NODE:
	    switch (hdr->req) {
	    case BPROC_MOVE:
	    case BPROC_EXEC:
		ret = ghost_deliver_msg(hdr->from, req);
		break;
	    case BPROC_ISORPHANEDPGRP: {
		struct bproc_pgrp_msg_t *msg;
		msg = bproc_msg(req);
		bproc_null_response(&bproc_ghost_reqs, req,
				    is_orphaned_pgrp(msg->pgid));
		ret = 0;
	        } break;
	    default:
		printk(KERN_ERR "master: received BPROC_ROUTE_NODE"
		       " of type %d\n", hdr->req);
		ret = -EINVAL;
	    }
	    break;
	case BPROC_ROUTE_GHOST:
	    switch (hdr->req) {
	    case BPROC_FWD_SIG:
		deliver_signal(0, (struct bproc_signal_msg_t *)hdr);
		ret = 0;	/* Don't pass errors out to bpmaster */
		break;
	    case BPROC_CONT:
	    case BPROC_STOP:
		ghost_update_status(req);
		break;
	    case BPROC_REPARENT:
		reparent_process(req);
		ret = 0;	/* Don't pass errors out to bpmaster */
		break;

		/* FIX ME: The master should probably wait for the
		 * SYS_KILL message to be processed before continuing
		 * on to other messages.  There's some slave side
		 * fixing to be done here too.  This is to make it
		 * look like process group signals get delivered all
		 * at once. */

	    default:
		ret = ghost_deliver_msg(hdr->to, req);
		break;
	    }
	    break;
	default:
	    printk(KERN_ERR "Unknown totype %d; reqtype = %d\n",
		   hdr->totype, hdr->req);
	    ret = -EINVAL;
	    break;
	}
    }
    bproc_put_req(req);
    return ret ? ret : size;
}

static
int bproc_master_ioctl(struct inode *ino, struct file * filp,
		       unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case BPROC_NODESET_INIT: {	/* Initialize */
	struct nodeset_init_t ini;
	if (copy_from_user(&ini, (void *) arg, sizeof(ini)))
	    return -EFAULT;
	return nodeset_init(ini.node_ct, ini.id_ct, ini.id_list);
    }
    case BPROC_NODESET_SETSTATE: { /* Set node state */
	struct nodeset_setstate_t ss;
	if (copy_from_user(&ss, (void *) arg, sizeof(ss)))
	    return -EFAULT;
	ss.state[BPROC_STATE_LEN] = 0; /* no shenanigans please */
	return nodeset_set_state(ss.id, ss.state);
    }
    case BPROC_NODESET_PERM: { /* Permission check (not implemented) */
	struct nodeset_perm_t mp;
	if (copy_from_user(&mp, (void *) arg, sizeof(mp)))
	    return -EFAULT;
	return nodeset_move_perm(filp, &mp);
    }
    case BPROC_NODESET_SETADDR: { /* Set node address */
	struct nodeset_setaddr_t addr;
	if (copy_from_user(&addr, (void *) arg, sizeof(addr)))
	    return -EFAULT;
	return nodeset_set_addr(addr.id, &addr.addr);
    }

    case BPROC_SETPROCLOC: {
	struct setprocloc_t procloc;
	if (copy_from_user(&procloc, (void *) arg, sizeof(procloc)))
	    return -EFAULT;
	return ghost_set_location(procloc.pid, procloc.node);
    }

    case BPROC_MSG_SIZE: {	/* return the size of the next message
				 * on the queue */
	int size;
	struct bproc_request_queue_t *queue = &bproc_ghost_reqs;
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
unsigned int bproc_master_poll(struct file * filp, poll_table * wait) {
    unsigned int mask = 0;
    poll_wait(filp, &bproc_ghost_reqs.wait, wait);
    if (!list_empty(&bproc_ghost_reqs.list)) mask |= POLLIN | POLLRDNORM;
    mask |= POLLOUT | POLLWRNORM;
    return mask;
}


#define REOPEN_QUEUE(q) \
   do { \
       spin_lock(&(q)->lock); \
       (q)->closing = 0; \
       spin_unlock(&(q)->lock); \
   } while(0)

static
int bproc_master_open(struct inode *ino, struct file *filp) {
    int rw;
    rw = filp->f_mode & (FMODE_READ|FMODE_WRITE);
    switch (rw) {
    case FMODE_READ|FMODE_WRITE: /* Open as a master */
	spin_lock(&ghost_lock);
	if (ghost_master != 0) {
	    spin_unlock(&ghost_lock);
	    printk(KERN_NOTICE "bproc: ghost: master already present.\n");
	    return -EBUSY;
	}
	REOPEN_QUEUE(&bproc_ghost_reqs);
	ghost_master = 1;
	spin_unlock(&ghost_lock);
#ifdef BPROC_MSG_DEBUG
	bproc_msg_debug_reset();
#endif
	return 0;
    default:
	return -EINVAL;
    }
}

static
int bproc_master_release(struct inode *ino, struct file *filp) {
    struct list_head *l;
    struct bproc_ghost_proc_t *g;
    DECLARE_WAITQUEUE(wait, current);

    /* Get rid of all the ghosts (forcefully) */
    spin_lock(&ghost_lock);
    ghost_master = 0;
    for (l = ghost_list.next; l != &ghost_list; l = l->next) {
	g = list_entry(l, struct bproc_ghost_proc_t, list);
	bproc_close_request_queue(&g->req);
    }
    spin_unlock(&ghost_lock);

    /* Throw out all my own requests. */
    bproc_purge_requests(&bproc_ghost_reqs);

    /* Wait for the ghost list to become empty. */
    add_wait_queue(&ghost_wait, &wait);
    set_current_state(TASK_UNINTERRUPTIBLE);
    while (!list_empty(&ghost_list)) {
	schedule();
	set_current_state(TASK_UNINTERRUPTIBLE);
    }
    remove_wait_queue(&ghost_wait, &wait);
    set_current_state(TASK_RUNNING);

#ifdef BPROC_MSG_DEBUG
    bproc_msg_debug_dump();
#endif

    /* Clear out nodeset */
    nodeset_init(0,0,0);
    return 0;			/* Is close allowed to fail? */
}

struct file_operations bproc_master_fops = {
    owner:   THIS_MODULE,
    open:    bproc_master_open,
    release: bproc_master_release,
    read:    bproc_master_read,
    write:   bproc_master_write,
    poll:    bproc_master_poll,
    ioctl:   bproc_master_ioctl,
};


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
