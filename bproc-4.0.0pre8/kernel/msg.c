/*-------------------------------------------------------------------------
 *  msg.c: Beowulf distributed PID space request management
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
 * $Id: msg.c,v 1.29 2004/06/22 18:24:20 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include "bproc.h"
#include "bproc_internal.h"

/*-------------------------------------------------------------------------
 *  Next request access functions.
 */
static inline struct bproc_krequest_t *
bproc_next_req_(struct bproc_request_queue_t *me) {
    struct bproc_krequest_t *req;
    if (!list_empty(&me->list)) {
	req = list_entry(me->list.next, struct bproc_krequest_t, list);
	list_del(&req->list);
	if (req->flags & BPROC_REQ_WANT_RESP) {
	    bproc_get_req(req);
	    list_add_tail(&req->list, &me->pending);
	}
	return req;
    }
    return 0;
}

struct bproc_krequest_t *bproc_next_req(struct bproc_request_queue_t *me) {
    struct bproc_krequest_t *req;
    spin_lock(&me->lock);
    req = bproc_next_req_(me);
    spin_unlock(&me->lock);
    return req;
}

struct bproc_krequest_t *bproc_next_req_wait(struct bproc_request_queue_t *me,
					     signed long timeout) {
    DECLARE_WAITQUEUE(wait, current);
    struct bproc_krequest_t *req;

    spin_lock(&me->lock);
    add_wait_queue(&me->wait, &wait);
    set_current_state(TASK_INTERRUPTIBLE);
    req = bproc_next_req_(me);
    while (!req && !me->closing && timeout && !signal_pending(current)) {
	spin_unlock(&me->lock);
	timeout = schedule_timeout(timeout);
	spin_lock(&me->lock);
	set_current_state(TASK_INTERRUPTIBLE);
	req = bproc_next_req_(me);
    }
    remove_wait_queue(&me->wait, &wait);
    set_current_state(TASK_RUNNING);
    spin_unlock(&me->lock);
    return req;
}


void __bproc_put_req(struct bproc_krequest_t *req) {
#ifdef ENABLE_DEBUG
    extern atomic_t msg_counters[];
    struct bproc_message_hdr_t *hdr;
    hdr = bproc_msg(req);
    atomic_dec(&msg_counters[BPROC_REQUEST(hdr->req)]);
#endif
    atomic_dec(&msg_count);

    if (req->response)
	bproc_put_req(req->response);
    kfree(req);
}

/*-------------------------------------------------------------------------
 *  bproc_send_req
 *
 */
static inline
void allocate_id(struct bproc_krequest_t *req) {
    static volatile long idseq = 1;
    static spinlock_t    idlock = SPIN_LOCK_UNLOCKED;
    struct bproc_message_hdr_t *hdr;

    hdr = bproc_msg(req);

    if (!hdr->id) {
	spin_lock(&idlock);
	hdr->id = (void *) idseq;
	idseq++;
	if (idseq == 0) idseq = 1;
	spin_unlock(&idlock);
    }
}

int bproc_send_req(struct bproc_request_queue_t *reqdest,
		   struct bproc_krequest_t *req) {
    allocate_id(req);

    spin_lock(&reqdest->lock);
    if (reqdest->closing) {
	spin_unlock(&reqdest->lock);
	return -EIO;
    }

    bproc_get_req(req);
    list_add_tail(&req->list, &reqdest->list);
    wake_up(&reqdest->wait);
    spin_unlock(&reqdest->lock);
    return 0;
}

/*-------------------------------------------------------------------------
 *  bproc_pending_req
 *
 */
int bproc_pending_req(struct bproc_request_queue_t *reqdest,
		      struct bproc_krequest_t *req) {
    struct bproc_message_hdr_t *hdr;
    hdr = bproc_msg(req);
    if (hdr->id == 0) {
	printk("bproc: ERROR: bproc_pending_req with zero request ID."
	       "  req=0x%x\n", hdr->req);
	return -EINVAL;
    }
    

    if (!(req->flags & BPROC_REQ_WANT_RESP)) {
	printk("bproc: WARNING: bproc_pending_req called with request w/o"
	       "WANT_RESP.  req=0x%x id=0x%lx\n", hdr->req, (long) hdr->id);
    }

    /*allocate_id(req);*/

    spin_lock(&reqdest->lock);
    if (reqdest->closing) {
	spin_unlock(&reqdest->lock);
	return -EIO;
    }

    bproc_get_req(req);
    list_add_tail(&req->list, &reqdest->pending);
    spin_unlock(&reqdest->lock);
    return 0;
}

/*-------------------------------------------------------------------------
 *  bproc_null_response
 */
int bproc_null_response(struct bproc_request_queue_t *dest, 
			struct bproc_krequest_t *req, long result) {
    struct bproc_krequest_t *resp;
    struct bproc_null_msg_t *msg;

    resp = bproc_new_resp(req, sizeof(*msg), GFP_KERNEL);
    if (!resp)
	return -ENOMEM;
    msg = bproc_msg(resp);
    msg->hdr.result = result;
    bproc_send_req(dest, resp);
    bproc_put_req(resp);
    return 0;
}


/*-------------------------------------------------------------------------
 *  bproc_put_back_req
 */
void bproc_put_back_req(struct bproc_request_queue_t *reqdest,
			struct bproc_krequest_t *req) {
    spin_lock(&reqdest->lock);
    if (!reqdest->closing) {
	list_add(&req->list, &reqdest->list);
	wake_up(&reqdest->wait);
    } else {
	/* XXX Mebbe we have to do something else here? */
	bproc_put_req(req);
    }
    spin_unlock(&reqdest->lock);
}

/*-------------------------------------------------------------------------
 *  bproc_deliver_response
 */
int bproc_deliver_response(struct bproc_request_queue_t *p,
			   struct bproc_krequest_t *req) {
    struct list_head *l;
    struct bproc_krequest_t *r;
    struct bproc_message_hdr_t *hdr, *rhdr;

    hdr = bproc_msg(req);

    if (BPROC_RESPONSE(hdr->req) != hdr->req) {
	printk("bproc: deliver_response: "
	       "request type is not a response type: 0x%x \n", hdr->req);
	hdr->req = BPROC_RESPONSE(hdr->req);
    }

    spin_lock(&p->lock);
    for (l = p->pending.next; l != &p->pending; l = l->next) {
	r = list_entry(l, struct bproc_krequest_t, list);
	rhdr = bproc_msg(r);
	if (BPROC_RESPONSE(rhdr->req) == hdr->req &&
	    rhdr->id                  == hdr->id) {
	    list_del(&r->list);
	    spin_unlock(&p->lock);

	    if (r == req) {
		printk("bproc: response == request in deliver_response\n");
		return -EIO;
	    }
	    bproc_get_req(req);
	    r->response = req;
	    wake_up(&r->wait);
	    bproc_put_req(r);
	    return 0;
	}
    }
#if 0
    /* For debugging response weirdness only */
    printk("req->req = 0x%x  req->id=0x%lx\n",req->req.req,(long)req->req.id);
    printk("Pending requests:\n");
    for (l = p->pending.next; l != &p->pending; l = l->next) {
	r = list_entry(l, struct bproc_krequest_t, list);
	printk("  req: 0x%x req->id=0x%lx\n", r->req.req, (long)r->req.id);
    }
#endif
    spin_unlock(&p->lock);
    return -ESRCH;
}


/* XXX Is this stuff really necessary?
 *
 *  If every request can always count on a response the NO.  If you
 *  want to deal with the case where a response might go missing, you
 *  have to do something like this.
 *    
 * */
void bproc_remove_req(struct bproc_request_queue_t *q,
		      struct bproc_krequest_t *req) {
    struct list_head *l;
    struct bproc_krequest_t *r;

    WARNING("bproc_remove_req is completely bogus.");

    spin_lock(&q->lock);
    for (l = q->list.next; l != &q->list; l = l->next) {
	r = list_entry(l, struct bproc_krequest_t, list);
	if (r == req) {
	    list_del(&r->list);
	    spin_unlock(&q->lock);
	    bproc_put_req(r);
	    return;
	}
    }
    for (l = q->pending.next; l != &q->pending; l = l->next) {
	r = list_entry(l, struct bproc_krequest_t, list);
	if (r == req) {
	    list_del(&r->list);
	    spin_unlock(&q->lock);
	    bproc_put_req(r);
	    return;
	}
    }
    spin_unlock(&q->lock);
}

/*-------------------------------------------------------------------------
 *  bproc_response_wait
 *
 *  Wait for a response to a request.
 */
int bproc_response_wait(struct bproc_krequest_t *req, signed long timeout, int intr) {
    DECLARE_WAITQUEUE(wait, current);

    add_wait_queue(&req->wait,&wait);
    set_current_state(intr ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
    while (timeout > 0 && bproc_pending(req) &&
	   (!(intr && signal_pending(current)))) {
	timeout = schedule_timeout(timeout);
	set_current_state(intr ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
    }
    remove_wait_queue(&req->wait,&wait);
    set_current_state(TASK_RUNNING);

    if (bproc_hasresponse(req))
	return 0;
    if (intr && signal_pending(current))
	return -EINTR;
    else
	return -EIO;
}

/*-------------------------------------------------------------------------
 *  bproc_send_req_wait
 *
 *  Send a request and wait for a response.  The returned response
 *  will be placed in the same request structure that was passed in.
 */
int bproc_send_req_wait(struct bproc_request_queue_t *reqdest,
			struct bproc_krequest_t *req) {
    int err;
    req->flags |= BPROC_REQ_WANT_RESP;
    err = bproc_send_req(reqdest, req);
    if (err) return err;
    return bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, 0);
}

#define EMPTY_BPROC_REQUEST_QUEUE(foo) \
    ((struct bproc_request_queue_t) {SPIN_LOCK_UNLOCKED,0, \
    LIST_HEAD_INIT((foo).list),__WAIT_QUEUE_HEAD_INITIALIZER((foo).wait),\
    LIST_HEAD_INIT((foo).pending)})

void bproc_init_request_queue(struct bproc_request_queue_t *q) {
    spin_lock_init(&q->lock);
    q->closing = 0;
    INIT_LIST_HEAD(&q->list);
    init_waitqueue_head(&q->wait);
    INIT_LIST_HEAD(&q->pending);
}

void bproc_close_request_queue(struct bproc_request_queue_t *q) {
    spin_lock(&q->lock);
    q->closing = 1;
    wake_up(&q->wait);
    spin_unlock(&q->lock);
}

void bproc_purge_requests(struct bproc_request_queue_t *q) {
    struct bproc_krequest_t *r;
    struct bproc_message_hdr_t *m;

    spin_lock(&q->lock);
    q->closing = 1;

    /* Dispose of all the requests on both lists.  Set req->req.req to
     * zero to notify anyone waiting on the request that we've just
     * ditched the request. */

    while (!list_empty(&q->list)) {
	r = list_entry(q->list.next, struct bproc_krequest_t, list);
	m = bproc_msg(r);
	list_del(&r->list);
#ifdef BPROC_MSG_DEBUG
	bproc_msg_debug_free(r); /* XXX DEBUGGING */
#endif
	m->req = 0;
	wake_up(&r->wait);
	bproc_put_req(r);
    }

    while (!list_empty(&q->pending)) {
	r = list_entry(q->pending.next, struct bproc_krequest_t, list);
	m = bproc_msg(r);
	list_del(&r->list);
#ifdef BPROC_MSG_DEBUG
	bproc_msg_debug_free(r); /* XXX DEBUGGING */
#endif
	m->req = 0;		/* Signal dead request */
	wake_up(&r->wait);
	bproc_put_req(r);
    }
    wake_up(&q->wait);
    spin_unlock(&q->lock);
}

void bproc_pack_siginfo(struct bproc_siginfo_t *bp_info, struct siginfo *info){
    bp_info->si_signo = info->si_signo;
    bp_info->si_errno = info->si_errno;
    bp_info->si_code  = info->si_code;
    switch(info->si_signo) {
    case SIGCHLD:
	bp_info->si_pid    = info->si_pid;	/* XXX Need to do PID translation here... */
	bp_info->si_uid    = info->si_uid;
	bp_info->si_status = info->si_status;
	bp_info->si_utime  = info->si_utime;
	bp_info->si_stime  = info->si_stime;
	break;
    case SIGILL:
    case SIGFPE:
    case SIGSEGV:
    case SIGBUS:
	bp_info->si_addr = info->si_addr;
	break;
    case SIGPOLL:
	bp_info->si_band = info->si_band;
	bp_info->si_fd   = info->si_fd;
	break;
    default:
	bp_info->si_pid = info->si_pid; /* XXX Need to do PID translation here... */
	bp_info->si_uid = info->si_uid;
    }
}

void bproc_unpack_siginfo(struct bproc_siginfo_t *bp_info,
			  struct siginfo *info) {
    info->si_signo = bp_info->si_signo;
    info->si_errno = bp_info->si_errno;
    info->si_code  = bp_info->si_code;
    switch(info->si_signo) {
    case SIGCHLD:
	info->si_pid    = bp_info->si_pid;
	info->si_uid    = bp_info->si_uid;
	info->si_status = bp_info->si_status;
	info->si_utime  = bp_info->si_utime;
	info->si_stime  = bp_info->si_stime;
	break;
    case SIGILL:
    case SIGFPE:
    case SIGSEGV:
    case SIGBUS:
	info->si_addr = bp_info->si_addr;
	break;
    case SIGPOLL:
	info->si_band = bp_info->si_band;
	info->si_fd   = bp_info->si_fd;
	break;
    default:
	info->si_pid = bp_info->si_pid;
	info->si_uid = bp_info->si_uid;
    }
}

atomic_t msg_count;
#ifdef ENABLE_DEBUG
/*-------------------------------------------------------------------------
 *  Message leak debugging
 */
atomic_t msg_counters[MSG_COUNTER_MAX];

void msg_counter_init(void) {
    int i;
    for (i=0; i < MSG_COUNTER_MAX; i++)
	atomic_set(&msg_counters[i], 0);
}
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
