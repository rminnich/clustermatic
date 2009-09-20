/*-------------------------------------------------------------------------
 *  move.c:  Beowulf distributed process space process migration code.
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
 * $Id: move.c,v 1.104 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/bproc.h>
#include <linux/syscalls.h>

#include <linux/net.h>
#include <linux/in.h>

#include "vmadump.h"
#include "bproc.h"
#include "bproc_internal.h"

#define MAX_CONNECT_TRY 10

/*--------------------------------------------------------------------
 *  Simplified wrappers for use by other parts of bproc.
 *------------------------------------------------------------------*/
static
struct file *bproc_setup_listen(void) {
    struct file *listen;
    int flags, err;
    struct sockaddr_in local;

    listen = k_socket_f(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (IS_ERR(listen)) {
	printk(KERN_ERR "bproc: sock: socket failed; errno=%d\n",
	       (int)- PTR_ERR(listen));
	return listen;
    }

    flags = 1;
    err = k_setsockopt_f(listen, SOL_SOCKET, SO_REUSEADDR,
			 &flags, sizeof(flags));
    if (err < 0) {
	/* This is non-fatal... it also should also never happen... */
	printk(KERN_ERR "bproc: sock: setsockopt failed; errno=%d\n", -err);
    }

    /* Bind the socket to some random port */
    local.sin_family      = AF_INET;
    local.sin_addr.s_addr = 0;
    local.sin_port        = 0;
    err = k_bind_f(listen, (struct sockaddr *)&local, sizeof(local));
    if (err < 0) {
	printk(KERN_ERR "bproc: sock: bind failed; errno=%d\n", -err);
	fput(listen);
	return ERR_PTR(err);
    }

    err = k_listen_f(listen, 5);
    if (err < 0) {
	printk(KERN_ERR "bproc: sock: listen failed; errno=%d\n", -err);
	fput(listen);
	return ERR_PTR(err);
    }

    lock_kernel();
    listen->f_flags |= O_NONBLOCK;
    unlock_kernel();
    return listen;
}

static
struct file *bproc_connect(uint32_t addr, uint16_t port) {
    struct file *file;
    int err, flags;
    struct sockaddr_in rem;

    file = k_socket_f(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (IS_ERR(file)) {
	printk(KERN_ERR "bproc: sock: socket failed; errno=%d\n",
	       (int) - PTR_ERR(file));
	return file;
    }

    flags = 1;
    err = k_setsockopt_f(file, SOL_SOCKET, SO_REUSEADDR, &flags,sizeof(flags));
    if (err < 0) {
	/* This is non-fatal... it also should never happen... */
	printk(KERN_ERR "bproc: sock: setsockopt failed; errno=%d\n", -err);
    }

    rem.sin_family      = AF_INET;
    rem.sin_addr.s_addr = addr;
    rem.sin_port        = port;
    err = k_connect_f(file, (struct sockaddr *)&rem, sizeof(rem));
    if (err < 0) {
	printk(KERN_ERR "bproc: connect: connect to %d.%d.%d.%d:%d failed;"
	       " errno=%d\n", (int) ((ntohl(addr) >> 24) & 0xff),
	       (int) ((ntohl(addr) >> 16) & 0xff),
	       (int) ((ntohl(addr) >>  8) & 0xff),
	       (int) ( ntohl(addr)        & 0xff),
	       (int) ntohs(port), -err);
	fput(file);
	return ERR_PTR(err);
    }
    return file;
}

static
struct file *bproc_accept(struct file *listen) {
    struct sockaddr_in rem;
    int remsize;
    struct file *file;

    remsize = sizeof(rem);
    file = k_accept_f(listen, (struct sockaddr *) &rem, &remsize);
    if (IS_ERR(file))
	printk(KERN_ERR "bproc: accept failed; errno=%d\n",
	       (int) -PTR_ERR(file));
    return file;
}

int bproc_get_port(struct file *file) {
    int err;
    struct sockaddr_in local;
    int locsize = sizeof(local);
    if ((err = k_getsockname_f(file, (struct sockaddr *) &local, &locsize))) {
	printk(KERN_ERR "bproc: sock: k_getsockname failed; errno=%d\n", -err);
	local.sin_port = 0;
    }
    return local.sin_port;
}

/*--------------------------------------------------------------------
 *  Process Credential handling stuff
 */
/* groups_to/from_user are taken from the Linux kernel */
static
void copy_from_groups(gid_t *grouplist, struct group_info *group_info, int ngroups) {
#if 0
    int i;
    int count = group_info->ngroups;

    for (i = 0; i < group_info->nblocks; i++) {
	int cp_count = min(NGROUPS_PER_BLOCK, count);
	int off = i * NGROUPS_PER_BLOCK;
	int len = cp_count * sizeof(*grouplist);
	
	memcpy(grouplist+off, group_info->blocks[i], len);
	count -= cp_count;
    }
#endif
    int i;
    for (i=0; i < ngroups; i++) {
	grouplist[i] = GROUP_AT(group_info, i);
    }
}

void copy_to_groups(struct group_info *group_info,  gid_t *grouplist, int ngroups) {
#if 0
    int i;
    int count = group_info->ngroups;

    for (i = 0; i < group_info->nblocks; i++) {
	int cp_count = min(NGROUPS_PER_BLOCK, count);
	int off = i * NGROUPS_PER_BLOCK;
	int len = cp_count * sizeof(*grouplist);
	
	memcpy(group_info->blocks[i], grouplist+off, len);
	count -= cp_count;
    }
#endif
    int i;
    for (i=0; i < ngroups; i++) {
	GROUP_AT(group_info, i) = grouplist[i];
    }
}

#define ROUND_UP(x,y) (((x)+(y)-1) & ~((y)-1))

int creds_size(struct task_struct *t) {
    int s;
    s = sizeof(struct bproc_credentials_t) +
	t->group_info->ngroups * sizeof(uint32_t);
    return ROUND_UP(s, sizeof(void*));
}

int creds_struct_size(struct bproc_credentials_t *creds) {
    int s;
    s = sizeof(*creds) + creds->ngroups * sizeof(creds->groups[0]);
    return ROUND_UP(s, sizeof(void*));
}

int creds_restore(struct bproc_credentials_t *creds, int dumpable) {
    struct user_struct *new_user;
    struct group_info *gi;

    gi = groups_alloc(creds->ngroups);
    if (!gi) {
	printk(KERN_ERR "bproc: Out of memory allocating groups (%d)\n",
	       creds->ngroups);
	return -ENOMEM;
    }
    copy_to_groups(gi, creds->groups, creds->ngroups);

    if (current->mm) {
	if (dumpable)
	    current->mm->dumpable = creds->dumpable;
	else
	    current->mm->dumpable = 0;
    }

    /*current->uid = creds->uid;*/ current->euid = creds->euid;
    current->suid = creds->suid; current->fsuid = creds->fsuid;
    current->gid = creds->gid;   current->egid = creds->egid;
    current->sgid = creds->sgid; current->fsgid = creds->fsgid;

    set_current_groups(gi);
    put_group_info(gi);
    
    current->cap_effective   = creds->cap_effective;
    current->cap_inheritable = creds->cap_inheritable;
    current->cap_permitted   = creds->cap_permitted;
    current->parent_exec_id  = creds->parent_exec_id;
    current->self_exec_id    = creds->self_exec_id;

    /* Changing the uid is a bit more complicated ... */
    if (creds->uid != current->uid) {
	new_user = alloc_uid(creds->uid);
	if (!new_user) {
	    printk(KERN_ERR "bproc: restore_creds alloc_uid failed.\n");
	    return -ENOMEM;
	}
	switch_uid(new_user);
	current->uid = creds->uid;
    }
    return 0;
}

/* It's up to the caller to make sure that the creds_t is big enough
   in this case. */
void creds_store(struct bproc_credentials_t *creds) {
    creds->uid = current->uid;   creds->euid = current->euid;
    creds->suid = current->suid; creds->fsuid = current->fsuid;
    creds->gid = current->gid;   creds->egid = current->egid;
    creds->sgid = current->sgid; creds->fsgid = current->fsgid;

    creds->cap_effective   = current->cap_effective;
    creds->cap_inheritable = current->cap_inheritable;
    creds->cap_permitted   = current->cap_permitted;
    creds->dumpable        = current->mm ? current->mm->dumpable : 0;
    creds->parent_exec_id  = current->parent_exec_id;
    creds->self_exec_id    = current->self_exec_id;

    /* FIX ME:  this is still capped to BPROC_NGROUPS */
    creds->ngroups = current->group_info->ngroups > BPROC_NGROUPS ?
	BPROC_NGROUPS : current->group_info->ngroups;
    copy_from_groups(creds->groups, current->group_info,
		     current->group_info->ngroups);
}

/*------------------------------------------------------------------*/


struct bproc_priority_t {
    unsigned long policy;
    long nice;
    unsigned long rt_priority;
};

/* Ok, nastiness here...  Here's the deal: We want to wake up on two
 * possible conditions: we receive a response from the client (which
 * would indicate an error at this point) or we receive a connection
 * from the client.  So, this bit is like a minimal select with
 * timeout and bproc_resp_wait rolled together. */
#define POLLIN_SET  (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
static
int bproc_send_proc_select(struct file *filp, struct bproc_krequest_t *req,
			   int pollset, long timeout) {
    struct poll_wqueues poll;
    DECLARE_WAITQUEUE(reqwait, current);
    int mask;

    poll_initwait(&poll);
    if (req) add_wait_queue(&req->wait,&reqwait);

    /* Loop waiting for the request to become ready or officially dead
     * or socket to be ready or the timeout to expire. */
    set_current_state(TASK_INTERRUPTIBLE);
    mask = filp->f_op->poll(filp, &poll.pt);
    while ((!req || bproc_pending(req)) &&!(mask & pollset) &&
	   timeout > 0 && !signal_pending(current)) {
	timeout = schedule_timeout(timeout);
	set_current_state(TASK_INTERRUPTIBLE);
	mask = filp->f_op->poll(filp,0);
    }
    set_current_state(TASK_RUNNING);
    if (req) remove_wait_queue(&req->wait, &reqwait);

    poll_freewait(&poll);
    if (mask & pollset) {
	return 1;
    } else {
	return signal_pending(current) ? -EINTR : 0;
    }
}

/**------------------------------------------------------------------------
 ** I/O helpers
 **
 ** These I/O routines all take a pending request as an argument.  If
 ** the request gets a response, the I/O routines will return with
 ** -EIO.
 **
 ** IMPORTANT NOTE: The _kern versions automagically map a complete
 ** read/write to a zero return value and anything else to -EIO.
 **/
static
ssize_t write_req_file_user(struct bproc_krequest_t *req, struct file *f,
		       const void *buffer, size_t size) {
    int ret;
    ret = bproc_send_proc_select(f, req, POLLOUT_SET, MAX_SCHEDULE_TIMEOUT);
    if (req && bproc_deadreq(req))  return -EIO;
    if (req && bproc_hasresponse(req)) {
	struct bproc_message_hdr_t *hdr = bproc_msg(req->response);
	return hdr->result;
    }
    if (ret == 1)
	ret = k_write_u_f(f, buffer,size);
    return ret;
}

static
ssize_t write_req_file_kern(struct bproc_krequest_t *req, struct file *f,
			    const void *buffer, size_t size) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = write_req_file_user(req, f, buffer, size);
    set_fs(oldfs);
    if (err == size)
	err = 0;
    else
	if (err > 0) err = -EIO; /* short writes become EIO */
    return err;
}

static
ssize_t read_req_file_user(struct bproc_krequest_t *req, struct file *f,
			   void *buffer, size_t size) {
    int ret = 1;
    size_t bytes = 0;

    while (size > 0 && ret > 0) {
	ret = bproc_send_proc_select(f, req, POLLIN_SET, MAX_SCHEDULE_TIMEOUT);
	if (req && bproc_deadreq(req)) return -EIO;
	if (req && bproc_hasresponse(req)) {
	    struct bproc_message_hdr_t *hdr = bproc_msg(req->response);
	    return hdr->result;
	}
	if (ret == 1) {
	    if ((ret = k_read_u_f(f, buffer, size)) > 0) {
		size -= ret;
		buffer += ret;
		bytes += ret;
	    }
	}
    }
    return (size == 0) ? bytes : ret;
}

static
ssize_t read_req_file_kern(struct bproc_krequest_t *req, struct file *f,
			   void *buffer, size_t size) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = read_req_file_user(req, f, buffer, size);
    set_fs(oldfs);
    if (err == size)
	err = 0;
    else
	if (err >= 0) err = -EIO; /* short reads become EIO */
    return err;
}

/*--------------------------------------------------------------------
 *  Data packing primitives.
 *------------------------------------------------------------------*/
int bproc_get_int(struct bproc_krequest_t *req, struct file *file, int *dest) {
    return read_req_file_kern(req, file, dest, sizeof(*dest));
}

int bproc_get_long(struct bproc_krequest_t *req, struct file *file,long *dest){
    return read_req_file_kern(req, file, dest, sizeof(*dest));
}

int bproc_get_str(struct bproc_krequest_t *req,struct file *file,char **dest){
    int len;
    char *str;
    if (bproc_get_int(req, file, &len)) return -1;
    str = (char *)kmalloc(len+1, GFP_KERNEL);
    if (!str) {
	printk(KERN_ERR "bproc: get_str: Out of memory.  len=%d\n", len);
	return -ENOMEM;
    }
    str[len]=0;
    if (read_req_file_kern(req, file, str, len)) {
	kfree(str);
	return -EIO;
    }
    *dest = str;
    return 0;
}

int bproc_get_strs(struct bproc_krequest_t *req, struct file *file,
		   char ***dest) {
    int i, nstrs, err;
    char **strs;
    if ((err = bproc_get_int(req, file, &nstrs)) < 0) return err;
    strs = (char **) kmalloc(sizeof(char *)*(nstrs+1), GFP_KERNEL);
    if (!strs) {
	printk(KERN_ERR "bproc: get_strs: Out of memory. nstrs=%d\n", nstrs);
	return -ENOMEM;
    }
    for (i=0; i < nstrs; i++)
	if ((err = bproc_get_str(req, file, &strs[i]))<0) {
	    /* cleanup and bail... */
	    for (i--; i >= 0; i--) kfree(strs[i]);
	    kfree(strs);
	    return err;
	}
    strs[i] = 0;
    *dest = strs;
    return 0;
}

static
void kfree_strs(char **strs) {
    int i;
    for (i=0; strs[i]; i++)
	kfree(strs[i]);
    kfree(strs);
}

static
int bproc_put_int(struct bproc_krequest_t *req, struct file *file, int i) {
    return write_req_file_kern(req, file, &i, sizeof(i));
}

#if 0
/* Unused */
static
int bproc_put_long(struct bproc_krequest_t *req, struct file *file, long i) {
    return write_req_file_kern(req, file, &i, sizeof(i));
}
#endif

static
int bproc_put_str(struct bproc_krequest_t *req, struct file *file, char *str) {
    int ret, len;
    len = strlen(str);
    if ((ret = bproc_put_int(req, file, len))) return ret;
    return write_req_file_kern(req, file, str, len);
}

static
int bproc_put_str_u(struct bproc_krequest_t *req,
		    struct file *file, char *str) {
    int ret, len;
    /* Try and be reasonable here... */
    len = strnlen_user(str, PAGE_SIZE);
    if (len == 0 || len > PAGE_SIZE)
	return -EINVAL;
    len--;			/* No need to send the trailing null */
    if ((ret = bproc_put_int(req, file, len))) return ret;
    ret = write_req_file_user(req, file, str, len);
    if (ret == len)
	ret = 0;
    else
	if (ret > 0) ret = -EIO;
    return ret;
}

static
int bproc_put_strs_u(struct bproc_krequest_t *req,
		     struct file *file, char **strs) {
    int i, nstrs=0, err;
    char *str_ptr;

    if ((err = get_user(str_ptr, strs+nstrs))) return err;
    while (str_ptr) {
	nstrs++;
	if ((err = get_user(str_ptr, strs+nstrs))) return err;
    }

    if ((err = bproc_put_int(req, file,nstrs))) return err;
    for (i=0; i < nstrs; i++) {
	if ((err = get_user(str_ptr, strs+i))) return err;
	if ((err = bproc_put_str_u(req, file, str_ptr))) return err;
    }
    return 0;
}

/**------------------------------------------------------------------------
 ** vmadump helpers
 **/
struct vmadump_priv_t {
    struct bproc_krequest_t *req;
};

static
ssize_t vmadump_write_file(struct vmadump_map_ctx *vmad_ctx, struct file *f,
			   const void *buffer, size_t size) {
    struct bproc_krequest_t *req;
    req = ((struct vmadump_priv_t *) vmad_ctx->private)->req;
    return write_req_file_user(req, f, buffer, size);
}

static
ssize_t vmadump_read_file(struct vmadump_map_ctx *vmad_ctx, struct file *f,
			  void *buffer, size_t size) {
    struct bproc_krequest_t *req;
    req = ((struct vmadump_priv_t *) vmad_ctx->private)->req;
    return read_req_file_user(req, f, buffer, size);
}

/**------------------------------------------------------------------------
 ** send
 **/

/* This function does the actual IO and for sending a process image */
static
int do_send(struct bproc_krequest_t *req, struct file *link,
	    struct bproc_kmove_t *arg, struct pt_regs *regs) {
    int ret, i;
    char *buffer, *filename;
    struct vmadump_map_ctx ctx;
    struct vmadump_priv_t  ctx_priv;
    __sighandler_t saved_sa;

    /* We need to ignore SIGPIPE during the move */
    spin_lock_irq(&current->sighand->siglock);
    saved_sa = current->sighand->action[SIGPIPE-1].sa.sa_handler;
    current->sighand->action[SIGPIPE-1].sa.sa_handler = SIG_IGN;
    spin_unlock_irq(&current->sighand->siglock);

    /*** Start sending the boring process details. ***/
    /* Send our rlimits */
    if ((ret = write_req_file_kern(req, link, &current->rlim,
				   sizeof(current->rlim))))
	goto bailout;

    /* Send our time information */
    if ((ret = write_req_file_kern(req, link, &current->utime,
				   sizeof(current->utime))))
	goto bailout;
    if ((ret = write_req_file_kern(req, link, &current->stime,
				   sizeof(current->utime))))
	goto bailout;

	
    /* Send times from the signal struct... */
    {
	unsigned long utime, stime, cutime, cstime;
	spin_lock_irq(&current->sighand->siglock);
	utime  = current->signal->utime;
	stime  = current->signal->stime;
	cutime = current->signal->cutime;
	cstime = current->signal->cstime;
	spin_unlock_irq(&current->sighand->siglock);
	if ((ret = write_req_file_kern(req, link, &utime, sizeof(utime))))
	    goto bailout;
	if ((ret = write_req_file_kern(req, link, &stime, sizeof(stime))))
	    goto bailout;
	if ((ret = write_req_file_kern(req, link, &cutime, sizeof(cutime))))
	    goto bailout;
	if ((ret = write_req_file_kern(req, link, &cstime, sizeof(cstime))))
	    goto bailout;
    }

    /* Send start time as time of day... */
    {
	struct timespec start_tmp;
	set_normalized_timespec
	    (&start_tmp,
	     current->start_time.tv_sec - wall_to_monotonic.tv_sec,
	     current->start_time.tv_nsec - wall_to_monotonic.tv_nsec);
	if ((ret=write_req_file_kern(req,link,&start_tmp,sizeof(start_tmp))))
	    goto bailout;
    }

    /* Send our current working directory */
    if (arg->type != BPROC_SYS_EXEC2) {
	buffer = (char *) __get_free_page(GFP_KERNEL);
	if (buffer) {
	    filename = d_path(current->fs->pwd, current->fs->pwdmnt,
			      buffer, PAGE_SIZE);
	    ret = bproc_put_str(req, link, filename);
	    free_page((long)buffer);
	} else {
	    /* No memory - fall back to "/" */
	    ret = bproc_put_str(req, link, "/");
	}
	if (ret) goto bailout;
    }

    /* Send some stuff about the IO we want to do. */
    if ((ret = bproc_put_int(req, link, arg->user.iolen +
 			     (arg->script_base ? 1 : 0) )))
	goto bailout;
    for (i=0; i < arg->user.iolen; i++) {
	/* The user.io pointer changed to a kernel pointer earlier */
	if ((ret = write_req_file_kern(req, link, &arg->user.io[i],
				       sizeof(struct bproc_io_t))))
	    goto bailout;
    }
    if (arg->script_base) {
	struct bproc_io_t io;
	io.fd    = 3;
	io.type  = BPROC_IO_MEMFILE;
	io.flags = 0;
	io.d.mem.base = arg->script_base;
	io.d.mem.size = arg->script_size;
	if ((ret=write_req_file_kern(req,link,&io,sizeof(struct bproc_io_t))))
	    goto bailout;
    }

    switch (arg->type) {
    case BPROC_SYS_REXEC:
    case BPROC_SYS_EXEC:
	if ((ret = bproc_put_str_u (req, link, arg->user.arg0)))
	    goto bailout;
	if ((ret = bproc_put_strs_u(req, link, arg->user.argv)))
	    goto bailout;
	if ((ret = bproc_put_strs_u(req, link, arg->user.envp)))
	    goto bailout;
	break;
    case BPROC_SYS_MOVE:
    case BPROC_SYS_RFORK:
    case BPROC_SYS_EXECMOVE:
    case BPROC_SYS_EXEC2:
    case BPROC_SYS_VRFORK:
    case BPROC_SYS_VEXECMOVE:
	memset(&ctx, 0, sizeof(ctx));
	ctx.read_file  = vmadump_read_file;
	ctx.write_file = vmadump_write_file;
	ctx.private    = &ctx_priv;
	ctx_priv.req   = req;
	ret = vmadump_freeze_proc(&ctx, link, regs, arg->user.flags);
	if (ret < 0) goto bailout;
	ret = 0;
	break;
    default:
	ret = -EINVAL;
	printk(KERN_ERR "bproc: do_send: unknown dump method: %d\n",arg->type);
	break;
    }
#ifndef LINUX_TCP_IS_BROKEN
    /* The broken-ass Linux TCP stack seems to randomly spit out RSTs
     * if we actually try to use shutdown... */
    k_shutdown_f(link, 1); /* EOF for vmadump... */
#endif

 bailout:
    /* Restore sigaction */
    spin_lock_irq(&current->sighand->siglock);
    current->sighand->action[SIGPIPE-1].sa.sa_handler = saved_sa;
    spin_unlock_irq(&current->sighand->siglock);
    return ret;
}

/*-------------------------------------------------------------------------
 * process2move
 *
 * This function takes a real process and makes it into a move
 * request.  As far as the rest of the system is concerned a process
 * becomes a move request and then becomes a real process again
 * somewhere else (or back here if the move fails).
 *
 * The actual task does one of two things depending on where it is:
 *  Master - the task becomes a ghost.
 *  Slave  - the task leaves the master's PID space.  (unmasq)
 *
 * In both cases, the task's state transition and the sending of the
 * move request is done atomically.  This way any system call that
 * finds it missing (e.g. kill()) will get its message in behind the
 * real process.
 */
extern spinlock_t(bproc_ptrace_attach_lock);
static
int process2move(struct bproc_krequest_t *req) {
    int ret;
    struct bproc_ghost_proc_t *gp = 0;
    int count;
    struct list_head *l;
    struct bproc_move_msg_t *msg;

    msg = bproc_msg(req);

    if (!BPROC_ISMASQ(current)) {
	gp = ghost_alloc(-1);
	if (!gp) return -ENOMEM;
    }
    
    /* NOTE: This function is called while holding a write_lock_irq on
     * tasklist_lock */

    /* The tasklist_lock is held while generating the message contents
     * and sending here for the following reasons:
     *
     *   - We want to count our children and become a ghost (or
     *   disappear) atomically to avoid races with CLONE_*, ptrace,
     *   etc.
     */

    spin_lock(&bproc_ptrace_attach_lock);
    write_lock_irq(&tasklist_lock);

    /* Fill in the pertinent current details of the move request */
    msg->pid      = BPROC_MASQ_PID(current);
    msg->tgid     = BPROC_MASQ_TGID(current);
    msg->oppid    = BPROC_MASQ_OPPID(current);
    msg->ppid     = BPROC_MASQ_PPID(current);
    msg->pgrp     = BPROC_MASQ_PGRP(current);
    msg->session  = BPROC_MASQ_SESSION(current);

    /* Count our children to keep 'nlchild' counts sane. */
    count = BPROC_ISMASQ(current) ? current->bproc.nlchild : 0;
    for (l = current->children.next; l != &current->children; l = l->next)
	count++;
    for (l = current->ptrace_children.next;
	 l != &current->ptrace_children; l = l->next)
	count++;
    msg->children = count;

    /* Misc process details */
    msg->exit_signal = current->exit_signal;

    /* Save our current ptrace state (the process tree part of the
     * info is above)
     *
     * Problem: The ptrace flags are protected by a different lock
     * which we're apparently not allowed to grab long with the
     * tasklist_lock in any order.  ptrace seems to be inherently racy
     * with attach + dealing with these flags.
     */
    msg->ptrace = current->ptrace;
    msg->thread = current->thread_info->flags; /* types? */

    /* Store priority state */

    /* Store pending signal information.  Handler state and signal
     * masks are handled by vmadump.  This has the short coming that
     * it basically ignores the signal queues.  queuing and additional
     * signal information won't work as advertised but that's ok. */
    spin_lock_irq(&current->sighand->siglock);
    memcpy(msg->sigblocked, &current->blocked, sizeof(sigset_t));
    memcpy(msg->sigpending, &current->pending.signal,
	   sizeof(sigset_t));
    memcpy(msg->sigpendingshared,
	   &current->signal->shared_pending.signal, sizeof(sigset_t));
    spin_unlock_irq(&current->sighand->siglock);

    /* Shortcoming: this will not deal with signal queues particularly
     * well. */
    
    /* The move request is.  Now send it */
    ret = bproc_send_req(bproc_msgdest(), req);
    if (ret == 0) {
	/* Success!  The process is now a message in the pipe.
	 * Therefore we get rid of it locallly at this point. */
	if (gp) {
	    ret = ghost_add(gp);
	    /* FIX ME: This is a sketchy error case.  This happens
	     * when the master daemon dies somewhere along the way and
	     * we can't send the messaage as a result. */
	    if (ret != 0)
		printk("bproc: ghost: ghost add failed.\n");
	} else {
	    masq_remove_proc(current, 1);
	}
    }
    write_unlock_irq(&tasklist_lock);
    spin_unlock(&bproc_ptrace_attach_lock);

    if (ret != 0) {
	/* Failure - free anything that we allocated here */
	if (gp) kfree(gp);
    }
    return ret;
}


/*-------------------------------------------------------------------------
 * move2process - 
 *
 * This function takes a move request and makes current look like the
 * process it's describing.  This is the opposite of process2move.
 *
 *
 */
int move2process(struct bproc_krequest_t *req,
		 struct bproc_masq_master_t *master) {
    int i;
    struct bproc_ghost_proc_t *g = 0;
    struct bproc_move_msg_t *msg;

    msg = bproc_msg(req);

    if (!master)
	g = current->bproc.ghost;

    /* This is the restoration we can safely do on our own outside of
     * the tasklist_lock. */

    current->exit_signal = msg->exit_signal;

    if (creds_restore(creds_ptr(msg, msg->proc_creds),1))
	return -ENOMEM;

    /* Do the magical bits under the tasklist_lock */
    write_lock_irq(&tasklist_lock);

    /* Restore signal state */
    spin_lock_irq(&current->sighand->siglock);
    memcpy(&current->blocked, msg->sigblocked, sizeof(sigset_t));
    for (i=0; i < _NSIG_WORDS; i++) {
	current->pending.signal.sig[i] |= msg->sigpending[i];
	current->signal->shared_pending.signal.sig[i] |=
	    msg->sigpendingshared[i];
    }
    /* Merge pending signal states together */
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);

    /* FIX ME: Restore ptrace state - this should really be done under
     * a different lock */
    current->ptrace = msg->ptrace;

    /* Copy this one flag from the thread information */
    if (msg->thread & (1 >> TIF_SYSCALL_TRACE))
	set_tsk_thread_flag(current, TIF_SYSCALL_TRACE);
    else
	clear_tsk_thread_flag(current, TIF_SYSCALL_TRACE);

    if (master) {
	current->bproc.pid             = msg->pid;
	current->bproc.tgid            = msg->tgid;
	current->bproc.ppid            = msg->ppid;
	current->bproc.oppid           = msg->oppid;
	current->signal->bproc.pgrp    = msg->pgrp;
	current->signal->bproc.session = msg->session;

	current->bproc.nlchild         = msg->children;
	current->bproc.last_update     = 0;

	masq_add_proc(master, current, 1);
    } else {
	current->bproc.ghost = 0;
    }
    write_unlock_irq(&tasklist_lock);

    if (g) ghost_drop(g);	/* don't need the ghost anymore */
    return 0;
}


/*-------------------------------------------------------------------------
 * This function sets up a sender connection by sending out a request
 * to the remote side and waiting for it to setup a connection
 * back.
 */
static
struct file *connection_setup_accept(struct file *listen,
				     struct bproc_krequest_t *req) {
    int ret = 0;
    struct file *link   = 0;

    /* Wait for a response.  The response will either be a connect to
     * the port we're listening at or an error returned via the bproc
     * message mechanisms. */
    /* XXX The timeout seems problematic here. */
    ret = bproc_send_proc_select(listen, req, POLLIN_SET,
				 MAX_SCHEDULE_TIMEOUT);
    if (bproc_deadreq(req)) {
	/* Our request has been killed... This probably means that the
	 * ghost master has died. */
	ret = -EIO;
	goto bailout;
    }
    if (bproc_hasresponse(req)) {
	/* Some remote error occurred... This is their response... */
	struct bproc_message_hdr_t *hdr = bproc_msg(req->response);
	ret = hdr->result;
	if (ret == 0) {
	    printk(KERN_ERR "bproc: received invalid move response.\n");
	    ret = -EIO;
	}
	goto bailout;
    }
    if (ret < 0) {
	/* EINTR during migrate is pretty normal.  (Ctrl-C, etc.) */
	if (ret != -EINTR)
	    printk(KERN_ERR "bproc: move: send proc select error %d;"
		   " id=%d(m:%d)\n", -ret, current->pid,
		   BPROC_MASQ_PID(current));
	goto bailout;
    }
    
    /* Socket is ready... do accept */
    ret = 0;
    link = bproc_accept(listen);
    if (IS_ERR(link)) {
	ret = PTR_ERR(link);
	goto bailout;
    }
    
#ifdef LINUX_TCP_IS_BROKEN
    {
	void *tmp=0;
	
	if ((ret = read_req_file_kern (req, link, &tmp, sizeof(tmp))))
	    goto bailout;
	
	if ((ret = write_req_file_kern(req, link, &tmp, sizeof(tmp))))
	    goto bailout;
    }
#endif

 bailout:
    if (ret != 0) {
	if (link && !IS_ERR(link)) fput(link);
	link = ERR_PTR(ret);
    }
    return link;
}

static
void do_fwd_sig(void) {
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
        printk(KERN_ERR "bproc: do_fwd_sig: [%d] signal forwarding: Out "
	       "of memory\n", (int)BPROC_MASQ_PID(current));
        return;
    }
    msg = bproc_msg(req);
    bpr_to_real(msg,    BPROC_MASQ_PID(current));
    /* Not always a ghost but oh well... */
    bpr_from_ghost(msg, BPROC_MASQ_PID(current));
    bproc_pack_siginfo(&msg->info, &info);
    bproc_send_req(bproc_msgdest(), req);
    bproc_put_req(req);
}

int send_process(int node, struct bproc_kmove_t *arg, struct pt_regs *regs) {
    int ret;
    struct file * listen = 0;
    struct file * link   = 0;
    struct file *f_out;
    struct bproc_krequest_t *req = 0 /*, *resp = 0*/;
    struct bproc_move_msg_t *msg, *resp_msg = 0;
    struct bproc_request_queue_t *msgdest;
    struct bproc_masq_master_t *master = 0;

    /* Keep track of who the current masq master is, this might be
     * required later to restore the process in the case of move
     * failure. */
    if (BPROC_ISMASQ(current)) {
	master = current->bproc.master;
	atomic_inc(&master->count);
    }
    msgdest = master ? &master->req : &bproc_ghost_reqs;

    /* Start working on a move request. */
    req = bproc_new_req(BPROC_MOVE,
			sizeof(*msg) +
			creds_struct_size(arg->creds) +
			creds_size(current),
			GFP_KERNEL);
    if (!req) {
	ret = -ENOMEM;
	goto bailout;
    }
    msg = bproc_msg(req);
    bpr_from_real(msg, BPROC_MASQ_PID(current));
    bpr_to_node(msg, node);
    req->flags = BPROC_REQ_WANT_RESP;

    msg->type  = arg->type;
    msg->index = arg->index;

    /* Setup a listening socket */
    if (arg->data_addr == 0) {
	/* If we're going to be sending the data, setup a socket to do it on */
	/* Get a socket to accept a connection on */
	listen = bproc_setup_listen();
	if (IS_ERR(listen)) {
	    ret = PTR_ERR(listen);
	    /* XXX Do we want to map errors related to socket resource
	     * exhaustion to EAGAIN here? */
	    printk(KERN_NOTICE "bproc: move: Couldn't open FD to listen.\n");
	    goto bailout;
	}
	msg->addr = 0; /* gets filled in by the daemon */
	msg->port = bproc_get_port(listen);
    } else {
	msg->addr = arg->data_addr;
	msg->port = arg->data_port;
    }

    /* Store process credentials.  There are two sets of credentials
     * here.  One from the time the system call was made and another
     * for the process itself.  These two can be different if execmove
     * was done on a suid binary.  We expect the caller to have stored
     * the call_creds before calling this
     */
    msg->call_creds = sizeof(*msg);
    memcpy(((void *)msg) + msg->call_creds, arg->creds,
	   creds_struct_size(arg->creds));

    msg->proc_creds = msg->call_creds + creds_struct_size(arg->creds);
    creds_store(((void *)msg) + msg->proc_creds);

    /* Finish up and send the move request... */
    ret = process2move(req);
    if (ret < 0)
	goto bailout;

    /* ... and wait for the connection to come back */
    if (arg->data_addr == 0) {
	link = connection_setup_accept(listen, req);
	if (!IS_ERR(link)) {
	    /* Connection good, do the send... */
	    ret = do_send(req, link, arg, regs);
	    if (ret != 0) {
		/* whups, failure.  close the connection immediately
		 * so the remote end will see EOF if it's not dead
		 * already. */
		fput(link);
		link = 0;
		/* we still wait for the move response to come back in
		 * the case of failure. */
	    }
	}
	/* If there's an error during link setup, skip ahead to
	 * waiting for our response to come back.  This won't report
	 * errors on the sending end very nicely... */
    }

    /* We're done on the sending end.  Wait for the move response to
     * come back. */
    ret = bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, 1);
    while (ret == -EINTR) {
	/* We need to forward signals during the move. */
	while (signal_pending(current))
	    do_fwd_sig();
	ret = bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, 1);
    }
    if (ret) {			/* Some kind of error happened */
	ret = -EIO;
	goto bailout_restore;
    }

    resp_msg = bproc_msg(req->response);
    ret = resp_msg->hdr.result;
    if (ret)
	goto bailout_restore;

    /* --- SUCCESS --- */
    
    /* Make note of just a few things from the move response */
    memcpy(current->comm, resp_msg->comm, sizeof(current->comm));
    if (creds_restore(creds_ptr(resp_msg, resp_msg->proc_creds),1)) {
	/* We can't just bail here since the remote process thinks
	 * it's good to go... */
	printk(KERN_ERR "bproc: failed to restore credentials after"
	       " move result.\n");
    }

    /* Save the addresses in there response and return them to the
     * caller.  These addresses are set by the remote node in case we
     * want to resend the data */
    arg->msg_id    = resp_msg->hdr.id;
    arg->data_addr = resp_msg->addr;
    arg->data_port = resp_msg->port;

    if (link) {
	/* Weak IO forwarding: grab the proc's original stdout and hand it
	 * and our existing link off to the IO daemon. */
	f_out = fget(1);
	if (f_out) {
	    get_file(link);/* up the ref count - we're giving it away */
	    bproc_new_io_connection(link, f_out);
	}
    }

 bailout:
    if (req) { bproc_put_req(req); }
    if (listen && !IS_ERR(listen)) fput(listen);
    if (link   && !IS_ERR(link))   fput(link);
    if (master) {
	if (atomic_dec_and_test(&master->count))
	    kfree(master);
    }
    return ret;			/* Ok!  Move complete, signal success! */

 bailout_restore:
    /* --- FAILURE --- */
    /* restore the process from the move response */
    if (resp_msg && resp_msg->hdr.size == sizeof(*resp_msg)) {
	/* We got a response so restore from that. */
	if (move2process(req->response, master)) {
	    printk(KERN_CRIT "bproc: %d: failed to restore process.\n",
		   current->pid);
	}
    } else {
	/* Our response is small - that means it's just an error code
	 * w/o process state.  Restore the process from the original
	 * request... */
	if (move2process(req, master)) {
	    printk(KERN_CRIT "bproc: %d: failed to restore process.\n",
		   current->pid);
	}
    }
    /* On move failure, we have to notify the master when we're done
     * restoring ourselves. */
    if (resp_msg && master)
	complete(&master->done);
    goto bailout;

}

/*--------------------------------------------------------------------
 *  Process RECV code
 */

int setup_io_fd(struct bproc_io_t *io) {
    int err, fd;
    struct file *f;
    struct inode *ino;

    switch(io->type) {
    case BPROC_IO_FILE:
	io->d.file.name[255] = 0; /* prevent bogosity */
	f = filp_open(io->d.file.name, io->d.file.flags, io->d.file.mode);
	if (IS_ERR(f)) return PTR_ERR(f);

	/* XXX lseek here */
	break;

    case BPROC_IO_SOCKET: /* Setup a socket connected to something */
	f = k_socket_f(io->d.addr.sa_family, SOCK_STREAM, 0);
	if (IS_ERR(f))
	    return PTR_ERR(f);
	/* XXX might need/want bind() support */
	if ((err = k_connect_f(f, (struct sockaddr *) &io->d.addr, sizeof(io->d.addr)))) {
	    fput(f);
	    return err;
	}
	break;

    case BPROC_IO_MEMFILE:
	f = bpfs_get_file(BPFS_MEMFILE_INO, "memfile");
	if (IS_ERR(f)) return PTR_ERR(f);

	ino = f->f_dentry->d_inode;
	ino->i_mode       = S_IFREG | S_IRUSR | S_IWUSR;
	ino->i_size       = io->d.mem.size;
	ino->u.generic_ip = io->d.mem.base;
	break;

    default:
	printk(KERN_ERR "Unknown IO type: 0x%x\n", io->type);
	return -EINVAL;
    }

    if (io->flags & BPROC_IO_SEND_INFO) {
	int tmp;
	tmp = BPROC_MASQ_PID(current);
	k_write_f(f, &tmp, sizeof(tmp));
	tmp = io->fd;
	k_write_f(f, &tmp, sizeof(tmp));
    }

    /* Install on the requested fd */
    fd = get_unused_fd();
    if (fd < 0) {
	fput(f);
	return -ENFILE;
    }
    fd_install(fd, f);
    if (fd != io->fd) {
	sys_dup2(fd, io->fd);
	sys_close(fd);
    }
    return 0;
}

static
struct file *connection_setup_2(struct bproc_krequest_t *req) {
    int err = 0;
    struct file *link;
    int connect_try = 0;
    struct bproc_move_msg_t *msg;

    msg = bproc_msg(req);

 connect_again:
    connect_try++;
    link = bproc_connect(msg->addr, msg->port);
    if (IS_ERR(link)) {
	err = PTR_ERR(link);
	printk("err from bproc_connect %d\n", err);
	if (err == -ETIMEDOUT) {
	    printk(KERN_ERR "bproc: recv: connection timed out (try %d/%d)\n",
		   connect_try, MAX_CONNECT_TRY);
	    if (connect_try < MAX_CONNECT_TRY) goto connect_again;
	}
	goto out;
    }
#ifdef LINUX_TCP_IS_BROKEN
    {
    void *tmp;
    err = k_write_f(link, &msg->hdr.id, sizeof(msg->hdr.id));
    if (err != sizeof(msg->hdr.id)) {
	if (err == -ECONNRESET || err == -EAGAIN) {
#if 0
	    printk(KERN_ERR "bproc: recv: broken tcp - connection reset"
		   " (try %d/%d)\n", connect_try, MAX_CONNECT_TRY);
#endif
	    fput(link);
	    if (connect_try < MAX_CONNECT_TRY) goto connect_again;
	}
	goto out;
    }
    err = k_read_all_f(link, &tmp, sizeof(tmp));
    if (err != sizeof(tmp)) {
	if (err == -ECONNRESET || err == -EAGAIN) {
#if 0
	    printk(KERN_ERR "bproc: recv: broken tcp - connection reset"
		   " (try %d/%d)\n", connect_try, MAX_CONNECT_TRY);
#endif
	    fput(link);
	    if (connect_try < MAX_CONNECT_TRY) goto connect_again;
	}
	goto out;
    }
    err = 0;
    }
#endif
 out:
    if (err) {
	if (link && !IS_ERR(link)) fput(link);
	link = ERR_PTR(err);
    }
    return link;
}


/* do_recv - do the actual IO and setup for receiving a process image */
static
int do_recv(struct bproc_krequest_t *req, struct file *link,
	    struct pt_regs *regs, struct bproc_kmove_t *move) {
    int err, i;
    char *cwd = 0, *arg0 = 0 , **argv = 0, **envp = 0;
    struct vmadump_map_ctx     ctx;
    struct vmadump_priv_t      ctx_priv;
    int iolen;
    struct bproc_io_t *io = 0;
    struct bproc_krequest_t      *move_compl = 0;
    struct bproc_move_msg_t *move_msg;

    move_msg = bproc_msg(req);

    /* this is an execve so make it look like one... */
    if (move_msg->type == BPROC_SYS_EXEC2) {
	struct linux_binprm bprm;
	/* These are dummy values for the benefit of flush_old_exec.
	 * All the proper credentials, etc will be setup by the move
	 * code.  WARNING: This is a pretty big hack right now... */
	bprm.filename = current->comm;
	bprm.e_uid    = current->euid;
	bprm.e_gid    = current->egid;
	bprm.file     = link;	/* Give it an inode... Whatever... */
	err = flush_old_exec(&bprm);
	if (err) goto out;
    }

    /* Get our rlimits */
    if ((err = read_req_file_kern(move_compl, link, &current->rlim,
				  sizeof(current->rlim))))
	goto out;

    /* Get time information for this process. */
    if ((err = read_req_file_kern(move_compl, link, &current->utime,
				  sizeof(current->utime))))
	goto out;
    if ((err = read_req_file_kern(move_compl, link, &current->stime,
				  sizeof(current->utime))))
	goto out;

    /* Restore times from the signal struct */
    {
	unsigned long utime, stime, cutime, cstime;

	if ((err=read_req_file_kern(move_compl, link, &utime, sizeof(utime))))
	    goto out;
	if ((err=read_req_file_kern(move_compl, link, &stime, sizeof(stime))))
	    goto out;
	if ((err=read_req_file_kern(move_compl, link, &cutime,sizeof(cutime))))
	    goto out;
	if ((err=read_req_file_kern(move_compl, link, &cstime,sizeof(cstime))))
	    goto out;
	spin_lock_irq(&current->sighand->siglock);
	current->signal->utime  = utime;
	current->signal->stime  = stime;
	current->signal->cutime = cutime;
	current->signal->cstime = cstime;
	spin_unlock_irq(&current->sighand->siglock);
    }
    
    /* Restore process start time */
    {
	struct timespec start_tmp;
	if ((err = read_req_file_kern(move_compl, link, &start_tmp,
				      sizeof(start_tmp))))
	    goto out;

	/* Don't touch start times on ghosts - they're accurate already. */
	if (BPROC_ISMASQ(current)) {
	    set_normalized_timespec
		(&current->start_time,
		 start_tmp.tv_sec  + wall_to_monotonic.tv_sec,
		 start_tmp.tv_nsec + wall_to_monotonic.tv_nsec);
	}
    }

    /* Now that our user ID is set we can try to set our working
     * directory to be the same as the front end. */
    if (move_msg->type != BPROC_SYS_EXEC2) {
	err = bproc_get_str(move_compl, link, &cwd); if (err) goto out;
    }

    /* Get IO forwarding information */
    if ((err = bproc_get_int(move_compl, link, &iolen)))
	goto out;
    if (iolen > 0) {
	if (!(io = kmalloc(sizeof(*io)*iolen, GFP_KERNEL))) {
	    err = -ENOMEM;
	    goto out;
	}
	if ((err = read_req_file_kern(move_compl, link, io,sizeof(*io)*iolen)))
	    goto out;
    }

    switch(move_msg->type) {
    case BPROC_SYS_REXEC:
    case BPROC_SYS_EXEC:
	err = bproc_get_str (move_compl, link, &arg0); if (err) goto out;
	err = bproc_get_strs(move_compl, link, &argv); if (err) goto out;
	err = bproc_get_strs(move_compl, link, &envp); if (err) goto out;
	/* Setup for shell script hack */
	clear_bit(BPROC_FLAG_SCRIPT, &current->bproc.flag);
	if (move_msg->type == BPROC_SYS_EXEC)
	    set_bit(BPROC_FLAG_EXECMOVE, &current->bproc.flag);
	err = k_execve(arg0, argv, envp, regs);
	clear_bit(BPROC_FLAG_EXECMOVE, &current->bproc.flag);
	if (err) goto out;
	if (current->ptrace & PT_PTRACED) {
	    /* If we're still traced, we just took a sigtrap.  Since
	     * we may have more stuff to do which will be disrupted by
	     * a pending signal, suppress it and send a new signal
	     * later on. */
	    sigset_t sigset;
	    struct siginfo info;
	    sigfillset(&sigset);
	    sigdelset(&sigset, SIGTRAP);
	    spin_lock_irq(&current->sighand->siglock);
	    dequeue_signal(current, &sigset, &info);
	    spin_unlock_irq(&current->sighand->siglock);
	}
	if (test_bit(BPROC_FLAG_SCRIPT, &current->bproc.flag))
	    execmove_load_script(arg0, &move->script_base, &move->script_size);
	break;
    case BPROC_SYS_MOVE:
    case BPROC_SYS_RFORK:
    case BPROC_SYS_VRFORK:
    case BPROC_SYS_EXECMOVE:
    case BPROC_SYS_VEXECMOVE:
    case BPROC_SYS_EXEC2:
	memset(&ctx, 0, sizeof(ctx));
	ctx.read_file  = vmadump_read_file;
	ctx.write_file = vmadump_write_file;
	ctx.private    = &ctx_priv;
	ctx_priv.req   = move_compl;
	err = vmadump_thaw_proc(&ctx, link, regs);
	if (err) goto out;

#if defined(CONFIG_BINFMT_ELF)
	/* XXX HACK ALERT XXX HACK ALERT XXX */
	/* Here's the deal.  We would really really like to be able to
	 * dump core on remote nodes.  The trouble is we have no idea
	 * what binary format handler goes with this binary anymore.
	 * (format handlers don't have any tags on them that would
	 * allow us to match them up with a handler on a different
	 * machine.)  Therefore, we'll slap the ELF handler on it and
	 * hope this turns out to be the useful binary format handler
	 * for this situation.  (This will be true in the overwhelming
	 * majority of cases.)  */
#if 0
	{
	    extern struct linux_binfmt elf_format;
	    if (current->binfmt && current->binfmt->module)
		__MOD_DEC_USE_COUNT(current->binfmt->module);
	    current->binfmt = &elf_format;
	    if (current->binfmt && current->binfmt->module)
		__MOD_INC_USE_COUNT(current->binfmt->module);
	}
#endif
	/* XXX HACK ALERT XXX HACK ALERT XXX */
#endif
	break;
    default:
	err = -EINVAL;
	printk(KERN_ERR "bproc: do_recv: unknown undump method: %d\n",
	       move_msg->type);
	goto out;
    }

    if (cwd) {
	if (k_chdir(cwd)) k_chdir("/");
    }

    if (iolen >= 0) {
	if (creds_restore(creds_ptr(move_msg, move_msg->call_creds),0)) {
	    err = -ENOMEM;
	    goto out;
	}
	for (i=0; i < iolen; i++) {
	    struct bproc_io_t *iop = &io[i];
	    /* FIXUP.  One cute hack we have here is to use the move
	     * address in a sockaddr if the connect address is
	     * zero. */
	    if (iop->type == BPROC_IO_SOCKET &&
		iop->d.addr.sa_family == AF_INET &&
		((struct sockaddr_in *)&iop->d.addr)->sin_addr.s_addr == 0) {
		/* HACK here: if we don't have a request use 0 as the
		 * address.  This seems to connect us to localhost. */
		((struct sockaddr_in *)&iop->d.addr)->sin_addr.s_addr =
		    move_msg->addr;
	    }

	    if (!(io[i].flags & BPROC_IO_DELAY)) {
		if ((err = setup_io_fd(iop)))
		    goto out;
	    }
	}
	/* Save this information for the caller */
	move->user.iolen = iolen;
	move->user.io    = io;

	if (creds_restore(creds_ptr(move_msg, move_msg->proc_creds),1)) {
	    err = -ENOMEM;
	    goto out;
	}
    } else {
	/* iolen == -1 */
	/* Fall back to crappy built-in IO forwarding if no other
	 * forwarding specificed... */
	int fd, nullfd;

	/* Put our link on a file descriptor */
	fd = get_unused_fd();
	if (fd < 0) {
	    printk(KERN_ERR "bproc: do_receive: no unused fd's available.\n");
	} else {
	    get_file(link);
	    fd_install(fd, link);

	    if (fd != 1) sys_dup2(fd, 1);
	    if (fd != 2) sys_dup2(fd, 2);
	    if (fd != 1 && fd != 2) sys_close(fd);
	    nullfd = k_open("/dev/null", O_RDONLY, 0);
	    if (nullfd >= 0) {
		sys_dup2(nullfd, 0);
		sys_close(nullfd);
	    }
	}
    }

    if (current->ptrace & PT_PTRACED &&
	(move_msg->type == BPROC_SYS_REXEC     ||
	 move_msg->type == BPROC_SYS_EXECMOVE  ||
	 move_msg->type == BPROC_SYS_VEXECMOVE ||
	 move_msg->type == BPROC_SYS_EXEC2)) {
	/* SYS_REXEC    - we trapped above and will regerate it here
	 * SYS_EXECMOVE - we trapped on the remote side and regenerate
	 *                it here
	 * SYS_EXEC     - we don't want to trap here at all.  That
	 *                signal be generated after the second half. */
	send_sig(SIGTRAP, current, 0);
    }

 out:
    if (cwd)  kfree(cwd);
    if (arg0) kfree(arg0);
    if (argv) kfree_strs(argv);
    if (envp) kfree_strs(envp);
    return err;
}

static
struct file *setup_resend(struct bproc_krequest_t *move_req) {
    struct file *f;
    struct bproc_move_msg_t *msg;

    msg = bproc_msg(move_req);

    f = bproc_setup_listen();
    if (IS_ERR(f)) {
	printk(KERN_NOTICE "resend listen error %ld\n", PTR_ERR(f));
	msg->addr = 0;
	msg->port = 0;
	return f;
    }

    /* Clear out non-block */
    lock_kernel();
    f->f_flags &= ~O_NONBLOCK;
    unlock_kernel();

    msg->addr = 0;
    msg->port = bproc_get_port(f);
    return f;
}

static
int do_resends(struct file *listen, struct bproc_krequest_t *req,
		struct pt_regs *regs, struct bproc_kmove_t *mv) {
    int r;
    struct file *link;

    while (!signal_pending(current) && bproc_pending(req)) {
	r = bproc_send_proc_select(listen,req,POLLIN_SET,MAX_SCHEDULE_TIMEOUT);
	if (r < 0) break;
	if (r == 0) continue;

	link = bproc_accept(listen);
	if (IS_ERR(link)) {
	    /*
	    printk(KERN_NOTICE "bproc: %d resend accept error %ld\n",
		   BPROC_MASQ_PID(current), PTR_ERR(link));
	    */
	    break;
	}
#ifdef LINUX_TCP_IS_BROKEN
	{void *tmp=0;
	if ((r = read_req_file_kern (0, link, &tmp, sizeof(tmp)))) {
	    fput(link);
	    break;
	}
	if ((r = write_req_file_kern(0, link, &tmp, sizeof(tmp)))) {
	    fput(link);
	    break;
	}
	}
#endif
	r = do_send(req, link, mv, regs);
	fput(link);
    }
    fput(listen);
    bproc_response_wait(req, MAX_SCHEDULE_TIMEOUT, 0);
    bproc_put_req(req);
    return 0;
}

int store_index_env(int index) {
    char *p, *end, *m, c;
    char rankstr[] = "BPROC_RANK=XXXXXXX";

    if (!current->mm) return -ENOENT;

    down_read(&current->mm->mmap_sem);
    p   = (char *) current->mm->env_start;
    end = (char *) current->mm->env_end;
    up_read(&current->mm->mmap_sem);

    m = rankstr;
    while (p < end) {
	if (get_user(c, p++))
	    return -EFAULT;
	if (m)			/* string matching */
	    m = (*m == c) ? m + 1 : 0;

	if (c == 0) {
	    if (m) {
		/* Match finished (includes the null).  Now back up
		 * and strcpy it into user space */
		m -= 8; p -= 8;
		sprintf(m, "%07d", index);
		while (*m) {
		    if (put_user(*m, p))
			return -EFAULT;
		    m++; p++;
		}
		return 0;
	    }
	    /* reset to try and match the next thing in the environment */
	    m = rankstr;
	}
    }
    /* No appropriate environment variable found */
    return -ENOENT;
}

int recv_process(struct bproc_krequest_t *move_req, struct pt_regs *regs) {
    int i, result;
    struct bproc_request_queue_t *msgdest;
    struct file *resend_socket, *link;
    struct bproc_kmove_t mv;
    struct bproc_move_msg_t *move_msg;

    /* We presume that the caller has already done the move2process()
     * step.  Extra information is needed there. */

    move_msg = bproc_msg(move_req);

    memset(&mv, 0, sizeof(mv));
    msgdest = bproc_msgdest();

    link = connection_setup_2(move_req);
    if (!IS_ERR(link)) {
	result = do_recv(move_req, link, regs, &mv);
	fput(link);
    } else
	result = PTR_ERR(link);
    if (result != 0)
	goto out;

    if (move_msg->type == BPROC_SYS_VRFORK ||
	move_msg->type == BPROC_SYS_VEXECMOVE) {
	/* This is the complicated case where we are going to wait
	 * around in order to be a re-sender for other processes. */
	struct bproc_krequest_t *stop_req;
	struct bproc_null_msg_t *stop_req_msg;
	struct bproc_krequest_t *move_resp;
	struct bproc_move_msg_t *move_resp_msg;

	/* We're going to BProc's automatic error cleanup here to deal
	 * with the case that our parent goes away without warning.
	 * We will send a message to the parent (real) process.  If
	 * that node goes away, the master daemon will kick us and
	 * tell us to go on.
	 *
	 * But.... This means we're sending a message to a real
	 * process with actual processing on the part of the daemon.
	 * Our parent will have to know the message ID in order to
	 * respond.  The ugly hack is that we hide away the ID in the
	 * move response so that the master can fish it out of there.
	 */
	stop_req = bproc_new_req(BPROC_MOVE_COMPLETE,
				 sizeof(*stop_req_msg), GFP_KERNEL);
	if (!stop_req) {
	    /* Punt... */
	    printk(KERN_ERR "bproc: Out of memory.\n");
	    result = -ENOMEM;
	    goto out;
	}
	stop_req_msg = bproc_msg(stop_req);

	bpr_from_real(stop_req_msg, BPROC_MASQ_PID(current));
	bpr_to_real(stop_req_msg, BPROC_MASQ_PID(current));
	stop_req->flags = BPROC_REQ_WANT_RESP;
	/* Ugly hack - pick a message ID we can guess remotely */
	/* Recycle the message ID from the original move request so
	 * that the remote side can guess the ID we're waiting for. */
	stop_req_msg->hdr.id = move_msg->hdr.id;
	bproc_pending_req(msgdest, stop_req);

	/* do_send() only uses the following pieces of the move argument:
	 *
	 * type
	 * user.io
	 * user.iolen
	 * user.flags
	 * script_base
	 *
	 * The type is copied from the receive request.
	 *
	 * The io stuff was filled in for use in do_recv.  That
	 * will include any memory loaded script since any script
	 * got translated to IO_MEMFILE on the first send.
	 *
	 * The move flags argument is basically irrelevant.  Dump
	 * none on the current memory space should reflect the
	 * right kind of move since anything we should dump won't
	 * be mapped from a file anymore. */
	mv.type        = move_msg->type;
	mv.user.flags  = 0;
	mv.script_base = 0;

	/* Build up the rest of the move response - note that this
	 * clobbers the original move request.  setup_resend() fills
	 * in the address and port parts.  Sore comm and creds parts
	 * here. */
	move_resp = bproc_new_resp(move_req,
				   sizeof(*move_resp_msg)+creds_size(current),
				   GFP_KERNEL);
	if (!move_resp) {
	    printk(KERN_CRIT "bproc: Out of memory on move response.\n");
	    return 0;
	}
	move_resp_msg = bproc_msg(move_resp);
	move_resp_msg->hdr.result = 0;

	resend_socket = setup_resend(move_resp);
	if (IS_ERR(resend_socket)) {
	    result = PTR_ERR(resend_socket);
	    move_resp_msg->hdr.result = result;
	}

	memcpy(move_resp_msg->comm, current->comm, sizeof(current->comm));
	move_resp_msg->call_creds = 0;
	move_resp_msg->proc_creds = sizeof(*move_resp_msg);
	creds_store(creds_ptr(move_resp_msg, move_resp_msg->proc_creds));
	
	bproc_send_req(msgdest, move_resp);
	bproc_put_req(move_resp);

	if (result != 0)
	    goto out;

	do_resends(resend_socket, stop_req, regs, &mv);
	/* do_resends will close the listen socket */

	store_index_env(move_msg->index);
    } else {
	/* Simple case where we're not waiting around, just respond */
	struct bproc_krequest_t *move_resp;
	struct bproc_move_msg_t *move_resp_msg;

	move_resp = bproc_new_resp(move_req,
				   sizeof(*move_resp_msg)+creds_size(current),
				   GFP_KERNEL);
	if (!move_resp) {
	    printk(KERN_CRIT "bproc: Out of memory on move response.\n");
	    return -ENOMEM;
	}
	move_resp_msg = bproc_msg(move_resp);
	move_resp_msg->hdr.result = 0;
	memcpy(move_resp_msg->comm, current->comm, sizeof(current->comm));

	move_resp_msg->call_creds = 0;
	move_resp_msg->proc_creds = sizeof(*move_resp_msg);
	creds_store(creds_ptr(move_resp_msg, move_resp_msg->proc_creds));

	bproc_send_req(msgdest, move_resp);
	bproc_put_req(move_resp);
    }

    /* Perform delayed IO setup (if any) */
    for (i=0; i < mv.user.iolen; i++) {
	if (mv.user.io[i].flags & BPROC_IO_DELAY) {
	    if (setup_io_fd(&mv.user.io[i])) {
		printk(KERN_ERR "bproc: I/O setup failed. (delayed)\n");
		/* Note that we can't report this error back to
		 * the client without aborting the move....  If
		 * you use the DELAY flag, you need to be prepared
		 * for this kind of problem.  */
		break;
	    }
	}
    }

 out:
    if (result != 0) { 
	/* --- FAILURE ---
	 * In the failed receive case we need to clean up this process.
	 * This is essentially equivalent to moving it off the node
	 * again.  Therefore we use process2move except that the request
	 * is a response in this case.
	 */
	struct bproc_krequest_t *move_resp;
	struct bproc_move_msg_t *move_resp_msg;

	move_resp = bproc_new_resp(move_req, sizeof(*move_resp_msg) +
				   creds_size(current), GFP_KERNEL);
	if (!move_resp) {
	    printk(KERN_CRIT "bproc:  Out of memory on move response.\n");
	    return -ENOMEM;
	}
	move_resp_msg = bproc_msg(move_resp);
	move_resp_msg->hdr.result = result;

	move_resp_msg->call_creds = 0;
	move_resp_msg->proc_creds = sizeof(*move_resp_msg);
	creds_store(creds_ptr(move_resp_msg, move_resp_msg->proc_creds));

	if (process2move(move_resp) != 0) /* This sends the response... */
	    printk("bproc: I'm so hosed... (%s:%d)\n", __FILE__, __LINE__);
	bproc_put_req(move_resp);
    }

    if (mv.user.io) kfree(mv.user.io);
    return result;
}

/* This is called by ghosts responding to remote exec requests */
int recv_send_process(struct bproc_krequest_t *req, struct pt_regs *regs) {
    int err = 0;
    struct file *link = 0;
    struct bproc_kmove_t move;

    /* Setup a send here.  A lot of the move structure (addresses,
     * uids) won't be used in this case. */
    memset(&move, 0, sizeof(move));
    move.type = BPROC_SYS_EXEC2;
    /* XXX should be an arg? */
    move.user.flags = VMAD_DUMP_EXEC|VMAD_DUMP_OTHER|VMAD_FLAG_BPROC;

    link = connection_setup_2(req);
    if (IS_ERR(link)) {
	err = PTR_ERR(link);
	goto out;
    }

    /* Only carry errors out of here if the connection setup step fails */
    if (do_recv(req, link, regs, &move))
	goto out;

    bproc_put_int(0, link, 0);

    if (do_send(0, link, &move, regs))
	goto out;
 out:
    if (link && !IS_ERR(link)) fput(link);
    if (move.user.io) {
	printk(KERN_ERR "huh? Got IO forwarding list in recv_send_process.\n");
	kfree(move.user.io);
    }
    return err;
}

/* This is called by processes wishing to do a remote exec */
int send_recv_process(struct bproc_kmove_t *arg, struct pt_regs *regs) {
#if 0
    int err;
    struct file *link = 0, *listen = 0;
    struct bproc_krequest_t *req = 0;
    struct bproc_request_queue_t *msgdest;
#endif

    WARNING("send_recv_process needs to be reworked to be consistent with the rest of the move code.");
    return -ENOSYS;
#if 0

    msgdest = BPROC_ISMASQ(current) ? &current->bproc.masq->master->req :
	&bproc_ghost_reqs;

    /* We have to do a BPROC_EXEC request here ... */
    req = bproc_new_req(BPROC_EXEC,sizeof(*msg), GFP_KERNEL);
    if (!req) { err = -ENOMEM; goto out; }
    bpr_from_real(&req->req, BPROC_MASQ_PID(current));
    bpr_to_node(&req->req, -1);
    req->flags = BPROC_REQ_WANT_RESP;
    
    printk("Remote exec request building needs to be finished.\n");
    goto out;

    /* Setup a listen socket. */
    listen = bproc_setup_listen();
    if (IS_ERR(listen)) {
	err = PTR_ERR(listen);
	/* XXX Do we want to map errors related to socket resource
	 * exhaustion to EAGAIN here? */
	printk(KERN_NOTICE "bproc: move: Couldn't open FD to listen.\n");
	goto out;
    }
    req->req.bpr_move_addr = 0; /* gets filled in by the daemon */
    req->req.bpr_move_port = bproc_get_port(listen);
    
    /* XX send the request. */
    link = connection_setup_accept(listen, req);
    if (IS_ERR(link)) {
	err = PTR_ERR(link);
	goto out;
    }

    /* Don't expect a response anymore since we have an established
     * connection. */
    WARNING("bproc_remove_req is completely bogus here.\n");
    bproc_remove_req(msgdest,req);

    if ((err = do_send(req, link, arg, regs)))
	goto out;

    /* If we should proceed to the receive step, the remote end will
     * write a zero at this point. */
    if ((err = bproc_get_int(0, link, &err)))
	goto out;

    req->req.bpr_move_type = BPROC_SYS_EXEC2;
    if ((err = do_recv(req, link, regs, arg)))
	goto out;

    /* If we're still traced at this point, we should have taken a
     * trap in execve.  Generate it here.  */
    if (current->ptrace & PT_PTRACED)
	send_sig(SIGTRAP, current, 0);
 out:
    if (req) bproc_put_req(req);
    if (listen && !IS_ERR(listen)) fput(listen);
    if (link   && !IS_ERR(link))   fput(link);
    return err;
#endif
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
