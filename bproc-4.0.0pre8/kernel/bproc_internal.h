/*-------------------------------------------------------------------------
 *  bproc_internal.h: Beowulf distributed PID space (bproc) definitions
 *
 *  These internal definitions are ONLY used by the kernel modules.
 *  They are not for daemons or client libraries.
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
 * $Id: bproc_internal.h,v 1.24 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#ifndef _BPROC_INTERNAL_H
#define _BPROC_INTERNAL_H

#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#undef BPROC_MSG_DEBUG

/*--------------------------------------------------------------------
 *  struct bproc_krequest_t
 *
 *  Requests are passed around the kernel inside bproc_krequest_t's.
 *  These are reference counted types.  When the count = 0, they will
 *  be freed.  If count > 1
 *
 *  struct bproc_request_queue_t
 *
 *  Request queues are places to deliver messages to.  They can be
 *  either the outside world or ghost processes.  In the case of the
 *  outside world, the queue also includes a "pending" list.  (This
 *  pointer is ignored for ghosts.)
 *
 */
/* Note: all requests should be allocated with kmalloc since they will
 * be freed with kfree when their ref count hits zero. */

#define BPROC_REQ_WANT_RESP  0x01

struct bproc_krequest_t {
    struct list_head         list;
    atomic_t                 count;

    /* For messages which are going to get responses */
    wait_queue_head_t        wait;
    int                      flags;
    struct bproc_krequest_t *response;
};

struct bproc_request_queue_t {
    spinlock_t               lock;
    int                      closing;
    struct list_head         list;
    wait_queue_head_t        wait;
    struct list_head         pending;
};

struct bproc_ghost_proc_t {
    atomic_t                      count;/* Reference count */
    spinlock_t                    lock;
    struct list_head              list;

    /* Flags */
    struct bproc_request_queue_t  req;

    /* Process status mirroring related stuff */
    volatile unsigned long        last_response;
    int                           state;
    wait_queue_head_t             wait;

    int                           node;	/* location of process. */

    /* Stuff for the benefit of procfs */
    struct {
	int                       dumpable; /* this is NOT for ptrace, etc. */
	struct file              *exe;
    } proc;
    struct bproc_vminfo_t vm;


    /* Ptrace read-ahead stuff */
    struct {
	unsigned long bytes;
	unsigned long addr;
	unsigned long data[BPROC_PTRACE_RA_BYTES / sizeof(long)];
    } ptrace;
};

struct bproc_masq_master_t {
    atomic_t                      count; /* Reference count */
    struct list_head              proc_list;
    struct bproc_request_queue_t  req;    

    /* This is all informational stuff for things on the slave node. */
    int                           node_number;
    struct sockaddr               my_addr;
    struct sockaddr               master_addr;

    /* Certain messages (e.g. MOVE) need to be processed before the
     * slave daemon continues and processes more messages.  These
     * messages are sometimes processes by other threads.  This
     * completion is used for that purpose. */
    struct completion             done;
};

struct bproc_kmove_t {
    int      type;
    void    *script_base;
    long     script_size;
    uint32_t data_addr;
    uint16_t data_port;
    void    *msg_id;		/* MSG ID used for actual move request */
    int      index;		/* index for vector moves + ret for child */
    struct bproc_move_t user;
    struct bproc_credentials_t *creds; /* user permissions at time of call */
};

struct bproc_ptrace_info_t {
    int from;
    int child;
};

/**------------------------------------------------------------------------
 ** BPROC variables
 **----------------------------------------------------------------------*/

/* These are the sets of file operations that we might want to connect
 * one of our magic file descriptors to. */

/* There is a single master and the state is stored in these global
 * variables. */
extern spinlock_t ghost_lock;
extern int        ghost_master;
extern struct list_head ghost_list;
extern wait_queue_head_t ghost_wait;
extern struct bproc_request_queue_t bproc_ghost_reqs;


/**------------------------------------------------------------------------
 ** BPROC weird file related stuff
 **----------------------------------------------------------------------*/
enum bpfs_inode {
    BPFS_ROOT_INO = 1,

    /* Daemon interfaces */
    BPFS_MASTER_INO,
    BPFS_SLAVE_INO,
    BPFS_IOD_INO,
    BPFS_MEMFILE_INO,
    BPFS_SELF_INO,		/* Self symlink in bpfs */

    /* Slave node specific stuff */
    BPFS_SLAVE_NODE_MASTER_INO,	/* Master's inode on slave */
    BPFS_SLAVE_NODE_SELF_INO,	/* Slave's  inode on slave */

    /* Master node specific stuff */
    BPFS_MASTER_STATUS_INO,		/* Magic status file */
    BPFS_MASTER_NODE_MASTER_INO,	/* -1 entry in file system */
    BPFS_MASTER_NODE0_INO
};

extern struct file_operations   bproc_master_fops;
extern struct file_operations   bproc_slave_fops;
extern struct file_operations   bproc_iod_fops;
extern struct file_operations   bproc_memfile_fops;
extern struct file_operations   bproc_notifier_fops;
extern struct file_system_type bprocfs_type;

/**------------------------------------------------------------------------
 ** BPROC macros and inlines and stuff
 **----------------------------------------------------------------------*/
#define BPROC_ISMASQ(task)      ((task)->bproc.master != 0)
#define BPROC_ISGHOST(task)     ((task)->bproc.ghost  != 0)

/* This is kind of a high-overhead question to ask. *Grumble.* */

#define BPROC_MASQ_TGID(task)    ((task)->bproc.master ? (task)->bproc.tgid : (task)->tgid)
#define BPROC_MASQ_PPID(task)    ((task)->bproc.master ? (task)->bproc.ppid   : (task)->parent->pid) /* XXX not SMP safe */
#define BPROC_MASQ_OPPID(task)   ((task)->bproc.master ? (task)->bproc.oppid  : (task)->real_parent->pid) /* XXX not SMP safe */
#define BPROC_MASQ_PID(task)     ((task)->bproc.master ? (task)->bproc.pid    : (task)->pid)
#define BPROC_MASQ_PGRP(task)    ((task)->bproc.master ? (task)->signal->bproc.pgrp   : process_group(task))
#define BPROC_MASQ_SESSION(task) ((task)->bproc.master ? (task)->signal->bproc.session: (task)->signal->session)

#define BPROC_MASQ_MASTER(task) ((task)->bproc.master)

#define bproc_msgdest()  (current->bproc.master ? \
                          &current->bproc.master->req:&bproc_ghost_reqs)

#define bproc_msg(kreq) ((void *)&(kreq)[1])

static inline
int bproc_pending(struct bproc_krequest_t *req) {
    struct bproc_message_hdr_t *hdr;
    hdr = bproc_msg(req);
    
    return (hdr->req != 0) && !(req->response);
}

static inline
int bproc_deadreq(struct bproc_krequest_t *req) {
    struct bproc_message_hdr_t *hdr;
    hdr = bproc_msg(req);
    return hdr->req == 0;
}

static inline
int bproc_hasresponse(struct bproc_krequest_t *req) {
    return req->response != 0;
}

#define EMPTY_BPROC_REQUEST_QUEUE(foo) \
    ((struct bproc_request_queue_t) {SPIN_LOCK_UNLOCKED,0, \
    LIST_HEAD_INIT((foo).list),__WAIT_QUEUE_HEAD_INITIALIZER((foo).wait),\
    LIST_HEAD_INIT((foo).pending)})

extern atomic_t msg_count;

static inline
struct bproc_krequest_t *bproc_new_req(int type, int size, int pri) {
    struct bproc_krequest_t *req;
    struct bproc_message_hdr_t *hdr;

    req = kmalloc(sizeof(*req) + size, pri);
    if (!req) return 0;
    hdr = bproc_msg(req);

    req->count   = (atomic_t) ATOMIC_INIT(1);
    init_waitqueue_head(&req->wait);
    req->flags    = 0;
    req->response = 0;

    hdr->req    = type;
    hdr->id     = 0;
    hdr->size   = size;
    hdr->result = 0;	/* cosmetic for debugging */
    atomic_inc(&msg_count);
#ifdef ENABLE_DEBUG
    {
	extern atomic_t msg_counters[];
	atomic_inc(&msg_counters[BPROC_REQUEST(hdr->req)]);
    }
#endif
    /* Zero out the routing stuff for paranoia  XXX DEBUGGING*/
    hdr->totype = hdr->fromtype = 0;
    hdr->to     = hdr->from     = 0;
    return req;
}


static inline
struct bproc_krequest_t *bproc_new_resp(struct bproc_krequest_t *req,
					int size, int pri) {
    struct bproc_krequest_t *resp;
    struct bproc_message_hdr_t *hdr, *req_hdr;

    req_hdr = bproc_msg(req);

    resp = kmalloc(sizeof(*resp) + size, pri);
    if (!resp) return 0;
    hdr = bproc_msg(resp);

    resp->count = (atomic_t) ATOMIC_INIT(1);
    init_waitqueue_head(&resp->wait);
    resp->flags = 0;
    resp->response = 0;

    hdr->req    = BPROC_RESPONSE(req_hdr->req);
    hdr->id     = req_hdr->id;
    hdr->size   = size;
    hdr->result = 0;	/* cosmetic for debugging */
    atomic_inc(&msg_count);
#ifdef ENABLE_DEBUG
    {
	extern atomic_t msg_counters[];
	atomic_inc(&msg_counters[BPROC_REQUEST(hdr->req)]);
    }
#endif
    /* Send this one back where it came from */
    hdr->totype   = req_hdr->fromtype;
    hdr->to       = req_hdr->from;
    hdr->fromtype = req_hdr->totype;
    hdr->from     = req_hdr->to;
    return resp;
}


static inline
void bproc_get_req(struct bproc_krequest_t *req) {
    atomic_inc(&req->count);
}

extern void __bproc_put_req(struct bproc_krequest_t *req);
static inline
void bproc_put_req(struct bproc_krequest_t *req) {
    if (atomic_read(&req->count) == 0) {
	printk(KERN_CRIT "bproc: EXTREME BADNESS!\n");
	*((char *)0) = 0;	/* we'd better segfault... no, really.
				 * stack traces are useful here. */
    }
    if (atomic_dec_and_test(&req->count))
	__bproc_put_req(req);
}

#ifdef ENABLE_DEBUG
#define MSG_COUNTER_MAX 50
static inline
void msg_xfer(int a, int b) {
    extern atomic_t msg_counters[];
    if (a < 0 || a >= MSG_COUNTER_MAX ||
	b < 0 || b >= MSG_COUNTER_MAX) {
	printk(KERN_CRIT "bproc: debug: invalid msg xfer %d -> %d\n", a, b);
	return;
    }
    atomic_dec(&msg_counters[a]);
    atomic_inc(&msg_counters[b]);
}
#endif

/**------------------------------------------------------------------------
 ** Functions for sending/receiving requests
 **----------------------------------------------------------------------*/
/* kernel/msg.c */
extern void                     bproc_init_request_queue (struct bproc_request_queue_t *q);
extern void                     bproc_close_request_queue(struct bproc_request_queue_t *q);
extern int                      bproc_deliver_response   (struct bproc_request_queue_t *pending, struct bproc_krequest_t *req);
extern struct bproc_krequest_t *bproc_next_req           (struct bproc_request_queue_t *me);
extern struct bproc_krequest_t *bproc_next_req_wait      (struct bproc_request_queue_t *me, signed long timeout);
extern void                     bproc_pack_siginfo       (struct bproc_siginfo_t *bpinfo, struct siginfo *info);
extern int                      bproc_pending_req        (struct bproc_request_queue_t *reqdest, struct bproc_krequest_t *req);
extern void                     bproc_purge_requests     (struct bproc_request_queue_t *q);
extern void                     bproc_put_back_req       (struct bproc_request_queue_t *reqdest, struct bproc_krequest_t *req);
extern void                     bproc_remove_req         (struct bproc_request_queue_t *q, struct bproc_krequest_t *req);
/*extern int                      bproc_respond            (struct bproc_request_queue_t *reqdest, struct bproc_krequest_t *req);*/

extern int                      bproc_response_wait      (struct bproc_krequest_t *req, signed long timeout, int intr);
extern int                      bproc_send_req           (struct bproc_request_queue_t *reqdest, struct bproc_krequest_t *req);
extern int                      bproc_send_req_wait      (struct bproc_request_queue_t *reqdest, struct bproc_krequest_t *req);
extern void                     bproc_unpack_process_status(struct bproc_krequest_t *req, struct task_struct *tsk);
extern void                     bproc_unpack_siginfo     (struct bproc_siginfo_t *msg, struct siginfo *info);
/*extern void                     bproc_make_response(struct bproc_krequest_t *req);*/

extern int bproc_null_response(struct bproc_request_queue_t *dest,
			       struct bproc_krequest_t *req, long result);

/* kernel/masq.c */
/**------------------------------------------------------------------------
 ** Functions for pid masquerading
 **----------------------------------------------------------------------*/
void  masq_add_proc(struct bproc_masq_master_t *m, task_t *newp, int sp);
void  masq_exit_notify (struct task_struct *tsk, long code);
int   masq_get_state_single(struct bproc_masq_master_t *m, int pid);
void  masq_get_state_all(struct bproc_masq_master_t *m);
int   masq_getpgid     (pid_t pid);
int   masq_getsid      (pid_t pid);
int   masq_is_orphaned_pgrp(int pgrp);
pid_t masq_masq2real   (struct bproc_masq_master_t *m, pid_t masq);
pid_t masq_masq2real__ (struct bproc_masq_master_t *m, pid_t masq);
int   masq_new_pid     (struct task_struct *child, int flags);
int   masq_parent_exit (struct bproc_masq_master_t *m, int ppid);
int   masq_modify_nlchild(struct bproc_masq_master_t *m, int pid, int adj);
int   masq_pgrp_change (struct bproc_masq_master_t *m, struct bproc_pgrp_msg_t *msg);
void  masq_remove_proc (struct task_struct *task, int update_nlchild);
int   masq_send_sig    (int sig, struct siginfo *info,pid_t pid);
void  masq_set_creds   (int new_exec);
int   masq_setpgid     (pid_t pid, pid_t pgid);
int   masq_setsid      (void);
long  masq_sys_ptrace  (long request, long pid, long addr, long data, long *errok);
void  masq_unmasq      (struct task_struct *proc);
void  masq_unmasq_     (struct task_struct *proc);
int   masq_wait        (pid_t pid, int options, struct siginfo *infop,
			unsigned int * stat_addr, struct rusage * ru) ;

void  masq_stop_notify (void);
void  masq_cont_notify (void);

struct task_struct *masq_find_task_by_pid(struct bproc_masq_master_t *m, pid_t pid);
int masq_find_id_mapping(struct bproc_masq_master_t *m, int id, struct task_struct *ignore);

void set_parents(struct task_struct *task,
		 struct task_struct *real_parent, struct task_struct *parent);

/**------------------------------------------------------------------------
 ** Functions for ghosts
 **----------------------------------------------------------------------*/
/*extern void bproc_ghost_put_ghost        (struct bproc_ghost_proc_t *g);*/
/*extern void bproc_ghost_get_status_update(struct task_struct **task, struct bproc_ghost_proc_t **ghost,int);*/
/*extern void bproc_ghost_put_status       (struct bproc_ghost_proc_t *ghost);*/
void bproc_ghost_unghost          (void);
void ghost_refresh_init(void);
void ghost_refresh_status(struct task_struct *p);

/* Ghost processes (ghost.c) */
int  ghost_thread(struct pt_regs *regs, struct bproc_krequest_t *fork_req);
int  ghost_update_status(struct bproc_krequest_t *req);
int  add_ghost(int node);
int  ghost_deliver_msg  (pid_t pid, struct bproc_krequest_t *req);
int  ghost_set_location (int pid, int location);
void ghost_ptrace_cache(struct bproc_ptrace_msg_t *);

int  ghost_add(struct bproc_ghost_proc_t *ghost);

struct bproc_ghost_proc_t *ghost_get(struct task_struct *);
void                       ghost_put(struct bproc_ghost_proc_t *);

void   ghost_drop(struct bproc_ghost_proc_t *);
int    bproc_get_new_mm(void);

void reparent_process(struct bproc_krequest_t *req);


/* (slave.c) */
struct bproc_ghost_proc_t *ghost_alloc(int node);

/* Process migration (move.c, interface.c) */
int  send_process(int, struct bproc_kmove_t *, struct pt_regs *);
int  recv_process(struct bproc_krequest_t *, struct pt_regs *);
int  send_recv_process(struct bproc_kmove_t *, struct pt_regs *);
int  recv_send_process(struct bproc_krequest_t *, struct pt_regs *);
int  execmove_load_script(const char *, void **, unsigned long *);
int  setup_io_fd(struct bproc_io_t *);

int  move2process(struct bproc_krequest_t *req, struct bproc_masq_master_t *m);


/* Credential swapping stuff */
int  creds_size(struct task_struct *t);
int  creds_struct_size(struct bproc_credentials_t *creds);
int  creds_restore(struct bproc_credentials_t *creds, int dumpable);
void creds_store(struct bproc_credentials_t *creds);
static inline
struct bproc_credentials_t *creds_ptr(void *ptr, int offset) {
    return (struct bproc_credentials_t *)(ptr + offset);
}
void copy_to_groups(struct group_info *group_info,  gid_t *grouplist, int ngroups);


/*extern int  memfile_setup(int desired_fd, void *base, long size);*/
/*extern struct file *bproc_get_file(struct file_operations *fops);*/
extern void do_notify(void);

/* IO forwarding (iod.c) */
extern int bproc_new_io_connection(struct file *infd, struct file *outfd);

/* Utility stuff... */
typedef int bproc_kthread_func(struct pt_regs *, void *);
extern int bproc_kernel_thread(int (*fn)(struct pt_regs *, void *), void *arg, unsigned long flags);

extern int ghost_deliver_msg (pid_t pid, struct bproc_krequest_t *req);

extern void silent_exit(void) __attribute__((noreturn));
extern int  deliver_signal(struct bproc_masq_master_t *m, struct bproc_signal_msg_t *req);

extern void ptrace_3rd_party(struct bproc_krequest_t *req,
			     struct bproc_masq_master_t *context);
extern void set_hooks  (void);	/* Setup,etc for hooks. */
extern void unset_hooks(void);

/**------------------------------------------------------------------------
 ** kernel system call stuff (socket handling, etc.)
 **----------------------------------------------------------------------*/
extern struct file *k_socket_f(int family, int type, int protocol);
extern int k_setsockopt_f(struct file *file, int level, int optname, void *optval, int optlen);
extern int k_bind_f(struct file *file, struct sockaddr *addr, int addrlen);
extern int k_listen_f(struct file *file, int backlog);
extern int k_connect_f(struct file *file, struct sockaddr *addr, int addrlen);
extern int k_getsockname_f(struct file *file, struct sockaddr *addr, int *addrlen);
extern struct file *k_accept_f(struct file *file, struct sockaddr *peeraddr, int *addrlen);
extern int k_shutdown_f(struct file *file, int how);

extern ssize_t k_read_all_u_f(struct file *file, void *buf, size_t count);
extern ssize_t k_read_all_f(struct file *file, void *buf, size_t count);
extern ssize_t k_read_u_f(struct file *file, void *buf, size_t count);
extern ssize_t k_write_u_f(struct file *file, const void *buf, size_t count);
extern ssize_t k_write_f(struct file *file, const void *buf, size_t count);

extern int  k_chdir(const char *path);
extern int  k_execve(char *filename, char **argv, char **envp, struct pt_regs *regs);
extern int  k_open(const char *file, int flags, int mode);
extern int  k_wait4(pid_t pid, int options, struct siginfo *infop,
		    unsigned int *status, struct rusage *ru);


/**------------------------------------------------------------------------
 ** bpfs nodeset interaction (for master daemon)
 **----------------------------------------------------------------------*/
extern struct file *bpfs_get_file(enum bpfs_inode ino, char *name);
extern int  nodeset_init(int new_node_ct, int new_id_ct, int *id_list);
extern int  nodeset_set_state(int id, char *state);
extern int  nodeset_move_perm(struct file *, struct nodeset_perm_t *);
extern int  nodeset_set_addr(int id, struct sockaddr *addr);
extern int  nodeset_nodeup(int node);
extern void nodeset_cleanup(void);

#define dbwedge(foo) do {unsigned long now=jiffies; printk(foo); while (jiffies < (now + 2*HZ)) schedule();} while(0)

/**------------------------------------------------------------------------
 ** sysdeps  (and stuff required by the sysdeps...)
 **----------------------------------------------------------------------*/
/* stuff used by sysdeps */
long do_bproc(long, long, long, struct pt_regs *regs);
int  generic_get_user_args(struct bproc_move_t *, struct bproc_move_t *);

/*--- Routines provided by the sysdeps ---*/
void sysdep_store_return_value(struct pt_regs *regs, int value);
int  sysdep_get_user_args(struct bproc_move_t *args,
			  struct bproc_move_t *user);

int  sysdep_ptrace_store_req(struct bproc_ptrace_msg_t *pt_req, 
			   long request, long pid, long addr, long data);
int  sysdep_ptrace_store_user(struct bproc_ptrace_msg_t *pt_resp,
			    long request, long pid, long addr, long data);
void sysdep_ptrace_syscall_trace_exit(struct pt_regs *regs);
long sysdep_ptrace_kcall(struct bproc_ptrace_msg_t *pt_resp,
			 long, long, long, long);
int  sysdep_do_execve(char *, char **, char **, struct pt_regs *);


#if 1
/* Some junky little macros to produce spew */
#define SPEW1(extra) do{printk("bproc: %d(m%d) %s:%d (%s) " extra "\n",current->pid, BPROC_MASQ_PID(current),__FILE__,__LINE__,__FUNCTION__);}while(0)
#define SPEW2(extra, foo ...) do{printk("bproc: %d(m%d) %s:%d (%s) " extra "\n",current->pid, BPROC_MASQ_PID(current),__FILE__,__LINE__,__FUNCTION__, foo);}while(0)

#if 0
static
void * x_kmalloc(size_t size, int flags,
		 const char *file, int line, const char *func) {
    void *ptr;
    ptr = kmalloc(size, flags);
    if (size > 128 && size <= 192) {
	printk("bproc: alloc %3ld %p %s:%d:%s\n", size, ptr, file, line, func);
    }
    return ptr;
}

static
void x_kfree(void *ptr, size_t size, const char *file, int line, const char *func) {
    if (size > 128 && size <= 192) {
	printk("bproc: free     %p %s:%d:%s\n", ptr, file, line, func);
    }
    kfree(ptr);
}

#define kmalloc(sz,pri) (x_kmalloc((sz),(pri),__FILE__,__LINE__,__FUNCTION__))
#define kfree(ptr)      (x_kfree((ptr),sizeof(*ptr),__FILE__,__LINE__,__FUNCTION__))
#endif

#else
#define SPEW1(extra)            do {} while(0)
#define SPEW2(extra, foo ...)   do {} while(0)
#endif

#define WARNING(extra) do{static int x=0;if(!x){x=1;printk("bproc: WARNING: %s:%d: " extra "\n", __FILE__, __LINE__);}}while(0);

static inline
void check_stack_(const char *func, int line) {
    long esp;

#define MY_STACK_WARN (THREAD_SIZE / 2)
    
    __asm__ __volatile__("andl %%esp,%0" :
			 "=r" (esp) : "0" (THREAD_SIZE - 1));
    printk("%s:%d: STACK LEFT: %ld\n", func, line, esp - sizeof(struct thread_info));

    if (unlikely(esp < (sizeof(struct thread_info) + MY_STACK_WARN))) {
	printk("check_stack: stack overflow: %ld\n",
	       esp - sizeof(struct thread_info));
	dump_stack();
    }
}

#define check_stack() check_stack_(__FUNCTION__, __LINE__)
#endif /* #ifndef _BPROC_INTERNAL_H */

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
