/*-------------------------------------------------------------------------
 *  bproc.h: Beowulf distributed PID space (bproc) definitions
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
 * $Id: bproc.h,v 1.106 2004/10/15 21:20:03 mkdist Exp $
 *-----------------------------------------------------------------------*/
#ifndef _BPROC_H
#define _BPROC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/resource.h>
#include <linux/socket.h>
#else
#include <stdint.h>
#include <sys/resource.h>
#include <sys/socket.h>
#endif

#include <sys/bproc_common.h>

enum bproc_request_types {
    BPROC_MOVE=1,		/* The basic bproc request */
    BPROC_MOVE_COMPLETE,	/* move finished for vector type moves */
    BPROC_EXEC,

    /* Messages from ghost->real process */
    BPROC_FWD_SIG,
    BPROC_GET_STATUS,

    /* Remote system calls for real processes */
    BPROC_SYS_FORK,
    BPROC_SYS_KILL,
    BPROC_SYS_WAIT,
    BPROC_SYS_GETSID,
    BPROC_SYS_SETSID,
    BPROC_SYS_GETPGID,
    BPROC_SYS_SETPGID,

    /* Real process -> ghost notifications */
    BPROC_STOP,
    BPROC_WAIT,
    BPROC_CONT,
    BPROC_EXIT,

    BPROC_PARENT_EXIT,		/* ppid,oppid exited. */
    BPROC_CHILD_ADD,		/* ADD a child to a remote process */
    /*BPROC_CHILD_DEL,*/	/* REMOVE a child from a remote process */
    BPROC_PGRP_CHANGE,		/* somebody changed your pgrp */
    BPROC_PTRACE,		/* Normal ptrace syscall stuff */
    BPROC_REPARENT,		/* Update parent pointer on a process. */
    BPROC_SET_CREDS,
    BPROC_ISORPHANEDPGRP,

    /* System control/status */
    BPROC_VERSION,	
    BPROC_NODE_CONF,		/* Node configuration message */
    BPROC_NODE_PING,		/* Ping message for my own keepalive... */
    BPROC_NODE_DOWN,		/* Node was set to down */
    BPROC_NODE_EOF,		/* EOF message */
    BPROC_NODE_RECONNECT,	/*  */

    BPROC_NODE_CHROOT,		/* Ask a slave daemon to chroot */

    BPROC_NODE_REBOOT,		/* Ask node to reboot */
    BPROC_NODE_HALT,		/* Ask node to halt */
    BPROC_NODE_PWROFF,		/* Ask node to power off */

};
#define BPROC_REQUEST(x)    ((x)& 0x7FFF)
#define BPROC_RESPONSE(x)   ((x)| 0x8000)
#define BPROC_ISRESPONSE(x) ((x)& 0x8000)

/*--- BPROC IOCTLS --------------------------------------------------------*/
/* slave daemon */
#define BPROC_MASQ_SET_MYADDR     0x104
#define BPROC_MASQ_SET_MASTERADDR 0x105
#define BPROC_MASQ_SET_NODENUM    0x106

/* master daemon */
#define BPROC_NODESET_INIT        0x204
#define BPROC_NODESET_SETSTATE    0x206
#define BPROC_NODESET_PERM        0x207
#define BPROC_NODESET_SETADDR     0x208
#define BPROC_SETPROCLOC          0x209

/* common */
#define BPROC_MSG_SIZE            0x301

/* BPROC IOD IOCTLs */
#define BPROC_GET_IO           0x200

/* BPROC Syscall Operations - these numbers are never supposed to change */
enum {
    BPROC_SYS_VERSION = 0x0001,
    BPROC_SYS_DEBUG   = 0x0002,

    BPROC_SYS_MASTER  = 0x0003,	/* get master FD */
    BPROC_SYS_SLAVE   = 0x0004,	/* get slave FD */
    BPROC_SYS_IOD     = 0x0005,	/* get IOD FD */
    /*BPROC_SYS_LIBC    = 0x0006,*/	/* No longer supported */
    /*BPROC_SYS_NOTIFY  = 0x0007,*/     /* No longer supported */

    /* System status and control interfaces */
    /*BPROC_SYS_INFO    = 0x0201,*/	/* No longer supported */
    /*BPROC_SYS_STATUS  = 0x0202,*/	/* No longer supported */
    /*BPROC_SYS_CHOWN   = 0x0203,*/	/* No longer supported */
    /*BPROC_SYS_CHGRP   = 0x0204,*/	/* No longer supported */
    /*BPROC_SYS_CHMOD   = 0x0205,*/	/* No longer supported */
    /*BPROC_SYS_ACCESS  = 0x0204,*/	/* No longer supported */
    BPROC_SYS_CHROOT  = 0x0207,	/* slave daemon chroot */
    BPROC_SYS_REBOOT  = 0x0208,	/* slave reboot */
    BPROC_SYS_HALT    = 0x0209,	/* slave halt */
    BPROC_SYS_PWROFF  = 0x020A,	/* slave power off */
    /*BPROC_SYS_PINFO   = 0x020B,*/	/* No longer supported */
    /*BPROC_SYS_FILEREQ_PFAIL = 0x020C,*/	/* No longer supported */
    /*BPROC_SYS_FILEREQ_POK   = 0x020D,*/	/* No longer supported */
    BPROC_SYS_RECONNECT=0x020E, /* daemon - reconnect to master */

    /* Process migration interfaces */
    BPROC_SYS_REXEC   = 0x0301,
    BPROC_SYS_MOVE    = 0x0302,
    BPROC_SYS_RFORK   = 0x0303,
    BPROC_SYS_EXECMOVE= 0x0304,
    /*BPROC_SYS_FILEREQ = 0x0305,*/	/* No longer supported */
    BPROC_SYS_VRFORK  = 0x0306,	/* Vector rfork */
    BPROC_SYS_EXEC    = 0x0307,	/* ghost exec request */
    BPROC_SYS_EXEC2   = 0x0308,	/*  2nd half - not actually used as syscall */
    BPROC_SYS_VEXECMOVE=0x0309,
};
#define BPROC_SYS_VMADUMP   0x1000

/*------------------------------------------------------------------*/
struct bproc_move_t {
    char              *arg0;
    char             **argv;
    char             **envp;
    int                flags;
    int                clone_flags; /* not supported yet... */
    int                iolen;
    struct bproc_io_t *io;
    /* For vrfork, vexecmove */
    int                nodeslen;
    int               *nodes;
    int               *pids;
};

struct bproc_connect_t {
    uint32_t raddr;
    uint32_t laddr;
    uint16_t rport;
    uint16_t lport;
};

#define BPROC_NGROUPS 32

/* This structure is basically a header.  It gets followed by fairly
 * free-form stuff like the supplementary groups.  Some day SE Linux
 * information might go in there too. */
struct bproc_credentials_t {
    uint32_t uid, euid, suid, fsuid;
    uint32_t gid, egid, sgid, fsgid;
    uint32_t cap_effective, cap_inheritable, cap_permitted;
    uint32_t parent_exec_id, self_exec_id;
    int dumpable;

    uint32_t ngroups;
    uint32_t groups[0];
};

/* This is basically a mirror of struct siginfo from
 * the kernel.  (compacted for space) It's reproduced
 * here because of various problems including this
 * structure in user space apps.  (collisions w/ glibc
 * defns and those glibc defns not being consistent w/
 * the kernel on all arch's) */
struct bproc_siginfo_t {
    int si_signo,si_errno,si_code;
    union {
	struct { int _pid, _uid; } _kill;
	struct { unsigned int _timer1, _timer2; } _timer;
	struct { int _pid, _uid;
	    union { int   sival_int;
		void *sival_ptr; /* XXX Danger? */
	    } _sigval; } _rt;
	struct { int _pid, _uid, _status;
	    long _utime, _stime; } _sigchld;
	struct { void *_addr; } _sigfault;
	struct { int _band, _fd; } _sigpoll;
    } _sifields;
};

struct bproc_vminfo_t {
    struct {
	unsigned long size;
	unsigned long resident;
	unsigned long shared;
	unsigned long text;
	unsigned long lib;
	unsigned long data;
    } statm;
    struct {
	unsigned long data;
	unsigned long stack;
	unsigned long lib;
	unsigned long exec;
	unsigned long rss;
	unsigned long total_vm;
	unsigned long locked_vm;
    } status;
};

/* Message flags */
#define BPROC_ROUTE_REAL  1
#define BPROC_ROUTE_NODE  2
#define BPROC_ROUTE_GHOST 3

#define BPROC_SILENT_EXIT 0x80000000



/* BPROC request structure */
/* Sidenote: int is used in favor of pid_t, uid_t, etc
 * because glibc and the kernel don't argee on what they are. */

/* THIS HEADER IS PLATFORM INDEPENDENT */
struct bproc_message_hdr_t {
    uint16_t req;		/* Request type */
    uint8_t  fromtype, totype;
    int32_t  from;			/* PID or node number */
    int32_t  to;			/* PID or node number */
    uint32_t size;			/* Request size */

    /* XXX FIX ME:  platform-independent-ize this */
    void *id;
    long result;
};

#define BPROC_MAX_MESSAGE_SIZE (256*1024)

/* bproc_null_msg_t - for messages with no extra data */
struct bproc_null_msg_t {
    struct bproc_message_hdr_t hdr;
};

#define BPROC_SIGSETWORDS (64 / (sizeof(long) * 8))

struct bproc_move_msg_t {
    struct bproc_message_hdr_t hdr;

    int type;		/* Move type */
    int index;		/* Process index for vector moves. */
    int pid;		/* my process id */
    int tgid;		/* my thread group id */
    int ppid;		/* parent */
    int oppid;		/* original/real parent */
    int pgrp;
    int session;
    int exit_signal;
    int children;

    uint32_t addr;	/* Address to connect back to */
    uint16_t port;	/* Connect back port. */

    /* There are two sets of credentials - one for the move
     * permission checks and one for the process itself.
     * These can be different if this is being done with a
     * setuid execmove. */
    int call_creds;		/* offset to credential structure */
    int proc_creds;		/* offset to credential structure */

    /* XXX Fix me: need pending signal information... and with
     * queued signals, this can be arbitrarily sized.
     * Shit. */

    unsigned long sigblocked[BPROC_SIGSETWORDS];
    unsigned long sigpending[BPROC_SIGSETWORDS];
    unsigned long sigpendingshared[BPROC_SIGSETWORDS];

    /* Process ptrace status */
    int ptrace, thread;

    char comm[16];

    /* FIX ME Need process priority information */
};

/* bproc_signal_req_t: this message is used to forward signals and
 *                     to attempt remote signal delivery. */

struct bproc_signal_msg_t {
    struct bproc_message_hdr_t hdr;

    int    pid;
    struct bproc_siginfo_t info;
};

/* bproc_rsyscall_msg_t:  generic remote syscall */
struct bproc_rsyscall_msg_t {
    struct bproc_message_hdr_t hdr;

    unsigned long blocked[BPROC_SIGSETWORDS];	/* Blocked signals */
    unsigned long arg[6];
};

struct bproc_creds_msg_t {
    struct bproc_message_hdr_t hdr;

    char comm[16];
    int  new_exec;		/* inappropriate here, maybe... */
    /*struct bproc_credentials_t creds;*/
};

/* bproc_status_msg_t - Used to update status on the front end including
 *                      process exit.
 */
struct bproc_status_msg_t {
    struct bproc_message_hdr_t hdr;

    int state;
    int exit_code;

    /* rusage type info that the kernel actually keeps track
     * of. */
    long utime, stime;
    long cutime, cstime;
    long minflt;
    long majflt;
    long nswap;

    struct bproc_vminfo_t vm;	/* memory stats for procfs */
};

struct bproc_pgrp_msg_t {
    struct bproc_message_hdr_t hdr;
    int mypid;
    int pid;
    int pgid;
};

/* this must be a multiple of sizeof(long) */
#define BPROC_PTRACE_RA_BYTES (8*sizeof(long))
struct bproc_ptrace_msg_t {
    struct bproc_message_hdr_t hdr;

    /* Credentials needed for ptrace stuff */
    int uid, gid;
    uint32_t cap_effective;

    long flags;			/* thread flags */

    long request;
    long addr;
    union {
	long data[BPROC_PTRACE_RA_BYTES / sizeof(long)];
#if defined(__i386__)
	long regs[17];
	long fpregs[27];
#endif
#if defined(__x86_64__)
	long regs[27]; /* sizeof(user_regs_struct) */
	long fpregs[27];
#endif
#if defined(__powerpc64__)
	long regs[32];
	long fpregs[32];
#endif
	struct bproc_siginfo_t siginfo;
    } data;

    unsigned bytes;
};

struct bproc_wait_msg_t {
    struct bproc_message_hdr_t hdr;

    int pid;
    int options;
};

struct bproc_reparent_msg_t {
    struct bproc_message_hdr_t hdr;

    int ptrace;
    int new_parent;
};

/* Most of the remote syscalls will have specific responses */
struct bproc_fork_resp_t {
    struct bproc_message_hdr_t hdr;

    int tgid;
    int ppid;			/* parent */
    int oppid;			/* real_parent */
    int pgrp;
    int session;
};

struct bproc_wait_resp_t {
    struct bproc_message_hdr_t hdr;

    int status;
    int utime;
    int stime;
    int minflt;
    int majflt;
    int nswap;
};

/*--------------------------------------------------------------------
 *  slave daemon control messages
 */
struct bproc_chroot_msg_t {
    struct bproc_message_hdr_t hdr;
    
    char path[0];
};
struct bproc_reconnect_msg_t {
    struct bproc_message_hdr_t hdr;

    struct bproc_connect_t conn;
};

/* Some routing macros */
#define bpr_to_node(req_, gid_)    do{(req_)->hdr.totype=BPROC_ROUTE_NODE;(req_)->hdr.to=(gid_);}while(0)
#define bpr_to_real(req_, gid_)    do{(req_)->hdr.totype=BPROC_ROUTE_REAL;(req_)->hdr.to=(gid_);}while(0)
#define bpr_to_ghost(req_, gid_)   do{(req_)->hdr.totype=BPROC_ROUTE_GHOST;(req_)->hdr.to=(gid_);}while(0)
#define bpr_from_node(req_, gid_)  do{(req_)->hdr.fromtype=BPROC_ROUTE_NODE;(req_)->hdr.from=(gid_);}while(0)
#define bpr_from_real(req_, gid_)  do{(req_)->hdr.fromtype=BPROC_ROUTE_REAL;(req_)->hdr.from=(gid_);}while(0)
#define bpr_from_ghost(req_, gid_) do{(req_)->hdr.fromtype=BPROC_ROUTE_GHOST;(req_)->hdr.from=(gid_);}while(0)


#define BPR_MAX_STRING       (sizeof(struct bproc_request_t)-(long)(&((struct bproc_request_t *) 0)->bpr_string))

#define BPROC_GHOST_DEFAULT_ACCEPT_TIMEOUT 5
#define BPROC_GHOST_DEFAULT_STATUS_TIMEOUT (2*HZ)
#define BPROC_DEFAULT_GHOST_ACCEPT_TIMEOUT 30
#define BPROC_DEFAULT_GHOST_STATUS_TIMEOUT (2*HZ)


/* Structures for master nodeset ioctls */
struct nodeset_init_t {
    int node_ct;
    int id_ct;
    int *id_list;
};

struct nodeset_setid_t {
    int idx;
    int id;
};

struct nodeset_setstate_t {	/* Used to update node state in bpfs */
    int id;
    char state[BPROC_STATE_LEN+1];
};

struct nodeset_setaddr_t {   /* Used to update node address in bpfs */
    int id;
    struct sockaddr addr;
};

struct nodeset_perm_t {
    int node;
    uint16_t euid, egid;
    uint32_t ngroups;
    uint32_t groups[BPROC_NGROUPS];
    uint32_t cap_effective;

};

struct setprocloc_t {
    int pid;
    int node;
};

#if defined(__i386__)
#define __NR_bproc 17		/* old break system call */
#elif defined(__alpha__)
#define __NR_bproc 291		/* random non-implemented call */
#elif defined(powerpc)
#define __NR_bproc 17		/* old break system call */
#elif defined(__x86_64__)
#define __NR_bproc 184
#define __NR_bproc32 17		/* old break system call */
#elif defined(__powerpc64__)
#define __NR_bproc   17		/* old break system call */
#define __NR_bproc32 17		/* old break system call */

#else
#error No BProc Syscall number defined for this architecture.
#endif

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
