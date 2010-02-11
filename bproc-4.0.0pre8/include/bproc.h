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
 * This file merges three bproc files. All were released under the license cited above. 
 * The copyrights and files of the other two are: 
 *  bproc_common.h: Beowulf distributed PID space (bproc) definitions
 *     This file contains definitions shared by user space and kernel space.
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
 * 
 *  bproc.h: Definitions for libbproc
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
 *
 *
 *-----------------------------------------------------------------------*/
#ifndef _BPROC_H
#define _BPROC_H

#include <stdint.h>
#include <sys/resource.h>
#include <sys/socket.h>

/*--- BProc version tag stuff --------------------------------------*/
#define BPROC_MAGIC {'B','P','r'}
enum {
	BPROC_ARCH_X86 = 1,
	BPROC_ARCH_ALPHA = 2,
	BPROC_ARCH_PPC = 3,
	BPROC_ARCH_X86_64 = 4,
	BPROC_ARCH_PPC64 = 5
};
#if defined(__i386__)
#define BPROC_ARCH BPROC_ARCH_X86
#elif defined(__alpha__)
#define BPROC_ARCH BPROC_ARCH_ALPHA
#elif defined(powerpc)
#define BPROC_ARCH BPROC_ARCH_PPC
#elif defined(__x86_64__)
#define BPROC_ARCH BPROC_ARCH_X86_64
#elif defined(__powerpc64__)
#define BPROC_ARCH BPROC_ARCH_PPC64
#else
#error "BProc does not support this architecture."
#endif

struct bproc_version_t {
	char bproc_magic[3];
	uint8_t arch;
	uint32_t magic;
	char version_string[24];
};

/*--- Structs passed in and out of the kernel ----------------------*/

/* All BProc attributes start with this */
#define BPROC_XATTR_PREFIX   "bproc."
#define BPROC_STATE_XATTR    "bproc.state"
#define BPROC_ADDR_XATTR     "bproc.addr"
#define BPROC_XATTR_MAX_NAME_SIZE  63
#define BPROC_XATTR_MAX_VALUE_SIZE 64
#define BPROC_XATTR_MAX      32	/* max # of extended attributes */

#define BPROC_STATE_LEN 15
struct bproc_node_info_t {
	int node;
	char status[BPROC_STATE_LEN + 1];
	unsigned int mode;
	unsigned int user;
	unsigned int group;
	struct sockaddr addr;
	time_t atime;
	time_t mtime;
};

/* I/O connection types */
#define BPROC_IO_MAX_LEN      16	/* max # of I/O redirections to setup */
#define BPROC_IO_FILE      0x000
#define BPROC_IO_SOCKET    0x001
#define BPROC_IO_MEMFILE   0x002	/* used internally by bproc */

/* I/O setup flags */
#define BPROC_IO_SEND_INFO 0x001
#define BPROC_IO_DELAY     0x002

struct bproc_io_t {
	int fd;
	short type;
	short flags;
	union {
		struct sockaddr addr;
		struct {
			int flags;
			int mode;
			long offset;
			char name[256];
		} file;
		struct {
			void *base;
			long size;
		} mem;
	} d;
};

struct bproc_proc_info_t {
	int pid;
	int node;
};

/*--- BProc specific errno values ----------------------------------*/

#define BE_BASE           300
#define BE_INVALIDNODE    (BE_BASE+0)
#define BE_NODEDOWN       (BE_BASE+1)
#define BE_SAMENODE       (BE_BASE+2)	/* formerly ELOOP */
#define BE_SLAVEDIED      (BE_BASE+3)
#define BE_INVALIDPROC    (BE_BASE+4)

enum bproc_request_types {
	BPROC_RUN = 1,		/* The basic bproc request */
	BPROC_RUN_COMPLETE,	/* exec finished  */
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

	BPROC_PARENT_EXIT,	/* ppid,oppid exited. */
	BPROC_CHILD_ADD,	/* ADD a child to a remote process */
	/*BPROC_CHILD_DEL, *//* REMOVE a child from a remote process */
	BPROC_PGRP_CHANGE,	/* somebody changed your pgrp */
	BPROC_PTRACE,		/* Normal ptrace syscall stuff */
	BPROC_REPARENT,		/* Update parent pointer on a process. */
	BPROC_SET_CREDS,
	BPROC_ISORPHANEDPGRP,

	/* System control/status */
	BPROC_VERSION,
	BPROC_NODE_CONF,	/* Node configuration message */
	BPROC_NODE_PING,	/* Ping message for my own keepalive... */
	BPROC_NODE_DOWN,	/* Node was set to down */
	BPROC_NODE_EOF,		/* EOF message */
	BPROC_NODE_RECONNECT,	/*  */

	BPROC_NODE_CHROOT,	/* Ask a slave daemon to chroot */

	BPROC_NODE_REBOOT,	/* Ask node to reboot */
	BPROC_NODE_HALT,	/* Ask node to halt */
	BPROC_NODE_PWROFF,	/* Ask node to power off */

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
	BPROC_SYS_DEBUG = 0x0002,

	BPROC_SYS_MASTER = 0x0003,	/* get master FD */
	BPROC_SYS_SLAVE = 0x0004,	/* get slave FD */
	BPROC_SYS_IOD = 0x0005,	/* get IOD FD */
	/*BPROC_SYS_LIBC    = 0x0006, *//* No longer supported */
	/*BPROC_SYS_NOTIFY  = 0x0007, *//* No longer supported */

	/* System status and control interfaces */
	/*BPROC_SYS_INFO    = 0x0201, *//* No longer supported */
	/*BPROC_SYS_STATUS  = 0x0202, *//* No longer supported */
	/*BPROC_SYS_CHOWN   = 0x0203, *//* No longer supported */
	/*BPROC_SYS_CHGRP   = 0x0204, *//* No longer supported */
	/*BPROC_SYS_CHMOD   = 0x0205, *//* No longer supported */
	/*BPROC_SYS_ACCESS  = 0x0204, *//* No longer supported */
	BPROC_SYS_CHROOT = 0x0207,	/* slave daemon chroot */
	BPROC_SYS_REBOOT = 0x0208,	/* slave reboot */
	BPROC_SYS_HALT = 0x0209,	/* slave halt */
	BPROC_SYS_PWROFF = 0x020A,	/* slave power off */
	/*BPROC_SYS_PINFO   = 0x020B, *//* No longer supported */
	/*BPROC_SYS_FILEREQ_PFAIL = 0x020C, *//* No longer supported */
	/*BPROC_SYS_FILEREQ_POK   = 0x020D, *//* No longer supported */
	BPROC_SYS_RECONNECT = 0x020E,	/* daemon - reconnect to master */

	/* Process migration interfaces */
	BPROC_SYS_REXEC = 0x0301,
	BPROC_SYS_MOVE = 0x0302,
	BPROC_SYS_RFORK = 0x0303,
	BPROC_SYS_EXECMOVE = 0x0304,
	/*BPROC_SYS_FILEREQ = 0x0305, *//* No longer supported */
	BPROC_SYS_VRFORK = 0x0306,	/* Vector rfork */
	BPROC_SYS_EXEC = 0x0307,	/* ghost exec request */
	BPROC_SYS_EXEC2 = 0x0308,	/*  2nd half - not actually used as syscall */
	BPROC_SYS_VEXECMOVE = 0x0309,
};
#define BPROC_SYS_VMADUMP   0x1000

/*------------------------------------------------------------------*/
/* was not sure how to do this but, for now, clients send this thing partially filled in and 
 * servers send it on. We'll see. 
 */
struct bproc_run_t {
	/* note that arg0 is also used for the path */
	char *arg0;
	char **argv;
	char **envp;
	int flags;
	int iolen;
	struct bproc_io_t *io;
	/* For vrrun */
	int nodeslen;
	int *nodes;
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
	int si_signo, si_errno, si_code;
	union {
		struct {
			int _pid, _uid;
		} _kill;
		struct {
			unsigned int _timer1, _timer2;
		} _timer;
		struct {
			int _pid, _uid;
			union {
				int sival_int;
				void *sival_ptr;	/* XXX Danger? */
			} _sigval;
		} _rt;
		struct {
			int _pid, _uid, _status;
			long _utime, _stime;
		} _sigchld;
		struct {
			void *_addr;
		} _sigfault;
		struct {
			int _band, _fd;
		} _sigpoll;
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
	uint8_t fromtype, totype;
	int32_t from;		/* PID or node number */
	int32_t to;		/* PID or node number */
	uint32_t size;		/* Request size */

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

	uint32_t addr;		/* Address to connect back to */
	uint16_t port;		/* Connect back port. */

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

	int pid;
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
	int new_exec;		/* inappropriate here, maybe... */
	/*struct bproc_credentials_t creds; */
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

	long flags;		/* thread flags */

	long request;
	long addr;
	union {
		long data[BPROC_PTRACE_RA_BYTES / sizeof(long)];
#if defined(__i386__)
		long regs[17];
		long fpregs[27];
#endif
#if defined(__x86_64__)
		long regs[27];	/* sizeof(user_regs_struct) */
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
	int ppid;		/* parent */
	int oppid;		/* real_parent */
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
	char state[BPROC_STATE_LEN + 1];
};

struct nodeset_setaddr_t {	/* Used to update node address in bpfs */
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

#define BPROC_API_VERSION 4

/* These need to be the same as the corresponding macros in the
 * vmadump headers. (FIXME) */
#define BPROC_DUMP_LIBS  1
#define BPROC_DUMP_EXEC  2
#define BPROC_DUMP_OTHER 4
#define BPROC_DUMP_ALL   7

/* Special node numbers */
#define BPROC_NODE_MASTER (-1)
#define BPROC_NODE_SELF   (-2)
#define BPROC_NODE_NONE   (-3)
#define BPROC_NODE_ANY    (-4)

#define BPROC_STATUS_NONE (-2)

#define BPROC_X_OK        1

struct sockaddr;

#include <stdint.h>
#include <sys/socket.h>

struct bproc_node_set_t {
	int size, alloc;
	struct bproc_node_info_t *node;
	/* XXX Maybe add ID map stuff in here ? */
};

#define BPROC_EMPTY_NODESET {0, 0, 0}

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------
 * Node information functions
 *------------------------------------------------------------------*/
	int bproc_numnodes(void);
	int bproc_currnode(void);
	int bproc_nodestatus(int node, char *status, int len);
	int bproc_nodeaddr(int node, struct sockaddr *s, int *size);

	int bproc_nodeinfo(int node, struct bproc_node_info_t *info);
	int bproc_nodelist(struct bproc_node_set_t *ns);
	int bproc_nodelist_(struct bproc_node_set_t *ns, int fd);

	int bproc_getnodeattr(int node, char *name, void *value, int size);

/* Node permission / access control stuff */
	int bproc_chmod(int node, int mode);
	int bproc_chown(int node, int user);
	int bproc_chgrp(int node, int group);
	int bproc_access(int node, int mode);

/* Process information functions */
	int bproc_proclist(int node, struct bproc_proc_info_t **list);
	int bproc_pidnode(int pid);

/*--------------------------------------------------------------------
 * Node set functions
 *------------------------------------------------------------------*/
	int bproc_nodeset_init(struct bproc_node_set_t *ns, int size);
	int bproc_nodeset_grow(struct bproc_node_set_t *ns, int size);
	void bproc_nodeset_free(struct bproc_node_set_t *ns);
#define bproc_node_set_node(ns,nn) (&(ns)->node[(nn)])
	int bproc_nodeset_add(struct bproc_node_set_t *ns,
			      struct bproc_node_info_t *n);
	int bproc_nodeset_append(struct bproc_node_set_t *a,
				 struct bproc_node_set_t *b);

	int bproc_nodefilter(struct bproc_node_set_t *out,
			     struct bproc_node_set_t *in, const char *str);

/*--------------------------------------------------------------------
 * Process migration / remote process creation interfaces.
 *------------------------------------------------------------------*/
	int bproc_rexec_io(int node, struct bproc_io_t *io, int iolen,
			   const char *cmd, char *const argv[],
			   char *const envp[]);
	int bproc_rexec(int node, const char *cmd, char *const argv[],
			char *const envp[]);
	int _bproc_move_io(int node, struct bproc_io_t *io, int iolen,
			   int flags);
	int bproc_move_io(int node, struct bproc_io_t *io, int iolen);
	int _bproc_move(int node, int flags);
	int bproc_move(int node);

	int _bproc_rfork_io(int node, struct bproc_io_t *io, int iolen,
			    int flags);
	int bproc_rfork_io(int node, struct bproc_io_t *io, int iolen);
	int _bproc_rfork(int node, int flags);
	int bproc_rfork(int node);

	int _bproc_vrfork_io(int nnodes, int *nodes, int *pids,
			     struct bproc_io_t *io, int iolen, int flags);
	int bproc_vrfork_io(int nnodes, int *nodes, int *pids,
			    struct bproc_io_t *io, int iolen);
	int _bproc_vrfork(int nnodes, int *nodes, int *pids, int flags);
	int bproc_vrfork(int nnodes, int *nodes, int *pids);

	int bproc_execmove_io(int node, struct bproc_io_t *io, int iolen,
			      const char *cmd, char *const argv[],
			      char *const envp[]);
	int bproc_execmove(int node, const char *cmd, char *const argv[],
			   char *const envp[]);

	int bproc_vexecmove_io(int nnodes, int *nodes, int *pids,
			       struct bproc_io_t *io, int iolen,
			       const char *cmd, char *const argv[],
			       char *const envp[]);
	int bproc_vexecmove(int nnodes, int *nodes, int *pids,
			    const char *cmd, char *const argv[],
			    char *const envp[]);

	int bproc_execve(const char *cmd, char *const argv[],
			 char *const envp[]);

/* Administrative type functions */
	int bproc_nodechroot(int node, char *path);
	int bproc_nodereboot(int node);
	int bproc_nodehalt(int node);
	int bproc_nodepwroff(int node);
	int bproc_nodereboot_async(int node);
	int bproc_nodehalt_async(int node);
	int bproc_nodepwroff_async(int node);

	int bproc_nodesetstatus(int node, char *status);
	int bproc_setnodeattr(int node, char *name, void *value, int size);

	int bproc_nodereconnect(int node, struct sockaddr *_rem, int remsize,
				struct sockaddr *_loc, int locsize);

	const char *bproc_strerror(int err);

	int bproc_version(struct bproc_version_t *vers);
	int bproc_notifier(void);

/* Utility functions - this one is going away... */
	int bproc_nodespec(struct bproc_node_set_t *ns, const char *str);
	int bprocnode(int node);
	int bprocuid(int node, int uid);
	int bprocgid(int node, int gid);
	int bprocmode(int node, int mode);

#ifdef __cplusplus
}
#endif
#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
