/*-------------------------------------------------------------------------
 *  slave.c:  Beowulf distributed PID space slave daemon
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: slave.c,v 1.101 2004/09/23 20:11:10 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>
#include <syscall.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#define SYSLOG_NAMES 1
#include <syslog.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/reboot.h>
#include <sys/ptrace.h>
#include <sched.h>
#include <getopt.h>

#include <sys/prctl.h>

#include "list.h"
#include "bproc.h"
#include "messages.h"		/* daemon-only messages */

int start_iod(void);

#define DEFAULT_PORT             2223
#define DEFAULT_PING_TIMEOUT     30
/*#define RECONNECT_RETRY_INTERVAL 10*/

#define TIME_ADJ_COMPLAIN 50000	/* bitch if time adjustment is > this (us). */
#define TIME_ADJ_MIN      10000	/* don't adjust if delta < than this. */

#define FS_NAMESPACE_DIR "/.slave-root-%d"

/*--------------------------------------------------------------------
 * State machine for connections
 *
 * NEW
 *  |
 *  V
 * RUNNING
 *  |
 *  V
 * CLOSING
 *  |
 *  V
 * {CLOSED}
 *
 *
 *------------------------------------------------------------------*/

enum c_state {
	CONN_NEW,		/* new connection */
	CONN_RUNNING,		/* up + running */
	CONN_CLOSING		/* EOF out... */
};

#define IBUFFER_SIZE (sizeof(struct bproc_message_hdr_t) + 64)
struct conn_t {
	struct list_head list;	/* List of connections */
	int fd;
	enum c_state state;

	struct request_t *req;	/* the reconnect request to respond to
				 * when we hit running or encounter
				 * some other error. */

	struct sockaddr_in laddr;
	struct sockaddr_in raddr;

	struct list_head reqs;	/* request queue just for this connection */

	int ioffset;
	char ibuffer[IBUFFER_SIZE];

	struct request_t *ireq;

	int ooffset;
	struct request_t *oreq;

};
#define conn_out_empty(x) (!(x)->oreq)

/* Global configuration goop */
static int verbose = 0;
static int auto_reconnect = 0;
static struct sockaddr local_addr;
static int ignore_version = 0;
static struct bproc_version_t version;/* = { BPROC_MAGIC, 386,
	PACKAGE_MAGIC, PACKAGE_VERSION
};*/

/* Slave daemon state */
static time_t cookie = 0;
static LIST_HEAD(clist);
static struct conn_t *conn_out = 0, *conn_in = 0;
static int ping_timeout = DEFAULT_PING_TIMEOUT;
static int node_number = BPROC_NODE_NONE;
static time_t lastping;
static int manager_fd;
static int private_namespace = -1;

static char *log_ident;
static int log_facility = LOG_DAEMON;
static int log_stderr = 0;
static int master_index;	/* my index */

/* Slave controller state */
struct master_t {
	struct list_head list;
	/* Slave information for this master */
	int index;		/* master number */

	int fd;			/* -1 = no slave daemon present */
	int attempted;		/*  */

	int naddr;
	struct sockaddr *addr;
};

static LIST_HEAD(masters);
static int nslaves = 0;

static int conn_write_refill(struct conn_t *c);

struct request_t {
	struct list_head list;
};

#define bproc_msg(req)  ((void *)(req+1))

static LIST_HEAD(reqs_to_master);
static LIST_HEAD(reqs_to_masq);

/**------------------------------------------------------------------------
 **  Misc crud
 **----------------------------------------------------------------------*/
static inline void *smalloc(size_t size)
{
	void *tmp;
	tmp = malloc(size);
	if (!tmp) {
		syslog(LOG_CRIT, "Out of memory. (alloc=%ld)\n", (long)size);
		exit(1);
	}
	return tmp;
}

/**------------------------------------------------------------------------
 **  Message tracing + debugging
 **----------------------------------------------------------------------*/
#include "debug.h"
static int tracefd = -1;

static
void msgtrace_off(void)
{
	if (tracefd != -1) {
		close(tracefd);
		tracefd = -1;
	}
}

static
void msgtrace_on(int fd)
{
	msgtrace_off();
	tracefd = dup(fd);
}

#define msgtrace(tf,n,r) do { if (tracefd != -1) _msgtrace((tf),(n),(r)); } while(0)
static
void _msgtrace(int tofrom, int node, struct request_t *req)
{
	struct debug_hdr_t dbg;
	struct bproc_message_hdr_t *msg;

	gettimeofday(&dbg.time, 0);
	dbg.tofrom = tofrom;
	dbg.node = node;
	msg = bproc_msg(req);

	if (msg->req == 0 || msg->size < 0) {
		abort();
	}

	write(tracefd, &dbg, sizeof(dbg));
	write(tracefd, msg, msg->size);
}

/**------------------------------------------------------------------------
 **  Request handling
 **----------------------------------------------------------------------*/
static
struct request_t *bproc_new_req(int type, int size)
{
	struct request_t *req;
	struct bproc_message_hdr_t *msg;

	req = smalloc(sizeof(*req) + size);
	msg = bproc_msg(req);
	msg->req = type;
	msg->id = 0;
	msg->size = size;
	msg->result = 0;	/* cosmetic for debugging */
	/* Zero out the routing stuff for paranoia  XXX DEBUGGING */
	msg->totype = msg->fromtype = 0;
	msg->to = msg->from = 0;
	return req;
}

static
struct request_t *bproc_new_resp(struct request_t *req, int size)
{
	struct request_t *resp;
	struct bproc_message_hdr_t *req_msg, *resp_msg;

	req_msg = bproc_msg(req);

	resp = smalloc(sizeof(*req) + size);
	resp_msg = bproc_msg(resp);
	resp_msg->req = BPROC_RESPONSE(req_msg->req);
	resp_msg->id = req_msg->id;
	resp_msg->size = size;
	resp_msg->result = 0;
	resp_msg->totype = req_msg->fromtype;
	resp_msg->to = req_msg->from;
	resp_msg->fromtype = req_msg->totype;
	resp_msg->from = req_msg->to;
	return resp;
}

static
void conn_send(struct conn_t *c, struct request_t *req);

static
void conn_respond(struct conn_t *c, struct request_t *req, int err)
{
	struct request_t *resp;
	struct bproc_null_msg_t *msg;

	resp = bproc_new_resp(req, sizeof(*msg));
	msg = bproc_msg(resp);
	msg->hdr.result = err;

	conn_send(c, resp);
}

static
void respond(struct request_t *req, int err)
{
	struct request_t *resp;
	struct bproc_null_msg_t *msg;

	resp = bproc_new_resp(req, sizeof(*msg));
	msg = bproc_msg(resp);
	msg->hdr.result = err;

	/*conn_send(conn_out, resp); */
	/*route_message(resp); */
	list_add_tail(&resp->list, &reqs_to_master);
	if (conn_out && conn_out_empty(conn_out))
		conn_write_refill(conn_out);
}

static inline void masq_send(struct request_t *req)
{
	list_add_tail(&req->list, &reqs_to_masq);
}

static inline void master_send(struct request_t *req)
{
	list_add_tail(&req->list, &reqs_to_master);
	if (conn_out_empty(conn_out))
		conn_write_refill(conn_out);
}

/*-----------------------------------------------------------------------*/
static
void set_keep_alive(int fd)
{
	int flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) == -1) {
		syslog(LOG_ERR, "setsockopt: %s\n", strerror(errno));
	}
}

static
void set_no_delay(int fd)
{
	int flag = 1;
	if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) {
		syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
	}
}

static
void set_non_block(int fd)
{
	int flags;
	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		syslog(LOG_ERR, "fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		return;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		syslog(LOG_ERR, "fcntl(%d, F_SETFL, 0x%x): %s",
		       fd, flags, strerror(errno));
		return;
	}
}

static
void conn_send(struct conn_t *c, struct request_t *req)
{
	list_add_tail(&req->list, &c->reqs);
	if (conn_out_empty(c))
		conn_write_refill(c);
}

static
void conn_send_version(struct conn_t *c)
{
	struct request_t *req;
	struct bproc_version_msg_t *msg;

	req = bproc_new_req(BPROC_VERSION, sizeof(*msg));
	msg = bproc_msg(req);
	bpr_from_node(msg, node_number);	/* no reasonable value here... */
	bpr_to_node(msg, -1);
	memcpy(&msg->vers, &version, sizeof(version));
	msg->cookie = cookie;

	conn_send(c, req);
}

static
void conn_eof(struct conn_t *c)
{
	struct request_t *req;
	struct bproc_null_msg_t *msg;

	c->state = CONN_CLOSING;

	req = bproc_new_req(BPROC_NODE_EOF, sizeof(*msg));
	msg = bproc_msg(req);
	bpr_from_node(msg, node_number);
	bpr_to_node(msg, -1);
	conn_send(c, req);
}

static
struct conn_t *conn_new(struct sockaddr_in *raddr, struct sockaddr_in *laddr)
{
	struct conn_t *c;
	int lsize, errnosave;
	struct sockaddr_in tmp;

	c = smalloc(sizeof(*c));
	memset(c, 0, sizeof(*c));
	c->state = CONN_NEW;
	INIT_LIST_HEAD(&c->reqs);

	if ((c->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		errnosave = errno;
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		free(c);
		errno = errnosave;
		return 0;
	}

	/* If this is not the first connection, do a non-blocking connect */
	if (!list_empty(&clist))
		set_non_block(c->fd);

	tmp = *laddr;		/* use a temp here because
				 * bindresvport writes it. */
	if (laddr->sin_port || bindresvport(c->fd, &tmp) == -1) {
		syslog(LOG_ERR, "bindresvport: %s (ignoring)", strerror(errno));
		/* If we specified a port or failed to bind to a reserved
		 * port for some reason, try a normal bind. */
		if (bind(c->fd, (struct sockaddr *)laddr, sizeof(*laddr)) == -1) {
			errnosave = errno;
			syslog(LOG_ERR, "bind(%s:%d): %s (ignoring)",
			       inet_ntoa(laddr->sin_addr),
			       ntohs(laddr->sin_port), strerror(errno));
			close(c->fd);
			free(c);
			errno = errnosave;
			return 0;
		}
	}

	if (verbose)
		syslog(LOG_INFO, "Connecting to %s:%d...",
		       inet_ntoa(raddr->sin_addr), ntohs(raddr->sin_port));

	if (connect(c->fd, (struct sockaddr *)raddr, sizeof(*raddr)) == -1) {
		if (errno != EINPROGRESS) {
			errnosave = errno;
			syslog(LOG_ERR, "connect(%s:%d): %s",
			       inet_ntoa(raddr->sin_addr),
			       ntohs(raddr->sin_port), strerror(errno));
			close(c->fd);
			free(c);
			errno = errnosave;
			return 0;
		}
	}

	/* Make note of our local address */
	lsize = sizeof(c->laddr);
	getsockname(c->fd, (struct sockaddr *)&c->laddr, &lsize);
	c->raddr = *raddr;

	/* Prime output buffer with version information and cookie */
	conn_send_version(c);

	set_keep_alive(c->fd);
	set_no_delay(c->fd);
	set_non_block(c->fd);

	/* Append to list of connections */
	list_add_tail(&c->list, &clist);
	return c;
}

static
void conn_remove(struct conn_t *conn, int reason)
{
	list_del(&conn->list);	/* remove from connection list */

	if (conn->req) {
		syslog(LOG_NOTICE, "Reconnect failed: %s\n", strerror(reason));
		respond(conn->req, -reason);
		free(conn->req);
		conn->req = 0;
	}

	if (conn->state == CONN_RUNNING) {
		syslog(LOG_NOTICE, "Lost connection to master");

		/* Clean up other connections */
		while (!list_empty(&clist)) {
			struct conn_t *c;
			c = list_entry(clist.next, struct conn_t, list);
			list_del(&c->list);

			if (c->req)
				free(c->req);
			close(c->fd);
			free(c);
		}
	}
	if (conn->req)
		free(conn->req);
	close(conn->fd);
	free(conn);
}

static
void do_slave_chroot(struct request_t *req)
{
	int err;
	struct bproc_chroot_msg_t *msg;

	msg = bproc_msg(req);
	((char *)msg)[msg->hdr.size - 1] = 0;	/* make sure path is null terminated */
	if (chroot(msg->path) == 0) {
		err = 0;
		if (verbose)
			syslog(LOG_INFO, "chroot to %s succeeded.", msg->path);
		chdir("/");
	} else {
		err = errno;
		syslog(LOG_ERR, "chroot to %s failed: %s", msg->path,
		       strerror(errno));
	}

	respond(req, -err);
}

/* The clone syscall is designed to get the child running on a
 * different stack.  We want to call clone but not for threads - just
 * so we can pass in CLONE_NEWNS.  Therefore we have our own
 * invocation of clone right here which is essentiall equivalent to
 * fork()
 */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
static
int fork_newns(void)
{
	/* Throw in a CLONE_PARENT so that our process tree ends up
	 * looking more or less the same as before. */
	return syscall(__NR_clone, CLONE_NEWNS | CLONE_PARENT | SIGCHLD,
		       NULL, NULL, NULL);
}

/* This is a bit of a mess.  It would be cleaner if the slave daemon *
 * could know ahead of time whether or not a private name space was
 * desired.  That would allow */
static
int privatize_namespace(void)
{
	int pid;
	char ns_path[100];

	/* First fork to get the new name space */
	pid = fork_newns();
	if (pid < 0) {
		syslog(LOG_ERR, "fork_newns: %s", strerror(errno));
		return -1;
	}
	/* parent goes away */
	if (pid > 0)
		exit(0);

	/* ... and child is now the slave daemon */
	sprintf(ns_path, FS_NAMESPACE_DIR, master_index);
	/* Blindly try to clean up.  If there's something mounted there,
	 * the kernel won't let us. */
	rmdir(ns_path);
	unlink(ns_path);
	if (mkdir(ns_path, 0666)) {
		syslog(LOG_ERR, "mkdir(\"%s\"): %s", ns_path, strerror(errno));
		return -1;
	}

	if (mount("none", ns_path, "tmpfs", 0, 0) != 0) {
		syslog(LOG_ERR, "mount(\"none\", \"%s\", \"tmpfs\", 0, 0): %s",
		       ns_path, strerror(errno));
		rmdir(ns_path);
		return -1;
	}

	if (chroot(ns_path) != 0) {
		syslog(LOG_ERR, "chroot(\"%s\"): %s", ns_path, strerror(errno));
		umount(ns_path);
		rmdir(ns_path);
		return -1;
	}
	chdir("/");
	return 0;
}

static
void do_node_reboot(struct request_t *req)
{
	int cmd, r;
	char *cmd_name;
	struct bproc_null_msg_t *msg;

	msg = bproc_msg(req);
	switch (msg->hdr.req) {
	case BPROC_NODE_REBOOT:
		cmd = RB_AUTOBOOT;
		cmd_name = "reboot";
		break;
	case BPROC_NODE_HALT:
		cmd = RB_HALT_SYSTEM;
		cmd_name = "halt";
		break;
	case BPROC_NODE_PWROFF:
		cmd = RB_POWER_OFF;
		cmd_name = "power off";
		break;
	default:
		syslog(LOG_ERR, "Unrecognized node state command: %d",
		       msg->hdr.req);
		return;
	}

	syslog(LOG_NOTICE, "Shutting down slave with command: %s", cmd_name);

	/* Shut down and get ready to restart the box. */
	close(conn_out->fd);
	/* Sync disks */
	sync();
	sync();
	sync();

	/* this should hopefully be enough to get the disks sync'ed and
	 * get the socket closed. */
	sleep(3);

	/* This is a mess.  Power off and halt just become exit(0) in the
	 * linux kernel if they don't work.  Therefore, we're goign to do
	 * it in another process here.  If we wait() on that process ok,
	 * we'll assume that whatever it was failed try something else */
	r = fork();
	if (r == 0) {
		reboot(cmd);
		syslog(LOG_ERR, "Reboot failed: %s", strerror(errno));
		exit(0);
	}
	waitpid(r, 0, 0);

	/* try the fall-back options */
	switch (cmd) {
	case RB_HALT_SYSTEM:
	case RB_POWER_OFF:
		while (1)
			pause();	/* simulate "halt" */
	default:
		syslog(LOG_ERR, "Failed to reboot.  Wow, that sucks.");
		exit(1);	/* Maybe our parent will do a better job? */
	}
}

/***-----------------------------------------------------------------------
 ***  IO
 ***---------------------------------------------------------------------*/
static
void set_running(struct conn_t *conn)
{
	struct conn_t *c;
	int addrsize;
	struct sockaddr addr;
	struct list_head *l;

	for (l = clist.next; l != &clist; l = l->next) {
		c = list_entry(l, struct conn_t, list);
		if (c != conn && c->state == CONN_RUNNING)
			conn_eof(c);
	}

	conn->state = CONN_RUNNING;
	conn_out = conn;
	if (!conn_in)
		conn_in = conn;

	if (conn->req) {
		respond(conn->req, 0);
		free(conn->req);
		conn->req = 0;
	}

	/* Update address information for our procs */
	addrsize = sizeof(addr);
	if (getsockname(conn->fd, &addr, &addrsize)) {
		syslog(LOG_ERR, "getsockname: %s", strerror(errno));
		return;
	}
	addrsize = sizeof(addr);
	if (getpeername(conn->fd, &addr, &addrsize)) {
		syslog(LOG_ERR, "getpeername: %s", strerror(errno));
		return;
	}
	if (verbose)
		syslog(LOG_INFO, "Connection to %s:%d up and running",
		       inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr),
		       ntohs(((struct sockaddr_in *)&addr)->sin_port));
}

static
void reconnect(struct conn_t *conn, struct request_t *req)
{
	struct conn_t *newc;
	struct sockaddr_in rem, loc;
	struct bproc_reconnect_msg_t *msg;
	/* First check to make sure there's only one connection on our
	 * list right now.  Otherwise return EBUSY. */

	msg = bproc_msg(req);

	if (msg->conn.raddr == INADDR_ANY || msg->conn.raddr == INADDR_NONE)
		msg->conn.raddr = conn->raddr.sin_addr.s_addr;
	if (msg->conn.rport == 0)
		msg->conn.rport = conn->raddr.sin_port;
	if (msg->conn.laddr == INADDR_NONE)
		msg->conn.laddr = conn->laddr.sin_addr.s_addr;
	if (msg->conn.lport == 0)
		msg->conn.lport = 0;

	rem.sin_family = AF_INET;
	rem.sin_addr.s_addr = msg->conn.raddr;
	rem.sin_port = msg->conn.rport;
	loc.sin_family = AF_INET;
	loc.sin_addr.s_addr = msg->conn.laddr;
	loc.sin_port = msg->conn.lport;

	newc = conn_new(&rem, &loc);
	if (!newc) {
		/* Early failure */
		respond(req, -errno);
		free(req);
		return;
	}
	newc->req = req;
}

static
void update_system_time(long time_sec, long time_usec)
{
	struct timeval sys_time_;
	int64_t sys_time, master_time;
	long adj;
	static int time_set = 0;

	if (time_sec == 0) {	/* no time stamp... */
		lastping = time(0);
		return;
	}

	/* NOTE: This isn't going to go well if there's multiple masters
	 * with clocks that disagree....  Only one should be sending
	 * times, I suppose.  Or maybe we need hierarchy or something.
	 *
	 * NOTE 2: I kinda just pulled this algorithm out of my ass.
	 */
	if (!time_set) {
		/* The first time through we just set our time to whatever the
		 * front end says. */
		time_set = 1;
		sys_time_.tv_sec = time_sec;
		sys_time_.tv_usec = time_usec;
		settimeofday(&sys_time_, 0);
		lastping = sys_time_.tv_sec;
		return;
	}

	gettimeofday(&sys_time_, 0);
	sys_time = (sys_time_.tv_sec * (uint64_t) 1000000) + sys_time_.tv_usec;
	master_time = (time_sec * (uint64_t) 1000000) + time_usec;
	adj = (master_time - sys_time) >> 1;	/* split the difference */

	/*printf("TIMES: %Ld %Ld %ld\n", sys_time, master_time, adj); */

	if (adj > TIME_ADJ_MIN || adj < -TIME_ADJ_MIN) {
		/* If the adjustment seems too big, just set. */
		if (adj > TIME_ADJ_COMPLAIN || adj < -TIME_ADJ_COMPLAIN)
			sys_time = master_time;
		else
			sys_time += adj;

		/* Update system time */
		sys_time_.tv_sec = sys_time / 1000000;
		sys_time_.tv_usec = sys_time % 1000000;
		settimeofday(&sys_time_, 0);

		/* Bitch if our time seems to be moving too much. */
		if (adj > TIME_ADJ_COMPLAIN || adj < -TIME_ADJ_COMPLAIN) {
			syslog(LOG_NOTICE, "Time adjustment: %.3f -> %ld.%06ld",
			       adj / 1000000.0, (long)sys_time_.tv_sec,
			       (long)sys_time_.tv_usec);
		}
	}
	lastping = sys_time / 1000000;
}

/* count is text, and ends with a non-numeric e.g. \n or \0
 * source is moved to end
 * err handling later. 
 */
int
buildarr(char **source, int *count, char ***list)
{
	char **arr;
	int i;
	char *cp = *source;
syslog(LOG_NOTICE, "cp %p %s", cp, cp);
	*count = strtoul(cp, 0, 10);
syslog(LOG_NOTICE, "COUNT %d", *count);
	/* alloc an extra for NULL terminating the array */
	arr = calloc(*count + 1, sizeof(char *));
	while (*cp)
		cp++;
	cp++;
syslog(LOG_NOTICE, "cp %p %s", cp, cp);	
	for(i = 0; i < *count; i++){
syslog(LOG_NOTICE, "cp %p", cp);
		arr[i] = cp;
		cp += strlen(cp) + 1;
	}

	*source = cp;
	*list = arr;
syslog(LOG_NOTICE, "buildarr done");
	return 0;
}

static
int setup_iofw(struct sockaddr_in *raddr)
{
	int lsize, errnosave;
	struct sockaddr_in tmp;
	int fd;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		errnosave = errno;
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		errno = errnosave;
		return 0;
	}

	if (verbose)
		syslog(LOG_INFO, "Connecting to %s:%d...",
		       inet_ntoa(raddr->sin_addr), ntohs(raddr->sin_port));

	if (connect(fd, (struct sockaddr *)raddr, sizeof(*raddr)) == -1) {
		if (errno != EINPROGRESS) {
			errnosave = errno;
			syslog(LOG_ERR, "connect(%s:%d): %s",
			       inet_ntoa(raddr->sin_addr),
			       ntohs(raddr->sin_port), strerror(errno));
			close(fd);
			errno = errnosave;
			return 0;
		}
	}

	set_keep_alive(fd);
	set_no_delay(fd);
	set_non_block(fd);

	return fd;
}

/* there is not struct that we can use; this is an array of bytes we have to interpret */
void 
do_run(struct conn_t *c, struct request_t *req)
{
	char *msg = bproc_msg(req), *cp;
	int len;
	int argc;
	char **argv;
	int envc, nodec;
	char **env, **nodes;
	int flags;
	char *dirname;
	char cmd[128];
	FILE *p;
	int cpiolen;
	struct bproc_message_hdr_t *hdr;
	char **ports;
	int portc;
	struct sockaddr_in addr;
	char *packstart;
	int packoff, node;

	hdr = (struct bproc_message_hdr_t *)msg;
	len = hdr->size;
	cp = msg + sizeof(*hdr);
	/* get the packet start. Nodes will start at 8 bytes past this point. */
	packoff = strtoul(cp, 0, 10);
	packstart = cp + packoff;
	syslog(LOG_NOTICE, "do_run: cp %p packoff %d packstart %p", cp, packoff, packstart);
	cp += 8;
	node = strtoul(cp, 0, 10);
syslog(LOG_NOTICE, "index @ %d i %s %d", (int)(cp-msg),cp, node);
	cp += strlen(cp) + 1;
	syslog(LOG_NOTICE, "do_run: cp %s\n", cp);
	syslog(LOG_NOTICE, "buildarr %p %p %p\n", &cp, &argc, &argv);
	buildarr(&cp, &nodec, &nodes);
	cp = packstart;
	buildarr(&cp, &argc, &argv);
syslog(LOG_NOTICE, "buildarr %p %p %p\n", &cp, &envc, &env);
	buildarr(&cp, &envc, &env);
	
	/* get the flags */
	flags = strtoul(cp, 0, 10);
	cp += strlen(cp) + 1;
	syslog(LOG_NOTICE, "flags %d\n", flags);
	/* host IP and ports */
	syslog(LOG_NOTICE, "hostip %s", inet_ntoa(addr.sin_addr));
	cp += strlen(cp) + 1;
	buildarr(&cp, &portc, &ports);
	/* nodes */
	/* now do the cpio unpack */
	/* let's depend on having a cpio command for now. */
syslog(LOG_NOTICE, "buildarr %p %p %p\n", &cp, &nodec, &nodes);
	dirname=strdup("/tmp/bproc2XXXXXX");
	mkdtemp(dirname);
syslog(LOG_NOTICE, "dirname %s", dirname);
	chdir(dirname);
	syslog(LOG_NOTICE, "chdir %s", dirname);
	cpiolen = len - (cp - msg);
	syslog(LOG_NOTICE, "do_run: cpio len %d\n", cpiolen);
	if (cpio(cp, cpiolen, "./") < 1) {
		syslog(LOG_NOTICE, "do_run: cpio failed");
		return;
	}
	/* let's run it. */
syslog(LOG_NOTICE, "ready to go");
	if (fork() == 0) {
		int fd;
		int i;
		/* fix up IO */
		/* weirdly it seems bproc forwarding current sends all the same port. But let's plan for the future. 
		 * new socket for each port (soon)
		 */
		for(i = 0; i < portc; i++) {
			addr.sin_addr = c->raddr.sin_addr;
			addr.sin_family = AF_INET;
			addr.sin_port = htons(strtoul(ports[i], 0, 10));
			fd = setup_iofw(&addr);
			write(fd, &node, sizeof(node));
			write(fd, &i, sizeof(i));
			dup2(fd, i);
		}
		syslog(LOG_NOTICE, "do_run: exec %s\n", argv[0]);
		execv(argv[0], argv);
		syslog(LOG_NOTICE, "do_run: exec %s FAILED\n", argv[0]);
	}
	
}

/*
 *  conn_msg_in - handle an incoming message
 *
 *  returns true if the connection is still alive after processing
 *  this message.
 */
static
int conn_msg_in(struct conn_t *c, struct request_t *req)
{
	struct bproc_message_hdr_t *hdr;

	msgtrace(BPROC_DEBUG_MSG_FROM_MASTER, -1, req);

	hdr = bproc_msg(req);
	switch (hdr->req) {
	case BPROC_VERSION:{
			struct bproc_version_msg_t *msg =
			    (struct bproc_version_msg_t *)hdr;

			if (version.magic != msg->vers.magic ||
			    version.arch != msg->vers.arch ||
			    strcmp(version.version_string,
				   msg->vers.version_string) != 0) {
				syslog(LOG_NOTICE,
				       "BProc version mismatch.  slave=%s-%u-%d;"
				       " master=%s-%u-%d (%s)",
				       version.version_string,
				       (int)version.magic, (int)version.arch,
				       msg->vers.version_string,
				       (int)msg->vers.magic,
				       (int)msg->vers.arch,
				       ignore_version ? "ignoring" :
				       "disconnecting");
				if (!ignore_version)
					return -1;
			}
			cookie = msg->cookie;
			free(req);
		}
		return 1;
	case BPROC_NODE_CONF:{
			struct bproc_conf_msg_t *msg;
			if (c->state == CONN_NEW) {
				/*syslog(LOG_DEBUG, "Received PING.  Setting to running."); */
				set_running(c);
			}
			msg = bproc_msg(req);

			update_system_time(msg->time_sec, msg->time_usec);

			/* This only gets setup on the FIRST conf message - we can't
			 * be flipping file system name spaces around. */
			if (private_namespace == -1) {
				private_namespace =
				    msg->private_namespace ? 1 : 0;
				if (private_namespace) {
					syslog(LOG_NOTICE,
					       "Setting up private FS name space.");
					privatize_namespace();
				}
			} else {
				static int complained = 0;
				if (private_namespace != msg->private_namespace
				    && !complained) {
					complained = 1;
					syslog(LOG_WARNING,
					       "private namespace option changed.  This "
					       "option cannot be changed without starting the slave "
					       "daemon.");
				}
			}

			/* Update configuration details */
			if (msg->hdr.to != node_number) {
				node_number = msg->hdr.to;
				syslog(LOG_NOTICE, "Setting node number to %d",
				       node_number);
			}
			if (msg->ping_timeout != ping_timeout) {
				ping_timeout = msg->ping_timeout;
				syslog(LOG_NOTICE, "Setting ping timeout to %d",
				       ping_timeout);
			}

			/* Pass master list up to the slave manager */
			write(manager_fd, &msg->masters_size,
			      sizeof(msg->masters_size));
			write(manager_fd, ((void *)msg) + msg->masters,
			      msg->masters_size *
			      sizeof(struct bproc_master_t));
			free(req);
		} return 1;
	case BPROC_NODE_PING:{
			struct bproc_ping_msg_t *msg;
			msg = bproc_msg(req);
			update_system_time(msg->time_sec, msg->time_usec);
			conn_respond(c, req, 0);
			free(req);
		} return 1;
	case BPROC_NODE_EOF:
		if (c->state != CONN_CLOSING)
			syslog(LOG_NOTICE,
			       "Received EOF on non-closing connection.");
		conn_remove(c, 0);
		free(req);
		return 0;

	/*--- Node commands ---*/
	case BPROC_NODE_CHROOT:
		do_slave_chroot(req);
		free(req);
		return 1;
	case BPROC_NODE_RECONNECT:
		reconnect(c, req);
		/* free handled internally */
		return 1;
	case BPROC_NODE_REBOOT:
	case BPROC_NODE_HALT:
	case BPROC_NODE_PWROFF:
		do_node_reboot(req);
		free(req);
		return 1;

	/* --- Process commands ---*/
	case BPROC_RUN:
		do_run(c, req);
		free(req);
		return 1;
	default:
		masq_send(req);
		return 1;
	}
}

/*
 *  conn_read - read a message from a connection
 */
static
void conn_read(struct conn_t *c)
{
	int r, size;
	struct bproc_message_hdr_t *hdr;

	while (1) {
		if (c->ireq) {
			/* Continue on partial request */
			hdr = bproc_msg(c->ireq);
			size = hdr->size - c->ioffset;

			r = read(c->fd, ((void *)hdr) + c->ioffset, size);
			if (r == -1) {
				if (errno == EAGAIN)
					return;
				syslog(LOG_ERR, "read(slave) (%p): %s", c,
				       strerror(errno));
			}
			if (r <= 0) {
				/*syslog(LOG_ERR, "lost connection to master"); */
				conn_remove(c, 0);
				return;
			}

			c->ioffset += r;
			if (c->ioffset == hdr->size) {
				/* message complete */
				if (!conn_msg_in(c, c->ireq))
					return;

				c->ioffset = 0;
				c->ireq = 0;
			}
		} else {
	    /*--- New request - read into ibuffer first ---*/
			size = sizeof(c->ibuffer) - c->ioffset;

			r = read(c->fd, c->ibuffer + c->ioffset, size);
			if (r == -1) {
				if (errno == EAGAIN)
					return;
				syslog(LOG_ERR, "read(slave) (%p): %s", c,
				       strerror(errno));
			}
			if (r <= 0) {
				/*syslog(LOG_ERR, "lost connection to master"); */
				conn_remove(c, 0);
				return;
			}
			c->ioffset += r;

			/* Suck messages out of ibuffer until we run out of data... */
			while (c->ioffset >= sizeof(struct bproc_message_hdr_t)) {
				hdr = (struct bproc_message_hdr_t *)c->ibuffer;

				/* Sanity checking */
				if (hdr->size <
				    sizeof(struct bproc_message_hdr_t)
				    || hdr->size > BPROC_MAX_MESSAGE_SIZE) {
					syslog(LOG_ERR,
					       "Invalid message size %d master",
					       hdr->size);
					conn_remove(c, 0);
					return;
				}

				c->ireq = smalloc(sizeof(*c->ireq) + hdr->size);
				if (c->ioffset >= hdr->size) {
					/* Complete message case */
					memcpy(bproc_msg(c->ireq), c->ibuffer,
					       hdr->size);

					/* Deal with message */
					if (!conn_msg_in(c, c->ireq))
						return;
					c->ireq = 0;

					/* Shift remaining data down */
					c->ioffset -= hdr->size;
					memmove(c->ibuffer,
						c->ibuffer + hdr->size,
						c->ioffset);
				} else {
					/* Incomplete message case */
					memcpy(bproc_msg(c->ireq), c->ibuffer,
					       c->ioffset);
					break;
				}
			}
		}
	}
}

/*
 *  conn_write_refill - get more data to write on a connection
 *
 *  returns true if more data is available.
 */
static inline void conn_write_load(struct conn_t *c, struct list_head *list)
{
	struct request_t *req;

	req = list_entry(list->next, struct request_t, list);
	list_del(&req->list);
	msgtrace(BPROC_DEBUG_MSG_TO_MASTER, -1, req);

	c->oreq = req;
	c->ooffset = 0;
}

static
int conn_write_refill(struct conn_t *c)
{
	switch (c->state) {
	case CONN_NEW:
		/* NEW connections don't read from the reqs to master queue */
		if (!list_empty(&c->reqs))
			conn_write_load(c, &c->reqs);
		break;
	case CONN_RUNNING:
		/* Get next outgoing request */
		if (!list_empty(&c->reqs)) {
			conn_write_load(c, &c->reqs);
		} else if (!list_empty(&reqs_to_master)) {
			conn_write_load(c, &reqs_to_master);
		}
		break;
	case CONN_CLOSING:
		if (!list_empty(&c->reqs)) {
			conn_write_load(c, &c->reqs);
		}
		/* Connection will hang around until we read the EOF... */
		break;
	}

	/* The kernel code doesn't know what the address of our links is.
	 * The daemon fills it in here for outgoing MOVE requests */
	if (c->oreq) {
		struct bproc_message_hdr_t *msg;
		msg = bproc_msg(c->oreq);
		switch (msg->req) {
		case BPROC_RUN:
		case BPROC_RESPONSE(BPROC_RUN):{
				struct bproc_move_msg_t *move_msg =
				    (struct bproc_move_msg_t *)msg;
				if (move_msg->hdr.size >= sizeof(*move_msg)
				    && move_msg->addr == 0)
					move_msg->addr =
					    c->laddr.sin_addr.s_addr;
			}
			break;
		}
	}

	return !conn_out_empty(c);
}

/*
 *  conn_write - write data to a slave node connection
 */
static
void conn_write(struct conn_t *c)
{
	int w;
	struct bproc_message_hdr_t *hdr;

	while (1) {
		/* see to it that we have data */
		if (conn_out_empty(c))
			return;	/* no data left... */

		hdr = bproc_msg(c->oreq);

		w = write(c->fd, ((void *)hdr) + c->ooffset,
			  hdr->size - c->ooffset);
		if (w < 0) {
			if (errno == EAGAIN)
				continue;
			syslog(LOG_NOTICE, "write(master): %s",
			       strerror(errno));
		}
		if (w <= 0) {
			/*syslog(LOG_NOTICE, "lost connection to master"); */
			conn_remove(c, 0);
			return;
		}
		c->ooffset += w;

		if (c->ooffset == hdr->size) {	/* done sending message */
			free(c->oreq);
			c->oreq = 0;

			/* c might be an invalid pointer after write_refill. */
			if (!conn_write_refill(c))
				return;
		}
	}
}

static
void select_loop(void)
{
	int r, maxfd;
	fd_set rset, wset;
	time_t now;
	struct conn_t *c;
	struct list_head *l, *next;
	struct timeval timeout;

	lastping = time(0);
	while (1) {
		/* Figure out how much time has passed since the last ping.
		 * If two ping intervals have passed, then we conclude the
		 * master is dead and blow chunks */
		now = time(0);
		timeout.tv_sec = now >= lastping + ping_timeout ? 0 :
		    ping_timeout - (now - lastping);
		timeout.tv_usec = 0;
		/*printf("now=%d lastping=%d ping_timeout=%d => %d\n",
		   (int)now,(int)lastping,(int)ping_timeout,(int)timeout.tv_sec); */

		/* Do the fdset thing... */
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		maxfd = -1;

		for (l = clist.next; l != &clist; l = l->next) {
			c = list_entry(l, struct conn_t, list);

			/* Reading is always good */
			FD_SET(c->fd, &rset);
			if (maxfd < c->fd)
				maxfd = c->fd;

			if (!conn_out_empty(c)) {
				FD_SET(c->fd, &wset);
				if (maxfd < c->fd)
					maxfd = c->fd;
			}
		}

		/*printf("timeout=%d.%06d\n", timeout.tv_sec, timeout.tv_usec); */
		r = select(maxfd + 1, &rset, &wset, 0, &timeout);
		if (r == -1 && errno != EINTR) {
			syslog(LOG_ERR, "select: %s", strerror(errno));
			exit(1);
		}
		if (r > 0) {

			for (l = clist.next; !list_empty(&clist) && l != &clist;
			     l = next) {
				next = l->next;
				c = list_entry(l, struct conn_t, list);
				if (FD_ISSET(c->fd, &wset)) {
					conn_write(c);
				}
			}
			for (l = clist.next; !list_empty(&clist) && l != &clist;
			     l = next) {
				next = l->next;
				c = list_entry(l, struct conn_t, list);
				if (FD_ISSET(c->fd, &rset)) {
					conn_read(c);
				}
			}
			/* We lost all our connections... That's BAD(tm) */
			if (list_empty(&clist))
				return;
		}
		if (r == 0) {
			/* We've timed out.  Blow chunks */
			syslog(LOG_NOTICE,
			       "ping timeout - lost connection to master");
			return;
		}
	}
}

/***-----------------------------------------------------------------------
 ***  Cleanup stuff for when a slave loses its master and resets itself.
 ***---------------------------------------------------------------------*/

static
void purge_requests(struct list_head *queue)
{
	struct request_t *req;
	while (!list_empty(queue)) {
		req = list_entry(queue->next, struct request_t, list);
		list_del(&req->list);
	}
}

static
void reset_slave(void)
{
	struct conn_t *c;
	syslog(LOG_NOTICE, "Slave Daemon Reset");
	while (!list_empty(&clist)) {
		c = list_entry(clist.next, struct conn_t, list);
		if (c->req)
			free(c->req);
		close(c->fd);
		free(c);
	}
	conn_in = 0;
	conn_out = 0;
	cookie = 0;

	purge_requests(&reqs_to_masq);
	purge_requests(&reqs_to_master);
}

static
int slave_setup(struct sockaddr *remaddr, struct sockaddr *locaddr)
{
	struct conn_t *newc;

	newc = conn_new((struct sockaddr_in *)remaddr,
			(struct sockaddr_in *)locaddr);
	if (!newc)
		return -1;

	return 0;

}

/***-----------------------------------------------------------------------
 ***  Multiple slave management
 ***---------------------------------------------------------------------*/

static
int start_slave(struct master_t *master)
{
	int pfd[2], i, pid;

	if (verbose)
		syslog(LOG_INFO, "Starting new slave %d", master->index);

	master->attempted = 1;
	if (pipe(pfd)) {
		syslog(LOG_ERR, "pipe: %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "fork: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		pid = 0;
		return -1;
	}
	if (pid == 0) {
		struct sched_param p;
		struct list_head *l;
		char *id;

		prctl(PR_SET_PDEATHSIG, SIGKILL);	/* kill me when parent dies */

		id = malloc(strlen(log_ident) + 10);
		if (!id) {
			syslog(LOG_ERR, "Out of memory.");
			exit(1);
		}
		sprintf(id, "%s-%d", log_ident, master->index);
		openlog(id, (log_stderr ? LOG_PERROR : 0), log_facility);

		master_index = master->index;

		/* Try and compact our file descriptor space */
		close(pfd[0]);
		for (l = masters.next; l != &masters; l = l->next) {
			struct master_t *m;
			m = list_entry(l, struct master_t, list);
			if (m->fd != -1)
				close(m->fd);
		}

		manager_fd = dup(pfd[1]);
		if (pfd[1] > manager_fd) {
			close(pfd[1]);
		} else {
			close(manager_fd);
			manager_fd = pfd[1];
		}

		/* Start trying to connect */
		for (i = 0; i < master->naddr; i++) {
			if (slave_setup(&master->addr[i], &local_addr) == 0)
				break;
		}
		if (i == master->naddr) {	/* failure */
			syslog(LOG_DEBUG, "Slave setup failed.");
			exit(1);
		}

		p.sched_priority = 1;
		select_loop();
		exit(0);
	}

	/* We don't make note of the slave's PID since the slave might do
	 * stuff like fork to get itself a new file system name space.  We
	 * just keep track of it with this pipe. */
	master->fd = pfd[0];
	close(pfd[1]);
	nslaves++;
	return 0;
}

static
long read_all(int fd, void *buf, long count)
{
	long r, bytes = count;
	while (bytes) {
		r = read(fd, buf, bytes);
		if (r < 0)
			return r;
		if (r == 0)
			return count - bytes;
		bytes -= r;
		buf += r;
	}
	return count;
}

static
struct master_t *master_new(void)
{
	struct master_t *m;
	static int index = 0;
	m = malloc(sizeof(*m));
	m->index = index++;
	m->fd = -1;
	m->naddr = 0;
	m->attempted = 0;
	m->addr = 0;
	list_add_tail(&m->list, &masters);
	return m;
}

static
void master_add_addr(struct master_t *m, struct sockaddr *addr)
{
	struct sockaddr *tmp;

	tmp = realloc(m->addr, sizeof(*m->addr) * (m->naddr + 1));
	if (!tmp) {
		syslog(LOG_ERR, "Out of memory.");
		abort();
	}
	m->addr = tmp;
	memcpy(&m->addr[m->naddr], addr, sizeof(*addr));
	m->naddr++;
}

static
struct master_t *master_find_by_addr(struct sockaddr *addr)
{
	struct list_head *l;
	struct master_t *m;
	int i;

	for (l = masters.next; l != &masters; l = l->next) {
		m = list_entry(l, struct master_t, list);
		for (i = 0; i < m->naddr; i++) {
			if (memcmp(&m->addr[i], addr, sizeof(*addr)) == 0)
				return m;
		}
	}
	return 0;
}

static
void read_master_set(struct master_t *s)
{
	int i, j, r, size;
	struct bproc_master_t *m;
	struct master_t *group, *group2;
	struct list_head *l;

	r = read_all(s->fd, &size, sizeof(size));
	if (r == 0) {
		/* EOF means that the slave actually exited.  Clear the status. */
		if (verbose)
			syslog(LOG_INFO, "Slave %d exited.", s->index);
		close(s->fd);
		s->fd = -1;
		nslaves--;
		return;
	}
	if (r != sizeof(size))
		goto barf;

	if (size < 0) {
		syslog(LOG_ERR, "Bogus master set. (size=%d)", size);
		close(s->fd);
		s->fd = -1;
		nslaves--;
		return;
	}

	/* We really only want to automagically reconnect to a slave if
	 * the previous connection was successfully established.
	 * Therefore we wait to get a master set.  If we get one we know
	 * the slave was successfully connected to and we can clear the
	 * attempted flag. */
	if (auto_reconnect)
		s->attempted = 0;

	if (size == 0)
		return;

	m = malloc(sizeof(*m) * size);
	if (!m) {
		syslog(LOG_ERR, "Out of memory.");
		exit(1);
	}

	r = read_all(s->fd, m, sizeof(*m) * size);
	if (r != sizeof(*m) * size)
		goto barf;

#if 0
	syslog(LOG_DEBUG, "Received master set: (%d entries)", size);
	for (i = 0; i < size; i++) {
		struct sockaddr_in *a;
		a = (struct sockaddr_in *)&m[i].addr;
		syslog(LOG_DEBUG, "  %3d: %-15s %d", m[i].tag,
		       inet_ntoa(a->sin_addr), ntohs(a->sin_port));
	}
#endif

	/* Merge this new data with our old set. */
	for (i = 0; i < size; i++) {
		if (i == 0 || m[i].tag != m[i - 1].tag) {
			/*syslog(LOG_DEBUG, "New group at offset %d", i); */

			group = 0;
			/* See if any of these addressses exist in a group yet. */
			for (j = i; j < size && m[j].tag == m[i].tag; j++) {
				group = master_find_by_addr(&m[i].addr);
				if (group)
					break;
			}
			/* All of these addresses are new, start a new group */
			if (!group)
				group = master_new();
		}

		group2 = master_find_by_addr(&m[i].addr);
		if (!group2) {
			master_add_addr(group, &m[i].addr);
		} else if (group2 != group) {
			syslog(LOG_ERR,
			       "ERROR: address moved to a different group.");
			syslog(LOG_ERR, "ERROR: ignoring address at %d", i);
			/* XXX is there something better that we could do in this case? */
		} else {
			/* Addres already in group - ok */
		}
	}

	/* Clear all the attempted flags */
	for (l = masters.next; l != &masters; l = l->next) {
		struct master_t *m;
		m = list_entry(l, struct master_t, list);
		if (m->fd == -1)
			m->attempted = 0;
	}

	/* Dump out the groups so far */
	syslog(LOG_DEBUG, "Master sets:");
	for (l = masters.next; l != &masters; l = l->next) {
		struct master_t *m;
		m = list_entry(l, struct master_t, list);
		for (i = 0; i < m->naddr; i++) {
			struct sockaddr_in *a;
			a = (struct sockaddr_in *)&m->addr[i];
			syslog(LOG_DEBUG, "  %d:  %-15s %d", m->index,
			       inet_ntoa(a->sin_addr), ntohs(a->sin_port));
		}
	}
	free(m);
	return;

      barf:
	if (r < 0)
		syslog(LOG_ERR, "Error reading: %s", strerror(errno));
	syslog(LOG_ERR, "Short read from slave %d", s->index);

	close(s->fd);
	s->fd = -1;
	nslaves--;
}

static
void slave_wait(void)
{
	int maxfd, r;
	fd_set rset;
	struct list_head *l, *next;
	struct master_t *m;

	while (nslaves > 0) {
		maxfd = -1;
		FD_ZERO(&rset);

		for (l = masters.next; l != &masters; l = l->next) {
			m = list_entry(l, struct master_t, list);
			if (m->fd != -1) {
				FD_SET(m->fd, &rset);
				if (m->fd > maxfd)
					maxfd = m->fd;
			}
		}

		r = select(maxfd + 1, &rset, 0, 0, 0);
		if (r < 0) {
			syslog(LOG_ERR, "select: %s", strerror(errno));
			return;
		}

		if (r > 0) {
			for (l = masters.next; l != &masters; l = next) {
				next = l->next;
				m = list_entry(l, struct master_t, list);
				if (m->fd != -1 && FD_ISSET(m->fd, &rset))
					read_master_set(m);
			}
		}

		/* Check to see if we want to start any more slaves. */
		for (l = masters.next; l != &masters; l = l->next) {
			m = list_entry(l, struct master_t, list);
			if (m->fd == -1 && m->attempted == 0) {
				start_slave(m);
			}
		}
	}
}

static
void daemonize(void)
{
	int fd, pid;
	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}
	if (pid != 0)
		exit(0);

	fd = open("/dev/null", O_RDWR);
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > 2)
		close(fd);

	chdir("/");
	umask(077);
	setsid();
	/* ignore some SIGHUP too? */
}

static
void usage(char *arg0)
{
	printf("Usage: %s [options] masteripaddr [port]\n"
	       "This program is the bproc distributed process space slave daemon.\n"
	       "\n"
	       "Options:\n"
	       "  -h        Show this message and exit\n"
	       "  -V        Print version information and exit\n"
	       "  -l <log>  Log to this log facility (default=daemon)\n"
	       "  -r        Automatic reconnect on error or lost connection\n"
	       "  -i        Ignore BProc version mismatches. (dangerous)\n"
	       "  -d        Do not daemonize self.\n"
	       "  -s <addr> Connect from source address addr.\n"
	       "\n"
	       "Debugging options:\n"
	       "  -m file   Enable message trace to file\n"
	       "  -v        Increase verbose level.\n", arg0);
}

int main(int argc, char *argv[])
{
	int c, i, err, fd;
	char *check;
	int port;
	int want_daemonize = 1;
	struct sockaddr_in *addrp, addrtmp;
	struct master_t *master;

	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};

	/* Defaults */
	addrp = (struct sockaddr_in *)&local_addr;
	addrp->sin_family = AF_INET;
	addrp->sin_addr.s_addr = INADDR_ANY;
	addrp->sin_port = 0;

	/*log_ident = argv[0]; */
	log_ident = "bpslave";

    /*--- Argument interpretation ---*/
	while ((c = getopt_long(argc, argv, "hVm:vrl:ds:iec:p:", long_options,
				0)) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s (%s-%u-%d)\n", argv[0],
			       PACKAGE_VERSION, version.version_string,
			       version.magic, version.arch);
			exit(0);
		case 'i':
			ignore_version = 1;
			break;
		case 'l':
			for (i = 0; facilitynames[i].c_name; i++) {
				if (strcasecmp(facilitynames[i].c_name, optarg)
				    == 0) {
					log_facility = facilitynames[i].c_val;
					break;
				}
			}
			if (facilitynames[i].c_name)
				break;
			fprintf(stderr, "Unknown log facility name: %s\n",
				optarg);
			exit(1);
		case 'm':
			if (strcmp(optarg, "-") == 0) {
				fd = dup(STDOUT_FILENO);
				msgtrace_on(fd);
			} else {
				fd = open(optarg,
					  O_WRONLY | O_CREAT | O_APPEND |
					  O_TRUNC, 0666);
				if (fd == -1) {
					perror(optarg);
					exit(1);
				}
				msgtrace_on(fd);
			}
			break;
		case 'r':
			auto_reconnect = 1;
			break;
		case 'v':
			verbose++;
			want_daemonize = 0;
			break;
		case 'd':
			want_daemonize = 0;
			break;
		case 's':
			addrp->sin_family = AF_INET;
			if (inet_aton(optarg, &addrp->sin_addr) == 0) {
				fprintf(stderr, "Invalid IP address: %s\n",
					optarg);
				exit(1);
			}
			addrp->sin_port = 0;
			break;
		case 'e':
			log_stderr = 1;
			break;
			break;

		default:
			exit(1);
		}
	}
	if (verbose && !want_daemonize)
		log_stderr = 1;

	if (optind + 1 != argc && optind + 2 != argc) {
		usage(argv[0]);
		exit(1);
	}

	openlog(log_ident, LOG_PERROR, log_facility);

	/* Add the server address we've been given to our list of masters */
	memset(&addrtmp, 0, sizeof(addrtmp));
	addrtmp.sin_family = AF_INET;
	if (inet_aton(argv[optind], &addrtmp.sin_addr) == 0) {
		syslog(LOG_ERR, "Invalid IP address: %s", optarg);
		exit(1);
	}

	if (optind + 2 == argc) {
		port = strtol(argv[optind + 1], &check, 0);
		if (*check) {
			syslog(LOG_ERR, "invalid port number: %s",
			       argv[optind + 1]);
			exit(1);
		}
	} else
		port = DEFAULT_PORT;
	addrtmp.sin_port = htons(port);

	/* Create the first master with just this address */
	master = master_new();
	master_add_addr(master, (struct sockaddr *)&addrtmp);

	/* daemonize ourself.  (this could happen after start_slave?) */
	openlog(log_ident, (log_stderr ? LOG_PERROR : 0), log_facility);
	if (want_daemonize == 1 && verbose == 0) {
		daemonize();
	} else {
		chdir("/");
	}
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* Start the first slave */
	err = start_slave(master);
	if (err)
		exit(1);

	slave_wait();
	syslog(LOG_INFO, "All slaves exited...  manager exiting.");
	exit(0);

}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
