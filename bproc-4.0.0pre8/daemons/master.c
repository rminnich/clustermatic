/*-------------------------------------------------------------------------
 *  master.c:  Beowulf distributed PID space master daemon
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
 * $Id: master.c,v 1.156 2004/10/18 20:02:24 mkdist Exp $
 *-----------------------------------------------------------------------*/

/* notes from Ron: 
 * Usage of the conf and tc structs. They are the same kind of thing, But they are used at different times. 
 * I'm having trouble with bpfs and it may be because I'm using the wrong one. 
 * I think tc means "temporary conf" and conf is the real thing. 
 * conf
 * setup_listen_socket
 * config_transfer_slaves -- as the "old" config
 * config_update_nodes (why not tc here? )
 * master_config --> tc is assigned to conf!
 * find_node_by_number
 * conn_send_conf
 * accept_new_slave
 * numnodes
 * do_get_status
 * send_pings
 * main
 * main io loop
 * 
 * tc -- note that tc is referenced here: Daemon Configuration
 * used directly in setup_listen_socket
 * config_interface
 * add_node
 * nodep (my stuff for bpfs)
 * add_node_ip
 * check_ip
 * config_timesync
 * config_privatefs
 * master_conf_callback
 * config_master
 * config_transfer_slaves --> " Transfer slaves from conf to tc "
 * config_fixup
 * master_config
 * conn_write_refill
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <sys/un.h>
#include <sys/resource.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#define SYSLOG_NAMES 1
#include <syslog.h>
#include <sys/reboot.h>


#include <sys/epoll.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sched.h>

#include "bproc.h"

#include "list.h"
#include "cmconf.h"

#include "messages.h"		/* daemon-only messages */

#define DEFAULT_PORT             2223
#define DEFAULT_CONFIG_FILE      CONFIGDIR "/config"
#define DEFAULT_NODE_UP_SCRIPT   CONFIGDIR "/node_up"
#define DEFAULT_NODE_UP_LOG      LOGDIR    "/node.%d"
#define DEFAULT_PING_TIMEOUT     30	/* seconds */
#define LISTEN_BACKLOG           64
#define EXTRA_FDS                64

#define EV(type, fd) 	((type)  | ((fd) <<3))
#define EVFD(ev) ((ev)>>3)
#define EVTYPE(ev) ((ev)&7)

/* slave mode private name space */
#define FS_NAMESPACE_DIR "/.slave-root-%d"
#define TIME_ADJ_COMPLAIN 50000	/* bitch if time adjustment is > this (us). */
#define TIME_ADJ_MIN      10000	/* don't adjust if delta < than this. */

#define conn_out_empty(x) (!(x)->oreq)

struct request_t {
	struct list_head list;
};

#define bproc_msg(req)  ((void *)(req+1))
static LIST_HEAD(masters);
static LIST_HEAD(reqs_to_master);
static LIST_HEAD(reqs_to_masq);

#define EPOLL_MAXEV 1024

/*--------------------------------------------------------------------
 * State machine for connections
 *
 *   New---+     (r)
 *    |1   |2
 *    V    |
 *   Ready |   (-)
 *    |3   |
 *    V    V
 *   Running (r)
 *    |4
 *    V
 *   EOF     (-)
 *    |6
 *    V
 *   {CLOSED}
 *
 * States:
 *   NEW     - Connection established, nothing sent or received yet
 *   READY   - Versions and cookies exchanged, this connection ready.
 *   RUNNING - This connection being used to send/receive messages.
 *   EOF     - Our EOF placed in output buffer, waiting for buffers to drain.
 *   CLOSED  - Buffers drained, connection ready to be cleaned up.
 *
 * Transitions:
 *   1 - Switch to ready when new version + cookie received, if there is
 *       already a running connection.
 *   2 - Switch to running when new version + cookie received, if this
 *       is the only connection for the slave.
 *   3 - Switch to running when the previous running connection closes (EOF)
 *   4 - Switch to EOF_IN when an EOF is received from the slave.
 *   5 - Switch to EOF when our outgoing EOF is placed in the buffer.
 *   6 - Switch to CLOSED when all buffers are drained.
 *------------------------------------------------------------------*/
enum c_state {
	CONN_NEW,		/* new connection */
	CONN_READY,
	CONN_RUNNING,		/* connection active */
	CONN_EOF,		/* waiting for buffers to drain */
	CONN_DEAD		/* Dead, needs to be cleaned up */
};

/* fd type */
enum fd_type {
	CLIENT_CONNECT = 0,
	CLIENT,
	SLAVE_CONNECT,
	SLAVE,
	MASTER
};
	
#define IBUFFER_SIZE (sizeof(struct bproc_message_hdr_t) + 64)

/* same struct now for slaves and clients and masters. I've tried 'case dependent structs' and unions and stuff 
 * but taking a lesson from Russ Cox's p9p --  make it one struct as it is simple and 
 * because of Erik's really nice code for sucking in bits of a request until it is complete. 
 */
/* clients that connect over the master file descriptor unix domain socket. 
 * we have to do this because in kernel module based bproc, the kernel muxes the "clients" -- 
 * really, ordinary Unix commands such as kill etc. In our case, Clients mux in over the 
 * unix domain socket. We're losing a lot of the power of bproc but gaining heterogeneity and 
 * portability, since we don't need the kernel module any more
 */
struct conn_t {
	struct list_head list;	/* connection list */
	int type; /* CLIENT or SLAVE */
	int fd;
	enum c_state state;
	time_t ctime;		/* connection time (for timeout) */
	struct node_t *node;	/* Node this connection is for */

	/* We should probably deal in "struct sockaddr"s for addresses to
	 * be a little more protocol agnostic... */
	struct in_addr laddr;	/* local  connection address */
	struct in_addr raddr;	/* remote connection address */

	struct list_head backlog;	/* Incoming backlog before req goes "running" */
	struct list_head reqs;	/* request queue just for this connection */

	int ioffset;
	char ibuffer[IBUFFER_SIZE];

	struct request_t *ireq;

	int ooffset;
	struct request_t *oreq;
	/* auth stuff for clients */
	uid_t user;
	gid_t group;
};

struct conn_t *connections;

#define conn_out_empty(x) (!(x)->oreq)

struct node_t {
	int id;
	int naddr;		/* size of address list */
	struct in_addr *addr;	/* list of addresses */
	time_t cookie;		/* slave cookie */
	struct list_head clist;	/* Connection list */
	struct conn_t *running;	/* current running connection */

	int status;		/* Node status */
	char state[32];
	struct list_head reqs;	/* Request queue to be sent to slave */
	int flag:1;		/* generic reusable flag */

	int ping_in;		/* Data in since last ping interval. */
	/* permissions -- used to be in kernel */
	int mode, user, group;
	/* for later. */
	time_t atime, mtime, ctime;
};

struct assoc_t {
	int client;		/* fd for client that owns this proc */
	struct node_t *proc;	/* Where a process exists */
	unsigned short req;	/* Outstanding request type */
	void *req_id;		/* Request ID of move in progress */
	struct node_t *req_dest;	/* Outstanding request destination */
};

struct interface_t {
	char *name;
	int fd;
	struct sockaddr_in addr;
};

/* slave mode connection state */
/* Slave controller state */
struct mymaster_t {
	struct list_head list;
	/* Slave information for this master */
	int index;		/* master number */

	int fd;			/* -1 = no slave daemon present */
	int attempted;		/*  */

	int naddr;
	struct sockaddr *addr;
};

/* struct master_t - this struct holds groups of addresses for other
 * master nodes in the system.  There's one array of these things.
 * The tag marks the group.  This is stored this way so that it will
 * be easy to pack these things into a message. */
struct master_t {
	int tag;		/* group tag */
	struct sockaddr addr;	/* The address */
};

struct config_t {
	int if_list_size;
	struct interface_t *if_list;

	int master_list_size;
	struct master_t *master_list;

	/* Machine state setup to do sparse node ranges in a reasonable fashion */
	struct node_t *nodes;
	struct node_t **node_map;	/* mapping id # -> index in nodes */
	int num_nodes;		/* total number of nodes */
	int num_ids;		/* nodes numbered 0 -> (num_ids - 1) */

	int ping_timeout;
	int bproc_port;		/* port in host byte order */
	int log_facility;
	int require_secure_port;
	int slave_time_sync;	/* XXX should be per-slave */
	int slave_private_namespace;	/* XXX should be per-slave */
};

struct config_t conf;

/* Sequence number for the cookies to hand out to slaves.  This isn't
 * intended to provide any security.  It's just there to prevent an
 * accidental slave reconnect as the wrong node number */
static time_t cookie_seq = 0;
static char *log_arg0;
static int log_opts;
char *udsname = "/tmp/bpmaster";

static int ignore_version = 1;
static int clientconnect;	/*, listenfd; */

static int epoll_fd;
/* indicates master is running as "secondary" -- i.e. as both master and slave. 
 * In this mode, the "client" connection is actually from a master, over TCP
 */
static int slavemode = 0;
/* Slave daemon state */
static time_t cookie = 0;
static LIST_HEAD(clist);
static struct conn_t *conn_out = 0, *conn_in = 0;
static int ping_timeout = DEFAULT_PING_TIMEOUT;
static int node_number = BPROC_NODE_NONE;
static time_t lastping;
static int private_namespace = -1;
static char *log_ident;
static int log_facility = LOG_DAEMON;
static int log_stderr = 0;

/* Machine state */
#define MAXPID 32768
static struct assoc_t associations[MAXPID];
/*static struct request_t *ghost_reqs = 0;*/
//static LIST_HEAD(ghost_reqs);

/* Global configuration stuff */
static int verbose = 0;
static char *node_up_script = DEFAULT_NODE_UP_SCRIPT;
static char *machine_config_file = DEFAULT_CONFIG_FILE;
static int maxfd = -1;

static struct bproc_version_t version =
    { 
	BPROC_MAGIC, 
	0, 
	PACKAGE_MAGIC, 
	PACKAGE_VERSION 
};

time_t now(void);
static void remove_slave(struct node_t *s, struct conn_t *c);
static void remove_slave_connection(struct conn_t *conn);
static LIST_HEAD(conn_dead);	/* list of dead connections which need to be cleaned up. */

static void send_msg(struct node_t *s, int clientfd, struct request_t *req);
static void slave_next_connection(struct node_t *s);

#define REQUEST_QUEUE(dest) ((dest) ? (dest)->reqs : ghost_reqs)

static int route_message(struct request_t *);
static void conn_send_conf(struct conn_t *c);
static void conn_update_epoll(struct conn_t *c);

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
void _msgtrace(int tofrom, struct conn_t *conn, struct request_t *req)
{
	struct debug_hdr_t dbg;
	struct bproc_message_hdr_t *msg;

	gettimeofday(&dbg.time, 0);
	dbg.tofrom = tofrom;
	dbg.node = conn  && conn->node ? conn->node->id : -1;
	dbg.connection = conn;
	msg = bproc_msg(req);

	write(tracefd, &dbg, sizeof(dbg));
	write(tracefd, msg, msg->size);
}

/**------------------------------------------------------------------------
 **
 **----------------------------------------------------------------------*/
static inline void *smalloc(size_t size)
{
	void *tmp;
	tmp = calloc(1, size);
	if (!tmp) {
		syslog(LOG_EMERG, "Out of memory. (alloc=%ld)", (long)size);
		assert(0);
	}
	return tmp;
}

/*static inline*/
void *srealloc(void *ptr, size_t size)
{
	void *tmp;
	tmp = realloc(ptr, size);
	if (!tmp) {
		syslog(LOG_EMERG, "Out of memory. (realloc=%ld)", (long)size);
		assert(0);
	}
	return tmp;
}

static
void set_keep_alive(int fd)
{
	int flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) == -1) {
		syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
	}
}

/* XXX This doesn't seem to actually do what we want.... */
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

/**------------------------------------------------------------------------
 **  Free list for connections
 **----------------------------------------------------------------------*/
/*static LIST_HEAD(free_reqs);*/

static
struct request_t *req_get(int size)
{
	struct request_t *req;
	req = smalloc(sizeof(*req) + size);
	return req;
}

static
struct request_t *req_clone(struct request_t *oldreq)
{
	struct request_t *req;
	struct bproc_message_hdr_t *msg;
	msg = bproc_msg(oldreq);
	/* use req_get in case the free list comes back */
	req = req_get(msg->size);
	memcpy(req, oldreq, msg->size + sizeof(*req));
	return req;
}

static
void req_free(struct request_t *req)
{
	/*list_add(&req->list, &free_reqs); */
	free(req);
}

static
struct request_t *bproc_new_req(int type, int size)
{
	struct request_t *req;
	struct bproc_message_hdr_t *msg;
	req = req_get(size);
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

	resp = req_get(size);
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
char *ip_to_str(struct sockaddr_in *_addr)
{
	static char str_addr[16];
	long addr = ntohl(_addr->sin_addr.s_addr);
	sprintf(str_addr, "%ld.%ld.%ld.%ld",
		(addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff,
		addr & 0xff);
	return str_addr;
}

static
char *ip_to_str_(struct in_addr _addr)
{
	static char str_addr[16];
	long addr = ntohl(_addr.s_addr);
	sprintf(str_addr, "%ld.%ld.%ld.%ld",
		(addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff,
		addr & 0xff);
	return str_addr;
}

/**------------------------------------------------------------------------
 **  Daemon Configuration
 **----------------------------------------------------------------------*/
struct config_t tc;
static
int get_interface_ip(int fd, char *interface, struct sockaddr_in *addr)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		syslog(LOG_ERR, "%s: %s", interface, strerror(errno));
		return -1;
	}
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	memcpy(&addr->sin_addr,
	       &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	return 0;
}

static
int setup_listen_socket(struct interface_t *ifc)
{
	int fd, r, flag, i;
	struct epoll_event ev;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		return -1;
	}
	flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1)
		syslog(LOG_WARNING, "setsockopt: %s\n", strerror(errno));
	set_non_block(fd);

	if (get_interface_ip(fd, ifc->name, &ifc->addr)) {
		close(fd);
		return -1;
	}
	ifc->addr.sin_port = htons(tc.bproc_port);
	r = bind(fd, (struct sockaddr *)&ifc->addr, sizeof(ifc->addr));
	if (r == -1 && errno == EADDRINUSE) {
		/* Craziness here... We might already have a socket on the
		 * address we're looking for.  If so, try and steal it. */
		for (i = 0; i < conf.if_list_size; i++) {
			if (memcmp(&ifc->addr, &conf.if_list[i].addr,
				   sizeof(ifc->addr)) == 0) {
				close(fd);
				fd = dup(conf.if_list[i].fd);
				r = 0;
				break;
			}
		}
	}
	if (r == -1) {
		syslog(LOG_ERR, "bind(): %s", strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, LISTEN_BACKLOG) == -1) {
		syslog(LOG_ERR, "listen(): %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	ifc->fd = fd;

	ev.events = EPOLLIN;
	ev.data.u32 = EV(SLAVE_CONNECT, fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ifc->fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD): %s",
		       strerror(errno));
		exit(1);
	}
	return 0;
}

static
int config_interface(struct cmconf *conf, char **args)
{
	struct interface_t *tmp;
	/* Add an interface to our list */
	if (!
	    (tmp =
	     realloc(tc.if_list,
		     sizeof(*tc.if_list) * (tc.if_list_size + 1)))) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	tc.if_list = tmp;
	tmp = &tc.if_list[tc.if_list_size];
	tmp->name = strdup(args[1]);
	if (setup_listen_socket(tmp)) {
		syslog(LOG_ERR, "Could not setup socket on interface %s",
		       tmp->name);
		free(tmp->name);
		return -1;
	}
	tc.if_list_size++;
	return 0;
}

static int next_node;

#define ALLOC_CHUNK 64		/* number of elements to allocate at a time */
static
struct node_t *add_node(int node)
{
	struct node_t **map_tmp, *nodes_tmp;
	int i, curr_size, new_size;
	struct node_t *n;

	/* Add this node to the list of nodes */
	curr_size = (tc.num_nodes + ALLOC_CHUNK - 1) / ALLOC_CHUNK;
	new_size = (tc.num_nodes + ALLOC_CHUNK) / ALLOC_CHUNK;

	if (curr_size != new_size) {
		nodes_tmp = realloc(tc.nodes,
				    new_size * sizeof(*tc.nodes) * ALLOC_CHUNK);
		if (!nodes_tmp) {
			syslog(LOG_ERR, "Out of memory allocating nodes.\n");
			return 0;
		}
		tc.nodes = nodes_tmp;

		/* Make sure the node map stays consistent */
		for (i = 0; i < tc.num_nodes; i++)
			tc.node_map[tc.nodes[i].id] = &tc.nodes[i];
	}
	n = &tc.nodes[tc.num_nodes];
	tc.num_nodes++;

	/* Make sure the node map is big enough to hold this node */
	if (node >= tc.num_ids) {
		curr_size = (tc.num_ids + ALLOC_CHUNK - 1) / ALLOC_CHUNK;
		new_size = (node + ALLOC_CHUNK) / ALLOC_CHUNK;
		if (curr_size != new_size) {
			map_tmp = realloc(tc.node_map,
					  new_size * sizeof(*tc.node_map) *
					  ALLOC_CHUNK);
			if (!map_tmp) {
				syslog(LOG_ERR, "Out of memory.\n");
				return 0;
			}
			tc.node_map = map_tmp;
		}

		/* zero out the newly allocated stuff */
		for (i = tc.num_ids; i < new_size * ALLOC_CHUNK; i++)
			tc.node_map[i] = 0;
		tc.num_ids = node + 1;
	}

	tc.node_map[node] = n;

	memset(n, 0, sizeof(*n));
	n->id = node;
	n->ctime = n->mtime = now();
	strcpy(n->state, "up");
	INIT_LIST_HEAD(&n->reqs);
	INIT_LIST_HEAD(&n->clist);
	return n;
}

/* mainly code used to support external .c e.g. bpfs */
static struct node_t *
nodep(int node)
{
	struct node_t *n = 0;
	if (node < conf.num_ids)
		n = conf.node_map[node];
	return n;
}
int
bprocnode(int node)
{
	struct node_t *n = nodep(node);
	if (! n)
		return -1;

	return n->id;
}

int
bprocnodeinfo(int n, struct bproc_node_info_t *node)
{
	struct node_t *bp = nodep(n);

	if (! bp)
		return -1;
	node->node = bp->id;
	if (bp->mode)
		strncpy(node->status, "up", sizeof(node->status));
	else
		strncpy(node->status, "down", sizeof(node->status));
	node->mode = bp->mode;
	node->user = bp->user;
	node->group = bp->group;
	node->atime = now();
	node->mtime = now();
	memcpy(&node->addr, bp->addr, sizeof(&node->addr));
	return 0;
}
int
numnodes(void)
{
	return conf.num_nodes;
}

int
bprocuid(int node, int uid)
{
	struct node_t *n = nodep(node);
	if (! n)
		return -1;

	if (uid > -1)
		n->user = uid;
	return n->user;
}

int
bprocgid(int node, int gid)
{
	struct node_t *n = nodep(node);
	if (! n)
		return -1;

	if (gid > -1)
		n->group = gid;
	return n->group;
}

int
bprocmode(int node, int mode)
{
	struct node_t *n = nodep(node);
	if (! n)
		return -1;

	if (mode > -1)
		n->mode = mode;
	return n->mode;
}

char *
bprocstate(int node, char *state)
{
	struct node_t *n = nodep(node);
	if (! n)
		return NULL;

	if (state) {
		memset(n->state, 0, sizeof(n->state));
		strncpy(n->state, state, sizeof(n->state));
	}
	return n->state;
}

static
int add_node_ip(int node, struct in_addr addr)
{
	struct in_addr *tmp;
	struct node_t *n = 0;

	if (node < tc.num_ids)
		n = tc.node_map[node];
	if (!n)
		n = add_node(node);
	if (!n)
		return -1;

	if (!(tmp = realloc(n->addr, sizeof(*n->addr) * (n->naddr + 1)))) {
		syslog(LOG_ERR, "Out of memory");
		return -1;
	}
	n->addr = tmp;
	n->addr[n->naddr] = addr;
	n->naddr++;
	n->mtime = now();
	return 0;
}

static
int check_ip(struct in_addr _ip1, struct in_addr _ip2)
{
	int i, j;
	struct node_t *n;
	unsigned long ip1, ip2, ip;

	ip1 = ntohl(_ip1.s_addr);
	ip2 = ntohl(_ip2.s_addr);
	for (i = 0; i < tc.num_nodes; i++) {
		n = &tc.nodes[i];
		for (j = 0; j < n->naddr; j++) {
			ip = ntohl(n->addr[j].s_addr);
			if (ip >= ip1 && ip <= ip2)
				return -1;	/* This IP range includes an allocated IP */
		}
	}
	return 0;
}

static
int get_node_num(char ***args, int *num)
{
	char *check;

	if (!(*args)[1]) {
		*num = next_node;
		(*args) += 1;
		return 0;
	}

	*num = strtol((*args)[1], &check, 0);
	if (*check) {
		/* No node number */
		*num = next_node;
		(*args) += 1;	/* move args past node args */
	} else {
		/* Got a node number */
		if (*num < 0 /*|| *num > tc.num_nodes */ ) {
			syslog(LOG_ERR, "Invalid node number: %s", (*args)[1]);
			*num = -1;	/* error value... */
			return -1;
		}
		(*args) += 2;	/* move args past node number */
	}
	return 0;
}

static
int config_ip(struct cmconf *conf, char **args)
{
	int node_num;
	struct in_addr addr;

	if (get_node_num(&args, &node_num))
		return -1;

	next_node = node_num + 1;

	while (*args) {
		if (inet_aton(*args, &addr) == 0) {
			syslog(LOG_ERR, "%s:%d: Invalid IP address: %s",
			       cmconf_file(conf), cmconf_lineno(conf), *args);
			return -1;
		}
		if (check_ip(addr, addr)) {
			syslog(LOG_ERR, "%s:%d: IP already allocated: %s",
			       cmconf_file(conf), cmconf_lineno(conf), *args);
			return -1;
		}
		if (add_node_ip(node_num, addr))
			return -1;
		args++;
	}

	return 0;
}

static
int config_iprange(struct cmconf *conf, char **args)
{
	int node_num, i;
	struct in_addr addr[2];
	unsigned long ip, ip1, ip2;

	if (get_node_num(&args, &node_num))
		return -1;

	for (i = 0; i < 2; i++)
		if (inet_aton(args[i], &addr[i]) == 0) {
			syslog(LOG_ERR, "%s:%d: Invalid IP address: %s",
			       cmconf_file(conf), cmconf_lineno(conf), args[i]);
			return -1;
		}

	/* check that these aren't already assigned somewhere */
	if (check_ip(addr[0], addr[1])) {
		syslog(LOG_ERR,
		       "%s:%d: Duplicate IP addresses in range: %s -> %s"
		       "   One or more of these addresses is already assigned.",
		       cmconf_file(conf), cmconf_lineno(conf), args[0],
		       args[1]);
		return -1;
	}
	ip1 = ntohl(addr[0].s_addr);
	ip2 = ntohl(addr[1].s_addr);
	for (ip = ip1; ip <= ip2; ip++) {
		struct in_addr addr;
		addr.s_addr = htonl(ip);
		if (add_node_ip(node_num, addr))
			return -1;
		node_num++;
	}
	next_node = node_num;
	return 0;
}

static
int config_timesync(struct cmconf *conf, char **args)
{
	if (strcasecmp(args[1], "yes") == 0) {
		tc.slave_time_sync = 1;
	} else if (strcasecmp(args[1], "no") == 0) {
		tc.slave_time_sync = 0;
	} else {
		syslog(LOG_ERR, "timesync argument must be either yes or no");
		return -1;
	}
	return 0;
}

static
int config_privatefs(struct cmconf *conf, char **args)
{
	if (strcasecmp(args[1], "yes") == 0) {
		tc.slave_private_namespace = 1;
	} else if (strcasecmp(args[1], "no") == 0) {
		tc.slave_private_namespace = 0;
	} else {
		syslog(LOG_ERR, "privatefs argument must be either yes or no");
		return -1;
	}
	return 0;
}

static
int master_conf_callback(struct cmconf *conf, char **args)
{
	int i;
	if (strcmp(args[0], "bprocport") == 0) {
		int portno;
		char *check;
		struct servent *s;

		s = getservbyname(args[1], "tcp");
		if (s) {
			tc.bproc_port = ntohs(s->s_port);
		} else {
			portno = strtol(args[1], &check, 0);
			if (*check || portno <= 0 || portno >= 65536) {
				syslog(LOG_ERR,
				       "%s:%d: bprocport: unknown service/invalid"
				       " port: %s", cmconf_file(conf),
				       cmconf_lineno(conf), args[1]);
				return -1;
			}
			tc.bproc_port = portno;
		}
	} else if (strcmp(args[0], "allowinsecureports") == 0) {
		tc.require_secure_port = 0;
	} else if (strcmp(args[0], "logfacility") == 0) {
		for (i = 0; facilitynames[i].c_name; i++) {
			if (strcasecmp(facilitynames[i].c_name, args[1]) == 0) {
				tc.log_facility = facilitynames[i].c_val;
				break;
			}
		}
		if (!facilitynames[i].c_name) {
			syslog(LOG_ERR, "%s:%d: Unknown log facility: %s",
			       cmconf_file(conf), cmconf_lineno(conf), args[1]);
			return -1;
		}
	} else if (strcmp(args[0], "pingtimeout") == 0) {
		char *check;
		int tmp;
		tmp = strtol(args[1], &check, 0);
		if (*check) {
			syslog(LOG_ERR, "%s:%d: Invalid number: %s",
			       cmconf_file(conf), cmconf_lineno(conf), args[1]);
			return -1;
		}
		if (tmp < 2) {
			syslog(LOG_ERR,
			       "%s:%d: Ping timeout must be 2 seconds or more.",
			       cmconf_file(conf), cmconf_lineno(conf));
			return -1;
		}
		tc.ping_timeout = tmp;
	} else if (strcmp(args[0], "slavetimesync") == 0) {
		return config_timesync(conf, args);
	} else {
		syslog(LOG_ERR, "unknown tag in master_conf_callback: %s",
		       args[0]);
		return -1;
	}
	return 0;
}

static
int config_master(struct cmconf *conf, char **args)
{
	int i, j, port, tag;
	char *colon, *check;
	struct hostent *h;
	struct sockaddr addr_;
	struct sockaddr_in *addr = (struct sockaddr_in *)&addr_;

	struct master_t *m, *tmp;

	tag = 0;
	if (tc.master_list_size > 0)
		tag = tc.master_list[tc.master_list_size - 1].tag + 1;

	/* Add each of the addresses on this line */
	for (i = 1; args[i]; i++) {
		/* check if the user supplied a port number */
		colon = strchr(args[i], ':');
		if (colon) {
			*colon = 0;
			port = strtol(colon + 1, &check, 0);
			if (*check || port < 0 || port >= 65536) {
				syslog(LOG_ERR, "%s:%d: Invalid port number %s",
				       cmconf_file(conf), cmconf_lineno(conf),
				       colon + 1);
				return -1;
			}
		} else {
			port = tc.bproc_port;
		}

		h = gethostbyname(args[i]);
		if (!h) {
			syslog(LOG_ERR, "%s:%d: Unknown host %s",
			       cmconf_file(conf), cmconf_lineno(conf), args[i]);
			return -1;
		}
		/* Don't be a dork and throw shit in here with multiple
		 * addresses per name, ok? */
		memset(&addr_, 0, sizeof(addr_));
		addr->sin_family = AF_INET;
		memcpy(&addr->sin_addr, h->h_addr_list[0], h->h_length);
		addr->sin_port = htons(port);

		/* Check to make sure this address isn't a duplicate */
		for (j = 0; j < tc.master_list_size; j++) {
			if (memcmp(&tc.master_list[j].addr, addr, sizeof(*addr))
			    == 0) {
				syslog(LOG_ERR,
				       "%s:%d: master address %s is a duplicate!",
				       cmconf_file(conf), cmconf_lineno(conf),
				       args[i]);
				return -1;
			}
		}

		/* Allocate another address */
		tmp = realloc(tc.master_list,
			      sizeof(*tc.master_list) * (tc.master_list_size +
							 1));
		if (!tmp) {
			syslog(LOG_ERR, "Out of memory.");
			return -1;
		}
		tc.master_list = tmp;
		m = &tc.master_list[tc.master_list_size++];

		/* .. and store */
		m->tag = tag;
		memcpy(&m->addr, &addr_, sizeof(addr_));
	}
	return 0;
}

static
int config_err(struct cmconf *conf, char **args)
{
	syslog(LOG_ERR, "%s:%d: Unknown configuration tag: %s",
	       cmconf_file(conf), cmconf_lineno(conf), args[0]);
	return -1;
}

/* Options to control slave behavior. */
static
struct cmconf_option configopts_slave[] = {
	{"timesync", 1, 1, 0, config_timesync},
	{"privatefs", 1, 1, 0, config_privatefs},
	{"*", 0, -1, 0, config_err},
	{0,}
};

static
int config_slave_opts(struct cmconf *conf, char **args)
{
	return cmconf_process_args(conf, args + 1, configopts_slave);
}

static
struct cmconf_option configopts[] = {
	{"interface", 1, 3, 1, config_interface},
	{"ip", 1, 2, 2, config_ip},
	{"iprange", 3, 3, 2, config_iprange},
	{"bprocport", 1, 1, 0, master_conf_callback},
	{"allowinsecureports", 0, 0, 0, master_conf_callback},
	{"logfacility", 1, 1, 0, master_conf_callback},
	{"pingtimeout", 1, 1, 0, master_conf_callback},
	{"slavetimesync", 1, 1, 0, master_conf_callback},
	{"master", 1, -1, 2, config_master},
	{"slave", 1, -1, 0, config_slave_opts},
	{0,}
};

/* Transfer slaves from conf to tc */
static
void config_transfer_slaves(void)
{
	int i, j, k, l;
	struct node_t *n, *old;
	struct in_addr addr;
	struct assoc_t *a;
	struct conn_t *c;
	struct list_head *list;

	/* Transfer slave nodes from the old configuration to the new
	 * configuration.
	 *
	 * What should rule be here for slaves that are up?
	 *  1 any change (addr, node number) -> reconnect
	 *  2 reassign slaves based on addr.
	 *  3 ignore addrs and keep valid node numbers.
	 *
	 *  1 or 3 seems most sane but the code here does 2....
	 */
	for (i = 0; i < tc.num_nodes; i++) {
		n = &tc.nodes[i];
		for (j = 0; j < n->naddr; j++) {
			addr = n->addr[j];
			for (k = 0; k < conf.num_nodes; k++) {
				old = &conf.nodes[k];
				if (old->status != 0 &&
				    addr.s_addr == old->running->raddr.s_addr) {
					if (!list_empty(&n->clist)) {
						syslog(LOG_ERR,
						       "Dropping node %d due to address"
						       " collision during reconfiguration",
						       k);
						break;
					}
					/* Steal the connection state */
					n->status = old->status;

					/* xfer the connection list to the new node structure */
					list_add_tail(&n->clist, &old->clist);
					list_del_init(&old->clist);

					/* Walk the connection list and update the node
					 * pointers. */
					for (list = n->clist.next;
					     list != &n->clist;
					     list = list->next) {
						c = list_entry(list,
							       struct conn_t,
							       list);
						c->node = n;
					}
					n->running = old->running;
					n->cookie = old->cookie;

					/* Transfer the request list to the new node */
					list_add_tail(&n->reqs, &old->reqs);
					list_del_init(&old->reqs);

					/* set this guy to down so that we'll ignore it if
					 * we hit it again. */
					old->status = 0;
					old->running = 0;

					/* Node state */
					n->ping_in = 2;

					/* Move the associations for this slave */
					for (l = 0; l < MAXPID; l++) {
						a = &associations[l];
						if (a->proc == old)
							a->proc = n;
						if (a->req_dest == old)
							a->req_dest = n;
					}
				}
			}
		}
	}

	/* Discard any slaves that haven't been picked up as part of the
	 * new configuration. */
	for (i = 0; i < conf.num_nodes; i++) {
		if (conf.nodes[i].status) {
			syslog(LOG_INFO, "Discarding node %d connections due to"
			       " configuration change.\n", conf.nodes[i].id);
			remove_slave(&conf.nodes[i], 0);
		}
	}
}

static
void config_update_nodes(void)
{
	int i;
	for (i = 0; i < conf.num_nodes; i++)
		if (conf.nodes[i].running) {
			conn_send_conf(conf.nodes[i].running);
		}
}

static
const char *get_bpfs_path(void)
{
	char *bpfs_path;
	bpfs_path = getenv("BPFS_PATH");
	if (!bpfs_path)
		bpfs_path = "/bpfs";
	return bpfs_path;
}

time_t now(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return t.tv_sec;
}

static
void config_free(struct config_t *c)
{
	int i;
	struct epoll_event ev;

	/* Free interfaces */
	for (i = 0; i < c->if_list_size; i++) {
		if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->if_list[i].fd, &ev)) {
			syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_DEL): %s",
			       strerror(errno));
			exit(1);
		}
		close(c->if_list[i].fd);
	}
	if (c->if_list)
		free(c->if_list);

	/* Free masters */
	if (c->master_list)
		free(c->master_list);

	/* Count on config_transfer_slaves to clean up slave daemons */
	for (i = 0; i < c->num_nodes; i++)
		if (c->nodes[i].addr)
			free(c->nodes[i].addr);
	free(c->nodes);
}

static
void setup_fdsets(int size)
{
	struct rlimit rlim;

	/* Add a little padding and round up */
	/* make sure these values are multiples of 8 (to avoid bits
	 * vs. bytes type issues) */
	size += (size + EXTRA_FDS + 7) & ~0x7;

	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		syslog(LOG_CRIT, "getrlimit(RLIMIT_NOFILE): %s",
		       strerror(errno));
		exit(1);
	}

	maxfd = rlim.rlim_cur;

	if (rlim.rlim_cur < size) {
		if (rlim.rlim_max < size)
			rlim.rlim_max = size;
		rlim.rlim_cur = size;
		if (setrlimit(RLIMIT_NOFILE, &rlim)) {
			syslog(LOG_CRIT,
			       "Failed to increase RLIMIT_NOFILE to %ld/%ld",
			       (long)rlim.rlim_cur, (long)rlim.rlim_max);
		} else
			maxfd = size;
	}
}

/* This stuff sets up pointers, etc. when things are done moving
 * around in memory. */
static
void config_fixup(void)
{
	int i;
	struct node_t *n;
	for (i = 0; i < tc.num_nodes; i++) {
		n = &tc.nodes[i];
		tc.node_map[n->id] = n;	/* make entry in the node map */
		INIT_LIST_HEAD(&n->reqs);
		INIT_LIST_HEAD(&n->clist);
	}
}

static
int master_config(char *filename)
{
	next_node = 0;
	memset(&tc, 0, sizeof(tc));
	/* Defaults */
	tc.log_facility = LOG_DAEMON;
	tc.require_secure_port = 1;
	tc.bproc_port = DEFAULT_PORT;
	tc.ping_timeout = DEFAULT_PING_TIMEOUT;
	tc.slave_time_sync = 1;

	if (cmconf_process_file(filename, configopts)) {
		config_free(&tc);
		return -1;
	}

	config_fixup();		/* Fixup pointers in new configuration */

	config_transfer_slaves();	/* Move existing slaves */
	openlog(log_arg0, log_opts, tc.log_facility);
	config_free(&conf);
	conf = tc;		/* Do it! */

	setup_fdsets(conf.num_nodes + conf.if_list_size);
	if (!cookie_seq)
		cookie_seq = time(0);
	config_update_nodes();	/* xmit possibly update ping interval,
				 * node number, etc. */

	return 0;
}

/**------------------------------------------------------------------------
 **  Message routing stuff.
 **----------------------------------------------------------------------*/
static struct assoc_t *assoc_find(int pid);
struct node_t *find_node_by_number(int n)
{
	if (n < 0 || n >= conf.num_ids)
		return 0;
	return conf.node_map[n];
}


/**------------------------------------------------------------------------
 **  Functions to manage our associations of pids with clients
 **----------------------------------------------------------------------*/

void
client_init(void)
{

}

/**------------------------------------------------------------------------
 **  Functions to manage our associations of pids with slave daemons.
 **----------------------------------------------------------------------*/

static
void assoc_init(void)
{
	/*int i; */
	memset(associations, 0, sizeof(struct assoc_t) * MAXPID);
	/*
	   for (i=0; i < MAXPID; i++)
	   INIT_LIST_HEAD(&associations[i].held_reqs);
	 */
}

static
struct assoc_t *assoc_find(int pid)
{
	if (pid <= 0 || pid >= MAXPID) {
		syslog(LOG_CRIT, "FATAL: assoc_find: invalid pid %d\n", pid);
		assert(0);
	}
	return &associations[pid];
}

static inline int assoc_pid(struct assoc_t *a)
{
	return (a - associations);
}

void assoc_dump(void)
{
	int i;
	FILE *f;
	struct assoc_t *a;
	f = fopen("/var/run/bproc_assoc", "w");
	if (!f)
		return;

	for (i = 0; i < MAXPID; i++) {
		a = &associations[i];
		fprintf(f, "%d\t%d", i, a->proc ? a->proc->id : -1);	/* pid, node */
		fprintf(f, "\t%d\t%d\t%p", a->req,
			a->req_dest ? a->req_dest->id : -1, a->req_id);
		fprintf(f, "\n");
	}
	fclose(f);
}

/* This forcably removes a remote process.  It removes all data for it
 * and sends an EXIT message to the process's ghost. */
static inline void assoc_clear_proc(struct assoc_t *a)
{
	/* Zero out this process */
	a->proc = 0;
	a->req = 0;
	a->client = -1;
}

/* This is the violent way to remove a process from BProc's view of
 * the world. */
static
void assoc_purge_proc(struct assoc_t *a)
{
	assoc_clear_proc(a);
}

static
void assoc_purge(struct node_t *s)
{
	int i;
	struct assoc_t *a;
	struct request_t *req;
	struct bproc_null_msg_t *msg;

	for (i = 0; i < MAXPID; i++) {
		a = &associations[i];

		while (a->req && a->req_dest == s) {
			/* this is a while loop because MOVE->MOVE_COMPLETE */

			/* If this process had an outstanding message to this
			 * slave, send a response ourselves */
			/* This is just too verbose
			   syslog(LOG_NOTICE, "sending EIO response to msg; req=%d; id=%p\n",
			   a->req, a->req_id);
			 */

			/* Problem here.  We don't know anything more about the
			 * message except for the message type.  We'll send a null
			 * message.  The recovery code should check for
			 * BE_SLAVEDIED and not expect a verbose error response in
			 * that case.
			 */
			req =
			    bproc_new_req(BPROC_RESPONSE(a->req), sizeof(*msg));
			msg = bproc_msg(req);
			bpr_from_node(msg, s->id);
			bpr_to_real(msg, i);
			msg->hdr.id = a->req_id;
			msg->hdr.result = -BE_SLAVEDIED;
			a->req = 0;	/* Cancel the request */
			route_message(req);
		}

		/* Remove any processes that existed on that node.
		 *
		 * Note: if a process was moving to this node, then bit above
		 * should have generated a move response which moves the
		 * process back to the node it was coming from.  It should
		 * avoid getting shot in the head here.
		 */
		if (a->proc == s) {
			if (verbose)
				syslog(LOG_NOTICE, "slave for pid %d died.", i);

			/* Ok, now we have to kill off the ghost since the slave
			 * disappeared.  How we do this depends on the state the
			 * ghost is in.  (This is kind of a hack, IMO.)  If the
			 * ghost is in a fully created state, we can just tell it
			 * that the real process exited.  If it's MOVE'ing, we
			 * tell it the move failed. */
			assoc_purge_proc(a);
		}
	}
}

/**------------------------------------------------------------------------
 **  Machine configuration management.
 **----------------------------------------------------------------------*/
static
void set_node_state(struct node_t *s, char *state)
{
	struct nodeset_setstate_t ss;
	ss.id = s->id;
	strncpy(ss.state, state, BPROC_STATE_LEN);

#if 0
	if (ioctl(ghostfd, BPROC_NODESET_SETSTATE, &ss)) {
		syslog(LOG_ERR, "nodeset_set_state(%d, %s): %s\n",
		       s->id, state, strerror(errno));
	}
#endif
	s->status = strcmp(state, "down") == 0 ? 0 : 1;
}

static
void set_node_addr(struct node_t *s)
{
	struct nodeset_setaddr_t addr;

	addr.id = s->id;
	s->mtime = now();
	if (s->running) {
		struct sockaddr_in *a = (struct sockaddr_in *)&addr.addr;
		memset(a, 0, sizeof(*a));
		a->sin_family = AF_INET;
		a->sin_addr = s->running->raddr;
	} else
		memset(&addr.addr, 0, sizeof(addr.addr));
	/* This is a bit of a questionable hack right now.  The master can
	 * have multiple addresses with slaves at once.  In order to try
	 * and do something reasonable for both the simple and complex
	 * case, just store the last address that something connected at
	 * in the file system. */
	if (s->running) {
		struct sockaddr_in *a = (struct sockaddr_in *)&addr.addr;
		addr.id = BPROC_NODE_MASTER;

		memset(a, 0, sizeof(*a));
		a->sin_family = AF_INET;
		a->sin_addr = s->running->laddr;
	}
}

static
void run_node_up(struct node_t *s)
{
	int pid, i;
	s->mtime = now();
	s->user = s->group = 0;
	s->mode = S_IFREG|0111;
	/* no longer needed */
	return;
	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR,
		       "failed to run setup script for node %d\nfork: %s\n",
		       s->id, strerror(errno));
		return;
	}
	if (pid == 0) {
		char arg[10];
		int fd;
		char filename[100];
		/* First cleanup... */
		for (i = 3; i < 4096; i++)
			close(i);	/* Ugh, yuck. */
		signal(SIGHUP, SIG_DFL);
		signal(SIGUSR1, SIG_DFL);
		signal(SIGUSR2, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		setpgrp();

		sprintf(filename, DEFAULT_NODE_UP_LOG, s->id);
		fd = open("/dev/null", O_RDWR);
		if (fd != -1)
			dup2(fd, STDIN_FILENO);
		close(fd);
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND,
			  0644);
		if (fd == -1) {
			syslog(LOG_ERR, "Failed to open node_up log: %s\n",
			       filename);
			dup2(STDIN_FILENO, STDOUT_FILENO);
			dup2(STDIN_FILENO, STDERR_FILENO);
		} else {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		sprintf(arg, "%d", s->id);
		execl(node_up_script, node_up_script, arg, (char *)NULL);
		if (errno == ENOENT)
			exit(0);	/* No script, ok. */
		else
			syslog(LOG_ERR, "exec(%s): %s", node_up_script,
			       strerror(errno));
		exit(255);
	}
}

/**------------------------------------------------------------------------
 **  Connection management
 **----------------------------------------------------------------------*/
static int conn_write_refill(struct conn_t *c);
static
void conn_send(struct conn_t *c, struct request_t *req)
{
	list_add_tail(&req->list, &c->reqs);
	if (conn_out_empty(c)) {
		conn_write_refill(c);
		conn_update_epoll(c);
	}
}

static
void conn_eof(struct conn_t *c)
{
	switch (c->state) {
	case CONN_NEW:
	case CONN_READY:
	case CONN_EOF:
		syslog(LOG_ERR, "Received EOF in state %d - removing slave\n",
		       c->state);
		remove_slave(c->node, 0);
		break;
	case CONN_RUNNING:{
			struct request_t *req;
			struct bproc_null_msg_t *msg;

			c->state = CONN_EOF;

			req = bproc_new_req(BPROC_NODE_EOF, sizeof(*msg));
			msg = bproc_msg(req);
			bpr_from_node(msg, -1);
			bpr_to_node(msg, c->node->id);
			conn_send(c, req);

			slave_next_connection(c->node);	/* start using next connection */
		}
		break;
	case CONN_DEAD:	/* should never happen */
		assert(0);
	}
}

static
void conn_send_ping(struct conn_t *c)
{
	struct request_t *req;
	struct bproc_ping_msg_t *msg;

	req = bproc_new_req(BPROC_NODE_PING, sizeof(*msg));
	msg = bproc_msg(req);
	bpr_from_node(msg, -1);
	bpr_to_node(msg, c->node->id);
	msg->time_sec = msg->time_usec = 0;	/* filled in at the last moment */
	conn_send(c, req);
}

static
void conn_send_conf(struct conn_t *c)
{
	struct request_t *req;
	struct bproc_conf_msg_t *msg;
	int masters_bytes;

	masters_bytes = conf.master_list_size * sizeof(*conf.master_list);

	req = bproc_new_req(BPROC_NODE_CONF, sizeof(*msg) + masters_bytes);
	msg = bproc_msg(req);
	bpr_from_node(msg, -1);
	bpr_to_node(msg, c->node->id);

	msg->ping_timeout = conf.ping_timeout;
	msg->private_namespace = conf.slave_private_namespace;

	/* append masters to the end of the message */
	msg->masters = sizeof(*msg);
	msg->masters_size = conf.master_list_size;
	memcpy(((void *)msg) + msg->masters, conf.master_list, masters_bytes);

	msg->time_sec = msg->time_usec = 0;	/* filled in at the last moment */
	conn_send(c, req);
}

/* Remove a single connection from a slave */
static
void remove_slave_connection(struct conn_t *conn)
{
	struct node_t *n = conn->node;

	/* Clean up this connection.  Only connections in the NEW or EOF
	 * states may be safely tossed without affecting the slave
	 * state. */
	if (conn->state != CONN_NEW && conn->state != CONN_EOF) {
		/* Remove slave will remove ALL (including this one) */
		remove_slave(n, 0);
	} else {
		list_del(&conn->list);
		conn->state = CONN_DEAD;
		list_add_tail(&conn->list, &conn_dead);
	}
}

static
void remove_client_connection(struct conn_t *conn)
{
	struct epoll_event ev;


	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL,conn->fd, &ev)) {
			syslog(LOG_ERR, 
				"remove_client_connection: fd %d: epoll_ctl(EPOLL_CTL_DEL): %s",
				conn->fd, strerror(errno));
	}
	(void) close(conn->fd);
	conn->fd = -1;
	conn->type = -1;
	conn->state = CONN_DEAD;
}

static
void remove_connection(struct conn_t *conn)
{
	if (conn->type == SLAVE)
		remove_slave_connection(conn);
	else
		remove_client_connection(conn);

}

/* This function will completely trash slave state, optionally keeping
 * one connection open. */
static
void remove_slave(struct node_t *s, struct conn_t *conn_to_keep)
{
	struct request_t *r;
	struct conn_t *conn;
	struct list_head *l, *next;

	/* Remove all connections except for conn */
	for (l = s->clist.next; l != &s->clist; l = next) {
		next = l->next;
		conn = list_entry(l, struct conn_t, list);
		if (conn != conn_to_keep) {
			/* Schedule this connection for deletion */
			list_del(&conn->list);
			conn->state = CONN_DEAD;
			list_add_tail(&conn->list, &conn_dead);
		}
	}

	s->running = 0;
	set_node_addr(s);	/* update connection address in bpfs */

	/* Reset slave state */
	set_node_state(s, "down");

	/* Remove associations and kill off ghosts? - yeah, that'd be a
	 * good thing to do... */
	assoc_purge(s);

	/* Dispose of queued requests for the slave.  Our other request
	 * tracking stuff should take care of generating responses that
	 * this slave was responsible for. */
	while (!list_empty(&s->reqs)) {
		r = list_entry(s->reqs.next, struct request_t, list);
		list_del(&r->list);
		req_free(r);
	}
}

/* Set a connection to "READY".  This is one once a slave has
 * connected and provided version information and a cookie. */
static
void slave_set_ready(struct node_t *s, struct conn_t *conn)
{
	/* If this node is just coming up we have to do a bunch of special
	 * stuff... */
	if (s->status == 0) {
		/* If the node is down, go straight to RUNNING */
		conn->state = CONN_RUNNING;
		s->running = conn;
		set_node_addr(s);	/* update connection address in bpfs */

		INIT_LIST_HEAD(&s->reqs);	/* should be redundant */
		s->ping_in = 2;
		set_node_state(s, "boot");
		run_node_up(s);

		/* This is gross, it should probably be done with write_refill */
		conn_send_conf(conn);	/* Conf means it's ready. */
	} else {
		conn->state = CONN_READY;
		/* If the node is reconnecting, just send the conf... This
		 * serves as an indication to the remote end that we like the
		 * cookie and version information that they just sent to
		 * us. */
		conn_send_conf(conn);
	}
	s->mtime = now();
}

static
void slave_next_connection(struct node_t *s)
{
	struct conn_t *c;
	struct list_head *l;
	struct request_t *req;

	for (l = s->clist.next; l != &s->clist; l = l->next) {
		c = list_entry(l, struct conn_t, list);
		if (c->state == CONN_READY)
			break;
	}

	if (c) {
		s->running = c;
		set_node_addr(s);	/* update connection address in bpfs */
		c->state = CONN_RUNNING;
		if (conn_out_empty(c))
			conn_write_refill(c);

		/* Process message backlog (if any) */
		while (!list_empty(&c->backlog)) {
			req =
			    list_entry(c->backlog.next, struct request_t, list);
			list_del(&req->list);
			route_message(req);
		}
	} else {
		/* No ready connection for this slave - ditch it */
		remove_slave(s, 0);
	}
}

/* Send a message down a connection (not to a particular slave) */

static
void send_version(struct conn_t *c)
{
	struct request_t *req;
	struct bproc_version_msg_t *msg;

	req = bproc_new_req(BPROC_VERSION, sizeof(*msg));
	msg = bproc_msg(req);
	bpr_from_node(msg, -1);
	bpr_to_node(msg, c->node->id);
	memcpy(&msg->vers, &version, sizeof(version));
	msg->cookie = c->node->cookie;

	conn_send(c, req);
}

static
void send_ping(struct node_t *s)
{
	s->atime = now();
	conn_send_ping(s->running);
}

static
void slave_new_connection(struct node_t *s, struct interface_t *ifc,
			  struct sockaddr_in *raddr, int fd)
{
	struct conn_t *conn;
	struct epoll_event ev;

	if (s->status == 0)
		s->cookie = cookie_seq++;
	s->mtime = now();

	conn = &connections[fd];
	conn->node = s;
	conn->fd = fd;
	conn->type = SLAVE;
	conn->state = CONN_NEW;
	conn->ctime = time(0);
	conn->laddr = ifc->addr.sin_addr;
	conn->raddr = raddr->sin_addr;

	/* I/O buffering */
	INIT_LIST_HEAD(&conn->backlog);
	INIT_LIST_HEAD(&conn->reqs);
	conn->ioffset = 0;
	conn->ireq = 0;
	conn->ooffset = 0;
	conn->oreq = 0;

	/* Append to connection list */
	list_add_tail(&conn->list, &s->clist);

	/* Add this FD to our world */
	ev.events = 0;
	ev.data.u32 = EV(SLAVE, conn->fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD, %d, %p): %s", conn->fd, &ev,
		       strerror(errno));
		exit(1);
	}

	/* Prime output buffer with version information and cookie */
	send_version(conn);
	conn_update_epoll(conn);
}

static
int accept_new_slave(struct interface_t *ifc)
{
	int slavefd, i, j;
	struct sockaddr_in remote;

	socklen_t remsize = sizeof(remote);
	slavefd = accept(ifc->fd, (struct sockaddr *)&remote, &remsize);
	if (slavefd == -1) {
		if (errno == EAGAIN)
			return 0;
		syslog(LOG_ERR, "accept: %s", strerror(errno));
		return -1;
	}

	if (verbose)
		syslog(LOG_INFO, "connection from %s", ip_to_str(&remote));
	if (conf.require_secure_port && ntohs(remote.sin_port) >= 1024) {
		syslog(LOG_NOTICE, "connect from insecure port (%d).",
		       (int)ntohs(remote.sin_port));
		close(slavefd);
		return -1;
	}
	set_keep_alive(slavefd);
	set_no_delay(slavefd);
	set_non_block(slavefd);

	/* determine node number based on remote IP address */
	for (i = 0; i < conf.num_nodes; i++) {
		for (j = 0; j < conf.nodes[i].naddr; j++) {
			if (remote.sin_addr.s_addr ==
			    conf.nodes[i].addr[j].s_addr) {
				if (verbose)
					syslog(LOG_INFO,
					       "connect from node %d.",
					       conf.nodes[i].id);
				slave_new_connection(&conf.nodes[i], ifc,
						     &remote, slavefd);
				return 0;
			}
		}
	}
	syslog(LOG_NOTICE, "Connect from unrecognized node %s",
	       ip_to_str(&remote));
	close(slavefd);
	return -1;
}

/**------------------------------------------------------------------------
 **  Process management
 **----------------------------------------------------------------------*/
static
void set_proc_location(struct assoc_t *a, struct node_t *loc)
{
	struct setprocloc_t nl;

	a->proc = loc;

	nl.pid = assoc_pid(a);
	nl.node = a->proc ? a->proc->id : BPROC_NODE_MASTER;
#if 0
	if (ioctl(ghostfd, BPROC_SETPROCLOC, &nl)) {
		syslog(LOG_ERR, "ioctl(BPROC_SETPROCLOC, {%d, %d}): %s",
		       nl.pid, nl.node, strerror(errno));
	}
#endif

	{			/* debugging spew */
		/* This is kind of a dummy request to say when process
		 * locations get updated */
		struct bproc_debug_1000_msg_t msg;
		msg.hdr.req = 1000;
		msg.hdr.size = sizeof(msg);
		msg.pid = nl.pid;
		msg.node = nl.node;
		msgtrace(BPROC_DEBUG_OTHER, 0, ((struct request_t *)&msg) - 1);
	}
}

static
struct request_t *response(struct request_t *req, int err)
{
	struct request_t *resp;
	struct bproc_null_msg_t *msg;

	resp = bproc_new_resp(req, sizeof(*msg));
	msg = bproc_msg(resp);
	msg->hdr.result = err;

	return resp;
}

static
void respond(struct request_t *req, int err)
{
	struct request_t *resp;

	resp = response(req, err);
	route_message(resp);
}

/* this either works or it doesn't. If it doesn't, we won't bother the parent 
 * with that knowledge. 
 */
static
int do_run_request(struct request_t *req)
{
	/* read in a run message. It is text except for the cpio part. */
	/* no */
	return -1;
}

static
void do_run_response(struct request_t *req)
{
	/* we don't do this ever */
	return;
}

static
void do_exit_request(struct request_t *req)
{
	struct assoc_t *a;
	struct bproc_status_msg_t *msg;
	msg = bproc_msg(req);
	a = assoc_find(msg->hdr.from);
	/* might want to send a kill here but the new protocol is incomplete. */
	assoc_clear_proc(a);
}

static
void do_fork_response(struct request_t *req)
{
	/* we're not supporting this one */
}

static
void do_get_status(struct request_t *req)
{
	int i;
	void *id;
	struct node_t *n;
	struct bproc_null_msg_t *msg;

	msg = bproc_msg(req);
	id = msg->hdr.id;
	req_free(req);

	/* Explode all this request out into a request for each node
	 * that's up. */
	for (i = 0; i < conf.num_nodes; i++) {
		n = &conf.nodes[i];
		if (n->status != 0) {
			req = bproc_new_req(BPROC_GET_STATUS, sizeof(*msg));
			msg = bproc_msg(req);
			bpr_to_node(msg, n->id);
			bpr_from_node(msg, -1);
			msg->hdr.result = 0;
			msg->hdr.id = id;
			route_message(req);
		}
	}
}

/**------------------------------------------------------------------------
 **  Handle incoming requests
 **----------------------------------------------------------------------*/
static
int route_message(struct request_t *req)
{
	struct node_t *node;
	struct assoc_t *assoc, *fromassoc = 0;
	struct bproc_message_hdr_t *hdr;

	hdr = bproc_msg(req);

	/* Keep track of requests and responses that come through us so
	 * that we can generate errors if a slave daemon dies. */
	if (BPROC_ISRESPONSE(hdr->req)) {
		if (hdr->totype == BPROC_ROUTE_REAL) {
			assoc = assoc_find(hdr->to);
			assoc->req = 0;	/* clear outstanding request */
		}
	} else {
		if (hdr->fromtype == BPROC_ROUTE_REAL &&
		    hdr->totype != BPROC_ROUTE_GHOST) {
			/* Don't make note of requests to ghosts...  We will never
			 * have to generate an error response due to ghost
			 * disappearance. */
			switch (hdr->req) {
				/* Don't make note of these because we don't ever want
				 * to auto-generate responses to these messages */
			case BPROC_GET_STATUS:
			case BPROC_NODE_REBOOT:
				break;
			default:
				fromassoc = assoc_find(hdr->from);
				fromassoc->req = hdr->req;
				fromassoc->req_id = hdr->id;
				break;
			}
		}
	}

    /*** SPECIAL HANDLING FOR CERTAIN MESSAGES ***/
	switch (hdr->req) {
	case BPROC_RUN:{	
		void *stack;

		stack = malloc(8192);
		if (!stack) {
			fprintf(stderr, "Out of memory.\n");
			return -1;
		}
		/* no need to CLONE_VM afaict */
		clone((int (*)(void *))do_run_request,
			   stack + 8192 - sizeof(long),
			   CLONE_FS | CLONE_FILES, bproc_msg(req));
		/* either it worked or did not, but we don't much care */
		/* IF WE EVER CLONEVM WE HAVE TO REMOVE THIS FREE */
		free(stack);
		if ((req)) {
			req_free(req);
			return 0;
		}
		break;
		}
	case BPROC_RESPONSE(BPROC_RUN):
		do_run_response(req);	/* Routing happens in here... */
		return 0;
	/* someday ... 
	case BPROC_EXIT:
		do_exit_request(req);
		break;
	*/
	case BPROC_NODE_DOWN:
		node = find_node_by_number(hdr->to);
		if (node) {
			syslog(LOG_INFO, "Disconnecting slave %d", node->id);
			remove_slave(node, 0);
		} else {
			syslog(LOG_ERR,
			       "Received NODE_DOWN for bad node number: %d",
			       hdr->to);
		}
		req_free(req);
		return 0;	/* message stops here. */
	}
    /*** END SPECIAL HANDLING FOR CERTAIN MESSAGES ***/

	switch (hdr->totype) {
	case BPROC_ROUTE_NODE:
		/* Handle the messages addressed to the master */
		if (hdr->to == -1) {
			if (fromassoc)
				fromassoc->req_dest = 0;
			switch (hdr->req) {
			case BPROC_NODE_PING:
				respond(req, 0);
				req_free(req);
				break;
			case BPROC_RESPONSE(BPROC_NODE_PING):
				/* we updated ping for the node when it came in... */
				req_free(req);
				break;
			case BPROC_GET_STATUS:
				do_get_status(req);
				break;
			default:
				/* there's probably nothing that falls in here (?) */
				/*list_add_tail(&req->list, &ghost_reqs); */
				//send_msg(0, req);
				syslog(LOG_ERR,
			       "Received BPROC_ROUTE_NODE but not sure what to do yet");
			}
		} else {
			node = find_node_by_number(hdr->to);
			if (!node) {
				if (!BPROC_ISRESPONSE(hdr->req)) {
					respond(req, -BE_INVALIDNODE);
					req_free(req);
				}
				return -1;
			}
			if (node->status == 0) {
				if (!BPROC_ISRESPONSE(hdr->req)) {
					respond(req, -BE_NODEDOWN);
					req_free(req);
				}
				return -1;
			}
			if (fromassoc)
				fromassoc->req_dest = node;
			/*list_add_tail(&req->list, &node->reqs); */
			send_msg(node, -1, req);
		}
		break;
	case BPROC_ROUTE_REAL:
		assoc = assoc_find(hdr->to);
		if (fromassoc)
			fromassoc->req_dest = assoc->proc;
		send_msg(assoc->proc, -1, req);
		break;
	case BPROC_ROUTE_GHOST:
		/* no idea yet. */
		if (fromassoc)
			fromassoc->req_dest = 0;
		//send_msg(0, req);
		break;
	default:
		syslog(LOG_ERR, "Unknown totype in route_message(): %d\n",
		       hdr->totype);
		break;
	}
	return 0;
}

static
int bytesavail(int fd)
{
	size_t ret;
	if (ioctl(fd, FIONREAD, &ret) < 0)
		return -1;

	return ret;
}

static
int accept_new_client(void)
{
	int clientfd;
	struct epoll_event ev;
	ev.events = EPOLLIN;
	struct sockaddr_in remote;
	struct conn_t *conn;
	struct ucred ucred;
	socklen_t size;

	socklen_t remsize = sizeof(remote);
	clientfd = accept(clientconnect, (struct sockaddr *)&remote, &remsize);
	if (clientfd == -1) {
		if (errno == EAGAIN)
			return 0;
		syslog(LOG_ERR, "accept: %s", strerror(errno));
		return -1;
	}

	/* if you can not get creds then you can not get the service. Too bad. */
	size = sizeof(ucred);
	if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &ucred, &size) == -1) {
		syslog(LOG_ERR, "getsockopt(SO_PEERCRED): %s", strerror(errno));
		return -1;
	}

	if (verbose)
		syslog(LOG_INFO, "connection from %s", ip_to_str(&remote));

	set_non_block(clientfd);

	conn = &connections[clientfd];
	conn->fd = clientfd;
	conn->type = CLIENT;
	conn->state = CONN_RUNNING;
	conn->ctime = time(0);
	conn->raddr = remote.sin_addr;
	conn->user = ucred.uid;
	conn->group = ucred.gid;

	/* I/O buffering */
	INIT_LIST_HEAD(&conn->backlog);
	INIT_LIST_HEAD(&conn->reqs);
	conn->ioffset = 0;
	conn->ireq = 0;
	conn->ooffset = 0;
	conn->oreq = 0;

	/* Add this FD to our world */
	ev.events = 0;
	ev.data.u32 = EV(CLIENT, conn->fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD, %d, %p): %s", conn->fd, &ev,
		       strerror(errno));
		exit(1);
	}

	conn_update_epoll(conn);
	return 0;
}

int
run_ok(struct node_t *s, uid_t uid, gid_t gid)
{
	/* root: always */
	if (uid == 0)
		return 1;
	if ((s->user == uid) && (s->mode & S_IXUSR))
		return 1;
	if ((s->group == gid) && (s->mode & S_IXGRP))
		return 1;
	if (s->mode & S_IXOTH)
		return 1;

	return 0;
}
/* be sensitive to possible bad messages from clients. */
int
run_nodes(struct conn_t *c, struct request_t *req, struct node_t ***s, int *max)
{
	char *msg = bproc_msg(req), *cp;
	struct bproc_message_hdr_t *hdr;
	int i, len;
	int maxnodes, actualnodes;
	uid_t uid;
	gid_t gid;
	struct node_t **list;
	/* unpack the request node list, and for each node, see if it is "real" */
	/* Just use the count they pass, if there is less, that is ok */
	hdr = (struct bproc_message_hdr_t *)msg;
	len = hdr->size;
	cp = msg + sizeof(*hdr);
	/* skip packoff, we don't care */
	cp += 8;
	/* Plug in the real uid and gid */
	snprintf(cp, 9, "%08d", c->user);
	cp += strlen(cp) + 1;
	snprintf(cp, 9, "%08d", c->group);
	cp += strlen(cp) + 1;
	/* skip index */
	cp += strlen(cp) + 1;
	if (len < (int)(cp-msg)){
		return 0;
	}
	maxnodes = strtoul(cp, 0, 10);
	*max = maxnodes;
	/* is it sane? This simple test captures much badness. It also ensures we can at least start on the path. */
	if (maxnodes > len)
		return 0;
	*s = calloc(maxnodes, sizeof(*s));
	if (! *s)
		return 0;
	list = *s;
	for(i = actualnodes = 0; i < maxnodes; i++) {
		struct node_t *node;
		cp += strlen(cp) + 1;
		if (len < (int)(cp-msg)){
			free(*s);
			return 0;
		}
		node = find_node_by_number(strtoul(cp, 0, 10));
		if (! node)
			continue;
		if (! run_ok(node, c->user, c->group))
			continue;
		/* what we'll do is run on all allowed -- this avoids weird races. */
		*list++ = node;
		actualnodes++;
	}
	if (! actualnodes){
		free(*s);
		*s = NULL;
	}

	return actualnodes;

}

void set_index(struct request_t *req, int i)
{
	char *msg = bproc_msg(req), *cp;
	struct bproc_message_hdr_t *hdr;
	hdr = (struct bproc_message_hdr_t *)msg;
	cp = msg + sizeof(*hdr);
	/* skip the packet start info */
	cp += 8;
	/* skip the uid and gid -- btw -- this way of doing RPCs sucks. My bad. */
	cp += strlen(cp) + 1;
	cp += strlen(cp) + 1;
	
	(void)snprintf(cp, 8, "%07d", i);
}
/* "ghost" is a little dated in this function name. */
/* we don't talk to the client much at all. They send a request to 
 * start a proc and we let them know if anything happened. That's about it. 
 * so we don't use route_message for now until we think we might. 
 */
static
int client_msg_in(struct conn_t *c, struct request_t *req)
{
	struct bproc_message_hdr_t *hdr;
	struct sockaddr_in addr;

	msgtrace(BPROC_DEBUG_MSG_FROM_SLAVE, c, req);

	hdr = bproc_msg(req);
	switch (hdr->req) {
	case BPROC_RUN:{
		int i;
		struct node_t **s;
		int nodecount;
		struct request_t *nreq;
		int maxnode;

		/* TODO: connect to the process's open TCP sockets and report errors via that way. We don't 
		 * ack or do any such thing right now. The logical place is via the io forwarding path since slaves
		 * are goint to use that path anyway
		 */
		nodecount = run_nodes(c, req, &s, &maxnode);

		/* don't rewrite header (yet) */
		for(i = 0; i < nodecount-1; i++) {
			nreq = req_clone(req);
			set_index(req, s[i]->id);
			/* need to adjust the "index" of this set of nodes, so they pick the right ports */
			send_msg(s[i], -1, req);
			req = nreq;
		}
		if (i < nodecount){
			set_index(req, s[i]->id);
			send_msg(s[i], -1, req);
		}
		free(s);
		break;
	}
	case BPROC_GET_STATUS:{
		/* TODO: return s-expression? Or just structs for now? Think a bit. */
		int i;
		struct bproc_node_info_t *nodes;
		struct bproc_nodestatus_resp_t *msg;
		struct request_t *resp;
		resp = bproc_new_resp(req, sizeof(*msg) + numnodes() * sizeof(*nodes));
		msg = bproc_msg(resp);
		nodes = msg->node;
		for(i = 0; i < numnodes(); i++)
			if (bprocnodeinfo(i, &nodes[i]) < 0)
				break;
		msg->numnodes = i;
		conn_send(c, resp);
		break;
	}
	default:{
			syslog(LOG_NOTICE,
			       "Received message of type %d on a client connection ", hdr->req);
			req_free(req);
			return 0;
		}
	}
	return 1;

}

static
void fd_update_epoll(int fd, int type, int in, int out)
{
	struct epoll_event ev;
	ev.events = 0;
	if (in)
		ev.events |= EPOLLIN;
	if (out)
		ev.events |= EPOLLOUT;
	ev.data.u32 = EV(type, fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD, %d, {0x%x, %p} ): %s",
		       fd, ev.events, ev.data.ptr, strerror(errno));
		exit(1);
	}

}
static
void conn_update_epoll(struct conn_t *c)
{
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = 0;
	if (c->state != CONN_EOF && c->state != CONN_DEAD)
		ev.events |= EPOLLIN;
	if (!conn_out_empty(c))
		ev.events |= EPOLLOUT;
	ev.data.u32 = EV(c->type, c->fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_MOD, %d, {0x%x, %p} ): %s",
		       c->fd, ev.events, ev.data.ptr, strerror(errno));
		exit(1);
	}
}

static
int slave_msg_in(struct conn_t *c, struct request_t *req)
{
	struct bproc_message_hdr_t *hdr;

	msgtrace(BPROC_DEBUG_MSG_FROM_SLAVE, c, req);

	hdr = bproc_msg(req);
	switch (hdr->req) {
	case BPROC_VERSION:{
			struct node_t *s = c->node;
			struct bproc_version_msg_t *msg;

			if (c->state != CONN_NEW) {
				syslog(LOG_NOTICE,
				       "Received VERSION on non-new connection.");
				remove_slave_connection(c);
			}

			msg = bproc_msg(req);

			if (msg->hdr.req != BPROC_VERSION
			    || msg->hdr.size != sizeof(*msg)) {
				syslog(LOG_ERR,
				       "Received invalid message on new connection "
				       "from slave %d.", c->node->id);
				remove_slave_connection(c);
				return 0;
			}

			/* Check version information */
			if (version.magic != msg->vers.magic ||
			    strcmp(version.version_string,
				   msg->vers.version_string) != 0) {
				syslog(LOG_NOTICE,
				       "node %d: version mismatch.  master=%s-%u;"
				       " slave=%s-%u (%s)", s->id,
				       version.version_string,
				       (int)version.magic,
				       msg->vers.version_string,
				       (int)msg->vers.magic,
				       ignore_version ? "ignoring" :
				       "disconnecting");
				if (!ignore_version) {
					remove_slave_connection(c);
					return 0;
				}
			}

			/* Inspect the cookie */
			if (s->status != 0) {
				if (msg->cookie == 0) {
					syslog(LOG_NOTICE, "replacing slave %d",
					       s->id);
					remove_slave(s, c);	/* c = connection to keep here. */
					slave_set_ready(s, c);
				} else if (msg->cookie == s->cookie) {
					syslog(LOG_NOTICE,
					       "new connection from node %d",
					       s->id);
					slave_set_ready(s, c);
				} else {
					syslog(LOG_NOTICE,
					       "bad slave connection from node %d",
					       s->id);
					/* node up, re-connect request is bad, just toss the new
					 * connection */
					remove_slave_connection(c);
					return 0;
				}
			} else {
				if (msg->cookie) {
					syslog(LOG_NOTICE,
					       "bad slave connection from node %d",
					       s->id);
					/* Can't reconnect if the node is down. */
					remove_slave_connection(c);
					return 0;
				} else {
					/* new, node down */
					slave_set_ready(s, c);
				}
			}

			return 1;
		};

	case BPROC_RESPONSE(BPROC_NODE_PING):
		if (c->state == CONN_RUNNING)
			c->node->ping_in = 2;
		req_free(req);
		return 1;
	case BPROC_NODE_EOF:
		if (c->state != CONN_RUNNING) {
			syslog(LOG_NOTICE,
			       "Received EOF on non-running connection.");
			remove_slave_connection(c);
			return 0;
		}
		conn_eof(c);
		return 1;
	default:
		if (c->state == CONN_RUNNING) {
			route_message(req);
		} else if (c->state == CONN_READY) {
			/* Buffer messages on ready connections */
			list_add_tail(&req->list, &c->backlog);
		} else {
			syslog(LOG_NOTICE,
			       "Received message of type %d on a connection "
			       " that was neither running or ready.", hdr->req);
			remove_slave_connection(c);
			return 0;
		}
		return 1;
	}
}

/* functions that implement a slave */
/* managing masters */
/* there is support here for multiple masters. It is not clear this is a good idea, we may delete it later */
static
struct mymaster_t *master_new(void)
{
	struct mymaster_t *m;
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
void master_add_addr(struct mymaster_t *m, struct sockaddr *addr)
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
struct mymaster_t *master_find_by_addr(struct sockaddr *addr)
{
	struct list_head *l;
	struct mymaster_t *m;
	int i;

	for (l = masters.next; l != &masters; l = l->next) {
		m = list_entry(l, struct mymaster_t, list);
		for (i = 0; i < m->naddr; i++) {
			if (memcmp(&m->addr[i], addr, sizeof(*addr)) == 0)
				return m;
		}
	}
	return 0;
}

static struct conn_t *conn_new(struct sockaddr_in *raddr, struct sockaddr_in *laddr);

static
int slave_setup(struct sockaddr_in *remaddr, struct sockaddr_in *locaddr)
{
	struct conn_t *newc;

	newc = conn_new((struct sockaddr_in *)remaddr,
			(struct sockaddr_in *)locaddr);
	if (!newc)
		return -1;

	return 0;

}

/* we don't fork per slave in this version. We add a new active fd per slave. */
static
int start_slave(struct mymaster_t *master)
{
	int i;
	struct sockaddr_in local_addr;

	memset(&local_addr, 0, sizeof(local_addr));
	if (verbose)
		syslog(LOG_INFO, "Starting new slave %d", master->index);

	master->attempted = 1;

	/* Start trying to connect */
	for (i = 0; i < master->naddr; i++) {
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = INADDR_ANY;
		if (slave_setup((struct sockaddr_in *)&master->addr[i], &local_addr) == 0)
			break;
	}
	if (i == master->naddr) {	/* failure */
		syslog(LOG_DEBUG, "Slave setup failed.");
		exit(1);
	}

//	nslaves++;
	return 0;
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
struct runargs {
	struct conn_t *c;
	struct request_t *req;
};
void 
runthread(struct runargs *r)
{
	struct conn_t *c = r->c;
	struct request_t *req = r->req;
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
	uid_t uid;
	gid_t gid;
	int ret;
	int fd;
	int i;
	/* clean path */
	if (umount("/tmp") || mount("none", "/tmp", "tmpfs", 0, 0)) {
		syslog(LOG_ERR, "mount(\"none\", \"%s\", \"tmpfs\", 0, 0): %s",
		       "/tmp", strerror(errno));
		exit(1);
	}

	dirname=strdup("/tmp/bproc2XXXXXX");
	mkdtemp(dirname);
	hdr = (struct bproc_message_hdr_t *)msg;
	len = hdr->size;
	cp = msg + sizeof(*hdr);
	/* get the packet start. Nodes will start at 8 bytes past this point. */
	packoff = strtoul(cp, 0, 10);
	packstart = cp + packoff;
	syslog(LOG_NOTICE, "do_run: cp %p packoff %d packstart %p", cp, packoff, packstart);
	cp += 8;
syslog(LOG_NOTICE, "cp %s", cp);
	uid = strtoul(cp, 0, 10);
	cp += strlen(cp) + 1;
syslog(LOG_NOTICE, "cp %s", cp);
	gid = strtoul(cp, 0, 10);
	cp += strlen(cp) + 1;
	syslog(LOG_NOTICE, "uid %d gid %d\n", uid, gid);
	node = strtoul(cp, 0, 10);
syslog(LOG_NOTICE, "index @ %d i %s %d", (int)(cp-msg),cp, node);
	cp += strlen(cp) + 1;
	syslog(LOG_NOTICE, "do_run: cp %s\n", cp);
	syslog(LOG_NOTICE, "buildarr %p %p %p\n", &cp, &argc, &argv);
	buildarr(&cp, &nodec, &nodes);
	syslog(LOG_NOTICE, "buildarr %p %p %p\n", &cp, &nodec, &nodes);

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
	/* fix the tmp directory permission while we are still root*/
	chmod(dirname, 0700);
	chown(dirname, uid, gid);
	setgid(gid);
	setuid(uid);
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
	/* note: don't worry about freeing this. We're  going to exec or exit either way */
	char *name = malloc(strlen(argv[0]) + strlen("./") + 1);
	name[0] = 0;
	strcat(name, "./");
	strcat(name, argv[0]);
	argv[0] = name;
	/* fix up IO */
	/* weirdly it seems bproc forwarding current sends all the same port. But let's plan for the future. 
	 * new socket for each port (soon)
	 */
	for(i = 0; i < portc; i++) {
		addr.sin_addr = c->raddr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(strtoul(ports[i], 0, 10));
		fd = setup_iofw(&addr);
		write(fd, &node, sizeof(node));
		write(fd, &i, sizeof(i));
		dup2(fd, i);
	}
	putenv("LD_LIBRARY_PATH=lib:lib64:usr/lib:usr/lib64");
	syslog(LOG_NOTICE, "do_run: exec %s\n", argv[0]);
	execv(argv[0], argv);
	syslog(LOG_NOTICE, "do_run: exec %s FAILED\n", argv[0]);
	exit(1);
}

int 
do_run(struct conn_t *c, struct request_t *req)
{
	int ret;
	void *stack;
	struct runargs *r;

	syslog(LOG_NOTICE, "do_run: startup");
	r = malloc(sizeof(*r));
	if (! r)  {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}
	stack = malloc(8192);
	if (!stack) {
		free(r);
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}
	r->c = c;
	r->req = req;
	/* no need to CLONE_VM afaict */
	clone((int (*)(void *))runthread,
		   stack + 8192 - sizeof(long),
		   CLONE_NEWNS, r);
	/* either it worked or did not, but we don't much care */
	/* IF WE EVER CLONEVM WE HAVE TO REMOVE THIS FREE */
	free(r);
	free(stack);
	if ((req)) {
		req_free(req);
		return 0;
	}

}

/* NOTE: as of 2/25/2010, these are in just enough to get it to build. Lots of work left. */
static
void reconnect(struct conn_t *conn, struct request_t *req)
{

}

/* This is a bit of a mess.  It would be cleaner if the slave daemon *
 * could know ahead of time whether or not a private name space was
 * desired.  That would allow */
static
int privatize_namespace(void)
{
	/* we sort of privatize always now. Only issue is whether to chroot and bpsh should indicate that. So this 
	 * function may have no use
	 */
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

static void conn_respond(struct conn_t *c, struct request_t *req, int err);
/* no real connection list yet. Ignore for now */
static
void set_running(struct conn_t *conn)
{
	struct conn_t *c;
	int addrsize;
	struct sockaddr addr;
	struct list_head *l;

#if 0
	for (l = clist.next; l != &clist; l = l->next) {
		c = list_entry(l, struct conn_t, list);
		if (c != conn && c->state == CONN_RUNNING)
			conn_eof(c);
	}
#endif
	conn->state = CONN_RUNNING;
	conn_out = conn;
	if (!conn_in)
		conn_in = conn;

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

/* special functions for slave IO to master. These need to be merged at some point. It may not be possible as the 
 * behavior is very different from slave io to master io. */
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
struct conn_t *conn_new(struct sockaddr_in *raddr, struct sockaddr_in *laddr)
{
	struct conn_t *c;
	int fd;
	int lsize, errnosave;
	struct sockaddr_in tmp;
	struct epoll_event ev;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		errnosave = errno;
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		errno = errnosave;
		return 0;
	}

	c = &connections[fd];
	memset(c, 0, sizeof(*c));
	c->fd = fd;
	c->type = MASTER;
	c->state = CONN_NEW;
	c->ctime = time(0);

	/* I/O buffering */
	INIT_LIST_HEAD(&c->backlog);
	INIT_LIST_HEAD(&c->reqs);
	c->ioffset = 0;
	c->ireq = 0;
	c->ooffset = 0;
	c->oreq = 0;

	/* not yet 
	set_non_block(c->fd);
	 */

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
			errno = errnosave;
			return 0;
		}
	}

	/* Make note of our local address */
	lsize = sizeof(c->laddr);
	getsockname(c->fd, (struct sockaddr *)&c->laddr, &lsize);
	c->raddr = raddr->sin_addr;

	/* Add this FD to our world */
	ev.events = 0;
	ev.data.u32 = EV(MASTER, c->fd);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->fd, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD, %d, %p): %s", c->fd, &ev,
		       strerror(errno));
		(void)close(c->fd);
		c->fd = -1;
	}

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

	if (conn->ireq) {
		syslog(LOG_NOTICE, "Reconnect failed: %s\n", strerror(reason));
		conn_respond(conn, conn->ireq, -reason);
		free(conn->ireq);
		conn->ireq = 0;
	}

	if (conn->state == CONN_RUNNING) {
		syslog(LOG_NOTICE, "Lost connection to master");

		/* Clean up other connections */
		while (!list_empty(&clist)) {
			struct conn_t *c;
			c = list_entry(clist.next, struct conn_t, list);
			list_del(&c->list);

			if (c->ireq)
				free(c->ireq);
			close(c->fd);
		}
	}
	if (conn->ireq)
		free(conn->ireq);
	close(conn->fd);
	conn->fd = -1;
}

/* what is this for, precisely? */
static inline void masq_send(struct request_t *req)
{
	list_add_tail(&req->list, &reqs_to_masq);
}


/*
 *  master_msg_in - handle an incoming master message
 *
 *  returns true if the connection is still alive after processing
 *  this message.
 */
static
int master_msg_in(struct conn_t *c, struct request_t *req)
{
	struct bproc_message_hdr_t *hdr;

	msgtrace(BPROC_DEBUG_MSG_FROM_MASTER, NULL, req);

	hdr = bproc_msg(req);
syslog(LOG_NOTICE, "master_msg_in: conn %p req %p type %d", c, req, hdr->req);

	switch (hdr->req) {
	case BPROC_VERSION:{
			struct bproc_version_msg_t *msg =
			    (struct bproc_version_msg_t *)hdr;

			if (version.magic != msg->vers.magic ||
			    strcmp(version.version_string,
				   msg->vers.version_string) != 0) {
				syslog(LOG_NOTICE,
				       "BProc version mismatch.  slave=%s-%u;"
				       " master=%s-%u (%s)",
				       version.version_string,
				       (int)version.magic,
				       msg->vers.version_string,
				       (int)msg->vers.magic,
				       ignore_version ? "ignoring" :
				       "disconnecting");
				if (!ignore_version)
					return -1;
			}
			cookie = msg->cookie;
			req_free(req);
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
syslog(LOG_NOTICE, "DONE CONF");

			conn_respond(c, req, 0);
			req_free(req);
		} return 1;
	case BPROC_NODE_PING:{
			struct bproc_ping_msg_t *msg;
syslog(LOG_NOTICE, "PING");
			msg = bproc_msg(req);
			update_system_time(msg->time_sec, msg->time_usec);
			conn_respond(c, req, 0);
			req_free(req);
		} return 1;
	case BPROC_NODE_EOF:
		/* not sure yet. 
		if (c->state != CONN_CLOSING)
			syslog(LOG_NOTICE,
			       "Received EOF on non-closing connection.");
		*/
		conn_remove(c, 0);
		req_free(req);
		return 0;

	/*--- Node commands ---*/
	case BPROC_NODE_CHROOT:
		/* not really supported */
		//do_slave_chroot(req);
		req_free(req);
		return 1;
	case BPROC_NODE_RECONNECT:
		reconnect(c, req);
		/* free handled internally */
		return 1;
	case BPROC_NODE_REBOOT:
	case BPROC_NODE_HALT:
	case BPROC_NODE_PWROFF:
		do_node_reboot(req);
		req_free(req);
		return 1;

	/* --- Process commands ---*/
	case BPROC_RUN:
		syslog(LOG_NOTICE, "RUN command");
		do_run(c, req);
		return 1;
	default:
		masq_send(req);
		return 1;
	}
}


static
int conn_msg_in(struct conn_t *c, struct request_t *req)
{
	int ret;
	if (c->type == SLAVE)
		ret = slave_msg_in(c, req);
	else if (c->type == CLIENT)
		ret = client_msg_in(c, req);
	else
		ret = master_msg_in(c, req);
	return ret;
}

static
void conn_err(struct conn_t *conn)
{
	if (conn->type == SLAVE) {
		struct node_t *s = conn->node;
		syslog(LOG_ERR, "lost connection to slave %d", s->id);
	} else if (conn->type == MASTER) {
		syslog(LOG_ERR, "lost connection to master");
	} else {
		syslog(LOG_ERR, "lost connection to client");
	}
}
/*
 *  conn_read - read data from a slave node connection
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
				syslog(LOG_ERR, "read(slave): %s",
				       strerror(errno));
			}
			if (r <= 0) {
				conn_err(c);
				remove_connection(c);
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
				syslog(LOG_ERR, "read(slave): %s",
				       strerror(errno));
			}
			if (r <= 0) {
				conn_err(c);
				remove_connection(c);
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
					       "Invalid message size %d", hdr->size);
					remove_connection(c);
					return;
				}
				c->ireq = req_get(hdr->size);
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
	msgtrace(BPROC_DEBUG_MSG_TO_SLAVE, c, req);

	c->oreq = req;
	c->ooffset = 0;
}

static
int conn_write_refill(struct conn_t *c)
{
	assert(conn_out_empty(c));

	switch (c->state) {
	case CONN_NEW:
	case CONN_READY:
		if (!list_empty(&c->reqs)) {
			conn_write_load(c, &c->reqs);
		}
		break;
	case CONN_RUNNING:
		/* Get next outgoing request */
		if (!list_empty(&c->reqs)) {
			conn_write_load(c, &c->reqs);
		} else if (c->node && !list_empty(&c->node->reqs)) {
			conn_write_load(c, &c->node->reqs);
		}
		break;
	case CONN_EOF:
		if (!list_empty(&c->reqs)) {
			conn_write_load(c, &c->reqs);
		} else {
			remove_connection(c);
			return 0;
		}
		break;
	case CONN_DEAD:
		fprintf(stderr, "CONN_DEAD: should never happen\n");
		abort();	/* should never happen */
	}

	if (!conn_out_empty(c)) {
		/* Special case: if this packet is a ping, put the current
		 * time of day in here. */
		struct bproc_message_hdr_t *msg;
		struct timeval now;
		msg = bproc_msg(c->oreq);
		if (tc.slave_time_sync) {
			if (msg->req == BPROC_NODE_CONF) {
				struct bproc_conf_msg_t *msg =
				    bproc_msg(c->oreq);
				gettimeofday(&now, 0);
				msg->time_sec = now.tv_sec;
				msg->time_usec = now.tv_usec;
			}
			if (msg->req == BPROC_NODE_PING) {
				struct bproc_ping_msg_t *msg =
				    bproc_msg(c->oreq);
				gettimeofday(&now, 0);
				msg->time_sec = now.tv_sec;
				msg->time_usec = now.tv_usec;
			}
		}
		/*FD_SETx(c->fd, wset_in, EPOLLOUT, c); */
		return 1;
	} else {
		/*FD_CLRx(c->fd, wset_in, c); */
		return 0;
	}
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
				return;
			syslog(LOG_NOTICE, "write(slave %d (%s)): %s",
			       c->node->id, ip_to_str_(c->raddr),
			       strerror(errno));
		}
		if (w <= 0) {
			syslog(LOG_NOTICE, "lost connection to slave %d",
			       c->node->id);
			remove_connection(c);
			return;
		}
		c->ooffset += w;
		if (c->ooffset == hdr->size) {	/* done sending message */
			req_free(c->oreq);
			c->oreq = 0;

			/* c might be an invalid pointer after write_refill. */
			if (!conn_write_refill(c))
				return;
		}
	}
}

static
void send_msg(struct node_t *s, int clientfd, struct request_t *req)
{
	if (s) {
		list_add_tail(&req->list, &s->reqs);
		if (!s->running) {
			fprintf(stderr, "%s:%d: slave %d is not running\n", __FUNCTION__, __LINE__, s->id);
			abort();
		}

		if (conn_out_empty(s->running)) {
			conn_write_refill(s->running);
			conn_update_epoll(s->running);
		}
	} else {
		list_add_tail(&req->list, &connections[clientfd].reqs);
		conn_update_epoll(&connections[clientfd]);
	}
}

static
void send_pings(void)
{
	int i;
	struct node_t *s;
	/* Send a ping to all nodes that are up... */
	for (i = 0; i < conf.num_nodes; i++) {
		s = &conf.nodes[i];
		if (s->status != 0) {
			if (s->ping_in == 0) {
				syslog(LOG_NOTICE, "ping timeout on slave %d",
				       s->id);
				remove_slave(s, 0);
			} else {
				send_ping(s);
				s->ping_in--;	/* Age the node */
			}
		}
	}
}

/* old meaning: set up the fd to talk the kernel
 * new meaning: set up the socket on which to accept requests from clients. 
 * Requests are pretty simple, of the form "run <command> on nodeset <nodeset>
 * The only request on this one, of course, is "hook me up!"
 */
static
int setup_master_fd(void)
{
	struct epoll_event ev;

	struct sockaddr_un sun;

 /*** set up socket crud ***/
	unlink(udsname);

	while ((clientconnect = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
   /*** with respect to BProc slaves, we need to wait ***/
   /***  for final file system to be set up (pivot_root) ***/
		if (errno != EACCES) {
     /*** unexpected error ***/
			exit(-1);
		}
		sleep(10);
	      /*** as per Ron's suggestion ***/
	}

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, udsname);
	umask(000);
	if (bind(clientconnect, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		perror("bind");
		return (-1);
	}
	if (listen(clientconnect, 16) != 0) {
		perror("listen");
		return (-1);
	}

	set_non_block(clientconnect);

	ev.events = EPOLLIN;
	ev.data.u32 = EV(CLIENT_CONNECT, clientconnect);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clientconnect, &ev)) {
		syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD): %s",
		       strerror(errno));
		exit(1);
	}
	return 0;
}

void daemonize(void)
{
	int fd, pid;
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "fork: %s", strerror(errno));
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
}

/* Signal handlers */
volatile int do_assoc_dump = 0;
volatile int do_config_reload = 0;
volatile int do_msgtrace = 0;
struct timeval timeleft;

void sigusr1_handler(void)
{
	signal(SIGUSR1, (void (*)(int))sigusr1_handler);
	do_assoc_dump = 1;
}

void sigusr2_handler(void)
{
	signal(SIGUSR2, (void (*)(int))sigusr2_handler);
	do_msgtrace = 1;
}

void sighup_handler(void)
{
	signal(SIGHUP, (void (*)(int))sighup_handler);
	do_config_reload = 1;
}

void usage(char *arg0)
{
	printf("Usage: %s [options]\n"
	       "\n"
	       "  -h        Print this message and exit.\n"
	       "  -V        Print version information and exit.\n"
	       "  -d        Do not daemonize self.\n"
	       "  -v        Increase verbose level.\n"
	       "  -i        Ignore interface version mismatch. (dangerous)\n"
	       "  -c file   Read configuration from file instead of %s\n"
	       "  -m file   Dump message trace to this file\n",
	       arg0, machine_config_file);
}

/* we've got this great async IO framework. There's no fundamental reason we can't function 
 * as a master and slave at the same time. So we'll allow it until convinced there is a reason not to. 
 * We only accept run commands over the Unix Domain Socket and the TCP connection to our master. 
 * From the UDS we only relay commands to our slaves. Is there a possibility for a cycle in the graph? 
 * Sort of. You can have cycles that don't include the root. So really it may in the long run be cleaner to 
 * have it bimodal, and run two copies of it on a tree-spawn node such that the slave relays run commands
 * to the master over the UDS. Maybe the right thing to do is the symlink trick: as the run requests
 * transit a master, increment a counter, and don't let them go more than four or five hops. 
 * At a reasonable fanout of 32, that is 32^5 nodes, or 32M nodes. 
 */
int main(int argc, char *argv[])
{
	char *check;
	struct sockaddr_in *addrp, addrtmp;
	int c, i, j, fd;
	int want_daemonize = 0;
	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};
	unsigned short port = DEFAULT_PORT;
	struct mymaster_t *master = NULL;

	memset(&addrtmp, 0, sizeof(addrtmp));
	addrp = &addrtmp;
	addrp->sin_family = AF_INET;

	while ((c =
		getopt_long(argc, argv, "f:hVc:m:p:s:dviu:", long_options, 0)) != EOF) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s (%s-%u)\n", argv[0],
			       PACKAGE_VERSION, version.version_string,
			       version.magic);
			exit(0);
		case 'i':
			ignore_version = 1;
			break;
		case 'c':
			machine_config_file = optarg;
			break;
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
				close(fd);
			}
			break;
		case 'p':
			port = strtol(optarg, &check, 0);
			if (*check) {
				syslog(LOG_ERR, "invalid port number: %s",
				       argv[optind + 1]);
				exit(1);
			}
			
		case 's': 
			if (inet_aton(optarg, &addrtmp.sin_addr) == 0) {
				syslog(LOG_ERR, "Invalid IP address: %s", optarg);
				exit(1);
			}
			slavemode = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			want_daemonize = 0;
			break;
		case 'u':
			udsname = optarg;
			break;
		default:
			exit(1);
		}
	}

	log_arg0 = argv[0];
	log_opts = verbose && !want_daemonize ? LOG_PERROR : 0;
	openlog(log_arg0, LOG_PERROR, conf.log_facility);

	epoll_fd = epoll_create(EPOLL_MAXEV);
	if (epoll_fd == -1) {
		syslog(LOG_ERR, "epoll_create: %s", strerror(errno));
		exit(1);
	}

	if (setup_master_fd())
		exit(1);

	memset(&conf, 0, sizeof(conf));
	if (master_config(machine_config_file)) {
		syslog(LOG_ERR,
		       "Failed to load machine configuration from \"%s\".",
		       machine_config_file);
		exit(1);
	}
	
	syslog(LOG_INFO, "machine contains %d nodes", conf.num_nodes);
	if (slavemode) {
		/* connect to the master */
		addrp->sin_port = htons(port);
		/* Create the first master with just this address */
		master = master_new();
		master_add_addr(master, (struct sockaddr *)&addrtmp);
	}
	connections = calloc(maxfd, sizeof(*connections));

	assoc_init();
	client_init();

	if (master)
		start_slave(master);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, (void (*)(int))sighup_handler);	/* reconfig */
	signal(SIGUSR1, (void (*)(int))sigusr1_handler);	/* debug */
	signal(SIGUSR2, (void (*)(int))sigusr2_handler);	/* debug */

	if (want_daemonize)
		daemonize();

	{
		int r;
		sigset_t sigset;
		time_t lastping, now;
		struct epoll_event epoll_events[EPOLL_MAXEV];
		lastping = time(0);

		sigemptyset(&sigset);
		sigaddset(&sigset, SIGHUP);
		sigaddset(&sigset, SIGUSR1);
		sigaddset(&sigset, SIGUSR2);
		sigprocmask(SIG_BLOCK, &sigset, 0);
		while (1) {
			/* Check random to-do items. */
			if (do_msgtrace) {
				/* TODO: Toggle message trace on and off */
				fd = open("/tmp/mtrace",
					  O_WRONLY | O_CREAT | O_APPEND |
					  O_TRUNC, 0666);
				if (fd != -1) {
					msgtrace_on(fd);	/* this does a dup */
					close(fd);
				}

				do_msgtrace = 0;
			}
			if (do_assoc_dump) {
				assoc_dump();
				do_assoc_dump = 0;
			}
			if (do_config_reload) {
				syslog(LOG_INFO,
				       "Rereading configuration from %s",
				       machine_config_file);
				master_config(machine_config_file);
				do_config_reload = 0;
			}

			now = time(0);
			timeleft.tv_sec =
			    now >=
			    lastping +
			    conf.ping_timeout / 2 ? 0 : conf.ping_timeout / 2 -
			    (now - lastping);
			if (timeleft.tv_sec == 0)
				timeleft.tv_sec = 2;
			timeleft.tv_usec = 0;

			sigprocmask(SIG_UNBLOCK, &sigset, 0);
			r = epoll_wait(epoll_fd, epoll_events, EPOLL_MAXEV,
				       timeleft.tv_sec * 1000 +
				       timeleft.tv_usec / 1000);

			if (r == -1) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "select: %s", strerror(errno));
				exit(1);
			}
			/* Block the update signals while doing work. */
			sigprocmask(SIG_BLOCK, &sigset, 0);

			/* the big IO loop change: The only FDs used to be connections to connections to slaves. No longer. 
			 * We will have fds for clients and the masterfd for taking new clients connections. 
			 */
			for (i = 0; i < r; i++) {
				struct conn_t *conn;
				int what = EVTYPE(epoll_events[i].data.u32);
				int whatfd = EVFD(epoll_events[i].data.u32);
				if (epoll_events[i].events & EPOLLOUT) {
					switch (what) {
					case CLIENT:
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_write(conn);
						conn_update_epoll(conn);
						break;
					case SLAVE:
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_write(conn);
						conn_update_epoll(conn);
						break;
					case MASTER:
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_write(conn);
						conn_update_epoll(conn);
						break;
					}
				}
				if (epoll_events[i].events & EPOLLIN) {
					switch (what) {
					case CLIENT_CONNECT:
						accept_new_client();
						break;
					case CLIENT:
						/* FIXME: this double check is bogus */
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_read(conn);
						if (conn->state == CONN_DEAD)
							break;
						conn_update_epoll(conn);
						break;
					case SLAVE_CONNECT:
						conn = 0;
						for (j = 0;
						     j < conf.if_list_size; j++)
							accept_new_slave(&conf.
									 if_list
									 [j]);
						break;
					case SLAVE:
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_read(conn);
						conn_update_epoll(conn);
						break;
					case MASTER:
						conn = &connections[whatfd];
						if (conn->state == CONN_DEAD)
							break;
						conn_read(conn);
						conn_update_epoll(conn);
						break;
					}
				}

				/* Clean up dead connections here */
				while (!list_empty(&conn_dead)) {
					struct epoll_event ev;
					conn =
					    list_entry(conn_dead.next,
						       struct conn_t, list);
					list_del(&conn->list);
					if (epoll_ctl
					    (epoll_fd, EPOLL_CTL_DEL, conn->fd,
					     &ev)) {
						syslog(LOG_ERR,
						       "epoll_ctl(EPOLL_CTL_DEL): %s",
						       strerror(errno));
						exit(1);
					}
					close(conn->fd);
				}
			}
			now = time(0);
			if (now >= lastping + conf.ping_timeout / 2) {
				send_pings();
				lastping = now;
			}
		}
	}
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
