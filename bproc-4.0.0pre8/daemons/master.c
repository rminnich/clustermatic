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
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#define SYSLOG_NAMES 1
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "bproc.h"
#include <sys/bproc.h>

#include "list.h"
#include "cmconf.h"

#include "messages.h"		/* daemon-only messages */

#define DEFAULT_PORT             2223
#define DEFAULT_CONFIG_FILE      CONFIGDIR "/config"
#define DEFAULT_NODE_UP_SCRIPT   CONFIGDIR "/node_up"
#define DEFAULT_NODE_UP_LOG      LOGDIR    "/node.%d"
#define DEFAULT_PING_TIMEOUT     30 /* seconds */
#define LISTEN_BACKLOG           64
#define EXTRA_FDS                64

struct request_t {
    struct list_head list;
};

#define bproc_msg(req)  ((void *)(req+1))


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
    CONN_NEW,			/* new connection */
    CONN_READY,
    CONN_RUNNING,		/* connection active */
    CONN_EOF,			/* waiting for buffers to drain */
    CONN_DEAD			/* Dead, needs to be cleaned up */
};

#define IBUFFER_SIZE (sizeof(struct bproc_message_hdr_t) + 64)

struct conn_t {
    struct list_head list;	/* connection list */
    int fd;
    enum c_state state;
    time_t ctime;		/* connection time (for timeout) */
    struct node_t *node;	/* Node this connection is for */

    /* We should probably deal in "struct sockaddr"s for addresses to
     * be a little more protocol agnostic... */
    struct in_addr laddr;	/* local  connection address */
    struct in_addr raddr;	/* remote connection address */

    struct list_head backlog;	/* Incoming backlog before req goes "running"*/
    struct list_head reqs;	/* request queue just for this connection */

    int   ioffset;
    char  ibuffer[IBUFFER_SIZE];

    struct request_t *ireq;

    int ooffset;
    struct request_t *oreq;
};

#define conn_out_empty(x) (!(x)->oreq)

struct node_t {
    int id;
    int naddr;			/* size of address list */
    struct in_addr *addr;	/* list of addresses */
    time_t cookie;		/* slave cookie */
    struct list_head clist; 	/* Connection list */
    struct conn_t *running;	/* current running connection */

    int status;			/* Node status */
    struct list_head reqs;	/* Request queue to be sent to slave */
    int flag:1;			/* generic reusable flag */

    int ping_in;		/* Data in since last ping interval. */
};

struct assoc_t {
    int client; /* fd for client that owns this proc */
    struct node_t *proc;	/* Where a process exists */
    unsigned short req;		/* Outstanding request type */
    void          *req_id;	/* Request ID of move in progress */
    struct node_t *req_dest;    /* Outstanding request destination */
};

extern int start_iod(void);

struct interface_t {
    char              *name;
    int                fd;
    struct sockaddr_in addr;
};

/* struct master_t - this struct holds groups of addresses for other
 * master nodes in the system.  There's one array of these things.
 * The tag marks the group.  This is stored this way so that it will
 * be easy to pack these things into a message. */
struct master_t {
    int tag;			/* group tag */
    struct sockaddr addr;	/* The address */
};

struct config_t {
    int                 if_list_size;
    struct interface_t *if_list;

    int                 master_list_size;
    struct master_t    *master_list;

    /* Machine state setup to do sparse node ranges in a reasonable fashion */
    struct node_t *     nodes;
    struct node_t **    node_map; /* mapping id # -> index in nodes */
    int                 num_nodes; /* total number of nodes */
    int                 num_ids; /* nodes numbered 0 -> (num_ids - 1) */

    int ping_timeout;
    int bproc_port;		/* port in host byte order */
    int log_facility;
    int require_secure_port;
    int slave_time_sync;	/* XXX should be per-slave */
    int slave_private_namespace; /* XXX should be per-slave */
};

static struct config_t conf;
/* Sequence number for the cookies to hand out to slaves.  This isn't
 * intended to provide any security.  It's just there to prevent an
 * accidental slave reconnect as the wrong node number */
static time_t cookie_seq = 0;
static char *log_arg0;
static int   log_opts;

static int ignore_version = 0;
static int ghostfd; /*, listenfd;*/

static int epoll_fd;

/* Machine state */
#define MAXPID 32768
static struct assoc_t    associations[MAXPID];
/*static struct request_t *ghost_reqs = 0;*/
static LIST_HEAD(ghost_reqs);

/* Global configuration stuff */
static int verbose=0;
static char *node_up_script      = DEFAULT_NODE_UP_SCRIPT;
static char *machine_config_file = DEFAULT_CONFIG_FILE;

static struct bproc_version_t version = { BPROC_MAGIC, BPROC_ARCH, PACKAGE_MAGIC, PACKAGE_VERSION };

static void remove_slave(struct node_t *s, struct conn_t *c);
static void remove_slave_connection(struct conn_t *conn);
static LIST_HEAD(conn_dead);	/* list of dead connections which need to be cleaned up. */

static void send_msg(struct node_t *s, struct request_t *req);
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
void msgtrace_off(void) {
    if (tracefd != -1) {
	close(tracefd);
	tracefd = -1;
    }
}

static
void msgtrace_on(int fd) {
    msgtrace_off();
    tracefd = dup(fd);
}

#define msgtrace(tf,n,r) do { if (tracefd != -1) _msgtrace((tf),(n),(r)); } while(0)
static
void _msgtrace(int tofrom, struct conn_t *conn, struct request_t *req) {
    struct debug_hdr_t dbg;
    struct bproc_message_hdr_t *msg;

    gettimeofday(&dbg.time, 0);
    dbg.tofrom = tofrom;
    dbg.node   = conn ? conn->node->id : -1;
    dbg.connection = conn;
    msg = bproc_msg(req);

    write(tracefd, &dbg, sizeof(dbg));
    write(tracefd, msg, msg->size);
}

/**------------------------------------------------------------------------
 **
 **----------------------------------------------------------------------*/
static inline
void * smalloc(size_t size) {
    void *tmp;
    tmp = malloc(size);
    if (!tmp) {
	syslog(LOG_EMERG, "Out of memory. (alloc=%ld)", (long) size);
	assert(0);
    }
    return tmp;
}

/*static inline*/
void * srealloc(void *ptr, size_t size) {
    void *tmp;
    tmp = realloc(ptr, size);
    if (!tmp) {
	syslog(LOG_EMERG, "Out of memory. (realloc=%ld)", (long) size);
	assert(0);
    }
    return tmp;
}

static
void set_keep_alive(int fd) {
    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) == -1) {
	syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
    }
}

/* XXX This doesn't seem to actually do what we want.... */
static
void set_no_delay(int fd) {
    int flag = 1;
    if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) {
	syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
    }
}

static
void set_non_block(int fd) {
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
struct request_t *req_get(int size) {
    struct request_t *req;
    req = smalloc(sizeof(*req) + size);
    return req;
}

static
void req_free(struct request_t *req) {
    /*list_add(&req->list, &free_reqs);*/
    free(req);
}


static
struct request_t *bproc_new_req(int type, int size) {
    struct request_t *req;
    struct bproc_message_hdr_t *msg;
    req = req_get(size);
    msg = bproc_msg(req);
    msg->req    = type;
    msg->id     = 0;
    msg->size   = size;
    msg->result = 0;	/* cosmetic for debugging */
    /* Zero out the routing stuff for paranoia  XXX DEBUGGING*/
    msg->totype = msg->fromtype = 0;
    msg->to     = msg->from     = 0;
    return req;
}

static
struct request_t *bproc_new_resp(struct request_t *req, int size) {
    struct request_t *resp;
    struct bproc_message_hdr_t *req_msg, *resp_msg;

    req_msg = bproc_msg(req);

    resp = req_get(size);
    resp_msg = bproc_msg(resp);
    resp_msg->req      = BPROC_RESPONSE(req_msg->req);
    resp_msg->id       = req_msg->id;
    resp_msg->size     = size;
    resp_msg->result   = 0;
    resp_msg->totype   = req_msg->fromtype;
    resp_msg->to       = req_msg->from;
    resp_msg->fromtype = req_msg->totype;
    resp_msg->from     = req_msg->to;
    return resp;
}

static
char *ip_to_str(struct sockaddr_in *_addr) {
    static char str_addr[16];
    long addr = ntohl(_addr->sin_addr.s_addr);
    sprintf(str_addr, "%ld.%ld.%ld.%ld",
	    (addr>>24)&0xff,(addr>>16)&0xff,(addr>>8)&0xff,addr&0xff);
    return str_addr;
}

static
char *ip_to_str_(struct in_addr _addr) {
    static char str_addr[16];
    long addr = ntohl(_addr.s_addr);
    sprintf(str_addr, "%ld.%ld.%ld.%ld",
	    (addr>>24)&0xff,(addr>>16)&0xff,(addr>>8)&0xff,addr&0xff);
    return str_addr;
}

/**------------------------------------------------------------------------
 **  Daemon Configuration
 **----------------------------------------------------------------------*/
struct config_t tc;
static
int get_interface_ip(int fd, char *interface, struct sockaddr_in *addr) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
	syslog(LOG_ERR, "%s: %s", interface, strerror(errno));
        return -1;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    memcpy(&addr->sin_addr,&((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr,4);
    return 0;
}

static
int setup_listen_socket(struct interface_t *ifc) {
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
	for (i=0; i < conf.if_list_size; i++) {
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
    if (listen(fd,LISTEN_BACKLOG) == -1) {
	syslog(LOG_ERR, "listen(): %s\n", strerror(errno));
	close(fd);
	return -1;
    }
    ifc->fd = fd;

    ev.events = EPOLLIN;
    ev.data.ptr = (void *) 1L;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ifc->fd, &ev)) {
	syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
	exit(1);
    }
    return 0;
}


static
int config_interface(struct cmconf *conf, char **args) {
    struct interface_t *tmp;
    /* Add an interface to our list */
    if (!(tmp = realloc(tc.if_list, sizeof(*tc.if_list)*(tc.if_list_size+1)))){
	syslog(LOG_ERR, "Out of memory.");
	return -1;
    }
    tc.if_list = tmp;
    tmp = &tc.if_list[tc.if_list_size];
    tmp->name = strdup(args[1]);
    if (setup_listen_socket(tmp)) {
	syslog(LOG_ERR, "Could not setup socket on interface %s", tmp->name);
	free(tmp->name);
	return -1;
    }
    tc.if_list_size++;
    return 0;
}

static int next_node;

#define ALLOC_CHUNK 64	 /* number of elements to allocate at a time */
static
struct node_t *add_node(int node) {
    struct node_t **map_tmp, *nodes_tmp;
    int i, curr_size, new_size;
    struct node_t *n;

    /* Add this node to the list of nodes */
    curr_size = (tc.num_nodes + ALLOC_CHUNK - 1) / ALLOC_CHUNK;
    new_size  = (tc.num_nodes + ALLOC_CHUNK) / ALLOC_CHUNK;

    if (curr_size != new_size) {
	nodes_tmp = realloc(tc.nodes,
			    new_size * sizeof(*tc.nodes) * ALLOC_CHUNK);
	if (!nodes_tmp) {
	    syslog(LOG_ERR, "Out of memory allocating nodes.\n");
	    return 0;
	}
	tc.nodes = nodes_tmp;

	/* Make sure the node map stays consistent */
	for (i=0; i < tc.num_nodes; i++)
	    tc.node_map[tc.nodes[i].id] = &tc.nodes[i];
    }
    n = &tc.nodes[tc.num_nodes];
    tc.num_nodes++;

    /* Make sure the node map is big enough to hold this node */
    if (node >= tc.num_ids) {
	curr_size = (tc.num_ids + ALLOC_CHUNK-1) / ALLOC_CHUNK;
	new_size  = (node + ALLOC_CHUNK) / ALLOC_CHUNK;
	if (curr_size != new_size) {
	    map_tmp = realloc(tc.node_map,
			      new_size * sizeof(*tc.node_map) * ALLOC_CHUNK);
	    if (!map_tmp) {
		syslog(LOG_ERR, "Out of memory.\n");
		return 0;
	    }
	    tc.node_map = map_tmp;
	}

	/* zero out the newly allocated stuff */
	for (i=tc.num_ids; i < new_size * ALLOC_CHUNK; i++)
	    tc.node_map[i] = 0;
	tc.num_ids = node + 1;
    }

    tc.node_map[node] = n;

    memset(n, 0, sizeof(*n));
    n->id = node;
    INIT_LIST_HEAD(&n->reqs);
    INIT_LIST_HEAD(&n->clist);
    return n;
}

static
int add_node_ip(int node, struct in_addr addr) {
    struct in_addr *tmp;
    struct node_t *n = 0;

    if (node < tc.num_ids)
	n = tc.node_map[node];
    if (!n)
	n = add_node(node);
    if (!n)
	return -1;

    if (!(tmp = realloc(n->addr, sizeof(*n->addr) * (n->naddr+1)))) {
	syslog(LOG_ERR, "Out of memory");
	return -1;
    }
    n->addr = tmp;
    n->addr[n->naddr] = addr;
    n->naddr++;
    return 0;
}

static
int check_ip(struct in_addr _ip1, struct in_addr _ip2) {
    int i, j;
    struct node_t *n;
    unsigned long ip1, ip2, ip;

    ip1 = ntohl(_ip1.s_addr);
    ip2 = ntohl(_ip2.s_addr);
    for (i=0; i < tc.num_nodes; i++) {
	n = &tc.nodes[i];
	for (j=0; j < n->naddr; j++) {
	    ip = ntohl(n->addr[j].s_addr);
	    if (ip >= ip1 && ip <= ip2)
		return -1;	/* This IP range includes an allocated IP */
	}
    }
    return 0;
}

static
int get_node_num(char ***args, int *num) {
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
	(*args) += 1;		/* move args past node args */
    } else {
	/* Got a node number */
	if (*num < 0 /*|| *num > tc.num_nodes*/) {
	    syslog(LOG_ERR, "Invalid node number: %s", (*args)[1]);
	    *num = -1;		/* error value... */
	    return -1;
	}
	(*args) += 2;		/* move args past node number */
    }
    return 0;
}

static
int config_ip(struct cmconf *conf, char **args) {
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
int config_iprange(struct cmconf *conf, char **args) {
    int node_num, i;
    struct in_addr addr[2];
    unsigned long ip, ip1, ip2;

    if (get_node_num(&args, &node_num))
	return -1;

    for (i=0; i < 2; i++)
	if (inet_aton(args[i], &addr[i]) == 0) {
	    syslog(LOG_ERR, "%s:%d: Invalid IP address: %s",
		   cmconf_file(conf), cmconf_lineno(conf), args[i]);
	    return -1;
	}

    /* check that these aren't already assigned somewhere */
    if (check_ip(addr[0], addr[1])) {
	syslog(LOG_ERR, "%s:%d: Duplicate IP addresses in range: %s -> %s"
	       "   One or more of these addresses is already assigned.",
	       cmconf_file(conf), cmconf_lineno(conf),  args[0], args[1]);
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
int config_timesync(struct cmconf *conf, char **args) {
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
int config_privatefs(struct cmconf *conf, char **args) {
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
int master_conf_callback(struct cmconf *conf, char **args) {
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
		syslog(LOG_ERR, "%s:%d: bprocport: unknown service/invalid"
		       " port: %s", cmconf_file(conf), cmconf_lineno(conf),
		       args[1]);
		return -1;
	    }
	    tc.bproc_port = portno;
	}
    } else if (strcmp(args[0], "allowinsecureports") == 0) {
	tc.require_secure_port = 0;
    } else if (strcmp(args[0], "logfacility") == 0) {
	for (i=0; facilitynames[i].c_name; i++) {
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
    } else
    if (strcmp(args[0], "pingtimeout") == 0) {
	char *check;
	int tmp;
	tmp = strtol(args[1], &check, 0);
	if (*check) {
	    syslog(LOG_ERR, "%s:%d: Invalid number: %s",
		   cmconf_file(conf), cmconf_lineno(conf), args[1]);
	    return -1;
	}
	if (tmp < 2) {
	    syslog(LOG_ERR, "%s:%d: Ping timeout must be 2 seconds or more.",
		   cmconf_file(conf), cmconf_lineno(conf));
	    return -1;
	}
	tc.ping_timeout = tmp;
    } else if (strcmp(args[0], "slavetimesync") == 0) {
	return config_timesync(conf, args);
    } else {
	syslog(LOG_ERR, "unknown tag in master_conf_callback: %s", args[0]);
	return -1;
    }
    return 0;
}


static
int config_master(struct cmconf *conf, char **args) {
    int i, j, port, tag;
    char *colon, *check;
    struct hostent *h;
    struct sockaddr addr_;
    struct sockaddr_in *addr = (struct sockaddr_in *) &addr_;
    
    struct master_t *m, *tmp;

    tag = 0;
    if (tc.master_list_size > 0)
	tag = tc.master_list[tc.master_list_size-1].tag + 1;

    /* Add each of the addresses on this line */
    for (i=1; args[i]; i++) {
	/* check if the user supplied a port number */
	colon = strchr(args[i], ':');
	if (colon) {
	    *colon = 0;
	    port = strtol(colon+1, &check, 0);
	    if (*check || port < 0 || port >= 65536) {
		syslog(LOG_ERR, "%s:%d: Invalid port number %s",
		       cmconf_file(conf), cmconf_lineno(conf), colon+1);
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
	for (j=0; j < tc.master_list_size; j++) {
	    if (memcmp(&tc.master_list[j].addr, addr, sizeof(*addr))== 0) {
		syslog(LOG_ERR, "%s:%d: master address %s is a duplicate!",
		       cmconf_file(conf), cmconf_lineno(conf), args[i]);
		return -1;
	    }
	}

	/* Allocate another address */
	tmp = realloc(tc.master_list,
		      sizeof(*tc.master_list) * (tc.master_list_size+1));
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
int config_err(struct cmconf *conf, char **args) {
    syslog(LOG_ERR, "%s:%d: Unknown configuration tag: %s",
	   cmconf_file(conf), cmconf_lineno(conf), args[0]);
    return -1;
}

/* Options to control slave behavior. */
static
struct cmconf_option configopts_slave[] = {
    {"timesync",  1, 1, 0, config_timesync},
    {"privatefs", 1, 1, 0, config_privatefs},
    {"*",         0,-1, 0, config_err},
    {0,}
};

static
int config_slave_opts(struct cmconf *conf, char **args) {
    return cmconf_process_args(conf, args+1, configopts_slave);
}

static
struct cmconf_option configopts[] = {
    {"interface",          1, 3, 1, config_interface},
    {"ip",                 1, 2, 2, config_ip},
    {"iprange",            3, 3, 2, config_iprange},
    {"bprocport",          1, 1, 0, master_conf_callback},
    {"allowinsecureports", 0, 0, 0, master_conf_callback},
    {"logfacility",        1, 1, 0, master_conf_callback},
    {"pingtimeout",        1, 1, 0, master_conf_callback},
    {"slavetimesync",      1, 1, 0, master_conf_callback},
    {"master",             1,-1, 2, config_master},
    {"slave",              1,-1, 0, config_slave_opts},
    {0, }
};

/* Transfer slaves from conf to tc */
static
void config_transfer_slaves(void) {
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
    for (i=0; i < tc.num_nodes; i++) {
	n = &tc.nodes[i];
	for (j=0; j < n->naddr; j++) {
	    addr = n->addr[j];
	    for (k=0; k < conf.num_nodes; k++) {
		old = &conf.nodes[k];
		if (old->status != 0 &&
		    addr.s_addr == old->running->raddr.s_addr) {
		    if (!list_empty(&n->clist)) {
			syslog(LOG_ERR, "Dropping node %d due to address"
			       " collision during reconfiguration", k);
			break;
		    }
		    /* Steal the connection state */
		    n->status   = old->status;

		    /* xfer the connection list to the new node structure */
		    list_add_tail(&n->clist, &old->clist);
		    list_del_init(&old->clist);

		    /* Walk the connection list and update the node
		     * pointers. */
		    for (list=n->clist.next; list != &n->clist; 
			 list = list->next) {
			c = list_entry(list, struct conn_t, list);
			c->node = n;
		    }
		    n->running  = old->running;
		    n->cookie   = old->cookie;

		    /* Transfer the request list to the new node */
		    list_add_tail(&n->reqs, &old->reqs);
		    list_del_init(&old->reqs);

		    /* set this guy to down so that we'll ignore it if
		     * we hit it again. */
		    old->status  = 0;
		    old->running = 0;

		    /* Node state */
		    n->ping_in  = 2;

		    /* Move the associations for this slave */
		    for (l=0; l < MAXPID; l++) {
			a = &associations[l];
			if (a->proc == old)     a->proc     = n;
			if (a->req_dest == old) a->req_dest = n;
		    }
		}
	    }
	}
    }

    /* Discard any slaves that haven't been picked up as part of the
     * new configuration. */
    for (i=0; i < conf.num_nodes; i++) {
	if (conf.nodes[i].status) {
	    syslog(LOG_INFO, "Discarding node %d connections due to"
		   " configuration change.\n", conf.nodes[i].id);
	    remove_slave(&conf.nodes[i], 0);
	}
    }
}

static
void config_update_nodes(void) {
    int i;
    for(i=0; i < conf.num_nodes; i++)
	if (conf.nodes[i].running) {
	    conn_send_conf(conf.nodes[i].running);
	}
}

static
void config_free(struct config_t *c) {
    int i;
    struct epoll_event ev;

    /* Free interfaces */
    for (i=0; i < c->if_list_size; i++) {
	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->if_list[i].fd, &ev)) {
	    syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_DEL): %s", strerror(errno));
	    exit(1);
	}
	close(c->if_list[i].fd);
    }
    if (c->if_list) free(c->if_list);

    /* Free masters */
    if (c->master_list) free(c->master_list);

    /* Count on config_transfer_slaves to clean up slave daemons */
    for (i=0; i < c->num_nodes; i++)
	if (c->nodes[i].addr)
	    free(c->nodes[i].addr);
    free(c->nodes);
}

static
void setup_fdsets(int size) {
    struct rlimit rlim;

    /* Add a little padding and round up */
    /* make sure these values are multiples of 8 (to avoid bits
     * vs. bytes type issues) */
    size += (size + EXTRA_FDS + 7) & ~0x7;

    if (getrlimit(RLIMIT_NOFILE, &rlim)) {
	syslog(LOG_CRIT, "getrlimit(RLIMIT_NOFILE): %s", strerror(errno));
	exit(1);
    }

    if (rlim.rlim_cur < size) {
	if (rlim.rlim_max < size)
	    rlim.rlim_max = size;
	rlim.rlim_cur = size;
	if (setrlimit(RLIMIT_NOFILE, &rlim)) {
	    syslog(LOG_CRIT, "Failed to increase RLIMIT_NOFILE to %ld/%ld",
		   (long) rlim.rlim_cur, (long) rlim.rlim_max);
	}
    }
}

/* This stuff sets up pointers, etc. when things are done moving
 * around in memory. */
static
void config_fixup(void) {
    int i;
    struct node_t *n;
    for (i=0; i < tc.num_nodes; i++) {
	n = &tc.nodes[i];
	tc.node_map[n->id] = n;	/* make entry in the node map */
	INIT_LIST_HEAD(&n->reqs);
	INIT_LIST_HEAD(&n->clist);
    }
}

static
int setup_bpfs(void) {
	/* in future, we'll have to do bpfs as a FUSE module */
	return -1;
}

static
int master_config(char *filename) {
    next_node = 0;
    memset(&tc, 0, sizeof(tc));
    /* Defaults */
    tc.log_facility        = LOG_DAEMON;
    tc.require_secure_port = 1;
    tc.bproc_port          = DEFAULT_PORT;
    tc.ping_timeout        = DEFAULT_PING_TIMEOUT;
    tc.slave_time_sync     = 1;

    if (cmconf_process_file(filename, configopts)) {
	config_free(&tc);
	return -1;
    }

    config_fixup();		/* Fixup pointers in new configuration */

    config_transfer_slaves();	/* Move existing slaves */
    openlog(log_arg0, log_opts, tc.log_facility);
    config_free(&conf);
    conf = tc;			/* Do it! */

    setup_bpfs();
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
struct node_t *find_node_by_number(int n) {
    if (n < 0 || n >= conf.num_ids) return 0;
    return conf.node_map[n];
}

/**------------------------------------------------------------------------
 **  Functions to manage our associations of pids with slave daemons.
 **----------------------------------------------------------------------*/

static
void assoc_init(void) {
    /*int i;*/
    memset(associations, 0, sizeof(struct assoc_t)*MAXPID);
    /*
    for (i=0; i < MAXPID; i++)
	INIT_LIST_HEAD(&associations[i].held_reqs);
    */
}

static
struct assoc_t *assoc_find(int pid) {
    if (pid <= 0 || pid >= MAXPID) {
	syslog(LOG_CRIT, "FATAL: assoc_find: invalid pid %d\n", pid);
	assert(0);
    }
    return &associations[pid];
}

static inline
int assoc_pid(struct assoc_t *a) {
    return (a - associations);
}

void assoc_dump(void) {
    int i;
    FILE *f;
    struct assoc_t *a;
    f = fopen("/var/run/bproc_assoc", "w");
    if (!f) return;

    for (i=0; i < MAXPID; i++) {
	a = &associations[i];
	fprintf(f, "%d\t%d", i, a->proc ? a->proc->id : -1); /* pid, node */
	fprintf(f, "\t%d\t%d\t%p", a->req,
		a->req_dest ? a->req_dest->id : -1, a->req_id);
	fprintf(f, "\n");
    }
    fclose(f);
}

/* This forcably removes a remote process.  It removes all data for it
 * and sends an EXIT message to the process's ghost. */
static inline
void assoc_clear_proc(struct assoc_t *a) {
    /* Zero out this process */
    a->proc = 0;
    a->req  = 0;
    a->client = -1;
}

/* This is the violent way to remove a process from BProc's view of
 * the world. */
static
void assoc_purge_proc(struct assoc_t *a) {
    int pid;
    struct request_t *req;
    struct bproc_status_msg_t *msg;

    pid = assoc_pid(a);

    /* Emit a EXIT message to get rid of the ghost on the front end */
    req = bproc_new_req(BPROC_EXIT, sizeof(*msg));
    msg = bproc_msg(req);
    bpr_from_real(msg, pid);
    bpr_to_ghost(msg, pid);
    msg->hdr.result = SIGKILL;
    msg->utime  = 0;
    msg->stime  = 0;
    msg->cutime = 0;
    msg->cstime = 0;
    send_msg(0, req);

    assoc_clear_proc(a);
}

static
void assoc_purge(struct node_t *s) {
    int i;
    struct assoc_t *a;
    struct request_t *req;
    struct bproc_null_msg_t *msg;

    for (i=0; i < MAXPID; i++) {
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
	    req = bproc_new_req(BPROC_RESPONSE(a->req), sizeof (*msg));
	    msg = bproc_msg(req);
	    bpr_from_node(msg, s->id);
	    bpr_to_real(msg, i);
	    msg->hdr.id     = a->req_id;
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
void set_node_state(struct node_t *s, char *state) {
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
void set_node_addr(struct node_t *s) {
    struct nodeset_setaddr_t addr;

    addr.id = s->id;
    if (s->running) {
	struct sockaddr_in *a = (struct sockaddr_in *) &addr.addr;
	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_addr = s->running->raddr;
    } else
	memset(&addr.addr, 0, sizeof(addr.addr));
#if 0
    if (ioctl(ghostfd, BPROC_NODESET_SETADDR, &addr)) {
	syslog(LOG_ERR, "nodeset_setaddr(%d): %s\n",
	       s->id, strerror(errno));
    }
#endif
    /* This is a bit of a questionable hack right now.  The master can
     * have multiple addresses with slaves at once.  In order to try
     * and do something reasonable for both the simple and complex
     * case, just store the last address that something connected at
     * in the file system. */
    if (s->running) {
	struct sockaddr_in *a = (struct sockaddr_in *) &addr.addr;
	addr.id = BPROC_NODE_MASTER;

	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_addr = s->running->laddr;
#if 0
	if (ioctl(ghostfd, BPROC_NODESET_SETADDR, &addr)) {
	    syslog(LOG_ERR, "nodeset_setaddr(%d): %s\n",
		   s->id, strerror(errno));
	}
#endif
    }
}

static
void run_node_up(struct node_t *s) {
    int pid, i;
    pid = fork();
    if (pid == -1) {
	syslog(LOG_ERR, "failed to run setup script for node %d\nfork: %s\n",
	       s->id, strerror(errno));
	return;
    }
    if (pid == 0) {
	char arg[10];
	int fd;
	char filename[100];
	/* First cleanup... */
	for (i=3; i < 4096; i++) close(i); /* Ugh, yuck. */
	signal(SIGHUP, SIG_DFL);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	setpgrp();

	sprintf(filename, DEFAULT_NODE_UP_LOG, s->id);
	fd = open("/dev/null", O_RDWR);
	if (fd != -1) dup2(fd, STDIN_FILENO);
	close(fd);
	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_APPEND, 0644);
	if (fd == -1) {
	    syslog(LOG_ERR, "Failed to open node_up log: %s\n", filename);
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
	    exit(0); /* No script, ok. */
	else
	    syslog(LOG_ERR, "exec(%s): %s", node_up_script, strerror(errno));
	exit(255);
    }
}



/**------------------------------------------------------------------------
 **  Connection management
 **----------------------------------------------------------------------*/
static int conn_write_refill(struct conn_t *c);
static
void conn_send(struct conn_t *c, struct request_t *req) {
    list_add_tail(&req->list, &c->reqs);
    if (conn_out_empty(c)) {
	conn_write_refill(c);
	conn_update_epoll(c);
    }
}

static
void conn_eof(struct conn_t *c) {
    switch(c->state) {
    case CONN_NEW:
    case CONN_READY:
    case CONN_EOF:
	syslog(LOG_ERR, "Received EOF in state %d - removing slave\n",
	       c->state);
	remove_slave(c->node, 0);
	break;
    case CONN_RUNNING: {
	struct request_t *req;
	struct bproc_null_msg_t *msg;

	c->state = CONN_EOF;

	req = bproc_new_req(BPROC_NODE_EOF, sizeof(*msg));
	msg = bproc_msg(req);
	bpr_from_node(msg, -1);
	bpr_to_node  (msg, c->node->id);
	conn_send(c, req);

	slave_next_connection(c->node);	/* start using next connection */
	} break;
    case CONN_DEAD:		/* should never happen */
	assert(0);
    }
}

static
void conn_send_ping(struct conn_t *c) {
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
void conn_send_conf(struct conn_t *c) {
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
    memcpy(((void*)msg) + msg->masters, conf.master_list, masters_bytes);

    msg->time_sec = msg->time_usec = 0;	/* filled in at the last moment */
    conn_send(c, req);
}

/* Remove a single connection from a slave */
static
void remove_slave_connection(struct conn_t *conn) {
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

/* This function will completely trash slave state, optionally keeping
 * one connection open. */
static
void remove_slave(struct node_t *s, struct conn_t *conn_to_keep) {
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
    set_node_addr(s);		/* update connection address in bpfs */

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
void slave_set_ready(struct node_t *s, struct conn_t *conn) {
    /* If this node is just coming up we have to do a bunch of special
     * stuff... */
    if (s->status == 0) {
	/* If the node is down, go straight to RUNNING */
	conn->state = CONN_RUNNING;
	s->running = conn;
	set_node_addr(s);		/* update connection address in bpfs */

	INIT_LIST_HEAD(&s->reqs); /* should be redundant */
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
}

static
void slave_next_connection(struct node_t *s) {
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
	set_node_addr(s);		/* update connection address in bpfs */
	c->state = CONN_RUNNING;
	if (conn_out_empty(c))
	    conn_write_refill(c);

	/* Process message backlog (if any) */
	while (!list_empty(&c->backlog)) {
	    req = list_entry(c->backlog.next, struct request_t, list);
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
void send_version(struct conn_t *c) {
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
void send_ping(struct node_t *s) {
    conn_send_ping(s->running);
}


static
void slave_new_connection(struct node_t *s, struct interface_t *ifc,
			  struct sockaddr_in *raddr, int fd) {
    struct conn_t *conn;
    struct epoll_event ev;

    if (s->status == 0)
	s->cookie = cookie_seq++;

    conn = smalloc(sizeof(*conn));
    conn->node  = s;
    conn->fd    = fd;
    conn->state = CONN_NEW;
    conn->ctime = time(0);
    conn->laddr = ifc->addr.sin_addr;
    conn->raddr = raddr->sin_addr;

    /* I/O buffering */
    INIT_LIST_HEAD(&conn->backlog);
    INIT_LIST_HEAD(&conn->reqs);
    conn->ioffset = 0;
    conn->ireq    = 0;
    conn->ooffset = 0;
    conn->oreq    = 0;

    /* Append to connection list */
    list_add_tail(&conn->list, &s->clist);

    /* Add this FD to our world */
    ev.events = 0;
    ev.data.ptr = conn;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev)) {
	syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
	exit(1);
    }

    /* Prime output buffer with version information and cookie*/
    send_version(conn);
    conn_update_epoll(conn);
}

static
int accept_new_slave(struct interface_t *ifc) {
    int slavefd, i, j;
    struct sockaddr_in remote;

    socklen_t remsize = sizeof(remote);
    slavefd = accept(ifc->fd, (struct sockaddr *) &remote, &remsize);
    if (slavefd == -1) {
	if (errno == EAGAIN) return 0;
	syslog(LOG_ERR, "accept: %s", strerror(errno));
	return -1;
    }

    if (verbose)
	syslog(LOG_INFO, "connection from %s", ip_to_str(&remote));
    if (conf.require_secure_port && ntohs(remote.sin_port) >= 1024) {
	syslog(LOG_NOTICE, "connect from insecure port (%d).",
	       (int) ntohs(remote.sin_port));
	close(slavefd);
	return -1;
    }
    set_keep_alive(slavefd);
    set_no_delay(slavefd);
    set_non_block(slavefd);

    /* determine node number based on remote IP address */
    for (i=0; i < conf.num_nodes; i++) {
	for (j=0; j < conf.nodes[i].naddr; j++) {
	    if (remote.sin_addr.s_addr == conf.nodes[i].addr[j].s_addr) {
		if (verbose)
		    syslog(LOG_INFO, "connect from node %d.",conf.nodes[i].id);
		slave_new_connection(&conf.nodes[i], ifc, &remote, slavefd);
		return 0;
	    }
	}
    }
    syslog(LOG_NOTICE,"Connect from unrecognized node %s",ip_to_str(&remote));
    close(slavefd);
    return -1;
}

/**------------------------------------------------------------------------
 **  Process management
 **----------------------------------------------------------------------*/
/* Returns 1 on permission ok. */
int do_move_permission(struct node_t *dest, struct request_t *req) {
    int i;
    struct nodeset_perm_t mp;
    struct bproc_move_msg_t *msg;
    struct bproc_credentials_t *creds;
    msg = bproc_msg(req);

    creds = ((void *)msg) + msg->call_creds;

    /* Fill in the structure required to do a permission check... */
    mp.node          = dest->id;
    mp.euid          = creds->euid;
    mp.egid          = creds->egid;
    mp.ngroups       = creds->ngroups;
    mp.cap_effective = creds->cap_effective;
    /* XXX FIX ME: arbitrary group counts */
    if (mp.ngroups > BPROC_NGROUPS) mp.ngroups = 0;
    for (i=0; i < mp.ngroups; i++)
	mp.groups[i] = creds->groups[i];

    return 1; //ioctl(ghostfd, BPROC_NODESET_PERM, &mp) == 0;
}

static
void set_proc_location(struct assoc_t *a, struct node_t *loc) {
    struct setprocloc_t nl;

    a->proc = loc;

    nl.pid  = assoc_pid(a);
    nl.node = a->proc ? a->proc->id : BPROC_NODE_MASTER;
#if 0
    if (ioctl(ghostfd, BPROC_SETPROCLOC, &nl)) {
	syslog(LOG_ERR, "ioctl(BPROC_SETPROCLOC, {%d, %d}): %s",
	       nl.pid, nl.node, strerror(errno));
    }
#endif

    {				/* debugging spew */
	/* This is kind of a dummy request to say when process
	 * locations get updated */
	struct bproc_debug_1000_msg_t msg;
	msg.hdr.req  = 1000;
	msg.hdr.size = sizeof(msg);
	msg.pid = nl.pid;
	msg.node = nl.node;
	msgtrace(BPROC_DEBUG_OTHER, 0,
		 ((struct request_t *)&msg)-1);
    }
}

static
struct request_t *response(struct request_t *req, int err) {
    struct request_t *resp;
    struct bproc_null_msg_t *msg;

    resp = bproc_new_resp(req, sizeof(*msg));
    msg  = bproc_msg(resp);
    msg->hdr.result = err;

    return resp;
}

static
void respond(struct request_t *req, int err) {
    struct request_t *resp;

    resp = response(req, err);
    route_message(resp);
}

static
int do_move_request(struct request_t *req) {
	/* no */
	return -1;
 }

static
void do_move_response(struct request_t *req) {
	/* we don't do this ever */
	return;
}

static
void do_exit_request(struct request_t *req) {
    struct assoc_t *a;
    struct bproc_status_msg_t *msg;
    msg = bproc_msg(req);
    a = assoc_find(msg->hdr.from);
    assoc_clear_proc(a);
}

static
void do_fork_response(struct request_t *req) {
	/* we're not supporting this one */
}

static
void do_get_status(struct request_t *req) {
    int i;
    void * id;
    struct node_t *n;
    struct bproc_null_msg_t *msg;

    msg = bproc_msg(req);
    id = msg->hdr.id;
    req_free(req);

    /* Explode all this request out into a request for each node
     * that's up. */
    for (i=0; i < conf.num_nodes; i++) {
	n = &conf.nodes[i];
	if (n->status != 0) {
	    req = bproc_new_req(BPROC_GET_STATUS, sizeof(*msg));
	    msg = bproc_msg(req);
	    bpr_to_node(msg, n->id);
	    bpr_from_node(msg, -1);
	    msg->hdr.result = 0;
	    msg->hdr.id     = id;
	    route_message(req);
	}
    }
}

static
void do_parent_exit(struct request_t *req) {
    int i, pid;
    struct assoc_t *a;
    struct node_t *n;
    struct bproc_null_msg_t *msg;

    msg = bproc_msg(req);
    pid = msg->hdr.from;	/* The pid that's exiting */
    req_free(req);

    for (i=0; i < conf.num_nodes; i++)
	conf.nodes[i].flag = 0;

    /* XXX I don't like this loop here... we should get all
     * associations on some kind of list */
    for (i=0; i < MAXPID; i++) {
	a = &associations[i];
	/* If PID is on a slave node or PID is moving... */
	if (a->proc || a->req == BPROC_MOVE) {
	}
    }

    /* Send the messages to the slaves */
    for (i=0; i < conf.num_nodes; i++) {
	n = &conf.nodes[i];
	if (n->flag) {
	    req = bproc_new_req(BPROC_PARENT_EXIT, sizeof(*msg));
	    msg = bproc_msg(req);
	    bpr_from_real(msg, pid);
	    bpr_to_node(msg, n->id);
	    route_message(req);
	}
    }
}

/**------------------------------------------------------------------------
 **  Handle incoming requests
 **----------------------------------------------------------------------*/
static
int route_message(struct request_t *req) {
    struct node_t *node;
    struct assoc_t *assoc, *fromassoc=0;
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
	    hdr->totype   != BPROC_ROUTE_GHOST) {
	    /* Don't make note of requests to ghosts...  We will never
	     * have to generate an error response due to ghost
	     * disappearance. */
	    switch(hdr->req) {
		/* Don't make note of these because we don't ever want
		 * to auto-generate responses to these messages */
	    case BPROC_GET_STATUS:
	    case BPROC_PGRP_CHANGE:
	    case BPROC_PARENT_EXIT:
	    case BPROC_NODE_REBOOT:
		break;
	    default:
		fromassoc = assoc_find(hdr->from);
		fromassoc->req    = hdr->req;
		fromassoc->req_id = hdr->id;
		break;
	    }
	}
    }

    /*** SPECIAL HANDLING FOR CERTAIN MESSAGES ***/
    switch(hdr->req) {
    case BPROC_MOVE:
	if (do_move_request(req)) {
	    req_free(req);
	    return 0;
	}
	break;
    case BPROC_RESPONSE(BPROC_MOVE):
	do_move_response(req);	/* Routing happens in here... */
	return 0;
    case BPROC_EXIT:
	do_exit_request(req);
	break;
    case BPROC_RESPONSE(BPROC_SYS_FORK):
	do_fork_response(req);
	break;
    case BPROC_NODE_DOWN:
	node = find_node_by_number(hdr->to);
	if (node) {
	    syslog(LOG_INFO, "Disconnecting slave %d", node->id);
	    remove_slave(node, 0);
	} else {
	    syslog(LOG_ERR, "Received NODE_DOWN for bad node number: %d",
		   hdr->to);
	}
	req_free(req);
	return 0;		/* message stops here. */
    }
    /*** END SPECIAL HANDLING FOR CERTAIN MESSAGES ***/

    switch(hdr->totype) {
    case BPROC_ROUTE_NODE:
	/* Handle the messages addressed to the master */
	if (hdr->to == -1) {
	    if (fromassoc) fromassoc->req_dest = 0;
	    switch(hdr->req) {
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
	    case BPROC_PARENT_EXIT:
		do_parent_exit(req);
		break;
	    default:
		/* there's probably nothing that falls in here (?) */
		/*list_add_tail(&req->list, &ghost_reqs);*/
		send_msg(0, req);
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
	    if (fromassoc) fromassoc->req_dest = node;
	    /*list_add_tail(&req->list, &node->reqs);*/
	    send_msg(node, req);
	}
	break;
    case BPROC_ROUTE_REAL:
	assoc = assoc_find(hdr->to);
	if (fromassoc) fromassoc->req_dest = assoc->proc;
	send_msg(assoc->proc, req);
	break;
    case BPROC_ROUTE_GHOST:
	if (fromassoc) fromassoc->req_dest = 0;
	send_msg(0, req);
	break;
    default:
	syslog(LOG_ERR, "Unknown totype in route_message(): %d\n",
	       hdr->totype);
	break;
    }
    return 0;
}

static
void ghost_update_epoll(void) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    if (!list_empty(&ghost_reqs))
	ev.events |= EPOLLOUT;
    ev.data.ptr = 0;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ghostfd, &ev)) {
	syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_MOD): %s", strerror(errno));
	exit(1);
    }
}

/* "ghost" is a little dated in this function name. */
static
void read_ghost_request(void) {
    int r, size;
    struct request_t * req;
    void *msg;

    while (1) {
	/* Get the size of the next message */
	size = ioctl(ghostfd, BPROC_MSG_SIZE);
	if (size <= 0) {
	    if (size == 0 || errno == EAGAIN) return;
	    syslog(LOG_CRIT, "read(ghost): MSG_SIZE: %s\n", strerror(errno));
	    return;
	}

	req = req_get(size);
	msg = bproc_msg(req);

	r = read(ghostfd, msg, size);
	if (r < 0) {
	    if (errno == EAGAIN) return;
	    syslog(LOG_CRIT, "read(ghost): %s", strerror(errno));
	    return;
	}

	msgtrace(BPROC_DEBUG_MSG_FROM_KERNEL, 0, req);
	route_message(req);
    }
}

static
void write_ghost_request(void) {
    int r;
    struct request_t *req;
    struct bproc_message_hdr_t *hdr;

    while (!list_empty(&ghost_reqs)) {
	req = list_entry(ghost_reqs.next, struct request_t, list);
	hdr = bproc_msg(req);

	msgtrace(BPROC_DEBUG_MSG_TO_KERNEL, 0, req);
	r = write(ghostfd, hdr, hdr->size);
	if (r == -1) {
	    if (errno == EAGAIN) {
		return;		/* done here... */
	    } else if (errno == ESRCH) {
		/* It's possible that someone is trying to send something
		 * to a process that doesn't exist anymore. */
		/* Cases where I think this should happen: signal forwarding,
		 * status requests .. although status requests should never
		 * show up on this list. */
		switch(hdr->req) {
		case BPROC_FWD_SIG:
		case BPROC_SYS_KILL:
		    /* this is basically a list of interruptible remote
		     * requests */
		case BPROC_RESPONSE(BPROC_NODE_CHROOT):
		case BPROC_RESPONSE(BPROC_NODE_RECONNECT):
		    break;
		default:
		    syslog(LOG_ERR, "write(ghost): missing process for message"
			   " type %d %s; to=%d,%d from=%d,%d result=%ld",
			   BPROC_REQUEST(hdr->req),
			   BPROC_ISRESPONSE(hdr->req) ? "resp" : "req",
			   hdr->totype,   hdr->to,
			   hdr->fromtype, hdr->from, hdr->result);
		    break;
		}
	    } else {
		syslog(LOG_CRIT, "write(ghost): error %s; req=%d",
		       strerror(errno), hdr->req);
	    }
	} else if (r != hdr->size)
	    syslog(LOG_CRIT,"write(ghost): short write; ignoring (Aaaieee!!)");

	/* Remove the request from the list and free it */
	list_del(&req->list);
	req_free(req);
    }
}

static
void conn_update_epoll(struct conn_t *c) {
    struct epoll_event ev;
    ev.events = 0;
    if (c->state != CONN_EOF && c->state != CONN_DEAD)
	ev.events |= EPOLLIN;
    if (!conn_out_empty(c))
	ev.events |= EPOLLOUT;
    ev.data.ptr = c;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c->fd, &ev)) {
	syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_MOD, %d, {0x%x, %p} ): %s",
	       c->fd, ev.events, ev.data.ptr, strerror(errno));
	exit(1);
    }
}

static
int conn_msg_in(struct conn_t *c, struct request_t *req) {
    struct bproc_message_hdr_t *hdr;

    msgtrace(BPROC_DEBUG_MSG_FROM_SLAVE, c, req);

    hdr = bproc_msg(req);
    switch (hdr->req) {
    case BPROC_VERSION: {
	struct node_t *s = c->node;
	struct bproc_version_msg_t *msg;

	if (c->state != CONN_NEW) {
	    syslog(LOG_NOTICE, "Received VERSION on non-new connection.");
	    remove_slave_connection(c);
	}

	msg = bproc_msg(req);

	if (msg->hdr.req != BPROC_VERSION || msg->hdr.size != sizeof(*msg)) {
	    syslog(LOG_ERR, "Received invalid message on new connection "
		   "from slave %d.", c->node->id);
	    remove_slave_connection(c);
	    return 0;
	}

	/* Check version information */
	if (version.magic != msg->vers.magic ||
	    version.arch  != msg->vers.arch  ||
	    strcmp(version.version_string, msg->vers.version_string) != 0) {
	    syslog(LOG_NOTICE, "node %d: version mismatch.  master=%s-%u-%d;"
		   " slave=%s-%u-%d (%s)", s->id,
		   version.version_string, (int) version.magic,
		   (int) version.arch, msg->vers.version_string,
		   (int) msg->vers.magic,   (int) msg->vers.arch,
		   ignore_version ? "ignoring" : "disconnecting");
	    if (!ignore_version) {
		remove_slave_connection(c);
		return 0;
	    }
	}

	/* Inspect the cookie */
	if (s->status != 0) {
	    if (msg->cookie == 0) {
		syslog(LOG_NOTICE, "replacing slave %d", s->id);
		remove_slave(s, c);	/* c = connection to keep here. */
		slave_set_ready(s, c);
	    } else if (msg->cookie == s->cookie) {
		syslog(LOG_NOTICE, "new connection from node %d", s->id);
		slave_set_ready(s, c);
	    } else {
		syslog(LOG_NOTICE, "bad slave connection from node %d", s->id);
		/* node up, re-connect request is bad, just toss the new
		 * connection */
		remove_slave_connection(c);
		return 0;
	    }
	} else {
	    if (msg->cookie) {
		syslog(LOG_NOTICE, "bad slave connection from node %d", s->id);
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
	if (c->state == CONN_RUNNING) c->node->ping_in = 2;
	req_free(req);
	return 1;
    case BPROC_NODE_EOF:
	if (c->state != CONN_RUNNING) {
	    syslog(LOG_NOTICE, "Received EOF on non-running connection.");
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
	    syslog(LOG_NOTICE, "Received message of type %d on a connection "
		   " that was neither running or ready.", hdr->req);
	    remove_slave_connection(c);
	    return 0;
	}
	return 1;
    }
}

/*
 *  conn_read - read data from a slave node connection
 */
static
void conn_read(struct conn_t *c) {
    int r, size;
    struct node_t *s = c->node;
    struct bproc_message_hdr_t *hdr;


    while (1) {
	if (c->ireq) {
	    /* Continue on partial request */
	    hdr = bproc_msg(c->ireq);
	    size = hdr->size - c->ioffset;

	    r = read(c->fd, ((void *)hdr) + c->ioffset, size);
	    if (r == -1) {
		if (errno == EAGAIN) return;
		syslog(LOG_ERR, "read(slave): %s", strerror(errno));
	    }
	    if (r <= 0) {
		syslog(LOG_ERR, "lost connection to slave %d", s->id);
		remove_slave_connection(c);
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
		if (errno == EAGAIN) return;
		syslog(LOG_ERR, "read(slave): %s", strerror(errno));
	    }
	    if (r <= 0) {
		syslog(LOG_ERR, "lost connection to slave %d", s->id);
		remove_slave_connection(c);
		return;
	    }
	    c->ioffset += r;

	    /* Suck messages out of ibuffer until we run out of data... */
	    while (c->ioffset >= sizeof (struct bproc_message_hdr_t)) {
		hdr = (struct bproc_message_hdr_t *) c->ibuffer;

		/* Sanity checking */
		if (hdr->size < sizeof(struct bproc_message_hdr_t) ||
		    hdr->size > BPROC_MAX_MESSAGE_SIZE) {
		    syslog(LOG_ERR, "Invalid message size %d from slave"
			   " node %d", hdr->size, c->node->id);
		    remove_slave_connection(c);
		    return;
		}

		c->ireq = req_get(hdr->size);
		if (c->ioffset >= hdr->size) {
		    /* Complete message case */
		    memcpy(bproc_msg(c->ireq), c->ibuffer, hdr->size);

		    /* Deal with message */
		    if (!conn_msg_in(c, c->ireq))
			return;
		    c->ireq = 0;

		    /* Shift remaining data down */
		    c->ioffset -= hdr->size;
		    memmove(c->ibuffer, c->ibuffer + hdr->size, c->ioffset);
		} else {
		    /* Incomplete message case */
		    memcpy(bproc_msg(c->ireq), c->ibuffer, c->ioffset);
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
static inline
void conn_write_load(struct conn_t *c, struct list_head *list) {
    struct request_t *req;

    req = list_entry(list->next, struct request_t, list);
    list_del(&req->list);
    msgtrace(BPROC_DEBUG_MSG_TO_SLAVE, c, req);

    c->oreq = req;
    c->ooffset = 0;
}

static
int conn_write_refill(struct conn_t *c) {
    assert(conn_out_empty(c));

    switch(c->state) {
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
	} else if (!list_empty(&c->node->reqs)) {
	    conn_write_load(c, &c->node->reqs);
	}
	break;
    case CONN_EOF:
	if (!list_empty(&c->reqs)) {
	    conn_write_load(c, &c->reqs);
	} else {
	    remove_slave_connection(c);
	    return 0;
	}
	break;
    case CONN_DEAD:
	abort();		/* should never happen */
    }

    if (!conn_out_empty(c)) {
	/* Special case: if this packet is a ping, put the current
	 * time of day in here. */
	struct bproc_message_hdr_t *msg;
	struct timeval now;
	msg = bproc_msg(c->oreq);
	if (tc.slave_time_sync) {
	    if (msg->req == BPROC_NODE_CONF) {
		struct bproc_conf_msg_t *msg = bproc_msg(c->oreq);
		gettimeofday(&now, 0);
		msg->time_sec  = now.tv_sec;
		msg->time_usec = now.tv_usec;
	    }
	    if (msg->req == BPROC_NODE_PING) {
		struct bproc_ping_msg_t *msg = bproc_msg(c->oreq);
		gettimeofday(&now, 0);
		msg->time_sec  = now.tv_sec;
		msg->time_usec = now.tv_usec;
	    }
	}	
	/*FD_SETx(c->fd, wset_in, EPOLLOUT, c);*/
	return 1;
    } else {
	/*FD_CLRx(c->fd, wset_in, c);*/
	return 0;
    }
}

/*
 *  conn_write - write data to a slave node connection
 */
static
void conn_write(struct conn_t *c) {
    int w;
    struct bproc_message_hdr_t *hdr;

    while (1) {
	/* see to it that we have data */
	if (conn_out_empty(c))
	    return;			/* no data left... */

	hdr = bproc_msg(c->oreq);

	w = write(c->fd, ((void*)hdr) + c->ooffset, hdr->size - c->ooffset);
	if (w < 0) {
	    if (errno == EAGAIN) return;
	    syslog(LOG_NOTICE, "write(slave %d (%s)): %s", c->node->id,
		   ip_to_str_(c->raddr), strerror(errno));
	}
	if (w <= 0) {
	    syslog(LOG_NOTICE, "lost connection to slave %d", c->node->id);
	    remove_slave_connection(c);
	    return;
	}
	c->ooffset += w;
	if (c->ooffset == hdr->size) { /* done sending message */
	    req_free(c->oreq);
	    c->oreq = 0;

	    /* c might be an invalid pointer after write_refill. */
	    if (!conn_write_refill(c))
		return;
	}
    }
}


static
void send_msg(struct node_t *s, struct request_t *req) {
    if (s) {
	list_add_tail(&req->list, &s->reqs);
	if (!s->running) abort();

	if (conn_out_empty(s->running)) {
	    conn_write_refill(s->running);
	    conn_update_epoll(s->running);
	}
    } else {
	list_add_tail(&req->list, &ghost_reqs);
	ghost_update_epoll();
    }
}

static
void send_pings(void) {
    int i;
    struct node_t *s;
    /* Send a ping to all nodes that are up... */
    for (i=0; i < conf.num_nodes; i++) {
	s = &conf.nodes[i];
	if (s->status != 0) {
	    if (s->ping_in == 0) {
		syslog(LOG_NOTICE, "ping timeout on slave %d", s->id);
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
int setup_master_fd(void) {
    struct epoll_event ev;

 	struct sockaddr_un sun;

 /*** set up socket crud ***/
	unlink("/tmp/bpmaster");

	while ((ghostfd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
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
	strcpy(sun.sun_path, "/tmp/bpmaster");
	umask(000);
	if (bind(ghostfd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		perror("bind");
		return (-1);
	}
	if (listen(ghostfd, 16) != 0) {
		perror("listen");
		return (-1);
	}

    set_non_block(ghostfd);

    ev.events = 0;
    ev.data.ptr = 0;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ghostfd, &ev)) {
	syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
	exit(1);
    }
    ghost_update_epoll();
    return 0;
}

void daemonize(void) {
    int fd, pid;
    pid = fork();
    if (pid < 0) {
	syslog(LOG_ERR, "fork: %s", strerror(errno));
	exit(1);
    }
    if (pid != 0) exit(0);

    fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) close(fd);
    chdir("/");
    umask(077);
    setsid();
}

/* Signal handlers */
volatile int do_assoc_dump=0;
volatile int do_config_reload=0;
volatile int do_msgtrace=0;
struct timeval timeleft;

void sigusr1_handler(void) {
    signal(SIGUSR1, (void(*)(int))sigusr1_handler);
    do_assoc_dump=1;
}

void sigusr2_handler(void) {
    signal(SIGUSR2, (void(*)(int))sigusr2_handler);
    do_msgtrace=1;
}

void sighup_handler(void) {
    signal(SIGHUP, (void(*)(int))sighup_handler);
    do_config_reload=1;
}

void usage(char *arg0) {
    printf(
"Usage: %s [options]\n"
"\n"
"  -h        Print this message and exit.\n"
"  -V        Print version information and exit.\n"
"  -d        Do not daemonize self.\n"
"  -v        Increase verbose level.\n"
"  -i        Ignore interface version mismatch. (dangerous)\n"
"  -c file   Read configuration from file instead of %s\n"
"  -m file   Dump message trace to this file\n",
arg0,machine_config_file);
}

int main(int argc, char *argv[]) {
    int c, i, j, fd;
    int want_daemonize = 1;
    static struct option long_options[] = {
	{"help",    0, 0, 'h'},
	{"version", 0, 0, 'V'},
	{ 0, 0, 0, 0}
    };

    while ((c=getopt_long(argc, argv, "hVc:m:dvi", long_options, 0))!=EOF) {
	switch (c) {
	case 'h':
	    usage(argv[0]);
	    exit(0);
	case 'V':
	    printf("%s version %s (%s-%u-%d)\n", argv[0], PACKAGE_VERSION,
		   version.version_string, version.magic, version.arch);
	    exit(0);
	case 'i': ignore_version = 1; break;
	case 'c': machine_config_file = optarg; break;
	case 'm':

	    if (strcmp(optarg, "-") == 0) {
		fd = dup(STDOUT_FILENO);
		msgtrace_on(fd);
	    } else {
		fd = open(optarg, O_WRONLY|O_CREAT|O_APPEND|O_TRUNC, 0666);
		if (fd == -1) {
		    perror(optarg);
		    exit(1);
		}
		msgtrace_on(fd);
		close(fd);
	    }
	    break;
	case 'v': verbose++; break;
	case 'd': want_daemonize = 0; break;
	default: exit(1);
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
	syslog(LOG_ERR, "Failed to load machine configuration from \"%s\".",
	       machine_config_file);
	exit(1);
    }

    syslog(LOG_INFO, "machine contains %d nodes", conf.num_nodes);

    assoc_init();

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  (void(*)(int))sighup_handler); /* reconfig */
    signal(SIGUSR1, (void(*)(int))sigusr1_handler); /* debug */
    signal(SIGUSR2, (void(*)(int))sigusr2_handler); /* debug */

    if (want_daemonize) daemonize();
    start_iod();

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
			  O_WRONLY|O_CREAT|O_APPEND|O_TRUNC, 0666);
		if (fd != -1) {
		    msgtrace_on(fd); /* this does a dup */
		    close(fd);
		}

		do_msgtrace = 0;
	    }
	    if (do_assoc_dump) {
		assoc_dump();
		do_assoc_dump = 0;
	    }
	    if (do_config_reload) {
		syslog(LOG_INFO, "Rereading configuration from %s",
		       machine_config_file);
		master_config(machine_config_file);
		do_config_reload = 0;
	    }

	    now = time(0);
	    timeleft.tv_sec = now >= lastping + conf.ping_timeout/2 ? 0 :
		conf.ping_timeout/2 - (now - lastping);
	    timeleft.tv_usec = 0;

	    sigprocmask(SIG_UNBLOCK, &sigset, 0);
	    r = epoll_wait(epoll_fd, epoll_events, EPOLL_MAXEV,
			   timeleft.tv_sec * 1000 + timeleft.tv_usec / 1000);

	    if (r == -1) {
		if (errno == EINTR) continue;
		syslog(LOG_ERR, "select: %s", strerror(errno));
		exit(1);
	    }
	    /* Block the update signals while doing work. */
	    sigprocmask(SIG_BLOCK, &sigset, 0);

	    for (i=0; i < r; i++) {
		struct conn_t *conn;
		conn = epoll_events[i].data.ptr;
		if (epoll_events[i].events & EPOLLOUT) {
		    switch ((long) conn) {
		    case 0:
			write_ghost_request();
			ghost_update_epoll();
			break;
		    default:
			if (conn->state == CONN_DEAD) break;
			conn_write(conn);
			conn_update_epoll(conn);
			break;
		    }			
		}
		if (epoll_events[i].events & EPOLLIN) {
		    switch ((long) conn) {
		    case 0:
			read_ghost_request();
			ghost_update_epoll();
			break;
		    case 1: /* hack hack hack magic value */
			conn = 0;
			for (j=0; j < conf.if_list_size; j++)
			    accept_new_slave(&conf.if_list[j]);
			break;
		    default:
			if (conn->state == CONN_DEAD) break;
			conn_read(conn);
			conn_update_epoll(conn);
			break;
		    }
		}

		/* Clean up dead connections here */
		while (!list_empty(&conn_dead)) {
		    struct epoll_event ev;
		    conn = list_entry(conn_dead.next, struct conn_t, list);
		    list_del(&conn->list);
		    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, &ev)) {
			syslog(LOG_ERR, "epoll_ctl(EPOLL_CTL_DEL): %s",
			       strerror(errno));
			exit(1);
		    }
		    close(conn->fd);
		    free(conn);
		}
	    }
	    now = time(0);
	    if (now >= lastping + conf.ping_timeout/2) {
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
