/*------------------------------------------------------------ -*- C -*-
 * send: unicast file sending stuff
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2001 University of California.  LA-CC Number 01-67.
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference to
 * http://www.gnu.org/licenses/gpl.html.
 *
 * This software is provided by the author(s) "as is" and any express
 * or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose
 * are disclaimed.  In no event shall the author(s) be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability,
 * whether in contract, strict liability, or tort (including
 * negligence or otherwise) arising in any way out of the use of this
 * software, even if advised of the possibility of such damage.
 *
 *  $Id: send.c,v 1.15 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <syslog.h>
#include "cmconf.h"

#include "send.h"
#include "list.h"

int verbose __attribute__((weak)) = 0;

#define MAXIFCNAME 31

enum client_state {
    CLIENT_REQ_READ,		/* Waiting to read request */
    CLIENT_DATA_WRITE,
    CLIENT_FILE_WRITE,
};

struct client_t {
    struct list_head list;

    struct timeval last_io;	/* last contact with client */

    enum client_state state;	/* Client state */
    int fd;			/* Socket to client */

    int bytes;
    union {
	struct send_request_t req;	/* buffer for incoming requests */
	struct send_data_t    data;
    } buffer;

    struct filelist_t *file;
    /* File information */
};

struct sender_t {
    struct list_head list;
    struct timeval created;	/* creation time */

    /* If this is a local sender then addr == 0 */
    struct sockaddr_in addr;	/* address and port of senders */

    /* List of clients here ? */
    struct filelist_t *file;

    int depth;
};

struct response_t {
    struct list_head list;
    struct sockaddr_in     addr;
    struct send_response_t resp;
};

struct interface_t {
    struct interface_t *next;

    char  name[MAXIFCNAME+1];
    int   req_fd;		/* For requests + responses */
    int   data_fd;		/* For data accepts */
    struct sockaddr_in addr;	/* The address of the request FD */

    struct list_head local_senders;
    struct list_head senders;	/* Available senders */
    struct list_head clients;	/* clients being served on this interface */
    struct list_head responses; /* Send queue for responses */
};


struct filelist_t {
    struct filelist_t *next;
    int  refct;

    /* File information */
    int mode;
    int user;
    int group;

    long len;
    void *map;

    char name[0];
};

struct config_t {
    struct interface_t *if_list;
    struct filelist_t  *file_list;
    int                 request_port;

    int                 sender_timeout;
    int                 connect_timeout;
    int                 io_timeout;
};

struct config_t conf = {0, 0, 0,
			DEFAULT_SENDER_TIMEOUT,
			DEFAULT_CONNECT_TIMEOUT,
			DEFAULT_IO_TIMEOUT
};

int send_file_port;		/* This symbol is made available so
				 * that other modules will know what
				 * port we're listening on. */

/*--------------------------------------------------------------------
 * Sender code
 */
static
int sender_new(struct interface_t *ifc, struct sender_t *parent,
	       struct sockaddr_in *addr) {
    struct list_head *l;
    struct sender_t *snd;

    /* XXX MAKE SURE THIS ONE ISN'T ALREADY ON THE LIST */
    for (l = ifc->senders.next; l != &ifc->senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);
	if (snd->addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
	    snd->addr.sin_port        == addr->sin_port) {
	    /* We have a match ... */
	    if (strcmp(snd->file->name, parent->file->name) != 0) {
		/* Update this entry like it's a new one and move it
		 * to the front */
		gettimeofday(&snd->created, 0);
		snd->file = parent->file;

		/* Move this one to the back of the list */
		list_del(&snd->list);
		list_add_tail(&snd->list, &ifc->senders);
	    }
	    return 0;
	}
    }

    /* If it's not on the list, make a new entry */
    snd = malloc(sizeof(*snd));
    if (!snd) {
	syslog(LOG_ERR, "Out of memory.");
	return -1;
    }
    memset(snd, 0, sizeof(*snd));

    gettimeofday(&snd->created, 0);
    memcpy(&snd->addr, addr, sizeof(*addr));
    snd->file = parent->file;
    snd->depth = parent->depth+1;

    list_add_tail(&snd->list, &ifc->senders);
    return 0;
}

static
void sender_remove(struct sender_t *snd) {
    list_del(&snd->list);
    free(snd);
}

static
int sender_setup(struct interface_t *ifc, struct filelist_t *f) {
    struct sender_t *snd;

    /* This creates all the dummy send interfaces */
    while (f) {
	snd = malloc(sizeof(*snd));
	if (!snd) {
	    fprintf(stderr, "Out of memory.\n");
	    return -1;
	}
	memset(snd, 0, sizeof(*snd));
	snd->addr  = ifc->addr;	/* Set the address (this is us) */
	snd->file  = f;
	snd->depth = 0;

	list_add_tail(&snd->list, &ifc->local_senders);

	f = f->next;
    }
    return 0;
}

static
int send_timeout(struct interface_t *ifc) {
    int elapsed;
    struct sender_t *snd;
    struct timeval now;
    struct list_head *l, *next;

    gettimeofday(&now, 0);

    /* Timeout senders on this interface */
    for (l = ifc->senders.next; l != &ifc->senders; l = next) {
	next = l->next;
	snd = list_entry(l, struct sender_t, list);

	if (snd->created.tv_sec) { /* only remote senders time out... */
	    elapsed = now.tv_usec - snd->created.tv_usec +
		(now.tv_sec - snd->created.tv_sec) * 1000000;
	    if (elapsed >= conf.sender_timeout) {
		if (verbose) {
		    printf("Expiring sender: %s %s:%d\n",
			   snd->file->name, inet_ntoa(snd->addr.sin_addr),
			   ntohs(snd->addr.sin_port));
		}
		/* Dispose */
		sender_remove(snd);
	    }
	}
    }
    return 0;
}

static
int send_responses(struct interface_t *ifc) {
    int r;
    struct response_t *resp;

    while (!list_empty(&ifc->responses)) {
	resp = list_entry(ifc->responses.next, struct response_t, list);

	r = sendto(ifc->req_fd, &resp->resp, sizeof(resp->resp), 0,
		   (struct sockaddr *) &resp->addr, sizeof(resp->addr));
	if (r == -1) {
	    if (errno == EAGAIN || errno == ENOBUFS)  return 0;
	    syslog(LOG_ERR, "sendto: %s", strerror(errno));
	    return -1;
	}

	if (r != sizeof(resp->resp)) {
	    syslog(LOG_ERR, "sendto: short write.");
	    return -1;
	}

	/* Sent, get rid of it... */
	list_del(&resp->list);
	free(resp);
    }
    return 0;
}



static
char *sender_str(struct sender_t *snd) {
    static char buf[100];
    struct timeval now;
    gettimeofday(&now,0);
    sprintf(buf, "%-20s %d %s:%d %.2fs", snd->file->name, snd->depth,
	    inet_ntoa(snd->addr.sin_addr), ntohs(snd->addr.sin_port),
	    snd->created.tv_sec == 0 ? 0.0 :
	    ((now.tv_usec - snd->created.tv_usec +
	      (now.tv_sec -  snd->created.tv_sec) * 1000000)) / 1000000.0);
    return buf;
}

static
void sender_dump(struct interface_t *ifc) {
    struct sender_t *snd;
    struct list_head *l;

    printf("Sender dump (%s):\n", ifc->name);
    for (l = ifc->senders.next; l != &ifc->senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);
	printf("    %s\n", sender_str(snd));
    }

    for (l = ifc->local_senders.next; l != &ifc->local_senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);
	printf("  L %s\n", sender_str(snd));
    }
}

static
struct sender_t *sender_find(struct interface_t *ifc,
			     struct send_request_t *req) {
    struct sender_t *snd;
    struct list_head *l;
    int depth;

    if (verbose > 2)
	sender_dump(ifc);

    depth = ntohl(req->depth);

    /* First try to find a remote sender for this file */
    for (l = ifc->senders.next; l != &ifc->senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);

	if ((depth == SEND_DEPTH_NONE || snd->depth < depth) &&
	    strcmp(snd->file->name, req->filename) == 0) {

	    /* Move the sender to the back of the queue */
	    list_del(&snd->list);
	    list_add_tail(&snd->list, &ifc->senders);

	    return snd;
	}
    }

    /* Otherwise, try out own list of senders */
    for (l = ifc->local_senders.next; l != &ifc->local_senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);

	if ((depth == SEND_DEPTH_NONE || snd->depth < depth) &&
	    strcmp(snd->file->name, req->filename) == 0)
	    return snd;
    }

    return 0;
}

static
void sender_fail(struct interface_t *ifc, struct send_request_t *req) {
    struct sender_t *snd;
    struct list_head *l;

    for (l = ifc->senders.next; l != &ifc->senders; l = l->next) {
	snd = list_entry(l, struct sender_t, list);

	if (snd->addr.sin_addr.s_addr == req->fail_addr &&
	    snd->addr.sin_port        == req->fail_port) {
	    if (verbose) {
		printf("%s:%d removing failing sender: %s\n",
		       inet_ntoa(*(struct in_addr *)&req->fail_addr),
		       ntohs(req->fail_port), sender_str(snd));
	    }
	    sender_remove(snd);
	    break;
	}
    }
}

/*--------------------------------------------------------------------
 * Request handling code
 */
static
int request_new(struct interface_t *ifc) {
    int addrsize, r;
    struct sockaddr_in addr, resend_addr;
    struct send_request_t req;
    struct sender_t *snd;
    struct response_t *resp = 0;

    /* Keep reading requests till we get an EAGAIN */
    while (1) {
	addrsize = sizeof(addr);
	r = recvfrom(ifc->req_fd, &req, sizeof(req), 0,
		     (struct sockaddr *) &addr, &addrsize);
	if (r == -1) {
	    if (errno == EAGAIN) return 0;
	    syslog(LOG_ERR, "recvfrom: %s\n", strerror(errno));
	    return -1;
	}

	if (r != sizeof(req)) {
	    if (verbose > 2)
		printf("%s:%d Request packet w/ incorrect size."
		       " (expecting %d, got %d)\n", inet_ntoa(addr.sin_addr),
		       ntohs(addr.sin_port), (int) sizeof(req), r);
	    continue;	/* wrong size, continue */
	}
	if (ntohl(req.req_magic) != SEND_REQUEST_MAGIC) {
	    if (verbose > 2)
		printf("%s:%d Request packet w/ magic number.\n",
		       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	    continue;
	}

	req.filename[MAX_FILE_NAME] = 0;

	if (verbose) {
	    printf("%s:%d request filename=%s depth=%d resend_port=%d",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
		   req.filename, ntohl(req.depth), ntohs(req.resend_port));
	    printf(" fail=%s:%d\n",
		   inet_ntoa(*(struct in_addr*)&req.fail_addr),
		   ntohs(req.fail_port));
	}

	if (ntohl(req.fail_addr))
	    sender_fail(ifc, &req);

	resp = malloc(sizeof(*resp));
	if (!resp) {
	    syslog(LOG_ERR, "Out of memory.\n");
	    return -1;
	}
	memset(resp, 0, sizeof(*resp));
	memcpy(&resp->addr, &addr, sizeof(addr)); /* where to send response */
	resp->resp.sender_timeout  = htonl(conf.sender_timeout);
	resp->resp.connect_timeout = htonl(conf.connect_timeout);
	resp->resp.io_timeout      = htonl(conf.io_timeout);

	/* Initialize response */
	resp->resp.magic     = htonl(SEND_RESPONSE_MAGIC);
	resp->resp.req_magic = req.req_magic;
	resp->resp.status    = htonl(SEND_ERROR_ENOENT);
	resp->resp.depth     = req.depth;

	snd = sender_find(ifc, &req);
	if (snd) {
	    if (verbose > 1) {
		printf("%s:%d req sender: %s\n",
		       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
		       sender_str(snd));
	    }

	    /* Turn this into a successful response */
	    resp->resp.status = 0;
	    resp->resp.addr   = snd->addr.sin_addr.s_addr;
	    resp->resp.port   = snd->addr.sin_port;
	    if (ntohl(req.depth) == SEND_DEPTH_NONE)
		resp->resp.depth = htonl(snd->depth + 1);

	    /* Add this request as a new sender */
	    resend_addr = addr;
	    resend_addr.sin_port = req.resend_port;

	    sender_new(ifc, snd, &resend_addr);
	}

	/* Append to the end of the list of responses to send */
	list_add_tail(&resp->list, &ifc->responses);

	if (verbose) {
	    printf("%s:%d response:", inet_ntoa(addr.sin_addr),
		   ntohs(addr.sin_port));
	    printf(" status=%d addr=%s:%d depth=%d\n",
		   ntohl(resp->resp.status),
		   inet_ntoa(*(struct in_addr *) &resp->resp.addr),
		   ntohs(resp->resp.port), ntohl(resp->resp.depth));
	}
    }
    return 0;
}

/*--------------------------------------------------------------------
 * Filelist handling code
 */
static
int filelist_open(struct filelist_t *f) {
    int fd;
    struct stat buf;

    if (stat(f->name, &buf)) {
	syslog(LOG_ERR, "stat(\"%s\"): %s", f->name, strerror(errno));
	return -1;
    }

    if (!S_ISREG(buf.st_mode)) {
	syslog(LOG_ERR, "%s: not a regular file", f->name);
	return -1;
    }

    fd = open(f->name, O_RDONLY);
    if (fd == -1) {
	syslog(LOG_ERR, "open(\"%s\"): %s", f->name, strerror(errno));
	return -1;
    }

    /* Make note of misc file details */
    f->mode  = buf.st_mode;
    f->user  = buf.st_uid;
    f->group = buf.st_gid;
    f->len   = buf.st_size;

    f->map = mmap(0, f->len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (f->map == MAP_FAILED) {
	syslog(LOG_ERR, "mmap(\"%s\"): %s", f->name, strerror(errno));
	close(fd);
	return -1;
    }
    close(fd);
    return 0;
}

static
struct filelist_t *filelist_get(const char *filename) {
    struct filelist_t *f;

    for (f = conf.file_list; f; f = f->next)
	if (strcmp(f->name, filename) == 0) {
	    if (f->refct == 0) {
		/* Open the file if it isn't open already */
		if (filelist_open(f))
		    return 0;
	    }
	    f->refct++;
	    return f;
	}
    return 0;
}

static
void filelist_put(struct filelist_t *f) {
    f->refct--;
    if (f->refct == 0) {
	/* Unmap the file if we're done with it */
	munmap(f->map, f->len);
    }
}

/*--------------------------------------------------------------------
 * Client IO code
 */

static
void client_remove(struct client_t *c) {
    list_del(&c->list);
    close(c->fd);

    if (c->file) filelist_put(c->file);
    free(c);
}

static
void client_accept(struct interface_t *ifc) {
    int fd, flag, addrsize;
    struct sockaddr_in addr;
    struct client_t *c;

    while (1) {
	addrsize = sizeof(addr);
	fd = accept(ifc->data_fd, (struct sockaddr *) &addr, &addrsize);
	if (fd == -1) {
	    if (errno == EAGAIN) return;
	    syslog(LOG_ERR, "accept: %s", strerror(errno));
	    return;
	}

	flag = fcntl(fd, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flag);

	if (verbose > 0)
	    printf("%s:%d new client accepted\n", inet_ntoa(addr.sin_addr),
		   ntohs(addr.sin_port));

	c = malloc(sizeof(*c));
	if (!c) {
	    syslog(LOG_ERR, "Out of memory.");
	    return;
	}
	memset(c, 0, sizeof(*c));
	c->fd = fd;
	gettimeofday(&c->last_io, 0);
	c->state = CLIENT_REQ_READ;

	/* Append to end of client list */
	list_add_tail(&c->list, &ifc->clients);
    }
}

static
void client_do_read_req(struct client_t *c) {
    int size, r;
    struct filelist_t *f;

    /* Note the client should be in CLIENT_READ_REQ */
    gettimeofday(&c->last_io, 0);

    size = sizeof(c->buffer.req);

    r = read(c->fd, ((void *)&c->buffer.req) + c->bytes, size - c->bytes);
    if (r == -1) {
	if (errno == EAGAIN) return;
	if (verbose)
	    printf("read: %s\n",strerror(errno));
	client_remove(c);
	return;
    }
    if (r == 0) {
	if (verbose)
	    printf("read: short read from client\n");
	client_remove(c);
	return;
    }

    c->bytes += r;
    if (c->bytes == size) {
	c->bytes = 0;		/* reset */
        /* We finished reading the request, check the file and make the
	 * state transition. */
	c->buffer.req.filename[MAX_FILE_NAME] = 0;

	f = filelist_get(c->buffer.req.filename);

	c->state = CLIENT_DATA_WRITE;
	c->buffer.data.magic  = htonl(SEND_DATA_MAGIC);
	c->file = f;
	if (f) {
	    c->buffer.data.status = htonl(0);
	    c->buffer.data.size   = htonl(f->len);
	    c->buffer.data.mode   = htonl(f->mode);
	    c->buffer.data.user   = htonl(f->user);
	    c->buffer.data.group  = htonl(f->group);

	    c->file = f;
	} else {
	    c->buffer.data.status = htonl(SEND_ERROR_ENOENT);
	    c->file = 0;
	}
    }
}

static
void client_do_write(struct client_t *c) {
    int size=0, w;
    void *p=0;

    gettimeofday(&c->last_io, 0);

    switch (c->state) {
    case CLIENT_REQ_READ:
	abort();
    case CLIENT_DATA_WRITE:
	p = &c->buffer.data;
	size = sizeof(c->buffer.data);
	break;
    case CLIENT_FILE_WRITE:
	p    = c->file->map;
	size = c->file->len;
	break;
    }

    w = write(c->fd, p + c->bytes, size - c->bytes);
    if (w == -1) {
	if (errno == EAGAIN) return;
	if (verbose)
	    syslog(LOG_ERR, "write: %s", strerror(errno));
	client_remove(c);
	return;
    }

    c->bytes += w;
    if (c->bytes == size) {
	/* Finished a chunk */

	c->bytes = 0;		/* reset */

	switch (c->state) {
	case CLIENT_REQ_READ:
	    abort();
	case CLIENT_DATA_WRITE:
	    if (c->file) {
		c->state = CLIENT_FILE_WRITE;
	    } else {
		client_remove(c);
		return;
	    }
	    break;
	case CLIENT_FILE_WRITE:
	    /* Finished */
	    client_remove(c);
	    return;
	}
    }
}

static
void timeout_clients(struct interface_t *ifc) {
    int elapsed;
    struct timeval now;
    struct client_t *c;
    struct list_head *l, *next;

    gettimeofday(&now, 0);
    for (l = ifc->clients.next; l != &ifc->clients; l = next) {
	next = l->next;
	c = list_entry(l, struct client_t, list);

	elapsed = now.tv_usec - c->last_io.tv_usec +
	    (now.tv_sec - c->last_io.tv_sec)*1000000;

	if (elapsed > conf.io_timeout)
	    client_remove(c);
    }
}



/*--------------------------------------------------------------------
 * Configuration code
 */
static
struct config_t tc;		/* Temporary configuration used duriung load */

static
int setup_sockets(struct interface_t *ifc) {
    int fd, flag, r, addrsize;
    struct sockaddr_in addr;
    struct ifreq ifr;
    struct interface_t *ifcp;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	syslog(LOG_ERR, "socket(AF_INET, SOCK_DGRAM): %s", strerror(errno));
	return -1;
    }

    /* Get the address for this interface */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifc->name, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
	syslog(LOG_ERR, "ioctl(SIOCGIFADDR): %s", strerror(errno));
	return -1;
    }

    memset(&addr, 0, sizeof(addr));
    memcpy(&addr.sin_addr,
	   &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr,
	   sizeof(addr.sin_addr));

    /* Setup the UDP socket for requests/responses */
    flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   &flag, sizeof(flag)) == -1) {
	syslog(LOG_ERR, "setsockopt(SOL_SOCKET, SO_REUSEADDR): %s",
	       strerror(errno));
	close(fd);
	return -1;
    }

    /* Set non-blocking mode */
    flag = fcntl(fd, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flag);

    addr.sin_port = htons(tc.request_port);
    r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (r == -1 && errno == EADDRINUSE) {
	/* Craziness here... We might already have a socket on the
	 * address we're looking for.  If so, try and steal it. */
	for (ifcp = tc.if_list; ifcp; ifcp = ifcp->next) {
	    if (ifc->addr.sin_addr.s_addr == ifcp->addr.sin_addr.s_addr &&
		ifc->addr.sin_port        == ifcp->addr.sin_port) {
		/* Steal the FD */
		close(fd);
		fd = dup(ifcp->req_fd);
		r = 0;
		break;
	    }
	}
    }
    if (r == -1) {
	syslog(LOG_ERR, "bind(%s:%d): %s",
	       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
	       strerror(errno));
	close(fd);
	return -1;
    }

    ifc->req_fd = fd;

    /*--- Setup the TCP socket for data ------------------------------*/
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	syslog(LOG_ERR, "socket(AF_INET, SOCK_STREAM): %s",
	       strerror(errno));
	return -1;
    }
    flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   &flag, sizeof(flag)) == -1) {
	syslog(LOG_ERR, "setsockopt(SOL_SOCKET, SO_REUSEADDR): %s",
	       strerror(errno));
	close(fd);
	return -1;
    }

    /* Set non-blocking mode */
    flag = fcntl(fd, F_GETFL);
    flag |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flag);

    /* Bind to the same address/port as the control socket */
    addr.sin_port = 0;		/* Any port here */
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr))) {
	syslog(LOG_ERR, "bind: %s\n", strerror(errno));
	close(fd);
	return -1;
    }

    addrsize = sizeof(ifc->addr);
    if (getsockname(fd, (struct sockaddr *)&ifc->addr, &addrsize)) {
	syslog(LOG_ERR, "getsockaddr: %s\n", strerror(errno));
	close(fd);
	return -1;
    }

    listen(fd, 1024);		/* BIG listen backlog... */

    ifc->data_fd = fd;
    return 0;
}

static
int send_config_interface(struct cmconf *conf, char **args) {
    struct interface_t *ifc;

    ifc = malloc(sizeof(*ifc));
    if (!ifc) {
	syslog(LOG_ERR, "Out of memory.");
	return -1;
    }

    memset(ifc, 0, sizeof(*ifc));
    strncpy(ifc->name, args[1], MAXIFCNAME);
    ifc->req_fd  = -1;
    ifc->data_fd = -1;

    INIT_LIST_HEAD(&ifc->local_senders);
    INIT_LIST_HEAD(&ifc->senders);
    INIT_LIST_HEAD(&ifc->clients);
    INIT_LIST_HEAD(&ifc->responses);

    if (setup_sockets(ifc)) {
	if (ifc->req_fd  != -1) close(ifc->req_fd);
	if (ifc->data_fd != -1) close(ifc->data_fd);
	free(ifc->name);
	free(ifc);
	return -1;
    }

    if (verbose)
	printf("%s: data socket %s:%d\n", args[1],
	       inet_ntoa(ifc->addr.sin_addr),
	       htons(ifc->addr.sin_port));

    /* Add it to the list */
    ifc->next = tc.if_list;
    tc.if_list = ifc;
    return 0;
}

static
int get_port(char *arg, char *type) {
    char *check;
    int portno;
    struct servent *s;


    portno = strtol(arg, &check, 0);
    if (*check) {
	s = getservbyname(arg, type);
	if (!s) {
	    syslog(LOG_ERR, "unknown service/invalid port: %s", arg);
	    return -1;
	}
	portno = ntohs(s->s_port);
    }
    if (portno < 0 || portno >= 65536) {
	syslog(LOG_ERR, "invalid port: %s", arg);
	return -1;
    }
    return portno;
}

static
int send_config_port(struct cmconf *conf, char **args) {
    tc.request_port = get_port(args[1], "udp");
    if (tc.request_port == -1) return -1;
    return 0;
}

static
int send_config_bootfile(struct cmconf *conf, char **args) {
    char *fname;
    struct filelist_t *f;

    fname = args[2] ? args[2] : args[1];

    f = malloc(sizeof(*f) + strlen(fname) + 1);
    if (!f) {
	fprintf(stderr, "Out of memory.\n");
	return -1;
    }
    memset(f, 0, sizeof(*f));
    strcpy(f->name, fname);

    f->next = tc.file_list;
    tc.file_list = f;
    return 0;
}

static
int send_config_timeout(struct cmconf *conf, char **args) {
    char *check;
    int timeout;
    timeout = strtod(args[1], &check) * 1000000; /* translate all to usec */
    if (*check || timeout <= 0) {
	syslog(LOG_ERR, "Invalid timeout: %s", args[1]);
	return -1;
    }

    switch(args[0][0]) {
    case 'c':			/* connect_timeout */
	tc.connect_timeout = timeout;
	break;
    case 'r':			/* resend_timeout */
	tc.sender_timeout = timeout;
	break;
    case 'i':			/* io_timeout */
	tc.io_timeout = timeout;
	break;
    }
    return 0;
}

static
int send_config_unknown(struct cmconf *conf, char **args) {
    syslog(LOG_ERR, "%s:%d unknown send configuration option: %s",
		cmconf_file(conf), cmconf_lineno(conf), args[0]);
    return -1;
}

static
struct cmconf_option send_configopts[] = {
    { "port",           1, 1, 0, send_config_port},
    { "connect_timeout", 1, 1, 0, send_config_timeout},
    { "resend_timeout",  1, 1, 0, send_config_timeout},
    { "io_timeout",      1, 1, 0, send_config_timeout},
    { "*",              0,-1, 0, send_config_unknown},
    { 0, }
};

static
int send_callback(struct cmconf *conf, char **args) {
    return cmconf_process_args(conf, args+1, send_configopts);
}

static
struct cmconf_option configopts[] = {
    { "interface",          1, 3, 1, send_config_interface},
    { "bootfile",           1, 2, 0, send_config_bootfile},
    { "send",               0,-1, 0, send_callback},
    { 0, }
};

static
void config_free(struct config_t *c) {
    struct interface_t *ifc;

    while (c->if_list) {
	ifc = c->if_list;
	c->if_list = ifc->next;

	close(ifc->req_fd);
	close(ifc->data_fd);

	/* Clean up clients first because they reference file list entries */
	while (!list_empty(&ifc->clients)) {
	    struct client_t *cl;
	    cl = list_entry(ifc->clients.next, struct client_t, list);
	    client_remove(cl);
	}

	/* Ditch our own senders */
	while (!list_empty(&ifc->local_senders)) {
	    struct sender_t *snd;
	    snd = list_entry(ifc->local_senders.next, struct sender_t, list);
	    sender_remove(snd);
	}

	/* And the remote ones */
	while (!list_empty(&ifc->senders)) {
	    struct sender_t *snd;
	    snd = list_entry(ifc->senders.next, struct sender_t, list);
	    sender_remove(snd);
	}

	while (!list_empty(&ifc->responses)) {
	    struct response_t *resp;
	    resp = list_entry(ifc->senders.next, struct response_t, list);
	    list_del(&resp->list);
	    free(resp);
	}

	free(ifc);
    }

    while (c->file_list) {
	struct filelist_t *f;
	f = c->file_list;
	c->file_list = f->next;
	free(f);
    }
}


int send_setup(char *configfile) {
    struct interface_t *ifc;

    signal(SIGPIPE, SIG_IGN);	/* sigpipe can be troublesome for us */

    memset(&tc, 0, sizeof(tc));
    tc.request_port    = DEFAULT_REQUEST_PORT;
    tc.sender_timeout  = DEFAULT_SENDER_TIMEOUT;
    tc.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    tc.io_timeout      = DEFAULT_IO_TIMEOUT;

    if (cmconf_process_file(configfile, configopts)) {
	config_free(&tc);
	return -1;
    }

    for (ifc = tc.if_list; ifc; ifc = ifc->next) {
	if (sender_setup(ifc, tc.file_list)) {
	    config_free(&tc);
	    return -1;
	}
    }

    config_free(&conf);		/* switch to new configuration */
    conf = tc;

    /* Make this port number available to external things */
    send_file_port = conf.request_port;
    return 0;
}


int send_select_1(int *maxfd, fd_set *rset, fd_set *wset,
		  fd_set *eset, struct timeval *tmo) {
    struct interface_t *ifc;
    struct client_t *c;
    struct list_head *l;

    for (ifc = conf.if_list; ifc; ifc = ifc->next) {
	/* Add our listen descriptors */

	FD_SET(ifc->req_fd, rset);
	if (!list_empty(&ifc->responses)) FD_SET(ifc->req_fd, wset);
	if (ifc->req_fd > *maxfd) *maxfd = ifc->req_fd;

	FD_SET(ifc->data_fd, rset);
	if (ifc->data_fd > *maxfd) *maxfd = ifc->data_fd;

	/* Check our clients */
	for (l = ifc->clients.next; l != &ifc->clients; l = l->next) {
	    c = list_entry(l, struct client_t, list);
	    if (c->fd > *maxfd) *maxfd = c->fd;
	    switch (c->state) {
	    case CLIENT_REQ_READ:
		FD_SET(c->fd, rset);
		break;
	    case CLIENT_DATA_WRITE:
	    case CLIENT_FILE_WRITE:
		FD_SET(c->fd, wset);
		break;
	    }
	}
    }

    /* XXX We should really come up with a timeout value based on our
     * senders and clients.... */

    return 0;
}

int send_select_2(fd_set *rset, fd_set *wset, fd_set *eset) {
    struct interface_t *ifc;
    struct list_head *l, *next;
    struct client_t *c;

    for (ifc = conf.if_list; ifc; ifc = ifc->next) {
	/* Start by removing any timed out senders */
	send_timeout(ifc);

	/* Deal with request traffic */
	if (FD_ISSET(ifc->req_fd, rset))
	    request_new(ifc);
	if (!list_empty(&ifc->responses) && FD_ISSET(ifc->req_fd, wset))
	    send_responses(ifc);

	if (FD_ISSET(ifc->data_fd, rset))
	    client_accept(ifc);

	for (l = ifc->clients.next; l != &ifc->clients; l = next) {
	    next = l->next;
	    c = list_entry(l, struct client_t, list);

	    switch (c->state) {
	    case CLIENT_REQ_READ:
		if (FD_ISSET(c->fd, rset))
		    client_do_read_req(c);
		break;
	    case CLIENT_DATA_WRITE:
	    case CLIENT_FILE_WRITE:
		if (FD_ISSET(c->fd, wset))
		    client_do_write(c);
		break;
	    }
	}

	/* Finally purge clients that have been idle too long */
	timeout_clients(ifc);
    }
    return 0;
}



/*--------------------------------------------------------------------
 * Debugging main for stand-alone testing
 */
int main(int argc, char *argv[]) __attribute__((weak));
int main(int argc, char *argv[]) {
    verbose = 999;

    openlog(argv[0], LOG_PERROR, LOG_DAEMON);

    if (send_setup(CONFIGDIR "/config"))
	exit(1);

    /* This is the basic driver for this selecting socket monkey
     * business */
    while (1) {
	int r, maxfd;
	fd_set rset, wset, eset;
	struct timeval tmo;
	maxfd = -1;
	FD_ZERO(&rset); FD_ZERO(&wset); FD_ZERO(&eset);
	tmo.tv_sec  = 99999;	/* bigger than anything we're gonna see. */
	tmo.tv_usec = 0;

	send_select_1(&maxfd, &rset, &wset, &eset, &tmo);
	r = select(maxfd+1, &rset, &wset, &eset,
		   tmo.tv_sec == 99999 ? 0 : &tmo);
	/*printf("select=%d\n", r);*/
	if (r == -1 && errno != EINTR) {
	    syslog(LOG_ERR, "select(): %s", strerror(errno));
	    exit(1);
	}
	if (r > 0) {
	    send_select_2(&rset, &wset, &eset);
	}
    }
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
