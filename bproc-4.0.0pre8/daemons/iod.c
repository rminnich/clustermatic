/*-------------------------------------------------------------------------
 *  iod.c:  Beowulf distributed PID IO daemon
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: iod.c,v 1.20 2004/04/19 15:47:31 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include "bproc.h"
#include <sys/bproc.h>

#include <sys/prctl.h>

#define BSIZE 4096

struct buffer_t {
    int start;
    int size, bytes;
    char end;
    char *buffer;
} buffer;

struct ioc {
    struct ioc *next;
    int in, out;
    struct buffer_t buffer;
};

static struct ioc *list=0;
static int file_table_full = 0, secondary_iod = 0;

/*--------------------------------------------------------------------
 *  Buffer handling stuff
 *------------------------------------------------------------------*/
static
int buffer_new(struct buffer_t *b, int size) {
    b->size = size;
    b->buffer = malloc(b->size);
    if (!b->buffer) {
	syslog(LOG_CRIT, "iod: Out of memory in IO buffer allocation.");
	exit(1);
    }
    b->start = b->bytes = 0;
    return 0;
}

static
void buffer_free(struct buffer_t *b) {
    free(b->buffer);
}

/* Return size of max contiguous buffer reads/writes */
static inline
int buffer_max_write(struct buffer_t *b) {
    if (b->start + b->bytes >= b->size)
	return b->size - b->bytes;
    return b->size - b->start - b->bytes;
}

static inline
int buffer_max_read(struct buffer_t *b) {
    if (b->start + b->bytes >= b->size)
	return b->size - b->start;
    return b->bytes;
}

static inline int   buffer_full      (struct buffer_t *b)           { return b->bytes == b->size; }
static inline int   buffer_empty     (struct buffer_t *b)           { return b->bytes == 0; }
static inline void  buffer_flush     (struct buffer_t *b)           { b->bytes = 0; }
static inline void *buffer_read_ptr  (struct buffer_t *b)           { return b->buffer + b->start; }
static inline void *buffer_write_ptr (struct buffer_t *b)           { return b->buffer + ((b->start + b->bytes) % b->size); }
static inline void  buffer_move_write(struct buffer_t *b, int offs) { b->bytes += offs; }
static inline void  buffer_move_read (struct buffer_t *b, int offs) { b->start = (b->start + offs) % b->size; b->bytes -= offs; }

/*-------------------------------------------------------------------------
 *
 *-----------------------------------------------------------------------*/
static inline
void iod_close(int *fd) {
    if (*fd == -1) return;
    close(*fd);
    *fd = -1;
    if (file_table_full) file_table_full--;
}

static
void do_conn_close(struct ioc *c) {
    iod_close(&c->in);
    iod_close(&c->out);
    buffer_flush(&c->buffer);
}

static
void do_conn_read(struct ioc *c) {
    int r;
    r = read(c->in,buffer_write_ptr(&c->buffer),buffer_max_write(&c->buffer));
    if (r == -1 || r == 0) {
	/* XXX treat any read error like EOF? (EAGAIN) */
	/* We've hit EOF! */
	iod_close(&c->in);
	if (c->buffer.bytes == 0) iod_close(&c->out);
	return;
    }
    buffer_move_write(&c->buffer, r);
}

static
void do_conn_write(struct ioc *c) {
    int r;
    r = write(c->out,buffer_read_ptr(&c->buffer),buffer_max_read(&c->buffer));
    if (r == -1 || r == 0) {
	do_conn_close(c);
	return;
    }
    buffer_move_read(&c->buffer, r);
    /* Check if there's no more input coming and we just finished
     * emptying the buffer. */
    if (c->in == -1 && buffer_empty(&c->buffer)) iod_close(&c->out);
}


/*--------------------------------------------------------------------
 * IO Connection handling stuff...
 *------------------------------------------------------------------*/
static
struct ioc *ioc_new(int in, int out) {
    struct ioc *tmp;
    tmp = malloc(sizeof(*tmp));
    if  (!tmp) {
	syslog(LOG_CRIT, "iod: Out of memory in new_buffer()\n");
	exit(1);
    }    
    tmp->next = 0;
    tmp->in = in; tmp->out = out;
    buffer_new(&tmp->buffer, BSIZE);
    return tmp;
}

static
void ioc_cleanup(struct ioc *conn) {
    /* Assume the connection (file descriptors) have been closed at
     * this point */
    buffer_free(&conn->buffer);
    free(conn);
}

static
void ioc_purge(void) {
    struct ioc dummy, *p, *next;
    dummy.next = list;
    p = &dummy;
    while(p->next) {
	next = p->next;
	if (next->in == -1 && next->out == -1) {
	    p->next = next->next;
	    buffer_free(&next->buffer);
	    free(next);
	} else
	    p = p->next;
    }
    list = dummy.next;
}

static
void pickup_new_ioc(int iodfd) {
    int fd[2], pid;
    struct ioc *conn;
    
    if (ioctl(iodfd, BPROC_GET_IO, fd) == -1) {
	switch (errno) {
        /*** We're out of file descriptors... time to fork... ---------***/
	case EMFILE:
	    /* Sanity check */
	    if (!list) {
		syslog(LOG_CRIT, "iod: Aaiiee!! No connections but still got EMFILE!");
		exit(1);
	    }
	    pid = fork();
	    if (pid < 0) {
		syslog(LOG_ERR, "iod: fork failed!");
		/* XXX What should I do here? */
		return;
	    }
	    if (pid == 0) {
		secondary_iod = 1;
		/* Get rid of all the connections that belong to the parent */
		while(list) {
		    conn = list; list = list->next;
		    do_conn_close(conn);
		    ioc_cleanup(conn);
		}
		pickup_new_ioc(iodfd);
		return;
	    }
	    file_table_full = 2; /* Set this to 2 because we want free
				  * 2 fd's before we try this
				  * again... */
	    return;
	/*** someone beat us to it, no problem... ---------------------***/
	case EAGAIN:
	    return;
	default:
	    syslog(LOG_ERR, "iod: get new ioc failed: %s  (ignoring)", strerror(errno));
	    return;
	}
    }

    /* Ok setup our structures for the new FD's */
    conn = ioc_new(fd[0], fd[1]);
    conn->next = list; list = conn; /* Insert into lists... */
}

/*-------------------------------------------------------------------------
 *  iod_main
 *-----------------------------------------------------------------------*/
static
void iod_main(int iodfd) {
    int r, maxfd;
    fd_set rset, wset;
    struct ioc *c;

    file_table_full = 0;
    secondary_iod   = 0;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
  
    while(1) {
	/*** Prepare fd_sets ------------------------------------------***/
	FD_ZERO(&rset); FD_ZERO(&wset);
	if (!file_table_full) FD_SET(iodfd, &rset);
	maxfd = iodfd;
	for (c = list; c; c = c->next) {
	    if (c->out!=-1 && !buffer_empty(&c->buffer)) FD_SET(c->out, &wset);
	    if (c->in !=-1 && !buffer_full (&c->buffer)) FD_SET(c->in, &rset);
	    /** XXX hack to help with SIGPIPE'ish issues... Bad? */
	    /* FD_SET(c->out, &rset); (broken) */
	    if (c->in  > maxfd) maxfd = c->in;
	    if (c->out > maxfd) maxfd = c->out;
	}
	
	r = select(maxfd+1, &rset, &wset, 0, 0);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "iod: select: %s\n", strerror(errno));
	    exit(1);
	}
	if (r > 0) {
	    if (FD_ISSET(iodfd, &rset))	pickup_new_ioc(iodfd);

	    /* Service connections */
	    for (c = list; c; c = c->next) {
		if (c->out !=-1 && FD_ISSET(c->out, &wset)) do_conn_write(c);
		if (c->in  !=-1 && FD_ISSET(c->in,  &rset)) do_conn_read(c);
		/*if (c->out !=-1 && FD_ISSET(c->out, &rset)) do_conn_close(c);*/
	    }

	    ioc_purge();
	    if (secondary_iod && list == 0) {
		syslog(LOG_ERR, "iod: exiting.\n");
		exit(0);
	    }
	}
    }
}

int start_iod(void) {

    int pid, iodfd;

    /* We do this in the parent process for 2 reasons: first, this way
     * we easily make sure that we can get the device before we go on,
     * secondly, this makes sure the kernel knows about an IO daemon
     * before we do anything else. */
    iodfd = syscall(__NR_bproc, BPROC_SYS_IOD);
    if (iodfd == -1) {
	perror("bproc iod");
	return -1;
    }

    pid = fork();
    if (pid == -1) {
	syslog(LOG_ERR, "Failed to start IO daemon: %s\n", strerror(errno));
	exit(1);
    }
    if (pid == 0) {
	/* Ditch open file descriptors we're not interested in.  This
	 * is pretty gross. */
	int i;
	for (i = 3; i < 20; i++) /* that should be enough */
	    if (i != iodfd)
		close(i);

	prctl(PR_SET_PDEATHSIG, SIGKILL); /* kill me when parent dies */
	iod_main(iodfd);
	exit(0);
    }

    close(iodfd);
    syslog(LOG_INFO, "IO daemon started; pid=%d", pid);
    return pid;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
