/*-------------------------------------------------------------------------
 *  bpsh.c: A simple rsh-like client for bproc
 *
 *  Erik Hendriks <erik@hendriks.cx>
 *
 *  This is a modified version of bpsh based on the original which was
 *  also written by me while I worked at Scyld.
 *
 *  Copyright (C) 2000 Scyld Computing Corporation
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
 * $Id: bpsh.c,v 1.61 2004/10/15 21:20:03 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <sys/un.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <bproc.h>
#include <bproc.h>
#include <sched.h>

#include <arpa/inet.h>
#include <netdb.h>

#define IO_STDIN         1
#define IO_SEQUENTIAL    2
#define IO_DIVIDERS      4
#define IO_LINEBUFF      8
#define IO_PREFIX     0x10

struct input_buffer {
	int num;		/* number of readers */
	int infd;
	int bytes;		/* Bytes in the buffer.   */
	int *outfds;		/* Slave file descriptors */
	char **readptrs;	/* Slave read pointers.   */
	char *buf;
};

struct output_buffer {
	int infd, outfd;
	int bytes;
	char *buf;
};

struct node_io {
	int node;
	int cnum;		/* connection number (0 = all done) */
	int pid;
	int alive;
	struct input_buffer *in;
	struct output_buffer io[2];
};

static int buffer_size = 4096;
static volatile int max_exit = 0;
static int num_nodes;
static struct node_io *nodes;
static int num_files;
/*static          int no_io = 0;*/

/* The kernel rounds the size of our fd_set up so we should do it as well. */
#define FDS_BITPERLONG  (8*sizeof(long))
#define FDS_LONGS(nr)   (((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)   (FDS_LONGS(nr)*sizeof(long))

extern char **environ;

static
void Usage(char *arg0)
{
	printf("usage: %s [options] nodenumber command\n"
	       "       %s -a [options] command\n"
	       "       %s -A [options] command\n"
	       "       -h     Display this message and exit\n"
	       "       -v     Display version information and exit\n"
	       "  Node selection options:\n"
	       "       -a     Run the command on all nodes which are up.\n"
	       "       -A     Run the command on all nodes which are not down.\n"
	       "  IO forwarding options:\n"
	       "       -n     Redirect stdin from /dev/null\n"
	       "       -N     No IO forwarding\n"
	       "       -L     Line buffer output from remote nodes.\n"
	       "       -p     Prefix each line of output with the node number\n"
	       "              it is from. (implies -L)\n"
	       "       -s     Show the output from each node sequentially.\n"
	       "       -d     Print a divider between the output from each\n"
	       "              node. (implies -s)\n"
	       "       -b ##  Set IO buffer size to ## bytes.  This affects the\n"
	       "              maximum line length for line buffered IO. (default=%d)\n"
	       "       -I file\n"
	       "       --stdin file\n"
	       "              Redirect standard in from file on the remote node.\n"
	       "       -O file\n"
	       "       --stdout file\n"
	       "              Redirect standard out to file on the remote node.\n"
	       "       -E file\n"
	       "       --stderr file\n"
	       "              Redirect standard error to file on the remote node.\n"
	       "       -t,--time\n"
	       "              Time how long the command takes to complete.  This includes\n"
	       "              the time for process creation.\n", arg0, arg0,
	       arg0, buffer_size);
	exit(1);
}

static
void set_non_block(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		perror("fcntl");
		exit(1);
	}
	flags |= O_NONBLOCK;
	flags = fcntl(fd, F_SETFL, flags);
	if (flags == -1) {
		perror("fcntl");
		exit(1);
	}
}

static
void set_close_exec(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		perror("fcntl");
		exit(1);
	}
	flags |= FD_CLOEXEC;
	flags = fcntl(fd, F_SETFL, flags);
	if (flags == -1) {
		perror("fcntl");
		exit(1);
	}
}

static
int setup_socket(struct sockaddr_in *listenaddr)
{
	int fd, addrsize;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		exit(1);
	}
	listenaddr->sin_family = AF_INET;
	listenaddr->sin_addr.s_addr = INADDR_ANY;
	listenaddr->sin_port = 0;
	if (bind(fd, (struct sockaddr *)listenaddr, sizeof(*listenaddr)) == -1) {
		perror("bind");
		exit(1);
	}

	if (listen(fd, 1024) == -1) {
		perror("listen");
		exit(1);
	}
	addrsize = sizeof(listenaddr);
	getsockname(fd, (struct sockaddr *)listenaddr, &addrsize);
	set_close_exec(fd);
	set_non_block(fd);
	return fd;
}

static
const char *which(const char *progname)
{
	char *ptr, *end, *path_try;

	if (!progname || !*progname)	/* no program */
		return NULL;

	/* simply return absolute paths */
	if (*progname == '/') {
		if (access(progname, X_OK) == 0)
			return strdup(progname);
		return 0;
	}

	/* Check if this is an ok relative path */
	if (strchr(progname, '/') && access(progname, X_OK) == 0)
		return strdup(progname);

	ptr = getenv("PATH");
	if (!ptr)
		ptr = ":/bin:/usr/bin";	/* same default as execvp */
	end = ptr - 1;
	while (*end) {
		ptr = end + 1;
		end = strchr(ptr, ':');
		if (!end)
			end = ptr + strlen(ptr);

		path_try = malloc(end - ptr + strlen(progname) + 3);
		if (!path_try)
			return 0;	/* out of memory */

		/* and empty path element means ".", not "/" */
		if (end - ptr == 0)
			sprintf(path_try, "./%s", progname);
		else
			sprintf(path_try, "%.*s/%s", (int)(end - ptr), ptr,
				progname);

		if (access(path_try, X_OK) == 0)
			return path_try;
		free(path_try);
	}
	return 0;
}

/*--------------------------------------------------------------------
 * Wacky IO forwarding stuff.
 *------------------------------------------------------------------*/
static int outstanding_connections;
static int late_connections;
static int io_to_do;
static struct input_buffer inbuf;

static
int do_line_buff_io(int nodenum, struct output_buffer *io, int flags)
{
	int r, i, lbegin;
	static char prefix[10];
	sprintf(prefix, "%3d: ", nodenum);

	r = read(io->infd, io->buf + io->bytes, buffer_size - io->bytes);
	if (r <= 0) {
		/* Flush out what's left */
		if (io->bytes) {
			if (flags & IO_PREFIX)
				write(io->outfd, prefix, strlen(prefix));
			write(io->outfd, io->buf, io->bytes);
			if (flags & IO_PREFIX)
				write(io->outfd, "\n", 1);
			io->bytes = 0;
		}
		if (io->infd >= 3)
			close(io->infd);
		io->infd = -1;
		if (io->outfd >= 3)
			close(io->outfd);
		io->outfd = -1;
		return -1;
	}
	io->bytes += r;

	/* Churn through what we just read */
	lbegin = 0;
	for (i = io->bytes - r; i < io->bytes; i++) {
		if (io->buf[i] == '\n') {
			/* Output the next chunk */
			if (flags & IO_PREFIX)
				write(io->outfd, prefix, strlen(prefix));
			write(io->outfd, io->buf + lbegin, i - lbegin + 1);	/*includes '\n' */
			lbegin = i + 1;
		}
	}

	/* move what we've got down... (lazy, lazy....) */
	if (lbegin > 0)
		memmove(io->buf, io->buf + lbegin, io->bytes - lbegin);
	io->bytes -= lbegin;

	/* Check if we're overflowing */
	if (io->bytes == buffer_size) {
		if (flags & IO_PREFIX)
			write(io->outfd, prefix, strlen(prefix));
		write(io->outfd, io->buf, io->bytes);
		if (flags & IO_PREFIX)
			write(io->outfd, "\n", 1);
		io->bytes = 0;
	}
	return 0;
}

static
int do_unbuff_io(struct output_buffer *io)
{
	int r;
	r = read(io->infd, io->buf, buffer_size);
	if (r <= 0) {
		if (io->infd >= 3)
			close(io->infd);
		io->infd = -1;
		if (io->outfd >= 3)
			close(io->outfd);
		io->outfd = -1;
		return -1;
	}
	write(io->outfd, io->buf, r);
	return 0;
}

static
int do_input_buffer_read(struct input_buffer *io, int *numclosed)
{
	int r, i;
	r = read(io->infd, io->buf + io->bytes, buffer_size - io->bytes);
	if (r <= 0) {
		close(io->infd);
		io->infd = -1;
		*numclosed = 0;
		for (i = 0; i < io->num; i++) {
			if (io->readptrs[i] == io->buf + io->bytes) {
				close(io->outfds[i]);
				io->outfds[i] = -1;
				(*numclosed)++;
			}
		}
		return -1;
	}
	io->bytes += r;
	return 0;
}

static
void do_input_buffer_close1(struct input_buffer *io, int idx)
{
	close(io->outfds[idx]);
	io->outfds[idx] = -1;
	io->readptrs[idx] = 0;
}

static
int do_input_buffer_add(struct input_buffer *io, int idx, int fd)
{
	/* Don't add a new reader if we've hit EOF on the input file
	 * descriptor and the buffer is empty for this reader. */
	if (io->infd == -1 && io->readptrs[idx] == io->buf + io->bytes)
		return -1;
	io->outfds[idx] = fd;
	return 0;
}

static
int do_input_buffer_write(struct input_buffer *io, int idx)
{
	int i, w;
	char *minptr;

	w = write(io->outfds[idx], io->readptrs[idx],
		  (io->buf + io->bytes) - io->readptrs[idx]);
	if (w <= 0) {
		do_input_buffer_close1(io, idx);
		return -1;
	}
	io->readptrs[idx] += w;
	if (io->infd == -1 && io->readptrs[idx] == io->buf + io->bytes) {
		do_input_buffer_close1(io, idx);
		return -1;
	}

	/* Check all the read pointers */
	minptr = io->readptrs[idx];
	for (i = 0; i < io->num; i++)
		if (io->readptrs[i] && minptr > io->readptrs[i])
			minptr = io->readptrs[i];
	if (minptr > io->buf) {
		/* Slide everything down (lazy, lazy...) */

		memmove(io->buf, minptr, (io->buf + io->bytes) - minptr);
		io->bytes -= (minptr - io->buf);
		/* Update the read pointers */
		for (i = 0; i < io->num; i++)
			io->readptrs[i] -= (minptr - io->buf);
	}
	return 0;
}

static struct timeval tmo;
static int got_sigchld = 0;
static void sigchld_handler(void)
{
	tmo.tv_sec = tmo.tv_usec = 0;	/* hack because pselect is busted */
	got_sigchld = 1;
}

static
void cleanup_children(void)
{
}

static
void forward_io_init(int flags, struct bproc_io_t *io, int iolen)
{
	int i, conn_per_node;
	char *buffer = 0;
	/* Initialize I/O forwarding data structures */

	signal(SIGPIPE, SIG_IGN);	/* don't blow up writing down dead sockets */

	/* Figure out how many connections we're going to want to see, etc */
	conn_per_node = 0;
	for (i = 0; i < iolen; i++) {
		if (io[i].type == BPROC_IO_SOCKET)
			conn_per_node++;
	}

	inbuf.num = num_nodes;
	inbuf.outfds = malloc(sizeof(int) * num_nodes);
	inbuf.readptrs = malloc(sizeof(char *) * num_nodes);
	inbuf.buf = malloc(buffer_size);
	if (io[0].type == BPROC_IO_SOCKET) {
		/* Setup the input buffer... */
		inbuf.bytes = 0;
		inbuf.infd = STDIN_FILENO;
	} else {
		/* otherwise tag it as "done" */
		inbuf.infd = -1;
		inbuf.bytes = 0;
	}

	if (!(flags & IO_LINEBUFF))
		buffer = malloc(buffer_size);

	outstanding_connections = 0;
	io_to_do = 0;
	late_connections = 0;

	/* Zero out all those file descriptors.. */
	for (i = 0; i < num_nodes; i++) {
		/* connections expected per node... */
		nodes[i].cnum = conn_per_node;

		inbuf.outfds[i] = -1;
		inbuf.readptrs[i] = inbuf.buf;

		nodes[i].io[0].infd = -1;
		nodes[i].io[0].outfd =
		    io[1].type == BPROC_IO_SOCKET ? STDOUT_FILENO : -1;
		nodes[i].io[0].bytes = 0;
		nodes[i].io[0].buf =
		    (flags & IO_LINEBUFF) ? malloc(buffer_size) : buffer;

		nodes[i].io[1].infd = -1;
		nodes[i].io[1].outfd =
		    io[2].type == BPROC_IO_SOCKET ? STDERR_FILENO : -1;
		nodes[i].io[1].bytes = 0;
		nodes[i].io[1].buf =
		    (flags & IO_LINEBUFF) ? malloc(buffer_size) : buffer;

		if (nodes[i].alive)
			outstanding_connections += conn_per_node;
	}
}

static int accept_sockfd, *accept_fdlist, accept_nfds, accept_listsize;
static int accept_pid;
static
void forward_io_accept(void)
{
	int r;
	sigset_t sset;
	fd_set *rset;
	int sasize;
	struct sockaddr sa;
	rset = alloca(FDS_BYTES(num_files));

	sigemptyset(&sset);
	sigaddset(&sset, SIGTERM);

	prctl(PR_SET_PDEATHSIG, SIGKILL);	/* kill me when parent dies */
	/* Just do this until we get killed by our parent */

	/* Resilliance - we should time out periodically and check that
	 * our parent proces hasn't gone away or anything. */
	while (accept_nfds < accept_listsize) {
		memset(rset, 0, FDS_BYTES(num_files));	/* FD_ZERO */
		FD_SET(accept_sockfd, rset);
		sigprocmask(SIG_UNBLOCK, &sset, 0);
		r = select(accept_sockfd + 1, rset, 0, 0, 0);
		sigprocmask(SIG_BLOCK, &sset, 0);
		if (r == -1)
			exit(1);
		if (r == 1) {
			sasize = sizeof(sa);
			accept_fdlist[accept_nfds] =
			    accept(accept_sockfd, &sa, &sasize);
			while (accept_fdlist[accept_nfds] >= 0) {
				accept_nfds++;
				sasize = sizeof(sa);
				accept_fdlist[accept_nfds] =
				    accept(accept_sockfd, &sa, &sasize);
			}
		}
	}
	exit(0);
}

#define STACK_SIZE 8192
static
int start_accepter(int sockfd)
{
	void *stack;

	accept_sockfd = sockfd;
	accept_listsize = num_nodes * 3;	/* up to 3 per node... */
	accept_fdlist = malloc(sizeof(int) * accept_listsize);
	accept_nfds = 0;
	if (!accept_fdlist) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}
	stack = malloc(STACK_SIZE);
	if (!stack) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}

	accept_pid = clone((int (*)(void *))forward_io_accept,
			   stack + STACK_SIZE - sizeof(long),
			   CLONE_VM | CLONE_FS | CLONE_FILES, 0);
	return (accept_pid > 0) ? 0 : -1;
}

static
void stop_accepter(void)
{
	kill(accept_pid, SIGTERM);
	waitpid(accept_pid, 0, __WCLONE);
}

static
void forward_io_new_fd(int fd)
{
	int i, pid, rfd;
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid) ||
	    read(fd, &rfd, sizeof(rfd)) != sizeof(rfd)) {
		fprintf(stderr, "bpsh: failed to read pid or fd"
			" from IO connection.\n");
		close(fd);
	} else {
		for (i = 0; i < num_nodes; i++) {
			{
				if (nodes[i].cnum == 0) {
					fprintf(stderr,
						"too many connections from"
						" pid %d (rfd=%d)\n", pid, rfd);
					close(fd);
					break;
				}
				nodes[i].cnum--;
				switch (rfd) {
				case STDIN_FILENO:
					set_non_block(fd);
					if (do_input_buffer_add(&inbuf, i, fd)
					    == 0)
						io_to_do++;
					else
						close(fd);
					if (nodes[i].alive)
						outstanding_connections--;
					break;
				case STDOUT_FILENO:
					nodes[i].io[0].infd = fd;
					io_to_do++;
					if (nodes[i].alive)
						outstanding_connections--;
					break;
				case STDERR_FILENO:
					nodes[i].io[1].infd = fd;
					io_to_do++;
					if (nodes[i].alive)
						outstanding_connections--;
					break;
				default:
					fprintf(stderr,
						"bpsh: %d: bad remote fd"
						" number: %d\n", pid, rfd);
					close(fd);
				}
				break;
			}
		}
		if (i == num_nodes) {
			/* Quietly ignore this error case - it can easily happen
			 * if part of the IO setup on the slave fails and causes
			 * the whole migration to fail. */
			close(fd);
		}
	}
}

static
void forward_io(int sockfd, int flags, struct bproc_io_t *io, int iolen,
		int *fds, int nfds)
{
	fd_set *rset, *wset;
	int max = -1;
	int r, i, j;
	int current_node = 0;
	sigset_t blocked;

	rset = alloca(FDS_BYTES(num_files));
	wset = alloca(FDS_BYTES(num_files));

	forward_io_init(flags, io, iolen);

	for (i = 0; i < nfds; i++)
		forward_io_new_fd(fds[i]);

	/* Adjust outstanding connections for the number of dead nodes */
	if (flags & IO_DIVIDERS) {
		printf
		    ("%d\t------------------------------------------------------"
		     "---------------\n", nodes[current_node].node);
		fflush(stdout);
	}

	/* Now that's all the accounting is done, setup the signal handler
	 * and call cleanup_children to cleanup any dead children we might
	 * already have. */
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blocked, 0);
	signal(SIGCHLD, (void (*)(int))sigchld_handler);
	cleanup_children();

	while (outstanding_connections > 0 || io_to_do > 0 ||
	       late_connections > 0) {
		memset(rset, 0, FDS_BYTES(num_files));	/* FD_ZERO */
		memset(wset, 0, FDS_BYTES(num_files));	/* FD_ZERO */

		if (sockfd != -1) {
			FD_SET(sockfd, rset);
			if (max < sockfd)
				max = sockfd;
		}

		/* Deal with the input buffer */
		if (inbuf.infd != -1 && inbuf.bytes < buffer_size) {
			FD_SET(inbuf.infd, rset);
			if (max < inbuf.infd)
				max = inbuf.infd;
		}
		for (i = 0; i < num_nodes; i++) {
			if (inbuf.outfds[i] != -1) {
				FD_SET(inbuf.outfds[i], rset);
				if (inbuf.readptrs[i] <
				    (inbuf.buf + inbuf.bytes))
					FD_SET(inbuf.outfds[i], wset);
				if (max < inbuf.outfds[i])
					max = inbuf.outfds[i];
			}
		}

		/* Deal with the output buffers */
		if (flags & IO_SEQUENTIAL && current_node < num_nodes) {
			/* Get node output in order */
			for (j = 0; j < 2; j++) {
				if (nodes[current_node].io[j].infd != -1 &&
				    nodes[current_node].io[j].outfd != -1) {
					FD_SET(nodes[current_node].io[j].infd,
					       rset);
					if (max <
					    nodes[current_node].io[j].infd)
						max =
						    nodes[current_node].io[j].
						    infd;
				}
			}
		} else {
			/* Setup to wait on all nodes for IO... */
			for (i = 0; i < num_nodes; i++) {
				for (j = 0; j < 2; j++) {
					if (nodes[i].io[j].infd != -1 &&
					    nodes[i].io[j].outfd != -1) {
						FD_SET(nodes[i].io[j].infd,
						       rset);
						if (max < nodes[i].io[j].infd)
							max =
							    nodes[i].io[j].infd;
					}
				}
			}
		}

		/* need timeouts for dead nodes and the like */
		if (late_connections) {
			tmo.tv_sec = 0;
			tmo.tv_usec = 50000;
		} else {
			tmo.tv_sec = 300;	/* completely arbitrary */
			tmo.tv_usec = 0;
		}
		sigprocmask(SIG_UNBLOCK, &blocked, 0);
		r = select(max + 1, rset, wset, 0, &tmo);
		sigprocmask(SIG_BLOCK, &blocked, 0);
		if (got_sigchld) {
			cleanup_children();
			got_sigchld = 0;
		}
		if (r > 0) {
			if (sockfd != -1 && FD_ISSET(sockfd, rset)) {
				int fd, sa_size;
				struct sockaddr sa;
				sa_size = sizeof(sa);
				fd = accept(sockfd, &sa, &sa_size);
				while (fd != -1) {
					forward_io_new_fd(fd);
					sa_size = sizeof(sa);
					fd = accept(sockfd, &sa, &sa_size);
				}
				if (fd == -1 && errno != EAGAIN) {
					perror("accept");
					close(sockfd);
					sockfd = -1;
				}
			}

			/* Do input fds */
			if (inbuf.infd != -1 && FD_ISSET(inbuf.infd, rset)) {
				int numclosed;
				if (do_input_buffer_read(&inbuf, &numclosed) !=
				    0)
					io_to_do -= numclosed;
			}
			for (i = 0; i < num_nodes; i++) {
				/* This is a bit of a hack... if an input FD becomes
				 * ready for reading, presume the other side has
				 * closed it and we're done with it here.  We might
				 * want to actually check for EOF or something. */
				if (inbuf.outfds[i] != -1
				    && FD_ISSET(inbuf.outfds[i], rset)) {
					do_input_buffer_close1(&inbuf, i);
					io_to_do--;
				}
				if (inbuf.outfds[i] != -1
				    && FD_ISSET(inbuf.outfds[i], wset))
					if (do_input_buffer_write(&inbuf, i) !=
					    0) {
						io_to_do--;
					}
			}
			/* Do output fds */
			for (i = 0; i < num_nodes; i++) {
				for (j = 0; j < 2; j++) {
					if (nodes[i].io[j].infd != -1 &&
					    FD_ISSET(nodes[i].io[j].infd,
						     rset)) {
						if (flags & IO_LINEBUFF) {
							if (do_line_buff_io
							    (nodes[i].node,
							     &nodes[i].io[j],
							     flags) != 0) {
								io_to_do--;
							}
						} else {
							if (do_unbuff_io
							    (&nodes[i].io[j]) !=
							    0) {
								io_to_do--;
							}
						}
					}
				}
			}
		}
		/* timeout... look for connections we haven't received yet.... */
		if (r == 0) {
			if (late_connections)
				late_connections = 0;
#if 0
			/* We need to re-think this in light of the signal
			 * handling hack issue. */
			else {
				for (i = 0; i < num_nodes; i++)
					if (!nodes[i].alive && nodes[i].cnum) {
						fprintf(stderr,
							"bpsh: timeout connection from"
							" node %d\n",
							nodes[i].node);
						outstanding_connections -=
						    nodes[i].cnum;
					}
			}
#endif
		}

		if ((flags & IO_SEQUENTIAL) && !late_connections) {
			while (current_node < num_nodes &&
			       nodes[current_node].alive == 0 &&
			       nodes[current_node].io[0].infd == -1 &&
			       nodes[current_node].io[1].infd == -1) {
				current_node++;
				if (flags & IO_DIVIDERS
				    && current_node < num_nodes) {
					printf
					    ("%d\t-------------------------------------------"
					     "--------------------------\n",
					     nodes[current_node].node);
					fflush(stdout);
				}
			}
		}
	}
}

static int
connectbpmaster(void)
{
	int bpmaster;
	struct sockaddr_un sun;

	bpmaster = socket(PF_UNIX, SOCK_STREAM, 0);
	if (bpmaster < 0)
		return bpmaster;

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, "/tmp/bpmaster");

	if (connect(bpmaster, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		return (-1);
	}

	return (bpmaster);

}
static
int start_processes(struct sockaddr_in *hostip, struct bproc_io_t *io, int iolen,
		    const char *progname, int argc, char **argv)
{
	int xp_ldd(const char *binary, char *sysroot, char ***deps);

	int i, r;
	FILE *iostream;
	unsigned char *data, *cp, *edata, *count;
	int amt;
	int envc;
	int bpmaster;
	int datalen = 2*1048576;
	static char cmd[4096], *ecmd = &cmd[4095], *cur;
	struct bproc_message_hdr_t *hdr;
	char **libs;
	
	/* The rank probably won't be interesting to the child process but
	 * who knows... */
	setenv("BPROC_RANK", "XXXXXXX", 1);
	setenv("BPROC_PROGNAME", progname, 1);
	xp_ldd(progname, "/", &libs);
	cur = cmd;
	cur += snprintf(cmd, ecmd-cur, "ls ");
	for(i = 0; libs[i]; i++) {
		/* simple mode: ignore libc. future complex mode: ?? */
		if (strstr(libs[i], "libc.so"))
			continue;
		cur += snprintf(cur, ecmd-cur, "%s ", libs[i]); 
	}
	cur += snprintf(cur, ecmd-cur, " | cpio -H newc -o");
fprintf(stderr, "CMD %s\n", cmd);
	iostream = popen(cmd, "r");

	/* format: Command (1), length(6), null(1), lines of: 
	 * argc text(line)
	 * argv, (set of null-terminated strings with extra null at end)
	 * envc text (line)
	 * env, (set of null-terminated strings with extra null at end)
	 * flags as string, then null, 
	 * host IP as text, null, 
	 * stdin port as text, null, 
	 * stdout port as text, null, 
	 * stderr port as text, null
	 * node count as text, null, 
	 * list of nodes (set of null-terminated strings with extra null at end)
	 * cpio archive
	 */

	data = calloc(datalen, sizeof(*data));

	/* now set up the data with the proper info. First 16 bytes will be command "R" and length in textual form. */
	edata = data + datalen;
	hdr = (struct bproc_message_hdr_t *) data;
	hdr->req = BPROC_RUN;
	cp = data + sizeof(*hdr);
	/* Nodes go first because the master may have to rewrite them. */
	cp += snprintf(cp, edata-cp, "%d", num_nodes);
	*cp++ = 0;
	for (i = 0; i < num_nodes; i++){
		cp += snprintf(cp, edata-cp, "%d", nodes[i].node);
		*cp++ = 0;
	}

	cp += snprintf(cp, edata-cp, "%d", argc);
	*cp++ = 0;
	for(i = 0; i < argc; i++) {
		cp += snprintf(cp, edata-cp, "%s", argv[i]);
		*cp++ = 0;
	}
	
	for(i = envc = 0; environ[i]; i++, envc++)
		;
	cp += snprintf(cp, edata-cp, "%d", envc);
	*cp++ = 0;
	for(i = 0; environ[i]; i++){
		cp += snprintf(cp, edata-cp, "%s", environ[i]);
		*cp++ = 0;
	}

	cp += snprintf(cp, edata-cp, "%d", 0); // flags
	*cp++ = 0;

	cp += snprintf(cp, edata-cp, "%s", inet_ntoa(hostip->sin_addr));
	*cp++ = 0;
	cp += snprintf(cp, edata-cp, "%d", (int) iolen);
	*cp++ = 0;
	for(i = 0; i < iolen; i++) {
		cp += snprintf(cp, edata-cp, "%d", ntohs(((struct sockaddr_in *)&io[i].d.addr)->sin_port));
		*cp++ = 0;
	}

	
	/* now read in the cpio archive. */
	
	amt = fread(cp, 1, edata-cp, iostream);
	pclose(iostream);
	cp += amt;
	bpmaster = connectbpmaster();
	/* do it in reasonable chunks, linux gets upset if you do too much and add in weird delays */
printf("SEND MSG %ld\n", cp-data);
	hdr->size = cp-data;
	write(bpmaster, data, sizeof(*hdr));
	for(i = sizeof(*hdr); i < cp-data; i += amt){
		int left = cp - (data + i);
		amt = left > 4096? 4096 : left;
		amt = write(bpmaster, data + i, amt);
		if (amt < 0){
			printf("fucked\n");
			return -1;
		}
	}

//	free(nodelist);
	return 0;
}

int bproc_addr2node(struct bproc_node_set_t *ns, char *addr)
{
	int i;
	int n;
	struct in_addr in;
	struct bproc_node_set_t nodes;

	if (!inet_aton(addr, &in))
		return 1;

	n = bproc_nodelist(&nodes);

	for (i = 0; i < n; i++) {
		struct sockaddr_in *sin =
		    (struct sockaddr_in *)&nodes.node[i].addr;
		if (memcmp(&in, &sin->sin_addr, sizeof(in)) == 0) {
			bproc_nodeset_init(ns, 1);
			ns->node[0].node = nodes.node[i].node;
			return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int c, i, r;
	int flags = 0;
	char *node_str = NULL;
	int cmd_argc = 0;
	char **cmd_argv = NULL;
	int non_option_args = 0;
	int all_avail = 0;
	int all_up = 0;
	const char *progname = NULL;
	char *check;
	char neg1[3] = "-1";
	int count, status, sockfd;
	int nullfd;
	struct rlimit rlim;
	struct bproc_node_set_t node_list;
	struct bproc_io_t io[3];
	int time_cmd = 0;
	struct timeval start, end;
	struct sockaddr_in hostaddr;
	char hostname[128];
	struct hostent *h;

	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{"stdin", 1, 0, 'I'},
		{"stdout", 1, 0, 'O'},
		{"stderr", 1, 0, 'E'},
		{"time", 0, 0, 't'},
		{0, 0, 0, 0}
	};

	for (i = 0; i < 3; i++) {
		io[i].fd = i;
		io[i].type = BPROC_IO_SOCKET;
		io[i].flags = BPROC_IO_SEND_INFO;
		((struct sockaddr_in *)&io[i].d.addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&io[i].d.addr)->sin_addr.s_addr = 0;
		/* Fill in port later */
	}

	/* This is a bit confusing... We need to run getopt in the posixly
	   correct mode so that we won't run over all the arguments to the
	   command given to rsh.  The tricky part is that the rsh
	   arguments might come before or after the node number.  Also the
	   node number may be omitted if -A or -a is given. */
	optind = 0;
	while (optind < argc) {
		if ((c = getopt_long(argc, argv, "+hl:nNaAv1Lpsdb:I:O:E:t",
				     long_options, 0)) != EOF) {
			switch (c) {
			case 'h':
				Usage(argv[0]);
				exit(0);
			case 'v':
				printf("%s version %s\n", argv[0],
				       PACKAGE_VERSION);
				exit(0);
			case '1':	/* the user wanted to run on node -1 */
				node_str = neg1;
				non_option_args++;
				break;
			case 'l':	/* silently ignore */
				break;
				/* Node selection */
			case 'a':
				all_up = 1;
				non_option_args = 1;
				break;
			case 'A':
				all_avail = 1;
				non_option_args = 1;
				break;
				/* IO forwarding options */
			case 'n':
				nullfd = open("/dev/null", O_RDONLY);
				if (nullfd == -1) {
					perror("/dev/null");
					exit(1);
				}
				if (nullfd != STDIN_FILENO) {
					dup2(nullfd, STDIN_FILENO);
					close(nullfd);
				}
				break;
			case 'N':
				for (i = 0; i < 3; i++) {
					io[i].type = BPROC_IO_FILE;
					io[i].flags = 0;
					io[i].d.file.offset = 0;
					strcpy(io[i].d.file.name, "/dev/null");
				}
				io[0].d.file.flags = O_RDONLY;	/* in */
				io[1].d.file.flags = O_WRONLY;	/* out */
				io[2].d.file.flags = O_WRONLY;	/* err */
				break;
			case 'L':
				flags |= IO_LINEBUFF;
				break;
			case 'p':
				flags |= (IO_LINEBUFF | IO_PREFIX);
				break;
			case 's':
				flags |= IO_SEQUENTIAL;
				break;
			case 'd':
				flags |= (IO_DIVIDERS | IO_SEQUENTIAL);
				break;
			case 'b':
				buffer_size = strtol(optarg, &check, 0);
				if (*check || buffer_size <= 0) {
					fprintf(stderr,
						"Invalid buffer size: %s\n",
						optarg);
					exit(1);
				}
				break;
			case 'I':
				io[0].type = BPROC_IO_FILE;
				io[0].d.file.flags = O_RDONLY;
				io[0].flags = 0;
				io[0].d.file.offset = 0;
				strcpy(io[0].d.file.name, optarg);
				break;
			case 'O':
				io[1].type = BPROC_IO_FILE;
				io[1].d.file.flags =
				    O_WRONLY | O_CREAT | O_TRUNC;
				io[1].d.file.mode = 0666;
				io[1].flags = 0;
				io[1].d.file.offset = 0;
				strcpy(io[1].d.file.name, optarg);
				break;
			case 'E':
				io[2].type = BPROC_IO_FILE;
				io[2].d.file.flags =
				    O_WRONLY | O_CREAT | O_TRUNC;
				io[2].d.file.mode = 0666;
				io[2].flags = 0;
				io[2].d.file.offset = 0;
				strcpy(io[2].d.file.name, optarg);
				break;
			case 't':
				time_cmd = 1;
				break;
			default:
				exit(1);
			}
		} else {
			if (non_option_args == 0) {
				node_str = argv[optind];
			} else if (non_option_args == 1) {
				cmd_argc = argc - optind;
				cmd_argv = argv + optind;
				optind = argc;
			} else {
				Usage(argv[0]);
				exit(1);
			}
			non_option_args++;
			optind++;
		}
	}

	if (!cmd_argv) {
		Usage(argv[0]);
		exit(1);
	}

	progname = which(*cmd_argv);	/* we can do this check early... */
	if (!progname) {
		fprintf(stderr, "%s: %s: command not found\n", argv[0],
			*cmd_argv);
		exit(1);
	}

	/* Build up a node list */
	if (all_avail) {
		bproc_nodespec(&node_list, "allnotdown");
	} else if (all_up) {
		bproc_nodespec(&node_list, "allup");
	} else {
		/* Try the node str as a node specification.  If that fails,
		 * try it as an IP address. */
		if (bproc_nodespec(&node_list, node_str)) {
			/* Try again as a list of addresses */
			if (bproc_addr2node(&node_list, node_str)) {
				fprintf(stderr,
					"Invalid node specification \"%s\"\n",
					node_str);
				exit(1);
			}
		}
	}

	/* Our node list is empty, that's fine with me... */
	if (node_list.size == 0) {
		if (node_str) {
			char hname[128];

			/* for added rsh compatibility, if the master's hostname is
			 * used, just exec it */
			if (gethostname(hname, sizeof(hname)) < 0)
				hname[0] = 0;

			if (!strcmp(node_str, hname) ||
			    !strcmp("n-1", node_str)
			    || !strcmp("localhost", node_str)) {
				execvp(progname, cmd_argv);
				exit(1);
			}
		}
		exit(0);
	}

	count = node_list.size;
	nodes = malloc(sizeof(*nodes) * count);
	for (i = 0; i < count; i++)
		nodes[i].node = node_list.node[i].node;
	bproc_nodeset_free(&node_list);

	/* Setup a socket here if bpsh is going to act as the IO
	 * forwarder */
	sockfd = -1;
	num_files = 0;
	for (i = 0; i < 3; i++) {
		if (io[i].type == BPROC_IO_SOCKET) {
			struct sockaddr_in addr;
			sockfd = setup_socket(&addr);
			/* Fill in the port number in our IO fields */
			for (i = 0; i < 3; i++)
				if (io[i].type == BPROC_IO_SOCKET) {
					num_files++;
					((struct sockaddr_in *)&io[i].d.addr)->
					    sin_port = addr.sin_port;
				}
			break;
		}
	}
	/* extra for personal use :) */
	num_files = (num_files * count) + 32;

	/* Check our rlimits and try to up them if applicable */
	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		fprintf(stderr, "getrlimit(RLIMIT_NOFILE): %s\n",
			strerror(errno));
		exit(1);
	}

	if (rlim.rlim_cur < num_files) {
		rlim.rlim_cur = num_files;
		if (rlim.rlim_max < num_files)
			rlim.rlim_max = num_files;

		if (setrlimit(RLIMIT_NOFILE, &rlim)) {
			fprintf(stderr,
				"WARNING: Failed to up RLIMIT_NOFILE to %ld\n",
				(long)rlim.rlim_cur);
		}
	}

	/* Normal mode of operation: use vexecmove to create processes and
	 * forward I/O for them... */
	num_nodes = count;

	/* FIX ME: Add clone flags to bproc interface so we don't need to
	 * do this horrible hack. Either that or pthread it now that
	 * threads aren't so completely horrible. */
	if (sockfd != -1)
		if (start_accepter(sockfd))
			exit(1);

	if (time_cmd)
		gettimeofday(&start, 0);
	r = start_processes(&hostaddr, io, 3, progname, cmd_argc, cmd_argv);
	if (sockfd != -1)
		stop_accepter();
	if (r)
		exit(1);

	if (sockfd != -1)
		forward_io(sockfd, flags, io, 3, accept_fdlist, accept_nfds);

	/* wait for all the child remaining processes to exit. */
	while (wait(&status) != -1) {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) > max_exit)
				max_exit = WEXITSTATUS(status);
		} else {
			fprintf(stderr,
				"bpsh: Child process exited abnormally.\n");
			max_exit = 255;	/* a segfault or something */
		}
	}
	if (time_cmd) {
		gettimeofday(&end, 0);
		printf("%.6f\n", ((end.tv_sec - start.tv_sec) * 1000000 +
				  end.tv_usec - start.tv_usec) / 1000000.0);
	}

	exit(max_exit);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
