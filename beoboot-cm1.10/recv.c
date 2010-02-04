/*------------------------------------------------------------ -*- C -*-
 * recv: unicast file receiving stuff
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
 *  $Id: recv.c,v 1.11 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cmconf.h"

#include "beoboot_boothooks.h"
#include "send.h"

/* This crud is to allow stand-alone operation for testing */
int verbose __attribute__ ((weak)) = 0;
void console_log(char *fmt, ...) __attribute__ ((weak));
struct boot_conf_t *boot_conf __attribute__ ((weak)) = 0;

static struct recv_arg_t recv_args = {
      initial_delay:RECV_INITIAL_DELAY,
      max_delay:RECV_MAX_DELAY,
      backoff:RECV_BACKOFF,
      max_time:RECV_MAX_TIME,
      rand:RECV_RAND
};

/* File contents */
struct file_t {
	char name[MAX_FILE_NAME + 1];
	int size;
	int mode;
	int user;
	int group;
	void *buffer;
};

static
int setup_listen(struct sockaddr_in *addr)
{
	int fd, flag;
	int addrsize;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "socket(AF_INET, SOCK_STREAM): %s",
			strerror(errno));
		return -1;
	}
	flag = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) == -1) {
		fprintf(stderr, "setsockopt(SOL_SOCKET, SO_REUSEADDR): %s",
			strerror(errno));
		close(fd);
		return -1;
	}

	/* Set non-blocking mode */
	flag = fcntl(fd, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flag);

	/* Bind to the same address/port as the control socket */
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0;
	addr->sin_port = 0;	/* Any port here */
	if (bind(fd, (struct sockaddr *)addr, sizeof(*addr))) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	addrsize = sizeof(*addr);
	if (getsockname(fd, (struct sockaddr *)addr, &addrsize)) {
		fprintf(stderr, "getsockaddr: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	listen(fd, 128);

	if (verbose)
		console_log("recv: resend listening on port %d\n",
			    ntohs(addr->sin_port));
	return fd;
}

static
void request_new(struct send_request_t *req,
		 const char *filename, struct sockaddr_in *resend_addr)
{
	memset(req, 0, sizeof(*req));
	req->req_magic = htonl(SEND_REQUEST_MAGIC);
	req->magic = time(0);	/* cruddy */
	req->resend_port = resend_addr->sin_port;
	req->depth = htonl(SEND_DEPTH_NONE);
	strncpy(req->filename, filename, MAX_FILE_NAME);
}

static
int request_file_do_send(int sockfd, struct sockaddr_in *addr,
			 struct send_request_t *req)
{
	int r;

	console_log("recv: requesting %s from %s:%d\n", req->filename,
		    inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	r = sendto(sockfd, req, sizeof(*req), 0,
		   (struct sockaddr *)addr, sizeof(*addr));
	if (r == -1) {
		fprintf(stderr, "sendto: %s\n", strerror(errno));
		return -1;
	}
	if (r != sizeof(*req)) {
		fprintf(stderr, "sendto: short write\n");
		return -1;
	}
	return 0;
}

static
int update_delay(struct recv_arg_t *args, int delay)
{
	float factor;
	delay = delay * args->backoff;

	/* Constrain delay to be within our bounds */
	if (delay > args->max_delay)
		delay = args->max_delay;
	if (delay < args->initial_delay)
		delay = args->initial_delay;

	/* Add some randomness to the delay */
	factor =
	    1.0 - args->rand + (rand() / ((float)RAND_MAX)) * args->rand * 2;
	delay = delay * factor;

	if (delay < 0)
		delay = 1;	/* safety net... */
	return delay;
}

static
int request_file(struct sockaddr_in *addr,
		 struct send_request_t *req,
		 struct send_response_t *resp, struct recv_arg_t *args)
{
	int req_fd, r;
	fd_set rset;
	struct timeval start, now, last_send, tmo;
	int elapsed, delay = 0;

	req_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (req_fd == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	gettimeofday(&start, 0);
	now = start;
	last_send = now;
	srand(now.tv_usec);

	delay = update_delay(args, 0);

	if (request_file_do_send(req_fd, addr, req)) {
		close(req_fd);
		return -1;
	}

	while (now.tv_sec - start.tv_sec < args->max_time) {
		elapsed = (now.tv_sec - last_send.tv_sec) * 1000000 +
		    now.tv_usec - last_send.tv_usec;
		if (elapsed >= delay) {
			delay = update_delay(args, delay);

			if (request_file_do_send(req_fd, addr, req)) {
				close(req_fd);
				return -1;
			}
			last_send = now;
			elapsed = 0;
		}

		/* Figure out what our timeout is going to be... */
		tmo.tv_sec = (delay - elapsed) / 1000000;
		tmo.tv_usec = (delay - elapsed) % 1000000;

		FD_ZERO(&rset);
		FD_SET(req_fd, &rset);
		r = select(req_fd + 1, &rset, 0, 0, &tmo);
		if (r == -1) {
			fprintf(stderr, "select: %s\n", strerror(errno));
			close(req_fd);
			return -1;
		}
		if (r == 1) {
			r = recv(req_fd, resp, sizeof(*resp), 0);
			if (r == -1) {
				fprintf(stderr, "recv: %s\n", strerror(errno));
				close(req_fd);
				return -1;
			}
			if (ntohl(resp->magic) == SEND_RESPONSE_MAGIC &&
			    resp->req_magic == req->req_magic) {
				/* byte swap stuff in the response for easy use later */
				resp->status = ntohl(resp->status);
				resp->sender_timeout =
				    ntohl(resp->sender_timeout);
				resp->connect_timeout =
				    ntohl(resp->connect_timeout);
				resp->io_timeout = ntohl(resp->io_timeout);

				close(req_fd);
				return 0;
			}
		}

		gettimeofday(&now, 0);
	}
	close(req_fd);
	fprintf(stderr, "recv: Max tries exhausted.\n");
	return -1;
}

static
int quick_connect(struct sockaddr_in *addr, int timeout)
{
	int flag, fd, r;
	fd_set wset;
	struct timeval tmo;
	int error, error_size;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	/* Set non-blocking mode */
	flag = fcntl(fd, F_GETFL);
	flag |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flag);

	r = connect(fd, (struct sockaddr *)addr, sizeof(*addr));
	if (r == -1 && errno != EINPROGRESS) {
		fprintf(stderr, "recv: connect(%s:%d): %s\n",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			strerror(errno));
		close(fd);
		return -1;
	}

	FD_ZERO(&wset);
	FD_SET(fd, &wset);
	tmo.tv_sec = timeout / 1000000;
	tmo.tv_usec = timeout % 1000000;
	r = select(fd + 1, 0, &wset, 0, &tmo);
	if (r == 0) {
		printf("Quick connect timed out\n");
		close(fd);
		return -1;
	}

	/* Check if the connect actually succeeded */
	error_size = sizeof(error);
	r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size);
	if (r == -1) {
		fprintf(stderr, "getsockopt: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (error) {
		fprintf(stderr, "recv: connect(%s:%d): %s\n",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port),
			strerror(error));
		close(fd);
		return -1;
	}
	return fd;
}

static
int read_all_timeout(int file, void *buf, int count, int tmo_usec)
{
	int r, bytes = count;
	fd_set rset;
	struct timeval tmo;

	while (bytes) {
		/* This file descriptor may be setup for non-blocking I/O so
		 * do a poll first. */
		FD_ZERO(&rset);
		FD_SET(file, &rset);
		tmo.tv_sec = tmo_usec / 1000000;
		tmo.tv_usec = tmo_usec % 1000000;
		r = select(file + 1, &rset, 0, 0, &tmo);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll returned %d errno=%d (%s)\n",
				r, errno, strerror(errno));
			return r;
		}
		if (r == 0) {
			/* Timeout */
			fprintf(stderr, "read timed out.\n");
			return -1;
		}
		r = read(file, buf, bytes);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "read returned %d errno=%d (%s)\n",
				r, errno, strerror(errno));
			return r;
		}
		if (r == 0)
			return count - bytes;
		bytes -= r;
		buf += r;
	}
	return count;
}

static
int write_all_timeout(int file, const void *buf, int count, int tmo_usec)
{
	int r, bytes = count;
	fd_set wset;
	struct timeval tmo;

	while (bytes) {
		/* This file descriptor may be setup for non-blocking I/O so
		 * do a poll first. */
		FD_ZERO(&wset);
		FD_SET(file, &wset);
		tmo.tv_sec = tmo_usec / 1000000;
		tmo.tv_usec = tmo_usec % 1000000;
		r = select(file + 1, 0, &wset, 0, &tmo);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll returned %d errno=%d (%s)\n",
				r, errno, strerror(errno));
			return r;
		}
		if (r == 0) {
			/* Timeout */
			fprintf(stderr, "read timed out.\n");
			return -1;
		}
		r = write(file, buf, bytes);
		if (r == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "read returned %d errno=%d (%s)\n",
				r, errno, strerror(errno));
			return r;
		}
		if (r == 0)
			return count - bytes;
		bytes -= r;
		buf += r;
	}
	return count;
}

static
int download_file(struct send_request_t *req, struct send_response_t *resp,
		  struct file_t *file)
{
	int fd, r;
	struct sockaddr_in addr;
	struct send_data_t data;
	void *buffer;
	int len;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = resp->addr;
	addr.sin_port = resp->port;

	fd = quick_connect(&addr, resp->connect_timeout);
	if (fd == -1)
		return -1;

	r = write(fd, req, sizeof(*req));
	if (r == -1) {
		fprintf(stderr, "write: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	if (r != sizeof(*req)) {
		fprintf(stderr, "write: short write\n");
		close(fd);
		return -1;
	}

	r = read_all_timeout(fd, &data, sizeof(data), resp->io_timeout);
	if (r != sizeof(data)) {
		fprintf(stderr,
			"recv: failed to read data from remote host.\n");
		close(fd);
		return -1;
	}

	if (verbose) {
		console_log("recv: file: size=%d mode=0%o user=%d group=%d\n",
			    ntohl(data.size), ntohl(data.mode),
			    ntohl(data.user), ntohl(data.group));
	}

	/* Malloc up some data */
	len = ntohl(data.size);
	buffer = malloc(len);
	if (!buffer) {
		fprintf(stderr, "Failed to allocate %d bytes for file.\n", len);
		close(fd);
		return -1;
	}

	r = read_all_timeout(fd, buffer, len, resp->io_timeout);
	if (r == -1) {
		free(buffer);
		close(fd);
		return -1;
	}
	if (r != len) {
		fprintf(stderr, "recv: Short file: expected %d; got %d\n",
			len, r);
		free(buffer);
		close(fd);
		return -1;
	}

	close(fd);

	/* store the info about this file */
	memset(file, 0, sizeof(*file));
	strncpy(file->name, req->filename, MAX_FILE_NAME);
	file->buffer = buffer;
	file->size = len;
	file->mode = ntohl(data.mode);
	file->user = ntohl(data.user);
	file->group = ntohl(data.group);
	return 0;
}

static
const char *send_strerror(int err)
{
	switch (err) {
	case SEND_ERROR_ENOENT:
		return "File unavailble";
	default:
		return "Unknown error";
	}
}

/*--------------------------------------------------------------------
 * This function sits around and tries to retransmit the file for the
 * specified period of time.
 */
static
int retransmit_file_once(int fd, struct file_t *file, int io_timeout)
{
	int r;
	struct send_request_t client_req;
	struct send_data_t data;

	data.magic = htonl(SEND_DATA_MAGIC);
	data.status = htonl(0);
	data.size = htonl(file->size);
	data.mode = htonl(file->mode);
	data.user = htonl(file->user);
	data.group = htonl(file->group);

	/* Read request */
	r = read_all_timeout(fd, &client_req, sizeof(client_req), io_timeout);
	if (r == -1)
		return -1;
	if (r != sizeof(client_req)) {
		fprintf(stderr, "recv: short read reading client request.\n");
		return -1;
	}
	client_req.filename[MAX_FILE_NAME] = 0;

	/* Check validity of the client request */
	if (strcmp(client_req.filename, file->name) != 0) {
		/* They're asking for the wrong file.... */
		data.status = htonl(SEND_ERROR_ENOENT);
	}

	/* Write out the header with file data and the status code */
	r = write_all_timeout(fd, &data, sizeof(data), io_timeout);
	if (r == -1)
		return -1;
	if (r != sizeof(data)) {
		fprintf(stderr, "recv: short write retransmitting.\n");
		return -1;
	}

	/* Bail out here if we're not sending it */
	if (ntohl(data.status) != 0)
		return -1;

	/* Write out the file data */
	r = write_all_timeout(fd, file->buffer, file->size, io_timeout);
	if (r == -1)
		return -1;
	if (r != file->size) {
		fprintf(stderr, "recv: short write retransmitting.\n");
		return -1;
	}
	return 0;
}

static
void retransmit_file(int resend_fd,
		     struct file_t *file, int sender_timeout, int io_timeout)
{
	int fd, flag;
	int elapsed;
	struct timeval start, now, tmo;
	int addrsize;
	int r;
	fd_set rset;
	struct sockaddr_in addr;

	gettimeofday(&start, 0);
	elapsed = 0;

	while (elapsed < sender_timeout) {
		FD_ZERO(&rset);
		FD_SET(resend_fd, &rset);
		tmo.tv_sec = (sender_timeout - elapsed) / 1000000;
		tmo.tv_usec = (sender_timeout - elapsed) % 1000000;
		r = select(resend_fd + 1, &rset, 0, 0, &tmo);
		if (r == 1) {
			addrsize = sizeof(addr);
			fd = accept(resend_fd, (struct sockaddr *)&addr,
				    &addrsize);
			if (fd == -1) {
				if (errno == EAGAIN)
					continue;
				/* XXX there are probably a few other errno's to
				 * ignore here */
				fprintf(stderr, "accept: %s\n",
					strerror(errno));
				return;
			}

			/* Set non-blocking mode */
			flag = fcntl(fd, F_GETFL);
			flag |= O_NONBLOCK;
			fcntl(fd, F_SETFL, flag);

			printf("recv: retransmit to %s:%d\n",
			       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			r = retransmit_file_once(fd, file, io_timeout);
			close(fd);
			if (r == 0)
				printf("recv: retransmit complete\n");
		}

		gettimeofday(&now, 0);
		elapsed = now.tv_usec - start.tv_usec +
		    (now.tv_sec - start.tv_sec) * 1000000;
	}
}

int recv_file(struct sockaddr_in *addr, const char *filename,
	      void **buffer, long *len)
{
	int resend_fd, try = 0;
	struct sockaddr_in resend_addr;
	struct send_request_t req;
	struct send_response_t resp;
	struct file_t file;

	signal(SIGPIPE, SIG_IGN);	/* sigpipe can be troublesome for us. */

	/* Dump out recv arguments for all to see */
	printf("recv: delay=%.1fs -> %.1fs backoff=%.2f max=%ds rand=%.2f\n",
	       recv_args.initial_delay / 1000000.0,
	       recv_args.max_delay / 1000000.0,
	       recv_args.backoff, recv_args.max_time, recv_args.rand);

	resend_fd = setup_listen(&resend_addr);
	if (resend_fd == -1) {
		fprintf(stderr, "recv: Failed to setup resend FD.\n");
		return -1;
	}

	request_new(&req, filename, &resend_addr);

	while (try < DEFAULT_MAX_TRIES) {
		if (request_file(addr, &req, &resp, &recv_args)) {
			fprintf(stderr, "recv: Request file failed.\n");
			close(resend_fd);
			return -1;
		}

		if (resp.status != 0) {
			fprintf(stderr, "recv: response from server: %s: %s\n",
				filename, send_strerror(resp.status));
			close(resend_fd);
			return -1;
		}

		printf("recv: response: download from addr=%s:%d depth=%d\n",
		       inet_ntoa(*(struct in_addr *)&resp.addr),
		       ntohs(resp.port), ntohl(resp.depth));
		req.depth = resp.depth;
		if (verbose)
			printf
			    ("recv: timeouts: resend=%.1fs connect=%.1fs io=%.1fs\n",
			     resp.sender_timeout / 1000000.0,
			     resp.connect_timeout / 1000000.0,
			     resp.io_timeout / 1000000.0);

		if (download_file(&req, &resp, &file) == 0) {
			console_log("recv: download ok - starting retransmits"
				    " (for %.1fs)\n",
				    resp.sender_timeout / 1000000.0);
			retransmit_file(resend_fd, &file, resp.sender_timeout,
					resp.io_timeout);
			console_log("recv: finished retransmitting\n");
			close(resend_fd);

			*buffer = file.buffer;
			*len = file.size;
			return 0;
		}

		/* Update the address we failed to download from */
		req.fail_addr = resp.addr;
		req.fail_port = resp.port;

		try++;
	}
	fprintf(stderr, "recv: retried too many times, giving up.\n");
	close(resend_fd);
	return -1;
}

/*--------------------------------------------------------------------
 * Client configuration loading code.  This stuff gets called by
 * boot's own configuration loader.
 */
static struct recv_arg_t recv_args;
static
int recv_initial_delay(struct cmconf *conf, char **args)
{
	char *check;
	int usec;
	usec = strtod(args[1], &check) * 1000000;
	if (*check || usec <= 0) {
		console_log("recv initial_delay invalid: %s (ignoring)\n",
			    args[1]);
		return 0;
	}
	recv_args.initial_delay = usec;
	return 0;
}

static
int recv_max_delay(struct cmconf *conf, char **args)
{
	char *check;
	int usec;
	usec = strtod(args[1], &check) * 1000000;
	if (*check || usec <= 0) {
		console_log("recv max_delay invalid: %s  (ignoring)\n",
			    args[1]);
		return 0;
	}
	recv_args.max_delay = usec;
	return 0;
}

static
int recv_backoff(struct cmconf *conf, char **args)
{
	char *check;
	float backoff;
	backoff = strtod(args[1], &check);
	if (*check || backoff < 1.0) {
		console_log("recv backoff invalid: %s  (ignoring)\n", args[1]);
		return 0;
	}
	recv_args.backoff = backoff;
	return 0;
}

static
int recv_max_time(struct cmconf *conf, char **args)
{
	char *check;
	int sec;
	sec = strtod(args[1], &check);
	if (*check || sec <= 0) {
		console_log("recv max_time invalid: %s\n", args[1]);
		return 0;
	}
	recv_args.max_time = sec;
	return 0;
}

static
int recv_rand(struct cmconf *conf, char **args)
{
	char *check;
	float rnd;
	rnd = strtod(args[1], &check);
	if (*check || rnd < 0.0 || rnd > 1.0) {
		console_log("recv rand invalid: %s  (ignoring)\n", args[1]);
		return 0;
	}
	recv_args.rand = rnd;
	return 0;
}

static
int recv_unknown(struct cmconf *conf, char **args)
{
	console_log("%s:%d unknown recv configuration option: %s\n",
		    cmconf_file(conf), cmconf_lineno(conf), args[0]);
	return 0;
}

static
struct cmconf_option recv_configoptions[] = {
	{"initial_delay", 1, 1, 0, recv_initial_delay},
	{"max_delay", 1, 1, 0, recv_max_delay},
	{"backoff", 1, 1, 0, recv_backoff},
	{"max_time", 1, 1, 0, recv_max_time},
	{"rand", 1, 1, 0, recv_rand},
	{"*", 0, -1, 0, recv_unknown},
	{0,}
};

BOOT_ADD_CONFIG(0, "recv", recv_configoptions);

/*--------------------------------------------------------------------
 * Debugging main for stand-alone testing
 */
void console_log(char *fmt, ...)
{
	va_list valist;
	va_start(valist, fmt);
	vprintf(fmt, valist);
	va_end(valist);
	fflush(stdout);
}

int main(int argc, char *argv[]) __attribute__ ((weak));
int main(int argc, char *argv[])
{
	char *host, *file;
	int port;
	struct sockaddr_in addr;
	void *buffer;
	long len;
	int r;

	verbose = 99;

	if (argc != 4) {
		printf("Usage: %s host port file\n", argv[0]);
		exit(1);
	}

	host = argv[1];
	port = strtol(argv[2], 0, 0);
	file = argv[3];

	/*printf("Getting host: %s:%d\nFile: %s\n", host, port, file); */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	r = recv_file(&addr, file, &buffer, &len);
#if 0
	printf("r = %d\n", r);

	if (r == 0) {
		int fd;
		printf("Writing out file to /tmp/recv.out\n");
		fd = open("/tmp/recv.out", O_CREAT | O_TRUNC | O_WRONLY, 0644);
		write(fd, buffer, len);
		close(fd);
	}
#endif
	exit(r);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
