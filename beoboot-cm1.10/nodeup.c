/*------------------------------------------------------------ -*- C -*-
 * nodeup: driver
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.  LA-CC Number 01-67.
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
 * $Id: nodeup.c,v 1.15 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>

#include "cmconf.h"

/* I don't want to induce another dependency just for this... */
enum loglevel {
	NODEUP_LOG_FATAL,
	NODEUP_LOG_ERROR,
	NODEUP_LOG_WARNING,
	NODEUP_LOG_INFO,
	NODEUP_LOG_DEBUG
};

#define L(x) { #x,  NODEUP_LOG_ ## x}
struct {
	char *name;
	int level;
} log_levels[] = {
	L(FATAL), L(ERROR), L(WARNING), L(INFO), L(DEBUG), {
	0, 0}
};

#undef L

#define DEFAULT_LISTENPATH  "/tmp/.node_up"
#define DEFAULT_WORKER      LIBDIR "/bin/node_up"
#define DEFAULT_MAXWORKERS  3
#define DEFAULT_MAXCLIENTS  256
#define DEFAULT_LOGLEVEL    LOG_INFO

#define DEFAULT_STARTUPDELAY 1500000	/* delay before concluding
					 * that there are no more
					 * connections coming
					 * (usec) */

struct config_t {
	int fd;
	char *listen_path;
	char *worker;		/* path to program that does the actual work */

	int max_clients;	/* max # of clients to setup at once */
	long startup_delay;
	int log_level;
};

static struct config_t conf = { -1, 0, 0, 0, 0, 0 };	/* bogus config */

static struct config_t tc;

static int child_pid = 0;
static int nclients = 0;
static int *clients = 0;
static struct timeval last_accept = { 0, 0 };

int verbose __attribute__ ((weak)) = 0;

static
int nodeup_config_max_clients(struct cmconf *c, char **args)
{
	char *check;
	tc.max_clients = strtol(args[1], &check, 0);
	if (*check || tc.max_clients <= 0) {
		syslog(LOG_ERR, "Invalid maximum number of clients: %s\n",
		       args[1]);
		return -1;
	}
	return 0;
}

static
int nodeup_config_startup_delay(struct cmconf *c, char **args)
{
	char *check;
	tc.startup_delay = strtod(args[1], &check) * 1000000;
	if (*check || tc.startup_delay < 0) {
		syslog(LOG_ERR, "Invalid startup delay: %s\n", args[1]);
		return -1;
	}
	return 0;
}

static
int nodeup_config_log_level(struct cmconf *c, char **args)
{
	int i;
	for (i = 0; log_levels[i].name; i++) {
		if (strcasecmp(args[1], log_levels[i].name) == 0) {
			tc.log_level = log_levels[i].level;
			return 0;
		}
	}
	syslog(LOG_ERR, "Invalid log level: %s\n", args[1]);
	return -1;
}

static
int nodeup_config_listen_path(struct cmconf *c, char **args)
{
	if (tc.listen_path)
		free(tc.listen_path);
	tc.listen_path = strdup(args[1]);
	return 0;
}

static
int nodeup_config_worker(struct cmconf *c, char **args)
{
	if (tc.worker)
		free(tc.worker);
	tc.worker = strdup(args[1]);
	return 0;
}

static
int nodeup_config_unknown(struct cmconf *conf, char **args)
{
	syslog(LOG_ERR, "%s:%d unknown nodeup configuration option: %s",
	       cmconf_file(conf), cmconf_lineno(conf), args[0]);
	return -1;
}

static
struct cmconf_option nodeup_configopts[] = {
	{"max_clients", 1, 1, 0, nodeup_config_max_clients},
	{"startup_delay", 1, 1, 0, nodeup_config_startup_delay},
	{"listen_path", 1, 1, 0, nodeup_config_listen_path},
	{"worker", 1, 1, 0, nodeup_config_worker},
	{"log_level", 1, 1, 0, nodeup_config_log_level},
	{"*", 0, -1, 0, nodeup_config_unknown},
	{0,}
};

static
int nodeup_callback(struct cmconf *conf, char **args)
{
	return cmconf_process_args(conf, args + 1, nodeup_configopts);
}

static
struct cmconf_option configopts[] = {
	{"node_up", 0, -1, 0, nodeup_callback},
	{0,}
};

static
int nodeup_setup_listen(char *socket_path)
{
	int lfd, flags;
	struct sockaddr_un addr;
	unlink(socket_path);	/* blindly unlink */

	lfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lfd == -1) {
		syslog(LOG_ERR, "socket(AF_UNIX, SOCK_STREAM, 0): %s",
		       strerror(errno));
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, socket_path);

	umask(0);		/* should be redundant */
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr))) {
		syslog(LOG_ERR, "bind(\"%s\"): %s\n", addr.sun_path,
		       strerror(errno));
		close(lfd);
		return -1;
	}

	if (listen(lfd, 1024) == -1) {
		syslog(LOG_ERR, "listen(1024): %s\n", strerror(errno));
		close(lfd);
		return -1;
	}
	flags = fcntl(lfd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(lfd, F_SETFL, flags);
	return lfd;
}

static
void config_free(struct config_t *c)
{
	if (c->fd != -1)
		close(c->fd);
	if (c->listen_path)
		free(c->listen_path);
	if (c->worker)
		free(c->worker);
}

int nodeup_setup(char *configfile)
{
	/* initialize our new clean configuration to default values */
	tc.fd = -1;
	tc.listen_path = strdup(DEFAULT_LISTENPATH);
	tc.worker = strdup(DEFAULT_WORKER);
	tc.max_clients = DEFAULT_MAXCLIENTS;
	tc.startup_delay = DEFAULT_STARTUPDELAY;
	tc.log_level = DEFAULT_LOGLEVEL;

	if (cmconf_process_file(configfile, configopts)) {
		config_free(&tc);
		return -1;
	}

	if (conf.listen_path && strcmp(tc.listen_path, conf.listen_path) == 0) {
		tc.fd = conf.fd;
		conf.fd = -1;
	} else {
		tc.fd = nodeup_setup_listen(tc.listen_path);
	}
	clients = realloc(clients, sizeof(int) * tc.max_clients);

	config_free(&conf);
	memcpy(&conf, &tc, sizeof(struct config_t));
	return 0;
}

/* it is *AMAZING* that so many  things in Linux do not *compile* 
 * in an architecture-independent fashion. I mean, setting up ucred
 * as u32? Yeesh! Plus the simple example you can find won't build
 * any more on ubongo 9.10. No wonder I'm going to port this to a mac.
 * Would be so cool if they could learn from Plan 9. 
 */
struct myucred {
	unsigned long pid, uid, gid;
};

static
int nodeup_accept_clients(void)
{
	int fd;
	int size;
	struct sockaddr addr;
	/* this won't compile on linux anymore. Who knows what they broke this 
	 * time but I'm sick of looking for it!
	 struct ucred creds;
	 */
	struct myucred creds;
	while (nclients < conf.max_clients) {
		size = sizeof(addr);
		fd = accept(conf.fd, &addr, &size);
		if (fd == -1) {
			if (errno != EAGAIN) {
				syslog(LOG_ERR, "accept: %s\n",
				       strerror(errno));
				exit(1);
			}
			break;
		}

		/* Check remote process credentials */
		size = sizeof(creds);
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &size)) {
			syslog(LOG_ERR,
			       "getsockopt(SOL_SOCKET, SO_PEERCRED): %s\n",
			       strerror(errno));
			close(fd);
			continue;
		}
		if (creds.uid != 0) {
			close(fd);
			continue;
		}

		if (verbose >= 2)
			syslog(LOG_NOTICE, "Accepted node_up client.\n");

		/* Add this one to our list of clients */
		clients[nclients++] = fd;
		gettimeofday(&last_accept, 0);
	}
	return 0;
}

static
int nodeup_start_worker(void)
{
	int i;
	char **argv;

	syslog(LOG_NOTICE, "Starting node_up worker for %d clients.\n",
	       nclients);

	argv = alloca(sizeof(char **) * (nclients + 4));
	argv[0] = conf.worker;
	argv[1] = "-fl";
	argv[2] = alloca(8);
	sprintf(argv[2], "%d", conf.log_level);
	for (i = 0; i < nclients; i++) {
		argv[i + 3] = alloca(8);
		sprintf(argv[i + 3], "%d", clients[i]);
	}
	argv[i + 3] = 0;

	child_pid = fork();
	if (child_pid == -1) {
		syslog(LOG_ERR, "fork: %s\n", strerror(errno));
		return -1;
	}
	if (child_pid == 0) {

		execv(argv[0], argv);
		syslog(LOG_ERR, "%s: %s\n", argv[0], strerror(errno));
		exit(1);
	}

	/* Parent */
	for (i = 0; i < nclients; i++)
		close(clients[i]);
	nclients = 0;
	return 0;
}

int nodeup_everytime(void)
{
	int pid;
	if (child_pid) {
		pid = waitpid(child_pid, 0, WNOHANG);
		if (pid == child_pid)
			child_pid = 0;
	}
	return 0;
}

#define TIMEVALDIFF(a,b)  (((a).tv_sec - (b).tv_sec)*1000000 + ((a).tv_usec - (b).tv_usec))

int nodeup_select_1(int *maxfd, fd_set * rset, fd_set * wset,
		    fd_set * eset, struct timeval *tmo)
{
	long tm;
	struct timeval now;

	if (child_pid == 0) {
		FD_SET(conf.fd, rset);
		if (conf.fd > *maxfd)
			*maxfd = conf.fd;

		/* If there's no worker running, figure out how much longer
		 * we're willing to wait for clients to appear. */
		if (nclients > 0) {
			gettimeofday(&now, 0);
			tm = conf.startup_delay - TIMEVALDIFF(now, last_accept);
			if (tm < 0)
				tm = 0;
			if (tmo->tv_sec * 1000000 + tmo->tv_usec > tm) {
				tmo->tv_sec = tm / 1000000;
				tmo->tv_usec = tm % 1000000;
			}
		}
	}
	return 0;
}

int nodeup_select_2(fd_set * rset, fd_set * wset, fd_set * eset)
{
	if (child_pid != 0)
		return 0;

	if (FD_ISSET(conf.fd, rset))
		nodeup_accept_clients();

	if (nclients == conf.max_clients)
		nodeup_start_worker();
	return 0;
}

int nodeup_timeout(void)
{
	struct timeval now;

	/* Start the worker if it's time... */
	gettimeofday(&now, 0);
	if (nclients > 0 && TIMEVALDIFF(now, last_accept) >= conf.startup_delay)
		nodeup_start_worker();
	return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
