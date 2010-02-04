/*------------------------------------------------------------ -*- C -*-
 * beoserv.c:
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
 *  $Id: beoserv.c,v 1.13 2003/10/23 21:02:14 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#ifdef HAVE_BPROC
#include <sys/bproc.h>
#endif

#define DEFAULT_CONFIG_FILE   CONFIGDIR "/config"

#define TIMEOUT_PERIOD 1

/* RARP server */
extern int rarp_setup(char *configfile, char *new_node_file);
extern void rarp_select_1(int *fdmax, fd_set * rset, fd_set * wset,
			  fd_set * eset, struct timeval *tmo);
extern void rarp_select_2(fd_set * rset, fd_set * wset, fd_set * eset);
/* Multicast/broadcast file server */
extern int send_setup(char *configfile);
extern int send_select_1(int *maxfd, fd_set * rset, fd_set * wset,
			 fd_set * eset, struct timeval *tmo);
extern int send_select_2(fd_set * rset, fd_set * wset, fd_set * eset);
/* Node setup server */
extern int nodeup_setup(char *configfile);
extern int nodeup_everytime(void);
extern int nodeup_select_1(int *maxfd, fd_set * rset, fd_set * wset,
			   fd_set * eset, struct timeval *tmo);
extern int nodeup_select_2(fd_set * rset, fd_set * wset, fd_set * eset);
extern int nodeup_timeout(void);

int verbose = 0;
int ignore_version = 0;

static
int do_config(char *conf)
{
	if (rarp_setup(conf, "/dev/null"))
		return -1;
	if (send_setup(conf))
		return -1;
	if (nodeup_setup(conf))
		return -1;
	return 0;
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
}

static volatile int do_config_reload = 0;

static struct timeval tmo;
static void sigchld_handler(void)
{
	tmo.tv_sec = tmo.tv_usec = 0;
}

static
void sighup_handler(void)
{
	tmo.tv_sec = tmo.tv_usec = 0;
	do_config_reload = 1;
}

void Usage(char *arg0)
{
	printf("Usage: %s [-h] [-V] [-f configfile]\n"
	       "\n"
	       "    -h         Display this message and exit.\n"
	       "    -V         Display version information.\n"
	       "    -f file    Read configuration from file.  (default=%s)\n"
	       "    -v         Increase verbose level for more debug info\n",
	       arg0, DEFAULT_CONFIG_FILE);
}

int main(int argc, char *argv[])
{
	int c;
	char *config_file = DEFAULT_CONFIG_FILE;
	sigset_t sigset;
	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "hVf:vi", long_options, 0)) != EOF) {
		switch (c) {
		case 'h':
			Usage(argv[0]);
			exit(0);
		case 'V':
			printf("beoserv version %s\n", PACKAGE_VERSION);
			exit(0);
			break;
		case 'i':
			ignore_version = 1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			exit(1);
		}
	}

	if (argc - optind != 0) {
		Usage(argv[0]);
		exit(1);
	}

	openlog(argv[0], LOG_PERROR, LOG_DAEMON);
	if (do_config(config_file))
		exit(1);

	openlog(argv[0], verbose ? LOG_PERROR : 0, LOG_DAEMON);
	if (verbose == 0)
		daemonize();

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sigset, 0);
	signal(SIGCHLD, (void (*)(int))sigchld_handler);
	signal(SIGHUP, (void (*)(int))sighup_handler);

	while (1) {
		int r, maxfd;
		fd_set rset, wset, eset;

		maxfd = -1;
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		FD_ZERO(&eset);
		tmo.tv_sec = 99999;	/* bigger than anything we're gonna see. */
		tmo.tv_usec = 0;
		send_select_1(&maxfd, &rset, &wset, &eset, &tmo);
		rarp_select_1(&maxfd, &rset, &wset, &eset, &tmo);
		nodeup_select_1(&maxfd, &rset, &wset, &eset, &tmo);
		sigprocmask(SIG_UNBLOCK, &sigset, 0);
		r = select(maxfd + 1, &rset, &wset, &eset, &tmo);
		sigprocmask(SIG_BLOCK, &sigset, 0);
		if (r == -1 && errno != EINTR) {
			syslog(LOG_ERR, "select(): %s", strerror(errno));
			exit(1);
		}
		nodeup_everytime();

		if (r > 0) {
			send_select_2(&rset, &wset, &eset);
			rarp_select_2(&rset, &wset, &eset);
			nodeup_select_2(&rset, &wset, &eset);
		}
		if (r == 0) {
			nodeup_timeout();
		}

		if (do_config_reload) {
			syslog(LOG_INFO, "Re-reading configuration from %s",
			       config_file);
			do_config(config_file);
			do_config_reload = 0;
		}
	}
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
