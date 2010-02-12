/* I REALLY am starting to hate linux */
#define PATH_MAX 1024.

/*------------------------------------------------------------ -*- C -*-
 * BJS:  a simple scheduler for BProc based environments.
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * bsub.c:  job submission program
 *
 * Copyright(C) 2002 University of California.
 *
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * Additionally, this program is free software; you can distribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software foundation; either version 2 of
 * the License, or any later version.  Accordingly, this program is
 * distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANY; without even the implied warranty of MARCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more detail.
 *
 *  $Id: bjssub.c,v 1.15 2004/08/23 22:19:42 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <getopt.h>

#include <sexp.h>
#include <bjs.h>

extern char **environ;

int verbose = 0;
int server_fd;

static
void Usage(const char *arg0)
{
	printf("Usage: %s [options..] command ...\n"
	       "       -h,--help                 Print this message and exit.\n"
	       "       -V,--version              Print version information and exit.\n"
	       "       -p name,--pool name       Submit the job to a particular pool.\n"
	       "       -i, --interactive         Run in interactive mode.\n"
	       "       -b, --batch               Run in batch mode.  This is the default.\n"
	       "       -n #, --nodes #           Request # nodes.\n"
	       "       -s #, --seconds #         Request # seconds of run time.\n"
	       "       -r, --restartable         Mark a job as restartable.\n"
	       "       -D dir, --directory dir   Set working directory to DIR.\n"
	       "       -O file, --output file    Redirect batch job output to file.\n"
	       "\n"
	       "       --socket path             Connect to bjs via path.\n",
	       arg0);
}

int main(int argc, char *argv[])
{
	int c, pid;
	int nodes = 1;
	int seconds = 1;
	int len, i, mask;
	int interactive = 0;
	int status;
	char *p;
	char *check;
	char *cmdline, *shell, *pwd = 0;
	char *bjs_path;
	char *pool = "default";
	char maskstr[20];
	char *nodesstr;
	struct sexp_t *job, *reqs, *nodesx, *sx;

	struct option longopts[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{"socket", 1, 0, 1},
		{"pool", 1, 0, 'p'},
		{"nodes", 1, 0, 'n'},
		{"seconds", 1, 0, 's'},
		{"requirement", 1, 0, 'R'},
		{"directory", 1, 0, 'D'},
		{"output", 1, 0, 'O'},
		{"interactive", 0, 0, 'i'},
		{"batch", 0, 0, 'b'},
		{"restartable", 0, 0, 'r'},
		{0, 0, 0, 0}
	};

	bjs_path = getenv("BJS_SOCKET");
	if (!bjs_path)
		bjs_path = DEFAULT_SOCKET_PATH;

	reqs = sexp_create(0);

	while ((c = getopt_long(argc, argv, "+hVvn:s:p:R:D:O:ibr",
				longopts, 0)) != -1) {
		switch (c) {
		case 'h':
			Usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'v':
			verbose++;
			break;
		case 'n':
			nodes = strtol(optarg, &check, 0);
			if (*check || nodes <= 0) {
				fprintf(stderr, "Invalid number of nodes: %s\n",
					optarg);
				exit(1);
			}
			break;
		case 's':
			seconds = strtol(optarg, &check, 0);
			if (*check || seconds < 0) {
				fprintf(stderr,
					"Invalid number of seconds: %s\n",
					optarg);
				exit(1);
			}
			break;
		case 'p':
			pool = optarg;
			break;
		case 'R':
			/* break A=B up into A and B */
			p = strchr(optarg, '=');
			if (p) {
				*(p++) = 0;
			} else {
				p = optarg + strlen(optarg);
			}

			/* Add a requirement */
			sexp_append_sx(reqs, sexp_create_list(optarg, p, NULL));
			break;
		case 'r':
			sexp_append_sx(reqs,
				       sexp_create_list("restartable", NULL));
			break;
		case 'D':	/* override working directory */
			if (optarg[0] != '/') {
				fprintf(stderr,
					"The working directory (%s) must be an"
					" absolute path.\n", optarg);
				exit(1);
			}
			pwd = optarg;
			break;
		case 'O':
			sexp_append_sx(reqs,
				       sexp_create_list("output", optarg,
							NULL));
			break;
		case 'i':
			interactive = 1;
			break;
		case 'b':
			interactive = 0;
			break;
		case 1:
			bjs_path = optarg;
			break;
		default:
			exit(1);
		}
	}

	if (argc - optind == 0) {
		Usage(argv[0]);
		exit(1);
	}

	/* Put our standard requirements in the list */
	{
		char tmp[20];
		sprintf(tmp, "%d", nodes);
		sexp_append_sx(reqs, sexp_create_list("nodes", tmp, NULL));
		sprintf(tmp, "%d", seconds);
		sexp_append_sx(reqs, sexp_create_list("secs", tmp, NULL));
	}

	/* Glue the bits of command line together */
	len = 0;
	for (i = optind; i < argc; i++)
		len += strlen(argv[i]) + 1;
	cmdline = alloca(len);
	cmdline[0] = 0;
	for (i = optind; i < argc; i++) {
		strcat(cmdline, argv[i]);
		if (i != argc - 1)
			strcat(cmdline, " ");
	}

	shell = getenv("SHELL");
	if (!shell)
		shell = "/bin/sh";

	mask = umask(0);
	umask(mask);
	sprintf(maskstr, "0%o", mask);

	if (interactive) {
		/* Interactive job submission. */
		job = sexp_create_list("jobi", pool, NULL);
		sexp_append_sx(job, reqs);
	} else {
		/* non-interactive job submission */
		if (!pwd) {
			/* Try $PWD to find the current working directory.  The
			 * reason for doing this is that this will sometimes hold
			 * the value we want when we're dealing with the old "amd"
			 * style automounter. */
			pwd = getenv("PWD");
			if (!pwd) {
				pwd = alloca(PATH_MAX + 1);
				if (!getcwd(pwd, PATH_MAX))
					pwd = "/";	/* Fallback */
			}
		}
		job =
		    sexp_create_list("job", pool, shell, cmdline, pwd, maskstr,
				     NULL);
		sexp_append_sx(job, sexp_create_list_v(environ));
		sexp_append_sx(job, reqs);
	}

	if (verbose > 2) {
		printf("JOB SEXP=");
		sexp_print(stdout, job);
		printf("\n");
		fflush(stdout);
	}

	if (bjs_connect(bjs_path) == -1) {
		fprintf(stderr,
			"Failed to connect to scheduler.\nIs bjs not running"
			" or is %s the wrong socket path?\n", bjs_path);
		exit(1);
	}

	bjs_send_sx(job);
	sexp_free(job);

	if (bjs_recv(&sx) == -1) {
		fprintf(stderr, "Failed to read sexp from the bjs.\n");
		exit(1);
	}

	/* Look at the response and report to the user */
	if (strcmp(sx->list->val, "error") == 0) {
		printf("Error: %s\n", sx->list->next->val);
		return 1;
	}
	if (strcmp(sx->list->val, "ok") != 0) {
		fprintf(stderr, "Unrecognized scheduler response: ");
		sexp_print(stderr, sx);
		fprintf(stderr, "\n");
		return 1;
	}

	/* Ok response */
	if (!interactive) {
		printf("JOBID=%s\n", sx->list->next->val);
		exit(0);
	}

    /*--- Interactive job startup ---------------------------------------*/

	printf("Waiting for interactive job nodes.\n");

	if (bjs_recv(&nodesx)) {
		fprintf(stderr,
			"Failed to read node list from the scheduler.\n");
		exit(1);
	}
	sexp_print(stdout, nodesx);
	printf("\n");

	printf("Starting interactive job.\n");

	if (strcmp(nodesx->list->val, "nodes") != 0) {
		fprintf(stderr, "Huh?  Didn't get a node list from bjs.\n");
		exit(1);
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "fork(): %s\n", strerror(errno));
		exit(1);
	}
	if (pid == 0) {
		bjs_close();

		/* Put together the nodes string and stick it in the environment */
		len = 0;
		for (sx = nodesx->list->next->next; sx; sx = sx->next)
			len += strlen(sx->val) + 1;
		nodesstr = alloca(len);
		nodesstr[0] = 0;
		for (sx = nodesx->list->next->next; sx; sx = sx->next) {
			strcat(nodesstr, sx->val);
			if (sx->next)
				strcat(nodesstr, ",");
		}
		setenv("NODES", nodesstr, 1);
		printf("NODES=%s\n", nodesstr);

		setenv("JOBID", nodesx->list->next->val, 1);
		printf("JOBID=%s\n", nodesx->list->next->val);

		if (pwd && chdir(pwd)) {
			fprintf(stderr, "chdir(\"%s\"): %s\n", pwd,
				strerror(errno));
			exit(1);
		}

		execl(shell, shell, "-c", cmdline, 0);
		fprintf(stderr, "execl(\"%s\",\"-c\", \"%s\", 0): %s\n", shell,
			cmdline, strerror(errno));
		exit(1);
	}

	pid = waitpid(pid, &status, 0);
	if (pid <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		exit(1);
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
