/*------------------------------------------------------------ -*- C -*-
 * BJS:  a simple scheduler for BProc based environments.
 * Erik Arjan Hendriks <hendriks@lanl.gov>
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
 *  $Id: bjsstat.c,v 1.10 2002/09/19 20:39:04 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <pwd.h>

#include <bjs.h>

static int cw[] = { 5, 8, 30, 30 };	/* column widths */

static
void Usage(char *arg0)
{
	printf("Usage: %s\n"
	       "       -h,--help                 Print this message and exit.\n"
	       "       -V,--version              Print version information and exit.\n"
	       "       -U,--update               Continuous update mode.\n"
	       "\n"
	       "       --socket path             Connect to bjs via path.\n",
	       arg0);
}

int verbose = 0;

int main(int argc, char *argv[])
{
	int c;
	int update = 0;
	char *bjs_path;
	struct sexp_t *sx, *reqs, *s, *s2, *s3;
	struct passwd *pwd;
	struct winsize sz;

	struct option longopts[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{"socket", 1, 0, 1},
		{"update", 0, 0, 'U'},
		{0, 0, 0, 0}
	};

	bjs_path = getenv("BJS_SOCKET");
	if (!bjs_path)
		bjs_path = DEFAULT_SOCKET_PATH;

	while ((c = getopt_long(argc, argv, "hVvU", longopts, 0)) != -1) {
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
		case 'U':
			update = 1;
			break;
		case 1:
			bjs_path = optarg;
			break;
		default:
			exit(1);
		}
	}

	if (bjs_connect(bjs_path)) {
		fprintf(stderr,
			"Failed to connect to scheduler.\nIs bjs not running"
			" or is %s the wrong socket path?\n", bjs_path);
		exit(1);
	}

	bjs_send_str(update ? "(statusupdate)" : "(status)");

	if (bjs_recv(&sx)) {
		fprintf(stderr, "Error reading response.\n");
		exit(1);
	}
      again:
	if (verbose) {
		printf("Got SEXP: ");
		sexp_print(stdout, sx);
		printf("\n");
	}
	if (update)
		printf("\33[H\33[J");	/* Clear the screen */

	/* Adjust column sizes based on terminal width */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &sz) == 0) {
		cw[2] = (sz.ws_col - (cw[0] + cw[1] + 7)) / 2;
		cw[3] = (sz.ws_col - (cw[0] + cw[1] + 7)) / 2;
	}

	/* XXX FIX ME: we're basically flying blind throught this
	 * S-expression */
	for (s = sx->list->next; s; s = s->next) {
#if 0
		printf("Pool: %s  Nodes:", s->list->val);

		/* Print the nodes */
		for (s2 = sexp_nth(s, 1)->list; s2; s2 = s2->next)
			printf(" %s", s2->val);
		printf("\n");
#else
		printf("Pool: %s   Nodes (total/up/free): %s/%s/%s\n",
		       s->list->val, sexp_nth(s, 1)->list->val, sexp_nth(s,
									 1)->
		       list->next->val, sexp_nth(s, 1)->list->next->next->val);
#endif

		/* Print the jobs */
		printf("%-*.*s   %-*.*s %-*.*s %-*.*s\n",
		       cw[0], cw[0], "ID",
		       cw[1], cw[1], "User",
		       cw[2], cw[2], "Command", cw[3], cw[3], "Requirements");
		for (s2 = sexp_nth(s, 2)->list; s2; s2 = s2->next) {
			char *user;
			int len;
			char reqstr[100];

			/* try and lookup the user name */
			user = sexp_nth(s2, SJX_UID)->val;
			pwd = getpwuid(strtol(sexp_nth(s2, 1)->val, 0, 0));
			user = pwd ? pwd->pw_name : sexp_nth(s2, 1)->val;

			/* Assemble a requirements string */
			printf("%*.*s %c %-*.*s %-*.*s",
			       cw[0], cw[0], sexp_nth(s2, SJX_JID)->val,
			       strtol(sexp_nth(s2, SJX_START)->val, 0,
				      0) ? 'R' : ' ', cw[1], cw[1], user, cw[2],
			       cw[2], sexp_nth(s2, SJX_CMD)->val);

			reqs = sexp_nth(s2, SJX_REQS);
			len = 0;
			for (s3 = reqs->list; s3; s3 = s3->next) {
				len +=
				    sprintf(reqstr + len, "%s", s3->list->val);
				if (s3->list->next)
					len +=
					    sprintf(reqstr + len, "=%s",
						    s3->list->next->val);
				len += sprintf(reqstr + len, " ");
			}
			printf(" %-*.*s", cw[3], cw[3], reqstr);

			printf("\n");
		}
	}
	sexp_free(sx);

	if (update && bjs_recv(&sx) == 0)
		goto again;
	return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
