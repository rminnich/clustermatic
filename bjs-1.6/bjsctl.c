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
 *  $Id: bjsctl.c,v 1.7 2004/11/02 21:56:06 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <bjs.h>

#include <getopt.h>

enum actions { NONE, REMOVE };

static
void do_remove(int argc, char *argv[]) {
    int i;
    struct sexp_t *sx;

    /* Create the request */
    sx = sexp_create_list("remove", NULL);
    for (i=optind; i < argc; i++) {
	sexp_append_sx(sx, sexp_create(argv[i]));
    }
    bjs_send_sx(sx);

    /* Read the responses */
    for (i=optind; i < argc; i++) {
	if (bjs_recv(&sx) == -1) {
	    fprintf(stderr, "Failed to read a response from BJS.\n");
	    exit(1);
	}
	
	printf("%s: ", argv[i]);
	sexp_print(stdout, sx);
	printf("\n");
    }
}

static
void Usage(char *arg0) {
    printf(
"Usage: %s -h\n"
"       %s -V\n"
"       %s -r id id id ...\n"
"       -h                 Display this message and exit.\n"
"       -V                 Display version information and exit.\n"
"       -r,--remove        Remove jobs from the system.  If the job is\n"
"                          currently running, removing it will kill the job.\n"
"\n"
"       --socket path      Connect to bjs via path.\n"
,arg0,arg0,arg0);
}

int main(int argc, char *argv[]) {
    int c;
    char *bjs_path;
    enum actions action = NONE;

    struct option longopts[] = { 
	{"help",   0, 0, 'h'},
	{"socket", 1, 0, 1},
	{"remove", 0, 0, 'r'},
	{0,0,0,0}
    };

    bjs_path = getenv("BJS_SOCKET");
    if (!bjs_path) bjs_path = DEFAULT_SOCKET_PATH;

    while ((c=getopt_long(argc, argv, "hVr", longopts, 0)) != -1) {
	switch(c) {
	case 'h':
	    Usage(argv[0]);
	    exit(0);
	case 'V':
	    printf("%s version %s\n", argv[0], PACKAGE_VERSION);
	    exit(0);
	case 'r':
	    action = REMOVE;
	    break;
	default:
	    exit(1);
	}
    }

    if (bjs_connect(bjs_path)) {
	fprintf(stderr, "Failed to connect to scheduler.\nIs bjs not running"
		" or is %s the wrong socket path?\n", bjs_path);
	exit(1);
    }

    switch(action) {
    case NONE:
	break;
    case REMOVE:
	do_remove(argc, argv);
	break;
    }
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
