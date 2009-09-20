/*-------------------------------------------------------------------------
 *  movetest.c:  test program... tests stuff basic process movement
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
 * $Id: movetest.c,v 1.4 2001/08/29 04:55:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/bproc.h>

int node[2];

/*-------------------------------------------------------------------------
 *  Move a process to a slave node and then back again.
 */
int there_and_back(void) {
    int err;
    err = bproc_move(node[0]);
    if (err == -1) {
	perror("bproc move #1");
	return 1;
    }

    err = bproc_move(-1);
    if (err == -1) {
	perror("bproc move #2");
	return 1;
    }

    return 0;
}

/*-------------------------------------------------------------------------
 *  Move a process to a slave node, then to another slave node and then
 *  back again.
 */
int there_there_and_back(void) {
    int err;

    err = bproc_move(node[0]);
    if (err == -1) {
	perror("bproc move #1");
	return 1;
    }

    err = bproc_move(node[1]);
    if (err == -1) {
	perror("bproc move #2");
	return 1;
    }

    err = bproc_move(-1);
    if (err == -1) {
	perror("bproc move #3");
	return 1;
    }

    return 0;
}

struct {
    char *name;
    int (*func)(void);
} testlist[] = {
    {"there,back",        there_and_back},
    {"there,there,back",  there_there_and_back},
    {0,0}
};

int main(int argc, char *argv[]) {
    int c, i, pid, status;
    char *check;

    node[0] = 0;
    node[1] = 1;

    while ((c=getopt(argc, argv, "n:"))!=EOF) {
	switch(c) {
	case 'n':
	    node[0] = strtol(optarg, &check,0);
	    if (*check != ',') {
		fprintf(stderr, "node arg format: node1,node2\n");
		exit(1);
	    }
	    node[1] = strtol(check+1, &check,0);
	    if (*check) {
		fprintf(stderr, "node arg format: node1,node2\n");
		exit(1);
	    }
	    break;
	case 'h':
	    fprintf(stderr, "Usage: %s [-n node,node]\n", argv[0]);
	    exit(1);
	default: exit(1);
	}
    }

    printf("Using nodes %d and %d\n", node[0], node[1]);
    if (!bproc_nodestatus(node[0])) fprintf(stderr,"Node %d is not up!\n",node[0]);
    if (!bproc_nodestatus(node[1]))	fprintf(stderr,"Node %d is not up!\n",node[1]);

    for (i=0; testlist[i].func; i++) {
	printf("%-40s: ", testlist[i].name);
	fflush(stdout);

	/* Perform the tests in a sub-process */
	pid = fork();
	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}
	if (pid == 0) {
	    if (testlist[i].func())
		exit(1);
	    else
		exit(0);
	}

	if (waitpid(pid, &status, 0) == -1) {
	    perror("waitpid");
	    exit(1);
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
	    printf("Passed\n");
	} else {
	    printf("Failed\n");
	    exit(1);
	}
	fflush(stdout);
    }

    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
