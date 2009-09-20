/*-------------------------------------------------------------------------
 *  bsh.c: A simple rsh-like client for bproc
 *
 *  Written 1999-2001 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: bsh.c,v 1.13 2002/10/18 16:28:23 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/bproc.h>

extern char **environ;

void Usage(char *arg0) {
    fprintf(stderr, "usage: %s node command\n", arg0);
    exit(1);
}

int main(int argc, char *argv[]) {
    int r;
    int node;
    char *check;

    if (argc < 3) Usage(argv[0]);

    node = strtol(argv[1], &check, 0);
    if (*check) {
	fprintf(stderr, "Invalid node number: %d\n", node);
	exit(1);
    }

#if 0
    r = bproc_rexec(node, argv[2], argv+2, environ);
    if (r != -1) {
	printf("Huh?  Syscall returned w/ result != -1\n");
	exit(1);
    }
#endif
    r = bproc_execmove(node, argv[2], argv+2, environ);
    switch (errno) {
    case EBUSY:
	fprintf(stderr, "No ghost master present.\n");
	break;
    default:
	fprintf(stderr, "%s\n", strerror(errno));
    }

    exit(1);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
