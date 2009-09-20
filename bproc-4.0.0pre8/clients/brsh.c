/*-------------------------------------------------------------------------
 *  brsh.c:
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
 * $Id: brsh.c,v 1.12 2001/08/29 04:55:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/bproc.h>

extern char **environ;

void Usage(char *arg0) {
    fprintf(stderr, "usage: %s command\n", arg0);
    exit(1);
}

int main(int argc, char *argv[]) {
    int i, pid;
    int sequential = 0;
    if (argc < 2) Usage(argv[0]);
    bproc_init();
    for (i=0; i < bproc_numnodes(); i++) {
	if (!bproc_nodeup(i)) continue;
#if 0
	pid = bproc_rfork(i, VMAD_DUMP_EXEC);
	if (pid < 0) {
	    fprintf(stderr, "rfork to node %d returned %d\n", i, pid);
	    exit(1);
	}
	if (pid == 0) {
	    execve(argv[1],argv+1, environ);
	    exit(-1);
	}
#else
	pid = fork();
	if (pid < 0) {
	    fprintf(stderr, "fork: %s\n", sys_errlist[errno]);
	    exit(1);
	}
	if (pid == 0) {
	    bproc_execmove(i, argv[1], argv+1, environ);
	    fprintf(stderr, "execmove failed: %s\n", strerror(errno));
	    exit(-1);
	}
#endif
	
	if (sequential) {
	    waitpid(pid, 0, 0);
	} else {
	    /* Pick up any procs that are already done. */
	    while (waitpid(-1,0,WNOHANG)>0);
	}
    }
    /* Wait for everything to complete */
    while (waitpid(-1,0,0)>0);
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
