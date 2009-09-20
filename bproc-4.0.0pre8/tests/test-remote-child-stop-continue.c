/*-------------------------------------------------------------------------
 *  jctest.c:  test program... tests stuff related to job control
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
 * $Id: test-remote-child-stop-continue.c,v 1.2 2001/08/29 04:55:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/bproc.h>
#include "libtest.h"

char *test_description =
"test-remote-child-stop-continue:\n"

"  A process forks a child which stays on the front end and moves itself to\n"
"  the remote node.  The parent then sends a SIGSTOP and a SIGCONT to it\n"
"  looking for the status change with wait().\n"
"\n"
"  Tests move, remote signal delivery and ghost wait behavior on SIGSTOP.\n";

volatile int dummy_flag=0;
void dummy_sighandler(void) { dummy_flag = 1; }

int test_main(void) {
    int pid, status, node;
    
    node = get_node();
    dummy_flag = 0;
    signal(SIGCONT, (void (*)(int)) dummy_sighandler);

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Wait for that SIGCONT... */
        while (dummy_flag == 0) usleep(10000);
        exit(0);
    }

    if (bproc_move(node)) {
        perror("bproc_move");
        return 2;
    }

    if (kill(pid, SIGSTOP)) {
        perror("kill");
        return 3;
    }

    /* Wait for the process to stop.. */
    if (waitpid(pid, &status, WUNTRACED)<0) {
        perror("waitpid");
        return 4;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process isn't stopped.\n");
        return 5;
    }

    if (kill(pid, SIGCONT)) {
        perror("kill");
        return 6;
    }

    /* Now wait for it to exit. */
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
	return 7;
    }
    if (bproc_move(-1))
	return 8;
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
