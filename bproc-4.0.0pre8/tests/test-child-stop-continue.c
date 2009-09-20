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
 * $Id: test-child-stop-continue.c,v 1.3 2001/08/29 04:55:36 mkdist Exp $
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
"test-child-stop-continue:\n"

"  A process forks a remote child and sends it a SIGSTOP and a SIGCONT\n"
"  looking for the status changes with wait().\n"
"  the parent picks up the exit status.\n"
"\n"
"  Tests rfork, remote signal delivery and ghost wait behavior on SIGSTOP.\n";

static int child_pid;
int test_init(void) {
    child_pid = bproc_rfork(get_node());
    if (child_pid == 0) {
	while(1) pause();
    }
    return child_pid < 0;
}

int test_main(void) {
    int status;

    if (kill(child_pid, SIGSTOP)) {
	perror("kill");
	return 2;
    }

    /* Wait for the process to stop.. */
    if (waitpid(child_pid, &status, WUNTRACED)<0) {
	perror("waitpid");
	return 3;
    }
    if (!WIFSTOPPED(status)) {
	fprintf(stderr, "Process isn't stopped.\n");
	return 4;
    }

    if (kill(child_pid, SIGCONT)) {
	perror("kill");
	return 5;
    }
    usleep(100000);
    return 0;
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
