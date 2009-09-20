/*-------------------------------------------------------------------------
 *  stress.c:  stress test program...
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
 *  $Id: stress.c,v 1.9 2001/08/29 04:55:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/bproc.h>
#include <limits.h>

static int target_node = -1;
static int retry = 0;
static int stat_interval = 100;
static int verbose = 0;
static char rank = 0;

/* Helper functions for stress2/3 */
void dumpfds(void) {
    int fd;
    fd = open("/dev/null", O_WRONLY);
    if (fd == -1) return;

    if (fd != STDOUT_FILENO) dup2(fd, STDOUT_FILENO);
    if (fd != STDERR_FILENO) dup2(fd, STDERR_FILENO);
    if (fd != 1 && fd != 2) close(fd);
}

void sayhi(void) {
    int fd;
    fd = open("/tmp/hi", O_WRONLY|O_APPEND|O_CREAT,0666);
    write(fd, &rank, 1);
    close(fd);
}

void write_stat(char *tag, struct timeval *start, struct timeval *end) {
    FILE *f;
    double msec;

    msec =  (end->tv_sec-start->tv_sec)*1000000+end->tv_usec-start->tv_usec;
    msec /= (1000*stat_interval);
    
    f = fopen ("/tmp/stress_stat", "w");
    if (!f) return;
    fprintf(f, "%s: %10.3f msec\n", tag, msec);
    fclose(f);
}

/**
 **  Some performance measurement stuff....
 **/
struct timeval iter_cur_start, iter_cur_end;
struct timeval iter_avg_start, iter_avg_end;
int iter_max = INT_MIN, iter_min = INT_MAX;
int iter_count=0, iter_count1=0;
void iter_start(void) {
    gettimeofday(&iter_cur_start,0);
    if (iter_count == 0)
	gettimeofday(&iter_avg_start,0);
}

void iter_write() {
    FILE *f;
    char filename[100];
    double msec;

    sprintf(filename, "/tmp/stress_stat.%d", rank);
    f = fopen (filename, "w");
    if (!f) return;

    msec =  (iter_avg_end.tv_sec - iter_avg_start.tv_sec) * 1000000.0 + 
	iter_avg_end.tv_usec - iter_avg_start.tv_usec;
    msec /= (1000*stat_interval);

    fprintf(f, "Iteration min/avg/max: %7.3f/%7.3f/%7.3f (msec)\n",
	    iter_min/1000.0, msec, iter_max/1000.0);
    fclose(f);
}

void iter_end(void) {
    int usec;
    gettimeofday(&iter_cur_end,0);
    
    usec = (iter_cur_end.tv_sec - iter_cur_start.tv_sec) * 1000000 +
	iter_cur_end.tv_usec - iter_cur_start.tv_usec;

    if (usec > iter_max) iter_max = usec;
    if (usec < iter_min) iter_min = usec;

    iter_count++;
    iter_count1++;
    if (iter_count == stat_interval) {
	gettimeofday(&iter_avg_end, 0);
	iter_write();
	iter_count = 0;
    }
}


/*-------------------------------------------------------------------------
 *  Test 1
 *
 *  Your basic stress test.  Have a lot of processes rforking from the master.
 *  The process then says "Hi" and exits right away.
 */
int stress1(void) {
    int node, r, pid, status;
    struct utsname buf;
    
    while (1) {
	if (target_node == -1) {
	    node = rand() % bproc_numnodes();
	    if (!bproc_nodestatus(node)) continue;
	} else
	    node = target_node;

	if (verbose > 1) {
	    printf("rforking to node %d\n", node+1);
	    fflush(stdout);
	}
	
	iter_start();

	/* Skip the libs when testing to keep the stress on the pieces
	 * that we're interested in stressing. */
	pid = bproc_rfork(node);
	if (pid < 0) {
	    /* If retrying and this is a known "ok" error.  Then try
	     * again. */
	    if (retry && (errno == EIO)) {
		sleep(1);
		continue;
	    }

	    fprintf(stderr, "%d: rfork: %d\n", getpid(), errno);
	    exit(1);
	}
	if (pid == 0) {
	    /* To be done remotely */
	    uname(&buf);
	    if (verbose)
		printf("%5d: Hello!  I'm on node %d (%s)\n",getpid(),
		       node, buf.nodename);
	    exit(0);
	} else {
	    /* Wait for remote thing to finish */
	    r = waitpid(pid, &status,0);
	    if (r == -1) {
		fprintf(stderr, "%5d: Wait on %d failed.\n", getpid(), pid);
	    } else {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		    fprintf(stderr, "%5d: remote proc (%d) exited with error condition: %04x\n", getpid(), pid, status);
		}
	    }
	}

	sayhi();
	iter_end();
    }
}

/*-------------------------------------------------------------------------
 *  Test 2
 *
 * A single process ping-pongs back and forth to slave node and back
 * to the front end node.
 */
int stress2(void) {
    int node,r;
    
    /* This process ping-pongs back and forth. */
    while(1) {
	if (target_node == -1) {
	    node = rand() % bproc_numnodes();
	    if (!bproc_nodestatus(node)) continue;
	} else
	    node = target_node;

	iter_start();
	r = bproc_move(node);
	if (r == -1) return 1;

	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	r = bproc_move(-1);
	if (r == -1) return 2;

	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	iter_end();
    }
}

/*-------------------------------------------------------------------------
 *  stress 3
 *
 *  This is the same as stress 2 except that the ping-ponging process
 *  also has a child process.  (This should test/stress BPROC_CHILD
 *  and the related ghost stuff.)
 */
int stress3(void) {
    int pid, node;

    /* Setup the child process */
    pid = fork();
    if (pid == -1) return 1;
    if (pid == 0) {
	while(1) pause();
    }

    /* This process ping-pongs back and forth. */
    while(1) {
	if (target_node == -1) {
	    node = rand() % bproc_numnodes();
	    if (!bproc_nodestatus(node)) continue;
	} else
	    node = target_node;
	
	iter_start();

	if (bproc_move(node) == -1) return 2;
	if (waitpid(pid, 0, WNOHANG) != 0) return 3; /* Check for child process */

	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	if (bproc_move(-1) == -1) return 4;
	if (waitpid(pid, 0, WNOHANG) != 0) return 5;

	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	iter_end();
    }
    
    return 0;
}


/*-------------------------------------------------------------------------
 *  stress 4
 *
 *  Fork a child, move to a remote node, send USR1 to that child, wait for
 *  the child to exit, move back to front end, repeat.
 *  
 *
 */
void stress4_helper(void) { exit(123); }

int stress4(void) {
    int node, pid, status, waiterr;

    while (1) {
	if (target_node == -1) {
	    node = rand() % bproc_numnodes();
	    if (!bproc_nodestatus(node)) continue;
	} else
	    node = target_node;
	
	iter_start();

	pid = fork();
	if (pid == -1) return 1;

	if (pid == 0) { /* child */
	    signal(SIGUSR1, (void(*)(int))stress4_helper);
	    while(1) pause();
	    /* Not reached */
	}

	if (bproc_move(node) == -1) return 2;
	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	if (kill(pid, SIGUSR1)) return 3;

	/* Now wait for the child process to actually exit. */
	waiterr = waitpid(pid, &status, 0);
	if (waiterr == -1) {
	    if (errno == ECHILD) return 4;
	    return 5;
	}
	if (waiterr == 0) return 6;
	if (waiterr != pid) return 7;
	if (!WIFEXITED(status)) return 8;
	if (WEXITSTATUS(status) != 123) return 9;

	/* Go back to the front end to repeat. */
	if (bproc_move(-1) == -1) return 10;
	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	iter_end();
    }
}

/*-------------------------------------------------------------------------
 *  stress 5
 *
 *  This one goes to a remote node, forks a child.  That child ping-pongs
 *  a few times and then exits.
 *  
 *
 */
int stress5(void) {
    int node, pid, status, waiterr;
    int i;

    while (1) {
	if (target_node == -1) {
	    node = rand() % bproc_numnodes();
	    if (!bproc_nodestatus(node)) continue;
	} else
	    node = target_node;
	
	iter_start();

	if (bproc_move(node) == -1)
	    return 1;

	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	pid = fork();
	if (pid == -1) return 2;

	if (pid == 0) { /* child */
	    /* Ping-pong a few times and exit */
	    for (i=0; i < 3; i++) {
		if (bproc_move(-1) == -1)
		    return 3 + i*2;
		if (bproc_move(node) == -1)
		    return 4 + i*2;
	    }
	    exit(123);
	}

	/* Parent: pick up the child */
	waiterr = waitpid(pid, &status, 0);
	if (waiterr == -1) {
	    if (errno == ECHILD) return 50;
	    return 5;
	}
	if (waiterr == 0) return 51;
	if (waiterr != pid) return 52;
	if (!WIFEXITED(status)) return 53;
	if (WEXITSTATUS(status) != 123) return 54;

	/* Go back to the front end to do it again */
	if (bproc_move(node) == -1) return 55;
	dumpfds();		/* Shake off my stupid IO forwarding */
	sayhi();

	iter_end();
    }
}


struct {
    char *desc;
    int  (*func)(void);
} tests[] = {{"rfork() to node, print message, exit",stress1},
	     {"process move() to and from a ndoe", stress2},
	     {0,0}};

int main(int argc, char *argv[]) {
    int c, i, result;
    int nprocs, pid, status;
    char *check;

    int (*test)(void) = stress1;

    while ((c=getopt(argc, argv, "hrn:v1234")) != EOF) {
	switch (c) {
	case 'h':
	    fprintf(stderr,
		    "Usage: %s [-h] [-r] [-n node]\n"
		    "  -h      Show this message\n"
		    "  -r      Retry if there are errors\n"
		    "  -v      Increase verbose level\n"
		    "  -n node Operate on this node (default=random)\n",
		    argv[0]);
	    exit(1);
	case 'v': verbose++; break;
	case 'r': retry = 1; break;
	case 'n':
	    target_node = strtol(optarg, &check, 0);
	    if (*check) {
		fprintf(stderr, "Invalid number: %s\n", optarg);
		exit(1);
	    }
	    break;
	    /*
	case '1': test = stress1; break;
	case '2': test = stress2; break;
	case '3': test = stress3; break;
	case '4': test = stress4; break;
	case '5': test = stress5; break;
	    */
	default: exit(1);
	}
    }
    
    if (argc < optind + 2) {
	fprintf(stderr,
		"Usage: %s testnum processes\n"
		"Test Descriptions:\n"
		"  1 - rfork to remote node and exit.  Parent on front end \n"
		"      waits and picks up status. \n"
		"  2 - process moves to and from a node repeatedly.\n"
		"  3 - process forks a child; parent moves back and forth repeatedly\n"
		"      and checks for presence of child on each iteration.\n"
		"  4 - Process forks a child; parent moves to node; parent sends child\n"
		"      a signal; child exits; parent performs wait()\n"
		"  5 - Process moves to remote node; forks; child migrates back and forth\n"
		"      a few times and exits.\n", argv[0]);
	exit(1);
    }

    nprocs = strtol(argv[optind], 0, 0);

    /* Fork off n copies of our stress tester */
    for (i=0; i < nprocs; i++) {
	pid = fork();
	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}
	if (pid == 0) {
	    srand(rank+time(0));
	    rank = i;
	    result = test();
	    exit(result);
	}
    }

    /* Wait for all of 'em ? */
    for (i=0; i < nprocs; i++) {
	wait(&status);
	if (!WIFEXITED(status) || WEXITSTATUS(status)!=0) {
	    if (WIFEXITED(status))
		printf("Bad exit status from stress tester: %d\n", WEXITSTATUS(status));
	    if (WIFSIGNALED(status))
		printf("stress tester received signal: %d\n", WTERMSIG(status));
	}
    }


    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
