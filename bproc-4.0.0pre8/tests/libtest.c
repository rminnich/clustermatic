/*-------------------------------------------------------------------------
 *  libtest.c:  A stress testing program.
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
 *  $Id: libtest.c,v 1.4 2004/04/19 15:47:31 mkdist Exp $
 *-----------------------------------------------------------------------*/
/* This is a generic driver for test programs.  test programs are
 * expected to define the following symbols:
 *
 * int test_main(void)     -  The main "do the test" function.
 * char *test_description  -  A pointer to a text description of the test.
 *
 * The test function should not migrate this test driver off the front
 * end machine for IO forwarding reasons.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/bproc.h>
#include "libtest.h"

char rank = 0;
int stat_interval = 100;
int target_node = -1;
int verbose = 0;

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

/**
 **  Some performance measurement stuff....
 **/
static struct timeval iter_cur_start, iter_cur_end;
static struct timeval iter_avg_start, iter_avg_end;
static int iter_max = INT_MIN, iter_min = INT_MAX;
static int iter_count = 0,     iter_count1 = 0;
void iter_start(void) {
    gettimeofday(&iter_cur_start,0);
    if (iter_count == 0)
	gettimeofday(&iter_avg_start,0);
}

void iter_write() {
    FILE *f;
    char filename[100];
    double msec;

    /*sprintf(filename, "/tmp/stress_stat.%d", rank);*/
    f = fopen("/dev/tty", "w");
    if (!f) {
	f = fopen("/proc/self/fd/1", "w");
	if (!f) return;
    }

    msec =  (iter_avg_end.tv_sec - iter_avg_start.tv_sec) * 1000000.0 + 
	iter_avg_end.tv_usec - iter_avg_start.tv_usec;
    msec /= (1000*iter_count);

    fprintf(f, "\rIteration min/avg/max total: %7.3f/%7.3f/%7.3f (msec) %d",
	    iter_min/1000.0, msec, iter_max/1000.0, iter_count1);
    fclose(f);
}

void iter_end(void) {
    int usec;
    time_t now;
    static time_t last_stat = 0;
    gettimeofday(&iter_cur_end,0);
    
    usec = (iter_cur_end.tv_sec - iter_cur_start.tv_sec) * 1000000 +
	iter_cur_end.tv_usec - iter_cur_start.tv_usec;

    if (usec > iter_max) iter_max = usec;
    if (usec < iter_min) iter_min = usec;

    iter_count++;
    iter_count1++;

    now = time(0);
    if (now - last_stat > 2) {
	last_stat = now;
	gettimeofday(&iter_avg_end, 0);
	iter_write();
	iter_count = 0;
    }
}

int get_node(void) {
    int node;
    if (target_node == -1) {
#if 0
	/* XXX This could spin forever if there are no available
	   nodes.... */
	node = rand() % bproc_numnodes();
	while (bproc_nodestatus(node) != bproc_node_up)
	    node = rand() % bproc_numnodes();
#endif
	node = 0;
    } else
	node = target_node;
    return node;
}
    

int test_init(void) __attribute__((weak));
int test_init(void) { return 0; }

extern int test_main(void);
extern char *test_description;

static
void usage(char *arg0) {
    printf("Usage: %s [-n node] [-v] numcopies\n"
	   " -n node   Run tests using node.  By default, nodes are chosen randomly.\n"
	   " -v        Increase verbose level.\n"
	   " -1        Run the test only once.\n"
	   "Test description:\n%s\n", arg0, test_description);
}

static
int start_test(int r) {
    int pid, result;
    pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(1);
    }
    if (pid == 0) {
	rank = r;
	srand(rank+time(0));
	if (test_init()) {
	    fprintf(stderr, "test_init() failed.\n");
	    exit(1);
	}
	while(1) {
	    iter_start();
	    result = test_main();
	    if (result) break;
	    /*if (verbose) { putchar('.'); fflush(stdout); }*/
	    iter_end();
	}
	exit(result);
    }
    return pid;
}

int main(int argc, char *argv[]) {
    int i, c, nprocs, status, pid;
    char *check;
    int *pids, restart=1;
    
    while ((c = getopt(argc, argv, "n:vh1")) != EOF) {
	switch(c) {
	case 'n':
	    target_node = strtol(optarg, &check, 0);
	    if (*check) {
		fprintf(stderr, "Invalid node number: %s\n", optarg);
		exit(1);
	    }
	    if (target_node < 0 || target_node >= bproc_numnodes()) {
		fprintf(stderr, "Invalid node number: %s\n", optarg);
		exit(1);
	    }
#if 0
	    if (bproc_nodestatus(target_node) != bproc_node_up) {
		fprintf(stderr, "WARNING: node %d is not up.\n", target_node);
	    }
#endif
	    break;
	case '1':
	    restart = 0;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'h':
	    usage(argv[0]); exit(0);
	    break;
	default:
	    exit(1);
	}
    }
    
    if (argc < optind + 1) { usage(argv[0]); exit(1); }

    nprocs = strtol(argv[optind], &check, 0);
    if (*check || nprocs <= 0) {
	fprintf(stderr, "Invalid number of copies: %s\n", argv[optind]);
	exit(1);
    }
    pids = malloc(sizeof(int)* nprocs);
    
    for (i=0; i < nprocs; i++)
	pids[i] = start_test(i);

    if (restart) {
	while (1) {
	    pid = wait(&status);
	    if (pid == -1) {
		perror("wait");
		exit(1);
	    }
	    if (!WIFEXITED(status) || WEXITSTATUS(status)!=0) {
		if (WIFEXITED(status))
		    printf("Bad exit status from stress tester: %d\n", WEXITSTATUS(status));
		if (WIFSIGNALED(status))
		    printf("stress tester received signal: %d\n", WTERMSIG(status));
	    }
	    for (i=0; i < nprocs; i++) {
		if (pids[i] == pid) {
		    pids[i] = start_test(i);
		    break;
		}
	    }
	}
    } else {
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
    }
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
