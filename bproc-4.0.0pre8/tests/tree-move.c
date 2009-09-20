#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "../kernel/bproc.h"
#include <sys/bproc.h>


/* Defaults */
static int nlevel    = 2;
static int nchildren = 2;


void usage(char *arg0) {
    printf(
"Usage: %s [options] node1 node2\n"
"       -h          Show this message\n"
"       -l level    Number of levels in process tree. (default = 2)\n"
"       -c num      Number of children per level.     (default = 2)\n"
"\n"
"This program builds a tree of processes.  All the processes try to migrate\n"
"back and forth as fast as they can.  At every iteration, the process tree is\n"
"checked with wait()\n"
"\n"
"WARNING:  This program can create HUGE numbers of processes :)\n", arg0);
}


int check_children(int *pidlist, int db) {
    int i,ct=0;
    for (i=0; i < nchildren; i++) {
	if (pidlist[i]) {
	    ct++;
#if 0
	    if (waitpid(pidlist[i], 0, WNOHANG) != 0) {
		printf("MISSING CHILD PID: %d\n", pidlist[i]);
		exit(1);
	    }
#endif
	}
    }
    if (ct != syscall(__NR_bproc, BPROC_SYS_DEBUG, 0)) {
	exit(1);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int c,i,level;
    int *children;
    int node1, node2;

    while ((c=getopt(argc,argv,"hl:c:")) != EOF) {
	switch(c) {
	case 'h': usage(argv[0]); exit(0);
	case 'c': nchildren = strtol(optarg, 0, 0); break;
	case 'l': nlevel = strtol(optarg, 0, 0); break;
	default: exit(1);
	}
    }

    if (optind+2 != argc) {
	usage(argv[0]);
	exit(1);
    }

    node1 = strtol(argv[optind],0,0);
    node2 = strtol(argv[optind+1],0,0);

    children = alloca(sizeof(int)*nchildren);

    for (level = 0; level < nlevel; level++) {
	for (i=0; i < nchildren; i++) {
	    children[i] = fork();
	    if (children[i] == 0) break;
	}
	if (i == nchildren) break;
	for (i=0; i < nchildren; i++) children[i] = 0;
    }

    srand(time(0)+getpid());

    sleep(1);
    check_children(children,0);
    while(1) {
	bproc_move_io(node1,0,0);
	check_children(children,1);
	usleep(rand() % 1000000);

	bproc_move_io(node2,0,0);
	check_children(children,0);
	usleep(rand() % 1000000);
    }


    while(1) pause();
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
