#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>

#include <sys/bproc.h>

#define contemplate
#define life

int main(int argc, char *argv[]) {
    int c, i;
    int nprocs, node, numnodes, pid;
    
    while ((c=getopt(argc, argv, "")) != EOF) {
	switch (c) {
	default: exit(1);
	}
    }
    
    if (argc < optind + 1) {
	fprintf(stderr, "Usage: %s processes\n", argv[0]);
	exit(1);
    }

    nprocs = strtol(argv[optind], 0, 0);

    close(STDIN_FILENO);
    node = 0;
    numnodes = bproc_numnodes();
    for (i=0; i < nprocs; i++) {
	/* Find a working node... */
	while (bproc_nodestatus(node) == bproc_node_down)
	    node = (node + 1) % numnodes;
	if (bproc_nodestatus(node)) {
	    pid = _bproc_rfork(node,BPROC_DUMP_ALL);
	    if (pid == 0) {
		while (1) contemplate life;
		exit(0);
	    }
	}
	node = (node + 1) % numnodes;
    }
    while (waitpid(0, 0, 0) != -1);
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
