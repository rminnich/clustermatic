/*
 * vrfork.c: A bproc_vrfork test program.
 *
 *
 * $Id: vrfork.c,v 1.1 2002/10/18 16:43:07 mkdist Exp $
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/bproc.h>

static
void show_nodes(int nnodes, int *nodes) {
    int i;
    printf("NODES:");
    for (i=0; i < nnodes; i++)
	printf(" %d", nodes[i]);
    printf("\n");
}

static
int do_vrfork(int nnodes, int *nodes) {
    int j, r, error_seen = 0,  *pids;

    pids = alloca(sizeof(int) * nnodes);

    r = bproc_vrfork(nnodes, nodes, pids);
    if (r < 0) {
	printf("bproc_vrfork error: %s\n", bproc_strerror(errno));
	exit(1);
    }

    if (r >= 0 && r < nnodes) {
	/* Child process */
	while (1) pause();
    }
    
    if (r == nnodes) {
	/* Parent process */
	for (j=0; j < nnodes; j++) {
	    if (pids[j] <= 0) {
		/* error */
		printf("ERROR CREATING PROCESS ON %d: %s\n",
		       nodes[j], bproc_strerror(pids[j]));
		error_seen = -1;
	    } else {
		kill(pids[j], SIGTERM);
		if (waitpid(pids[j], 0, 0) != pids[j]) {
		    printf("ERROR WAITING ON PROCESS %d\n",
			   pids[j]);
		    error_seen = -1;
		}
	    }
	}
    }
    return error_seen;
}

static
int do_vrfork_allnodes(int nnodes, int *nodes) {
    int i;

    for (i=0; i < nnodes; i++) {
	if (bproc_move(nodes[i])) {
	    printf("Couldn't move to node %d\n", nodes[i]);
	    return -1;
	}
	printf("Calling vrfork from node %d...", nodes[i]); fflush(stdout);

	if (do_vrfork(nnodes, nodes)) {
	    printf("Failed\n"); fflush(stdout);
	    return -1;
	}

	printf("Ok\n"); fflush(stdout);
    }
    return 0;
}


int main(int argc, char *argv[]) {
    int i, j, k, listlen;
    struct bproc_node_info_t *list;
    int nnodes, *nodes;

    setlinebuf(stdout);
    
    /* Figure out the node set */
    if ((listlen = bproc_nodelist(&list)) == -1) {
	fprintf(stderr, "bproc_nodelist: %s\n", bproc_strerror(errno));
	return -1;
    }

    /* This should be big enough for all the tests we want to do */
    nodes = alloca(sizeof(int) * (listlen*10+1)); /* big enough  */

    /*--- TEST1:  basic rfork to every node w/o front end */
    printf("Running basic test w/o front end.\n");
    nnodes = 0;
    for (i=0; i < listlen; i++)
	if (_bproc_access(&list[i], 1) == 0)
	    nodes[nnodes++] = list[i].node;
    show_nodes(nnodes, nodes);
    do_vrfork(nnodes, nodes);

    /*--- TEST:  basic rfork to every node w/ front end from every node */
    printf("TEST: vrfork to all from FE\n");
    nnodes = 0;
    nodes[nnodes++] = -1;
    for (i=0; i < listlen; i++)
	if (_bproc_access(&list[i], 1) == 0)
	    nodes[nnodes++] = list[i].node;
    show_nodes(nnodes, nodes);
    do_vrfork_allnodes(nnodes, nodes);

    /*--- TEST:  basic rfork to every node w/ front end from every node */
    printf("TEST: vrfork to all from FE (duplicates)\n");
    nnodes = 0;
    nodes[nnodes++] = -1;
    nodes[nnodes++] = -1;
    nodes[nnodes++] = -1;
    for (i=0; i < listlen; i++)
	if (_bproc_access(&list[i], 1) == 0) {
	    nodes[nnodes++] = list[i].node;
	    nodes[nnodes++] = list[i].node;
	    nodes[nnodes++] = list[i].node;
	}
    show_nodes(nnodes, nodes);
    do_vrfork_allnodes(nnodes, nodes);


    /*--- TEST:  basic rfork to every node w/ front end from every node */
    printf("TEST: vrfork to all from FE (duplicates, random)\n");
    nnodes = 0;
    nodes[nnodes++] = -1;
    nodes[nnodes++] = -1;
    nodes[nnodes++] = -1;
    for (i=0; i < listlen; i++)
	if (_bproc_access(&list[i], 1) == 0) {
	    nodes[nnodes++] = list[i].node;
	    nodes[nnodes++] = list[i].node;
	    nodes[nnodes++] = list[i].node;
	}
    for (i=0; i < 5; i++) {
	for (j=0; j < nnodes; j++) {
	    int tmp;
	    k = rand() % nnodes;
	    tmp = nodes[j];
	    nodes[j] = nodes[k];
	    nodes[k] = tmp;
	}
	show_nodes(nnodes, nodes);
	do_vrfork_allnodes(nnodes, nodes);
    }
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
