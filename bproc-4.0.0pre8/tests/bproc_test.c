/*--------------------------------------------------------------------
 *  Process arrangement enumerator
 *
 * $Id: bproc_test.c,v 1.2 2004/06/08 18:37:32 mkdist Exp $
 *------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/bproc.h>

#include "bproc_test.h"

char *proc_names[] = {"FrontEnd",   "Slave0",  "Slave1",  "Slave2",
		      "Invalid",    "Slave0 D","Slave1 D","Slave2 D",
};

static
int proc_slaveno(int a, int i) {
    a = proc_arr(a,i);
    if (a == proc_fe || a == proc_inv)
	return -1;
    if (a >= proc_sl_d)
	a -= proc_sl_d - proc_sl;
    a -= proc_sl;
    return a;
}

/* Arrangements are stored in integers.  The first 3 bits specifiy the
 * location of the first process, the next three bits are the first
 * child, then the next child and so on.  */
typedef int arr_t;

void print_col(int nprocs) {
    int i;
    printf("Arr  %10s", "Parent");
    for (i=1; i < nprocs; i++)
	printf(" %9s%d", "Child", i);
    printf("\n");
}

char *arr_str(int nprocs, int arr) {
    int i, a, n;
    static char buf[1000];
    n = sprintf(buf, "%0*o%*s", nprocs, arr, 4 - nprocs, "");
    for (i=0; i < nprocs; i++) {
	a = proc_arr(arr,i);
	n += sprintf(buf+n, " %10s", proc_names[a]);
    }
    return buf;
}

void print_arr(int nprocs, int arr) {
    printf("%s\t", arr_str(nprocs, arr));
    fflush(stdout);
}

static
int enumerate(int nprocs, int flags, int start) {
    int i, j, a, got;
    int end = (1 << (nprocs * proc_shift));

    /* This loop is not terribly efficient */
    for (i=start+1; i < end; i++) {
	/* Filter for bogus or redundant arrangements */
	/* 1: no "undefs" */
	for (j = 0; j < nprocs; j++) {
	    a = proc_arr(i, j);
	    if (a >= proc_last) goto skip_it;
	}

	/* Avoid redundant configurations: use the slaves in order
	 * only. */
	got = 0;
	for (j = 0; j < nprocs; j++) {
	    a = proc_slaveno(i,j);
	    if (a == -1) continue;

	    got |= (1 << a);
	    /* check to see if any lesser slaves are missing.  This
	     * should be a fine check since we're doing everything in
	     * order after the previous check */
	    if ((got & ((1<<a)-1)) != ((1<<a)-1))
		goto skip_it;
	}
	/* 3: No detaches for process 1 - the parent */
	if (proc_isdetach(proc_arr(i,0))) goto skip_it;
	/* 4: check flags */
	for (j = 0; j < nprocs; j++) {
	    a = proc_arr(i,j);
	    if (!(flags & bproc_test_detach) && proc_isdetach(a))
		goto skip_it;
	    if ((flags & bproc_test_no_attach) && proc_isattach(a))
		goto skip_it;
	    if (!(flags & bproc_test_invalid) && a == proc_inv) goto skip_it;
	}

	/*print_arr(nprocs, i);*/
	return i;
    skip_it:
	continue;
    }
    return -1;
}

static
int read_all(int file, void *buf, int count) {
    int r, bytes = count;
    while (bytes) {
        r = read(file, buf, bytes);
        if (r < 0)  return r;
        if (r == 0) return count - bytes;
        bytes -= r; buf += r;
    }
    return count;

}

/* Get information about usable nodes in the system */
static int nnodes = -1;
static int nodes[BPROC_TEST_NODES_MAX];
static int node_inv=0;

int bproc_test_init(const char *nstr) {
    int i;
    struct bproc_node_set_t ns;

    if (bproc_nodelist(&ns) == -1) {
	fprintf(stderr, "bproc_nodelist: %s\n", bproc_strerror(errno));
	fprintf(stderr, "Failed to read node list, using front end only.\n");
	nnodes = 0;
	return 0;
    }

    if (!nstr)
	nstr = getenv("NODES");
    if (nstr) {
	/* Get the node set from the environment */
	struct bproc_node_set_t ns1;

	if (bproc_nodefilter(&ns1, &ns, nstr)) {
	    fprintf(stderr, "Invalid node set: %s\n", nstr);
	    return -1;
	}

	nnodes = 0;
	for (i=0; i < ns1.size && nnodes < BPROC_TEST_NODES_MAX; i++) {
	    if (bproc_access(ns1.node[i].node, 1) == 0)
		nodes[nnodes++] = ns1.node[i].node;
	    else
		fprintf(stderr, "bproc_test: Ignoring user specified node %d "
			"- node is not accessible.\n", ns1.node[i].node);
	}

	bproc_nodeset_free(&ns1);
    } else {
	/* Find a nodeset automatically */
	nnodes = 0;
	for (i=0; i < ns.size && nnodes < BPROC_TEST_NODES_MAX; i++) {
	    if (bproc_access(ns.node[i].node, 1) == 0)
		nodes[nnodes++] = ns.node[i].node;
	}
    }

    /* Find an invalid node number */
    for (i=0; i < ns.size; i++) {
	if (node_inv <= ns.node[i].node)
	    node_inv = ns.node[i].node + 1;
    }

    bproc_nodeset_free(&ns);

    printf("bproc_test: node_set = -1");
    for (i=0; i < nnodes; i++)
	printf(" %d", nodes[i]);
    printf("\n");
    printf("bproc_test: invalid node = %d\n", node_inv);
    return 0;
}

/* XXX it would really be good to have a built-in I/O forwarder so
 * that we can make sure the output from this test program looks
 * somewhat reasonable.  It's also the sure-fire way to make sure that
 * we know what's really going on. */
static
int test_run_arr(int nprocs, int arr, int flags,
		 int (*test_func)(int, struct bproc_test_info_t *)) {
    int pid,a,r,i;
    int pfd[2];
    int status;

    struct bproc_test_info_t ti;

    if (nnodes == -1) {
	fprintf(stderr, "bproc_test: call bproc_test_init() first!\n");
	exit(1);
    }

    /* Assign nodes to this arrangement */
    ti.nprocs  = nprocs;
    ti.arr     = arr;
    ti.scratch = 0;
    for (i=0; i < nprocs; i++) {
	if (proc_arr(arr, i) == proc_fe)
	    ti.node[i] = BPROC_NODE_MASTER;
	else if (proc_arr(arr, i) == proc_inv)
	    ti.node[i] = node_inv;
	else {
	    a = proc_arr(arr, i);
	    if (a >= proc_sl_d)
		a -= proc_sl_d - proc_sl;
	    a -= proc_sl;

	    if (a >= nnodes)
		return 2;
	    ti.node[i] = nodes[a];
	}
    }

    /* Setup the first (parent) process */
    pid = bproc_rfork(ti.node[0]);
    if (pid < 0) {
	fprintf(stderr, "bproc_rfork(%d)=%d; errno=%d (%s)\n",
		ti.node[0], pid, errno, bproc_strerror(errno));
	return 3;
    }
    if (pid > 0) {
	if (waitpid(pid, &status, 0) != pid) {
	    fprintf(stderr, "Failed to wait on proc 0: %s\n", strerror(errno));
	    return 1;
	}
	if (!WIFEXITED(status)) {
	    printf(" abnormal exit");
	    return 1;
	} else if (WEXITSTATUS(status) != 0) {
	    printf(" exit_status=%d", WEXITSTATUS(status));
	    return 1;
	} else {
	    return 0;
	}
    }

    /* PROC 0: PARENT */
    ti.pid[0] = getpid();

    if (flags & bproc_test_no_auto_create)
	exit(test_func(0, &ti));	

    /* Create cihld processes */
    for (i=1; i < nprocs; i++) {
	a = proc_arr(arr,i);
	pipe(pfd);
	pid = fork();
	if (pid < 0) {
	    perror("fork");
	    exit(100);
	}
	if (pid == 0) {
	    close(pfd[0]);
	    if (pfd[1] != STDOUT_FILENO) {
		dup2(pfd[1], STDOUT_FILENO);
		close(pfd[1]);
	    }

	    /* We need the cruddy built-in I/O forwarding here because
	     * we use it to inform the parent about the PID *after*
	     * moving.  The side-effect of doing it this way is that
	     * we know that child process is on the node where it
	     * should be before going on. */
	    if (ti.node[i] != ti.node[0]) {
		if (bproc_move(ti.node[i]))
		    exit(101);
	    }

	    /* PROC i: CHILD */
	    if (proc_isdetach(a)) {
		/* Detach self from parent by forking again. */
		pid = fork();
		if (pid < 0)
		    exit(102);
		if (pid > 0)
		    exit(0);
		/* child continues and does stuff */
	    }
	    /* Tell parent about PID */
	    ti.pid[i] = getpid();
	    if (write(STDOUT_FILENO, &ti.pid[i], sizeof(ti.pid[i]))
		!= sizeof(ti.pid[i])) {
		exit(103);
	    }
	    close(STDOUT_FILENO);

	    /* Do the test */
	    exit(test_func(i, &ti));
	}
	/* PROC 0: PARENT */
	close(pfd[1]);
	r = read_all(pfd[0], &ti.pid[i], sizeof(ti.pid[i]));
	if (r != sizeof(ti.pid[i])) {
	    fprintf(stderr, "Failed to get PID from child %d\n", i);
	    exit(104);
	}
	close(pfd[0]);

	if (proc_isdetach(a)) {
	    int status;
	    /* Wait for intermediate process to exit */
	    if (waitpid(pid, &status, 0) != pid)
		exit(105);
	    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		exit(106);
	}
    }

    exit(test_func(0, &ti));
}

int __bproc_test_run(struct bproc_test_t *t, int nproc, int arr) {
    printf("    %-40s", arr_str(nproc, arr)); fflush(stdout);
    
    switch (test_run_arr(nproc, arr, t->flags, t->func)) {
    case 0:
	printf(" Ok\n");
	break;
    case 1:
	printf(" **** FAILED ****\n");
	return 1;
    case 2:
	printf(" (not enough nodes)\n");
	break;
    case 3:
	printf(" **** PROCESS CREATION ERROR.\n");
	return 1;
    default:
	printf(" internal error.\n");
	return 1;
    }
    return 0;
}


int _bproc_test_run(struct bproc_test_t *t, int nproc) {
    int arr, error;

    arr = enumerate(nproc, t->flags, -1);
    while (arr != -1) {
	error = __bproc_test_run(t, nproc, arr);
	if (error) return 1;
	arr = enumerate(nproc, t->flags, arr);
    }
    return 0;
}

int bproc_test_run(struct bproc_test_t *t) {
    int nproc, error;

    printf("Running test: %s\n", t->name);
    for (nproc  = t->np_min;
	 nproc <= t->np_max && nproc <= BPROC_TEST_NODES_MAX;
	 nproc++) {
	error = _bproc_test_run(t, nproc);
	if (error) return error;
    }
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
