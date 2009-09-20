#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/bproc.h>

#define SIGWAIT 500000

enum proc_loc {proc_fe=0, proc_sl, proc_inv };

char *proc_names[] = {"FrontEnd", "Slave", "Invalid"};

int nnodes;
int nodes[2];

int fill_node_list(int *list, int *num, int wanted) {
    int i;
    struct bproc_node_info_t *info;
    /* Find two valid nodes */
    nnodes = bproc_nodelist(&info);

    *num = 0;
    for (i=0; i < nnodes && (*num) < wanted; i++) {
	if (info[i].status == bproc_node_up) {
	    printf("using node %d\n", info[i].node);
	    list[*num] = info[i].node;
	    (*num)++;
	}
    }
    free(info);
    return (*num == wanted);
}

volatile int sigchld_flag;
void child_handler(int foo) {
    sigchld_flag++;
}

int main(int argc, char *argv[]) {
    int nnodes, pid;
    int n1, n2;
    enum proc_loc p, c;

    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);

    nodes[0] = -99;
    nodes[1] = -99;

    fill_node_list(nodes, &nnodes, 2);
    if (nnodes < 2) {
	printf("Only got %d slaves - not doing all tests.\n", nnodes);
    }
    signal(SIGCHLD, child_handler);
    for (p = proc_fe; p < proc_inv; p++) {
	for (c = proc_fe; c <= proc_inv; c++) {
	    printf("parent=%-10s child=%-10s : ",proc_names[p], proc_names[c]);
	    /* Setup parent */
	    switch (p) {
	    case proc_fe: n1 = BPROC_NODE_MASTER; break;
	    case proc_sl: n1 = nodes[0];          break;
	    default:      printf("Huh?\n");       exit(1);
	    }
	    switch (c) {
	    case proc_fe:  n2 = BPROC_NODE_MASTER; break;
	    case proc_sl:
		n2 = (n1 == BPROC_NODE_MASTER) ? nodes[0] : nodes[1];
		break;
	    case proc_inv: n2 = -100; break;
	    default:       printf("What?\n");     exit(1);
	    }
	    if (n1 == -99 || n2 == -99) {
		printf("not enough nodes");
		goto next;
	    }

	    if (bproc_currnode() != n1 && bproc_move(n1) != 0) {
		printf("\nbproc_move(%d): %s\n", n1, strerror(errno));
		exit(1);
	    }

	    sigchld_flag = 0;
	    if (n2 != -100) {
		/* Expect a valid move */
		pid = bproc_rfork(n2);
		if (pid < 0) {
		    printf("rfork failed: %s", strerror(errno));
		    goto next;
		}
		if (pid == 0) exit(0);
		if (waitpid(pid, 0, 0) != pid) {
		    printf("wait failed: %s", strerror(errno));
		    goto next;
		}
		if (sigchld_flag != 1) {
		    printf("wrong number of SIGCHLDs - expecting %d; got %d",
			   1, sigchld_flag);
		    goto next;
		}
		printf("Ok.");
	    } else {
		/* Expect an error and no SIGCHLD */
		pid = bproc_rfork(n2);
		if (pid == 0) {
		    printf("bproc_rfork returned zero for an invalid"
			   " node number.\n");
		    exit(1);
		}
		if (pid > 0) {
		    printf("bproc_rfork returned > zero for an"
			   "invalid node number.\n");
		    goto next;
		}
		usleep(SIGWAIT);
		if (sigchld_flag) {
		    printf("Got an unexpected SIGCHLD on a failed "
			   "bproc_rfork.\n");
		    goto next;
		}
		printf("Ok.");
	    }
	next:
	    printf("\n");
	}
    }
    usleep(SIGWAIT);		/* allow IO to flush. */
    exit(0);
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
