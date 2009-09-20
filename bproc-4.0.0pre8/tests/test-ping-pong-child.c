#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/bproc.h>
#include "libtest.h"

char *test_description =
"test-ping-pong-child:\n"
"  A process ping-pongs back and forth between a slave node and the front end.\n"
"  The process has a child process on the front end and checks for its existence\n"
"  every time it reaches a node.\n";

static int childpid =0;
int test_main(void) {
    int node;

    node = get_node();

    /* If first time through, setup a child process */
    if (childpid == 0) {
	childpid = fork();
	if (childpid == 0) {
	    /*bproc_move(node);*/
	    while (1) pause();
	}
	sleep(1);
    }

    if (bproc_move(node) == -1) return 1;
    if (waitpid(-1, 0, WNOHANG) != 0) return 2;

    dumpfds();		/* Shake off my stupid IO forwarding */
    sayhi();

    if (bproc_move(-1) == -1) return 3;
    if (waitpid(-1, 0, WNOHANG) != 0) return 4;

    dumpfds();		/* Shake off my stupid IO forwarding */
    sayhi();
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
