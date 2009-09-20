#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/bproc.h>
#include "libtest.h"

char *test_description =
"test-fork-move:\n"
"  A process running on the front end forks and the child moves to a slave node.\n"
"  Once there, the child exits and the parent picks up wait status.\n";

int test_main(void) {
    int pid, node;
    int waiterr, status;

    node = get_node();

    pid = fork();
    if (pid == -1) return 1;
    if (pid == 0) {
	if (bproc_move(node) == -1)
	    return 2;
 	exit(123);
    }

    waiterr = waitpid(pid, &status, 0);
    if (waiterr == -1) {
	if (errno == ECHILD) return 50;
	return 5;
    }
    if (waiterr == 0) return 51;
    if (waiterr != pid) return 52;
    if (!WIFEXITED(status)) return 53;
    if (WEXITSTATUS(status) != 123) return 54;
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
