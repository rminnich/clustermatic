#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/bproc.h>
#include "libtest.h"

char *test_description =
"test-rfork:\n"
"  A process running on the front end rforks.  The child exits and\n"
"  the parent picks up the exit status.\n"
"\n"
"  Tests rfork and wait on ghost.\n";

int test_main(void) {
    int pid, node;
    int waiterr, status;

    node = get_node();

    pid = bproc_rfork(node);
    if (pid == -1) return 1;
    if (pid == 0)
 	exit(123);

    waiterr = waitpid(pid, &status, 0);
    if (waiterr == -1) {
	if (errno == ECHILD) {
	    printf("pid=%d\n", pid);
	    return 50;
	}
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
