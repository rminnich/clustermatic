#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/bproc.h>
#include "libtest.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

char *test_description =
"test-ping-pong:\n"
"  A process ping-pongs back and forth between a slave node and the front end.\n";

/*#define BULKSIZE (50*1024*1024)*/
#define BULKSIZE 0
int test_main(void) {
    int node;
    static void *ptr=0;

    printf("PID=%d\n", getpid());
    /*sleep(5);*/

    if (BULKSIZE > 0 && !ptr) {
	ptr = malloc(BULKSIZE);
	memset(ptr, 1, BULKSIZE);
    }

    node = get_node();

    if (bproc_move(node) == -1) return 2;

    dumpfds();		/* Shake off my stupid IO forwarding */
    sayhi();

    {
	int fd;
	fd = open("/dev/console", O_WRONLY);
	write(fd, ".", 1);
	close(fd);
    }

    if (bproc_move(-1) == -1) return 2;

    dumpfds();		/* Shake off my stupid IO forwarding */
    sayhi();


    if (0) {
	int fd;
	fd = open("/dev/tty", O_WRONLY);
	write(fd, ".", 1);
	close(fd);
    }

    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
