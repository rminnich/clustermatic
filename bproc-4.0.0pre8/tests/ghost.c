/*------------------------------------------------
 * ghost.c
 *
 * Simple test.  Become a ghost.
 *----------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <linux/bproc.h>

extern char **environ;
char *g_argv[] = { "/bin/ls", "-l", "/", 0 };

int main(int argc, char *argv[]) {
    int fd, r;
    struct bproc_request_t req;
    
    fd = open("/dev/bproc_ghost", O_WRONLY);
    if (fd == -1) {
	perror("/dev/bproc_ghost");
	exit(1);
    }
    req.req = BPROC_JOIN;
    req.join_node = 0;
    req.data.join.cmd = "/bin/ls";
    req.data.join.argv = g_argv;
    req.data.join.envp = environ;
    r = write(fd, &req, sizeof(req));
    if (r != sizeof(req)) perror("write");
    printf("I wasn't expecting that to return.\n");
    exit(1);
}



