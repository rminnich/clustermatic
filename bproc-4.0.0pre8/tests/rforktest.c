#include <sys/wait.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>

#include <sys/bproc.h>

void Usage(char *arg0) {
    fprintf(stderr, "usage: %s node\n", arg0);
    exit(1);
}

void fork_fail_test(void) {
    int pid;
    int indent;
    /* Fork until fork fails... then bail out. */
    printf("%5d\n", getpid());
    pid = bproc_rfork(0);
    if (pid < 0) {
	fprintf(stderr,"initial rfork failed: %d\n", errno);
	exit(1);
    }
    if (pid == 0) {
	indent = 0;
	printf("%*s%5d %5d\n",indent,"",getppid(), getpid()); fflush(0);
	pid = fork();
	while (pid == 0) {
	    indent += 6;
	    if (indent > 60) indent = 0;
	    printf("%*s%5d %5d\n",indent,"",getppid(), getpid()); fflush(0);
	    sleep(1);
	    pid = fork();
	}
	/*printf("PARENT(%d): child=%d\n", getpid(), pid);*/
	if (pid > 0)
	    wait(0);
	else {
	    printf("Got fork error: %d\n", errno);
	    sleep(20);
	}
	exit(0);
    } else
	wait(0);
}


int main(int argc, char *argv[]) {
    fork_fail_test();
    exit(0);
}
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
