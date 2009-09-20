#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/bproc.h>

int main(int argc, char *argv[]) {
    int pid;
    int rfork=0;
    int c;
	
    while ((c=getopt(argc, argv, "r"))!=EOF) {
	switch(c) {
	case 'r': rfork=1; break;
	default: exit(1);
	}
    }

    printf("%d: My SID: %d\n", getpid(), getsid(0));
    setsid();
    printf("%d: My SID: %d\n", getpid(), getsid(0));

    if (rfork)
      pid = bproc_rfork(0);
    else
      pid = fork();
    if (pid < 0) {
	perror("fork");
	exit(1);
    }
    
    if (pid == 0) {
	printf("%d: My SID: %d  Parent SID: %d\n", getpid(), getsid(0), getsid(getppid()));
	sleep(1);
	setsid();
	printf("%d: My SID: %d  Parent SID: %d\n", getpid(), getsid(0), getsid(getppid()));
	exit(0);
    }
    printf("%d: My SID: %d  Child SID: %d\n", getpid(), getsid(0), getsid(pid));
    sleep(2);
    printf("%d: My SID: %d  Child SID: %d\n", getpid(), getsid(0), getsid(pid));
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
