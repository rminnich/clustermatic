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

    printf("%d parent pgrp = %d\n", getpid(), getpgrp());

    if (rfork)
      pid = bproc_rfork(0);
    else
      pid = fork();
    if (pid < 0) {
	perror("fork");
	exit(1);
    }
    
    if (pid == 0) {
	printf("%d: My PGRP: %d  Parent PGRP: %d\n", getpid(), getpgid(0), getpgid(getppid()));
	sleep(1);
	setsid();
	printf("%d: My PGRP: %d  Parent PGRP: %d\n", getpid(), getpgid(0), getpgid(getppid()));
	exit(0);
    }
    printf("%d: My PGRP: %d  Child PGRP: %d\n", getpid(), getpgid(0), getpgid(pid));
    sleep(2);
    printf("%d: My PGRP: %d  Child PGRP: %d\n", getpid(), getpgid(0), getpgid(pid));
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
