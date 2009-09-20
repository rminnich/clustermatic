#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/bproc.h>

int main(int argc, char *argv[]) {
    int pid;
    int stat;
    setlinebuf(stdout);

    if (fork() == 0) {
      sleep(20);
    }
    bproc_move(0);
  
    while(1) {
	printf("iter.\n");
	pid = fork();
	if (pid == 0) {
	    exit(1);
	}

	printf("wait=%d\n", wait4(-1, &stat, 0, 0));
	sleep(1);
    }
}
