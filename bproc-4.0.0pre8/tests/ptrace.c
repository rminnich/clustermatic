#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/bproc.h>


int pid;
void bailout(char *msg) {
    perror(msg);
    kill(pid, SIGKILL);
    exit(1);
}

void ptrace_tracer(int pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
	bailout("ptrace(PTRACE_ATTACH)");
}



void ptrace_tracee(void) {
    while(1) {
	printf("Inside tracee.\n");
	pause();
    }
}


int start_tracee(int rem) {
    int pid;
    int fd[2];
    
    pipe(fd);

    /* Fork twice to make sure that the process we're making isn't our
     * child. */
    pid = fork();
    if (pid == -1) { perror("fork"); exit(1); }
    if (pid == 0) {
	pid = fork();
	if (pid == -1) { perror("fork"); exit(1); }
	if (pid == 0) {
	    pid = getpid();
	    write(fd[1], &pid, sizeof(pid));
	    close(fd[0]);
	    close(fd[1]);
	    
	    ptrace_tracee();
	}
	exit(0);
    }
    wait(0);
    read(fd[0], &pid, sizeof(pid));

    close(fd[0]);
    close(fd[1]);
    return pid;
}

int main (int argc, char *argv[]) {
    pid = start_tracee();
    printf("Tracee pid = %d\n", pid);

    ptrace_tracer(pid);



    kill(pid, SIGKILL);
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
