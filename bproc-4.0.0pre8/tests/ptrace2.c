#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <syscall.h>
int main(int argc, char *argv[]) {
    int pid,r,status;
    pid = strtol(argv[1],0,0);
    printf("pid = %d\n", pid);

    r = ptrace(PTRACE_ATTACH, pid, 0, 0);
    printf("attach returned %d  errno = %d\n", r, errno);

    waitpid(pid, &status, 0);

    r = ptrace(PTRACE_PEEKTEXT, pid, 0x11ffff9b0, 0);
    printf("peek returned %d  errno = %d\n", r, errno);

    errno=0;			/* clear out errno */
    r = ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
    printf("detach returned %d  errno = %d\n", r, errno);

    exit(0);
}
