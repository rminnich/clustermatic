#include <sys/wait.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>

#include <sys/bproc.h>

extern char **environ;
int main(int argc, char *argv[]) {
    char *args[] = {"/tmp/uptime1", 0};
    bproc_rexec(0, args[0], args, environ);
    perror("bproc_rexec");
    exit(0);
}
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
