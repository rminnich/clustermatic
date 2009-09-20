#include <stdio.h>
#include <unistd.h>
#include <sys/bproc.h>


int main(int argc, char *argv[]) {
    int x, r;
    int node = 0;

    setlinebuf(stdout);
    r = bproc_move(node);
    printf("BProc move returned: %d\n", r);

 again:
    x = 1;
    while (x) {
	x = x + 1;
	printf("Hi %d (pid = %d; x at %p\n", x, getpid(), &x);
	sleep(1);
    }

    node++;
    r = bproc_move(node);
    printf("BProc move returned: %d\n", r);
    goto again;
}
