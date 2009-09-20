#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/bproc.h>

int main(int argc, char *argv[]) {
  int r;
  printf("yippie!\n");

  if (fork() == 0)
    sleep(1000);
  bproc_move(0);
  wait(0);
  while(1) {
    r = bproc_move(0);
    printf("move 0: r=%d errno=%d\n", r, errno);
    r = bproc_move(-1);
    printf("move -1: r=%d errno=%d\n", r, errno);
  }
}
