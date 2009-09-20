#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/bproc.h>


int main (int argc, char *argv[]) {
  int i, pid;
  /*bproc_move(0);*/
  
  for (i=0; i <3 ; i++) {
    pid = fork();
    if (pid) break;
  }
  switch(i) {
  case 3 : sleep(100); break;
  case 1:
    while (1) {
      bproc_move(0);
      sleep(1);
      bproc_move(-1);
      sleep(1);
    }
    
  default:
    sleep(i);
    bproc_move(0);
    waitpid(pid,0,0);
    break;
  }
  
  exit(0);
}
