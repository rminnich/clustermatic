#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#define DELAY 30

volatile int next;
void alrm(void) {
    next = 1;
}

int main(int argc, char *argv[]) {
    time_t start, now;

    signal(SIGALRM, (void(*)(int))alrm);
    while (1) {
	printf("spinning for %d seconds\n", DELAY); fflush(0);
	next = 0;
	alarm(DELAY);
	while(next == 0);
	printf("syscalling for %d seconds\n",DELAY); fflush(0);
	start = time(0);
	while (time(0) < start+DELAY);
	printf("sleeping for %d seconds\n",DELAY); fflush(0);
	sleep(DELAY);
    }
}
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
