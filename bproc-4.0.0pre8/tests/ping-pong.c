#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/bproc.h>


enum states {
    local,
    remote,
    pingpong
};

int main (int argc, char *argv[]) {
    int c;
    int pid;
    int parent = local;
    int child = pingpong;

    int node = 0;

    while ((c = getopt(argc, argv, "lrpLRP")) != EOF) {
	switch (c) {
	case 'l': parent = local; break;
	case 'r': parent = remote; break;
	case 'p': parent = pingpong; break;

	case 'L': child = local; break;
	case 'R': child = remote; break;
	case 'P': child = pingpong; break;

	default: exit(1);
	}
    }

    pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(1);
    }

    if (pid == 0) {
	switch (child) {
	case remote:
	    bproc_move(node);
	    /* fall thru */
	case local:
	    while (1) pause();
	case pingpong:
	    while (1) {
		if (bproc_move(node)) { perror("bproc_move"); exit(1); }
		if (bproc_move(-1)) { perror("bproc_move"); exit(1); }
	    }
	}
    }

    switch (parent) {
    case remote:
	bproc_move(node);
    case local:
	while (1) {
	    /* check presence of child */
	    if (waitpid(pid, 0, WNOHANG)) {
		perror("waitpid");
		kill(pid, SIGKILL);
		exit(1);
	    }
	}
    case pingpong:
	while (1) {
	    if (bproc_move(node)) { perror("bproc_move"); exit(1); }
	    /* check presence of child */
	    if (waitpid(pid, 0, WNOHANG)) {
		perror("waitpid");
		kill(pid, SIGKILL);
		exit(1);
	    }
	    if (bproc_move(-1)) { perror("bproc_move"); exit(1); }
	    /* check presence of child */
	    if (waitpid(pid, 0, WNOHANG)) {
		perror("waitpid");
		kill(pid, SIGKILL);
		exit(1);
	    }
	}
    }
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
