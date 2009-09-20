#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>

#include "bproc_test.h"

static
void wait_pass_exit(int status) {
    if (WIFEXITED(status))
	exit(WEXITSTATUS(status));
}

/*--------------------------------------------------------------------
 * setpgid1
 */
static char desc_setpgid1[] =
"    A process tries to set its own process ID and check that it has\n"
"    changed.  The parent will also check that it has changed after the\n"
"    process exits.\n"
"  Tests:\n"
"    setpgid on self\n"
"    getpgid on self\n"
"    getpgid on other\n"
"    getpgrp\n";
static
int test_setpgid1(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	int status, pgid;
	/* PARENT PROCESS */

	/* Wait for child to stop itself */
	if (waitpid(info->pid[1], &status, WUNTRACED) != info->pid[1])
	    exit(4);

	if (!WIFSTOPPED(status)) {
	    wait_pass_exit(status);
	    exit(5);
	}

	pgid = getpgid(info->pid[1]);
	if (pgid != info->pid[1]) {
	    printf(" %d != %d", pgid, info->pid[1]);
	    exit(6);
	}

	/* Ok, shoot it in the head and finish. */
	kill(info->pid[1], SIGKILL);
	if (waitpid(info->pid[1], &status, 0) != info->pid[1])
	    exit(7);
	return 0;
    }
    if (idx == 1) {
	/* CHILD PROCESS */
	if (setpgid(0,0) != 0)		/* setpgrp case */
	    exit(1);

	if (getpgid(0) != getpid())
	    exit(2);

	if (getpgrp() != getpid())
	    exit(3);

	kill(getpid(), SIGSTOP);
    }
    return 99;			/* should never get here... */
}

/*--------------------------------------------------------------------
 * setsid1
 */
static char desc_setsid1[] =
"    \n";


static
int test_setsid1(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	int status, sid;
	/* Wait for child to stop itself */
	if (waitpid(info->pid[1], &status, WUNTRACED) != info->pid[1])
	    exit(3);

	if (!WIFSTOPPED(status)) {
	    wait_pass_exit(status);
	    exit(4);
	}

	sid = getsid(info->pid[1]);
	if (sid != info->pid[1]) {
	    printf(" %d != %d", sid, info->pid[1]);
	    exit(5);
	}

	/* Ok, shoot it in the head and finish. */
	kill(info->pid[1], SIGKILL);
	if (waitpid(info->pid[1], &status, 0) != info->pid[1])
	    exit(6);
	return 0;
    }
    if (idx == 1) {
	if (setsid() < 0)
	    exit(1);

	if (getsid(0) != getpid())
	    exit(2);

	kill(getpid(), SIGSTOP);
    }
    return 99;
}




struct bproc_test_t testlist[] = {
    BPROC_TEST(setpgid1, 2, 2, 0),
    BPROC_TEST(setsid1, 2, 2, 0),
    {0}
};


/* Everything below this line is the same as ptree... */
#define MAXTESTS 100
void Usage(char *arg0) {
    struct bproc_test_t *t;
    printf("Usage: %s [--help] [--all] [--arr arrangement] [--<testname>]\n",
	   arg0);
    for (t = testlist; t->name; t++)
	printf("%s:\n%s\n", t->name, t->desc);
}


#include <getopt.h>
int main(int argc, char *argv[]) {
    struct bproc_test_t *t;
    int error;
    int c, i, arr=-1;
    struct option long_opts[MAXTESTS];

    setlinebuf(stdout);

    /* Setup a bunch of options to run particular tests */
    for (i=0; testlist[i].name; i++) {
	t = &testlist[i];

	long_opts[i].name    = t->name;
	long_opts[i].has_arg = 0;
	long_opts[i].flag    = &t->runflag;
	long_opts[i].val     = 1;

	t->runflag = 0;
    }
    long_opts[i].name    = "all";
    long_opts[i].has_arg = 0;
    long_opts[i].flag    = 0;
    long_opts[i].val     = 'a';
    i++;
    long_opts[i].name    = "arr";
    long_opts[i].has_arg = 1;
    long_opts[i].flag    = 0;
    long_opts[i].val     = 'r';
    i++;
    long_opts[i].name    = "help";
    long_opts[i].has_arg = 0;
    long_opts[i].flag    = 0;
    long_opts[i].val     = 'h';
    i++;
    long_opts[i].name    = 0;

    while ((c=getopt_long(argc, argv, "har:", long_opts, 0)) != EOF) {
	switch (c) {
	case 0:
	    break;
	case 'a':
	    for (t=testlist; t->name; t++)
		t->runflag = 1;
	    break;
	case 'r':
	    arr = strtol(optarg, 0, 8);
	    break;
	case 'h':
	    Usage(argv[0]);
	    exit(0);
	default:
	    exit(1);
	}
    }

    bproc_test_init(0);

#warning "No way to try a particular arrangement anymore."    
    for (t = testlist; t->name; t++) {
	if (t->runflag) {
	    error = bproc_test_run(t);
	    if (error) exit(error);
	}
    }
    exit(0);
    return 0;
}
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
