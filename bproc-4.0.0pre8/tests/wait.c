/*
 * BProc wait() test program.
 *
 * Erik Hendriks <erik@hendriks.cx>

Cases to be checked:
1: Parent: local   wait on pid, pick up exit status
   Child : remote  exit

2: Parent: local   wait on pid, pick up stop status then exit.
   Child : remote  stop, continue and exit

3: Parent: remote  wait on pid, (check wait type) pick up exit status
   Child : remote  exit

4: Parent: remote  wait on -1, (check wait type) pick up exit status
   Child : remote  exit

5: Parent: remote  wait on pid, pick up stop status then exit.
   Child : remote  stop, continue and exit

*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include "../kernel/bproc.h"	/* for crazy debugging whack */
#include <sys/bproc.h>

int node = 0;
int verbose = 0;

/*#define DELAY 250000*/
#define DELAY 400000
/*#define DELAY 1000000*/

#define EXITSTATUS 123

#define PREMOTE    0x0001
#define C1REMOTE   0x0002
#define C2REMOTE   0x0004
#define C2PRESENT  0x0008
#define C1DETACH   0x0010
#define C2DETACH   0x0020

#define PDIFFSLAVE 0x0040	/* Not implemented yet... */
#define CDIFFSLAVE 0x0080

int arrangements[] = {
    /* Single child cases */
    0,				/* All local */
            C1REMOTE,
    PREMOTE,
    PREMOTE|C1REMOTE,
    PREMOTE|C1REMOTE|PDIFFSLAVE,

    /* Single child cases with detached parent. */
    0                          |C1DETACH,
            C1REMOTE           |C1DETACH,
    PREMOTE                    |C1DETACH,
    PREMOTE|C1REMOTE           |C1DETACH,
    PREMOTE|C1REMOTE|PDIFFSLAVE|C1DETACH,
    

    /* Two child cases */
    C2PRESENT,
    C2PRESENT|        C1REMOTE,
    C2PRESENT|                 C2REMOTE,
    C2PRESENT|        C1REMOTE|C2REMOTE,
    C2PRESENT|        C1REMOTE|C2REMOTE|CDIFFSLAVE,
    C2PRESENT|PREMOTE,
    C2PRESENT|PREMOTE|C1REMOTE,
    C2PRESENT|PREMOTE|C1REMOTE|         PDIFFSLAVE,
    C2PRESENT|PREMOTE|         C2REMOTE,
    C2PRESENT|PREMOTE|         C2REMOTE|PDIFFSLAVE,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|           CDIFFSLAVE,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|PDIFFSLAVE,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|PDIFFSLAVE|CDIFFSLAVE,

    /* Two child cases with detached parent */
    C2PRESENT|                                                C1DETACH|C2DETACH,
    C2PRESENT|        C1REMOTE|                               C1DETACH|C2DETACH,
    C2PRESENT|                 C2REMOTE|                      C1DETACH|C2DETACH,
    C2PRESENT|        C1REMOTE|C2REMOTE|                      C1DETACH|C2DETACH,
    C2PRESENT|        C1REMOTE|C2REMOTE|CDIFFSLAVE|           C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|                                        C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|                               C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|         PDIFFSLAVE|           C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|         C2REMOTE|                      C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|         C2REMOTE|PDIFFSLAVE|           C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|                      C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|           CDIFFSLAVE|C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|PDIFFSLAVE|           C1DETACH|C2DETACH,
    C2PRESENT|PREMOTE|C1REMOTE|C2REMOTE|PDIFFSLAVE|CDIFFSLAVE|C1DETACH|C2DETACH,

    -1
};

int x_fork(void) {
    int pid = fork();
    if (pid == -1) {
	perror("fork");
	exit(1);
    }
    return pid;
}

void x_bproc_move(int node) {
    if (bproc_move(node) != 0) {
	if (errno != ELOOP) {
	    perror("bproc_move");
	    exit(1);
	}
    }
}

struct arr_info {
    int arr;
    int node[3];
    int children[2];
    int attached[2];
};

int nlist[] = {-1,4,5,7};

void mk_procs(int arr, void (*func)(int, struct arr_info *)) {
    int i, pid, status, nn;
    int pfds[2];
    struct arr_info info;

    info.arr = arr;
    info.attached[0] = info.attached[1] = 0;
#if 1
    info.node[0] = (arr & C1REMOTE) ? 0 : -1;
    info.node[1] = (arr & C2REMOTE) ? 0 : -1;
    info.node[2] = (arr & PREMOTE)  ? 0 : -1;
    if (arr & PDIFFSLAVE) {
	if (arr & C1REMOTE) info.node[0]++;
	if (arr & C2REMOTE) info.node[1]++;
    }
    if (arr & CDIFFSLAVE) { info.node[1]++; }
#else
    info.node[0] = (arr & C1REMOTE) ? 1 : 0;
    info.node[1] = (arr & C2REMOTE) ? 1 : 0;
    info.node[2] = (arr & PREMOTE)  ? 1 : 0;
    if (arr & PDIFFSLAVE) {
	if (arr & C1REMOTE) info.node[0]++;
	if (arr & C2REMOTE) info.node[1]++;
    }
    if (arr & CDIFFSLAVE) { info.node[1]++; }
    {int i;
    for (i=0; i < 3; i++)
	info.node[i] = nlist[info.node[i]];
    }
#endif

    printf("p=%-2d  c=%-2d", info.node[2], info.node[0]);
    if (arr & C2PRESENT)
	printf("  c=%-2d", info.node[1]);
    else
	printf("      ");
    printf(": "); fflush(stdout);

    nn = bproc_numnodes();

    for (i=0; i < 3; i++) {
	char status[30];
	bproc_nodestatus(info.node[i], status, 30);
	if (strcmp(status, "up") || info.node[i] >= nn) {
	    printf(" ** not enough nodes *** "); fflush(stdout);
	}
	return;
    }

    pid = x_fork();
    if (pid == 0) {
	/* THIS IS THE "PARENT" PROCESS */
	/* Setup child 1 */
	pipe(pfds);
	info.children[0] = x_fork();
	if (info.children[0] == 0) {
	    if (arr & C1DETACH) {
		pid = x_fork();
		if (pid > 0) exit(0);
	    }
	    pid = getpid(); write(pfds[1], &pid, sizeof(int)); close(pfds[0]); close(pfds[1]); /* tell parent our pid */
	    if (arr & C1REMOTE) x_bproc_move(info.node[0]); /* w/ better IO we could do this first... */
	    usleep(DELAY);
	    func(0, &info);
	    exit(EXITSTATUS);
	} else {
	    if (arr & C1DETACH) waitpid(info.children[0],&status,0);
	    read(pfds[0], &info.children[0], sizeof(int)); close(pfds[0]); close(pfds[1]); /* get pid we're interested in */
	}

	if (arr & C2PRESENT) {
	/* Setup child 2 */
	pipe(pfds);
	info.children[1] = x_fork();
	if (info.children[1] == 0) {
	    if (arr & C2DETACH) {
		pid = x_fork();
		if (pid > 0) exit(0);
	    }
	    pid = getpid(); write(pfds[1], &pid, sizeof(int)); close(pfds[0]); close(pfds[1]); /* tell parent our pid */
	    if (arr & C2REMOTE) x_bproc_move(info.node[1]); /* w/ better IO we could do this first... */
	    usleep(DELAY);
	    func(1, &info);
	    exit(EXITSTATUS);
	} else {
	    if (arr & C2DETACH) waitpid(info.children[1],&status,0);
	    read(pfds[0], &info.children[1], sizeof(int)); close(pfds[0]); close(pfds[1]); /* get pid we're interested in */
	}
	} else
	    info.children[1] = 0;

	if (info.node[2] != -1) x_bproc_move(info.node[2]);
	usleep(DELAY);
	func(2, &info);
	exit(0);
    }
    pid = waitpid(pid, &status, 0);
    if (pid <= 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
	printf("Bad exit status from tester: 0x%x\n", status);
	exit(1);
    }
}

int child_count(void) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 0);
}
int nlchild_count(void) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 2);
}
int local_wait(int pid) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 1, pid);
}
void check_tree(void) {
    struct {
	long mppid, moppid;
	long rppid, roppid;
    } tmp;
    int err;
    if (syscall(__NR_bproc, BPROC_SYS_DEBUG, 3, &tmp)) {
	perror("bproc_sys_debug #3");
	return;
    }
    err = ((tmp.roppid != -1 && tmp.roppid != tmp.moppid)||(tmp.rppid != -1  && tmp.rppid  != tmp.mppid));
    if (verbose >= 2 || err) {
	printf("\nProcess ID state:\n");
	printf("  %-5d  masq   ptree\n", getpid());
	printf("  oppid  %-5ld  %-5ld%s\n", tmp.moppid, tmp.roppid,  (tmp.roppid!=-1 && tmp.roppid != tmp.moppid) ? "  ** MISMATCH **" : "");
	printf("   ppid  %-5ld  %-5ld%s\n", tmp.mppid,  tmp.rppid,   (tmp.rppid !=-1 && tmp.rppid  != tmp.mppid ) ? "  ** MISMATCH **" : "");
	if (err) sleep(600);
    }
}

#define WAIT_WANTEXIT 0x0001
#define WAIT_USEANY   0x0002

void wait_data_check(struct arr_info *info, int wpid) {
    int i, err;
    int ccount = 0, nlcount = 0, lwait = 1;
    int knlcount, kccount, klwait;

    if (info->node[2] != -1) {
	/* Check up on BProc's book keeping of our children... */
	for (i=0; i < 2; i++) {
	    if (info->children[i]) {
		if ((info->arr & (C1DETACH << i)) && !info->attached[i]) continue;
		ccount++;
		if (info->node[i] != info->node[2]) {
		    nlcount++;
		    if (info->children[i] == wpid || wpid == -1) lwait = 0;
		}
	    }
	}

	/* Ask the kernel for the same info */
	knlcount = nlchild_count();
	kccount  = child_count();
	klwait   = local_wait(wpid);
	err = kccount != ccount || knlcount != nlcount || klwait != lwait;
	if (verbose >= 2 || err) {
	    printf("\nProcess State:\n");
	    printf("                  kern  mine\n"); 
	    printf("  child_count   = %-4d  %d%s\n", kccount, ccount, kccount != ccount ? "  ** MISMATCH **":"");
	    printf("  nlchild_count = %-4d  %d%s\n", knlcount, nlcount, knlcount != nlcount ? "  ** MISMATCH **":"");
	    printf("  local_wait    = %-4d  %d%s\n", klwait, lwait, klwait != lwait ? "  ** MISMATCH **":"");
	    printf("  wpid=%d  mynode=%d", wpid, info->node[2]);
	    for (i=0; i < 2; i++) printf("  ch[%d]=%d(n%d)", i, info->children[i], info->node[i]);
	    printf("\n");
	    if (err) sleep(600);
	}
    }

    check_tree();
}


void wait_on_child1(struct arr_info *info, int num, int flags) {
    int pid, wpid, status;
    
    wpid = (num == -1 || flags & WAIT_USEANY) ? -1 : info->children[num];
    wait_data_check(info,wpid);
    if ((pid = waitpid(wpid, &status, WUNTRACED)) == -1) {
	perror("waitpid");
	exit(2);
    }
    if (num != -1 && pid != info->children[num]) {
	printf("Got wrong PID back.  expected %d; got %d\n", info->children[num], pid);
	exit(3);
    }
    if (flags & WAIT_WANTEXIT) {
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXITSTATUS) {
	    printf("Got wrong status: 0x%0x  (expecting exit w/ %d)\n", status, EXITSTATUS);
	    exit(4);
	}
    } else {
	if (!WIFSTOPPED(status)) {
	    printf("Got wrong status: 0x%0x  (expecting stop)\n", status);
	    exit(4);
	}
    }
    /* Clear out the PID entry */
    if (!WIFSTOPPED(status)) {
	if (pid == info->children[0])
	    info->children[0] = 0;
	else if (pid == info->children[1])
	    info->children[1] = 0;
	else
	    printf("Got unknown pid back from wait... (%d)\n", pid);
    }
}

void test1(int ch, struct arr_info *info) {
    switch (ch) {
    case 0: case 1:
	check_tree();
	exit(EXITSTATUS);
    default:
	wait_on_child1(info, 0, WAIT_WANTEXIT);
	if (info->children[1])
	    wait_on_child1(info, 1, WAIT_WANTEXIT);
    }
}

void test1_2(int ch, struct arr_info *info) {
    switch (ch) {
    case 0: case 1:
	check_tree();
	exit(EXITSTATUS);
    default:
	wait_on_child1(info, -1, WAIT_WANTEXIT|WAIT_USEANY);
	if (info->children[1])
	    wait_on_child1(info, -1, WAIT_WANTEXIT|WAIT_USEANY);
    }
}

void test2(int ch, struct arr_info *info) {
    switch (ch) {
    case 0: case 1:
	check_tree();
	kill(getpid(), SIGSTOP);
	check_tree();
	exit(EXITSTATUS);
    default:
	wait_on_child1(info, 0, 0);
	kill(info->children[0], SIGCONT);
	if (info->children[1]) {
	    wait_on_child1(info, 1, 0);
	    kill(info->children[1], SIGCONT);
	}
	wait_on_child1(info, 0, WAIT_WANTEXIT);
	if (info->children[1])
	    wait_on_child1(info, 1, WAIT_WANTEXIT);
    }
}

#include <sys/ptrace.h>
void test_ptrace(int ch, struct arr_info *info) {
    int i;
    long val;
    static volatile long magicflag = 0x32124312;

    switch(ch) {
    case 0: case 1:
	check_tree();
	while (magicflag) { usleep(100000); }
	check_tree();
	exit(EXITSTATUS);
    default:
	for (i=0; i < 2 && info->children[i]; i++) {
	    if (ptrace(PTRACE_ATTACH, info->children[i])) {
		perror("ptrace");
		exit(1);
	    }
	    printf(" A "); fflush(stdout);
	    info->attached[i] = 1;

	    wait_on_child1(info, i, 0); /* wait for the stop */
	    printf(" S "); fflush(stdout);

	    if ((val = ptrace(PTRACE_PEEKDATA, info->children[i], &magicflag)) != magicflag) {
		fprintf(stderr, "PE: expected 0x%lx; got 0x%lx\n", magicflag, val);
	    }
	    printf(" PE "); fflush(stdout);
	    
	    if (ptrace(PTRACE_POKEDATA, info->children[i], &magicflag, 0)) {
		perror("ptrace(pokedata)");
	    }
	    printf(" PO "); fflush(stdout);

	    wait_data_check(info, -1);
	    if (ptrace(PTRACE_DETACH, info->children[i], 0, 0)) {
		perror("ptrace(detach)");
	    }
	    printf(" D "); fflush(stdout);
	    info->attached[i] = 0;

	    if (!(info->arr & (C1DETACH << i))) {
		wait_on_child1(info, i, WAIT_WANTEXIT);
		printf(" W ");
	    }
	}
    }
}

void test_ptrace_2(int ch, struct arr_info *info) {
    int i;
    long val;
    static volatile long magicflag = 0x32124312;

    switch(ch) {
    case 0: case 1:
	check_tree();
	while (magicflag) { usleep(100000); }
	check_tree();
	
	bproc_move(0);

	check_tree();
	kill(getpid(), SIGSTOP);
	while (!magicflag) { usleep(100000); }
	check_tree();
	exit(EXITSTATUS);
    default:
	for (i=0; i < 2 && info->children[i]; i++) {
	    if (ptrace(PTRACE_ATTACH, info->children[i])) {
		perror("ptrace");
		exit(1);
	    }
	    printf(" A "); fflush(stdout);
	    info->attached[i] = 1;

	    wait_on_child1(info, i, 0); /* wait for the stop */
	    printf(" S "); fflush(stdout);
	    if ((val=ptrace(PTRACE_PEEKDATA, info->children[i], &magicflag)) != magicflag) {
		fprintf(stderr, "PE: expected 0x%lx; got 0x%lx\n", magicflag, val);
	    }
	    printf(" PE "); fflush(stdout);
	    
	    if (ptrace(PTRACE_POKEDATA, info->children[i], &magicflag, 0)) {
		perror("ptrace(pokedata)");
	    }
	    printf(" PO "); fflush(stdout);

	    if (ptrace(PTRACE_CONT, info->children[i], 0, 0)) {
		perror("ptrace(cont)");
	    }
	    printf(" C "); fflush(stdout);

	    wait_data_check(info, -1);
	    wait_on_child1(info, i, 0);
	    printf(" S "); fflush(stdout);

	    if (ptrace(PTRACE_POKEDATA, info->children[i], &magicflag, 1)) {
		perror("ptrace(pokedata)");
	    }
	    printf(" PO "); fflush(stdout);

	    wait_data_check(info, -1);
	    if (ptrace(PTRACE_DETACH, info->children[i], 0, 0)) {
		perror("ptrace(detach)");
	    }
	    printf(" D "); fflush(stdout);
	    info->attached[i] = 0;

	    if (!(info->arr & (C1DETACH << i))) {
		wait_on_child1(info, i, WAIT_WANTEXIT);
		printf(" W ");
	    }
	}
    }
}

void test_getppid(int ch, struct arr_info *info) {
    int i;
    switch (ch) {
    case 0: case 1:
	for (i=0; i < 30; i++) {
	    if (getppid() == 1)
		exit(EXITSTATUS);
	    usleep(100000);
	}
	fprintf(stderr, "getppid didn't change in 3 seconds: arr=0x%x\n", info->arr);
	exit(EXITSTATUS);
    default:
	exit(0);		/* parent goes away */
    }

}

void test_setpgid(int ch, struct arr_info *info) {
    int i, pid;
    switch(ch) {
    case 0: case 1:
	pid = getpid();
	for (i=0; i < 30; i++) {
	    if (getpgid(0) == pid)
		exit(EXITSTATUS);
	    usleep(100000);
	}
	fprintf(stderr, "getpgid didn't change in 3 seconds: arr=0x%x\n", info->arr);
	exit(EXITSTATUS);
    default:
	for (i=0; i < 2 && info->children[i]; i++) {
	    setpgid(info->children[i], 0);
	    wait_on_child1(info, i, WAIT_WANTEXIT);
	}
	exit(0);
    }
}

struct {
    char *name;
    int  casemask;		/* Avoid these cases */
    void (*func)(int, struct arr_info *);
} testlist[] = 

{{"ptrace", 0, test_ptrace},
/* {"ptrace 2", 0, test_ptrace_2}, busted */
 {"getppid",       C1DETACH|C2DETACH, test_getppid},
 {"setpgid",       C1DETACH|C2DETACH, test_setpgid},
 {"fork / wait 1", C1DETACH|C2DETACH, test1},
 {"fork / wait 2", C1DETACH|C2DETACH, test1_2},
 {"fork / stop / wait", C1DETACH|C2DETACH, test2},
 {0, 0, 0}};

int main(int argc, char *argv[]) {
    int i,t,c;
    int arr = -1;
    while ((c=getopt(argc,argv,"va:"))!=EOF) {
	switch(c) {
	case 'v': verbose++; break;
	case 'a': arr = strtol(optarg,0,0); break; 
	default: exit(1);
	}
    }
    
    for (t = 0; testlist[t].name; t++) {
	printf("Test %2d %-30s:\n", t, testlist[t].name);
	if (arr == -1) {
	    for (i=0; arrangements[i] != -1; i++) {
		if (arrangements[i] & testlist[t].casemask) continue;
		printf("\t%02x: ", arrangements[i]);
		mk_procs(arrangements[i], testlist[t].func);
		printf(" ok\n");
	    }
	} else {
	    if (arr & testlist[t].casemask) continue;
	    printf("\t%02x: ", arr);
	    mk_procs(arr, testlist[t].func);
	    printf(" ok\n");
	}

    }
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
