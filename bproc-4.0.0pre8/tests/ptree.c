/*--------------------------------------------------------------------
 *
 * BProc process book keeping test program.
 *
 *  Copyright (C) 2002 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ptree.c,v 1.13 2004/10/27 15:49:37 mkdist Exp $
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <getopt.h>
#include "../kernel/bproc.h"

#include <sys/bproc.h>

#include "bproc_test.h"


#ifndef CLONE_PARENT
#define CLONE_PARENT    0x00008000 
#endif

#define DELAY 250000


/*--------------------------------------------------------------------
 *  Functions to call BProc process tree debug hooks
 *------------------------------------------------------------------*/
int child_count(void) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 0);
}
int nlchild_count(void) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 2);
}
int local_wait(int pid) {
    return syscall(__NR_bproc, BPROC_SYS_DEBUG, 1, pid);
}

/*--------------------------------------------------------------------
 *  Test functions
 *------------------------------------------------------------------*/


/*-------------------------------------------------------------------------
 * wait process book keeping tests
 *-----------------------------------------------------------------------*/

#define WAIT_WANTEXIT   0x0001
#define WAIT_EXITZERO   0x0002
#define WAIT_EXITSTATUS 123	/* magic status for these tests */


static
void check_tree(void) {
    struct {
	int32_t mppid, moppid;
	int32_t rppid, roppid;
    } tmp;
    int err;
    if (syscall(__NR_bproc, BPROC_SYS_DEBUG, 3, &tmp)) {
	perror("bproc_sys_debug #3");
	return;
    }
    err = ((tmp.roppid != -1 && tmp.roppid != tmp.moppid) ||
	   (tmp.rppid != -1  && tmp.rppid  != tmp.mppid));
    if (err) {
	printf("\nProcess ID state:\n");
	printf("  %-5d  masq   ptree\n", getpid());
	printf("  oppid  %-5d  %-5d%s\n", tmp.moppid, tmp.roppid,
	       (tmp.roppid!=-1 && tmp.roppid != tmp.moppid) ?
	       "  ** MISMATCH **" : "");
	printf("   ppid  %-5d  %-5d%s\n", tmp.mppid,  tmp.rppid,
	       (tmp.rppid !=-1 && tmp.rppid  != tmp.mppid ) ?
	       "  ** MISMATCH **" : "");
	if (err) sleep(600);
    }
}

/* This function checks if our view of the world matches with the
 * kernel before doing a wait() call. */
#define MAX_RETRY   1000000
#define RETRY_DELAY 10000
static
void wait_data_check(struct bproc_test_info_t *info, int wpid) {
    int i, err, a; 
    int ccount, nlcount, lwait;
    int knlcount, kccount, klwait;
    int retry=0;

    a = proc_arr(info->arr,0);
    
    /* If parent is not on front end, do a bunch of process tree checking */
    if (a != proc_fe) {
    try_again:
	ccount = 0;
	nlcount = 0;
	lwait = 1;
	/* Check up on BProc's book keeping of our children... */
	for (i=1; i < info->nprocs; i++) {
	    if (info->pid[i]) {
		a = proc_arr(info->arr,i);
		if (proc_isdetach(a) && !(info->scratch & (1<<i)))
		    continue;
		ccount++;
		if (!proc_samenode(a,proc_arr(info->arr,0))) {
		    nlcount++;
		    if (info->pid[i] == wpid || wpid == -1) lwait = 0;
		}
	    }
	}

	/* Ask the kernel for the same info */
	knlcount = nlchild_count();
	kccount  = child_count();
	klwait   = local_wait(wpid);
	err = kccount != ccount || knlcount != nlcount || klwait != lwait;
	if (err) {
	    /* It is possible that we'll end up looking at these
	     * values a bit too soon - before something has finished
	     * moving or before a masq process has finished cleaning
	     * itself up.  In that case, our child_count should still
	     * be correct but the others may be off.  If that's the
	     * case, retry a few times.  Really, the debug stuff
	     * should be fixed to atomically return all of that. */
	    if (kccount == ccount && retry < MAX_RETRY/RETRY_DELAY ) {
		usleep(RETRY_DELAY);
		retry ++;
		goto try_again;
	    }

	    printf("\nProcess State:\n");
	    printf("                  kern  mine\n"); 
	    printf("  child_count   = %-4d  %d%s\n", kccount, ccount,
		   kccount != ccount ? "  ** MISMATCH **":"");
	    printf("  nlchild_count = %-4d  %d%s\n", knlcount, nlcount,
		   knlcount != nlcount ? "  ** MISMATCH **":"");
	    printf("  local_wait    = %-4d  %d%s\n", klwait, lwait,
		   klwait != lwait ? "  ** MISMATCH **":"");
	    printf("  wpid=%d  mynode=%s",
		   wpid, proc_str(proc_arr(info->arr,0)));
	    for (i=1; i < info->nprocs; i++)
		printf("  ch[%d]=%d(%s)", i,
		       info->pid[i], proc_str(proc_arr(info->arr,i)));
	    printf("\n");
	    if (err) sleep(10000);
	}
    }

    check_tree();
}

/* This function is basically a wait() wrapper with tons of sanity
 * checking. */
static
void wait_on_child1(struct bproc_test_info_t *info, int num, int flags) {
    int pid, wpid, status, i;

    wpid = (num == -1) ? -1 : info->pid[num];
    wait_data_check(info, wpid);
    if ((pid = waitpid(wpid, &status, WUNTRACED)) == -1) {
	perror("waitpid");
	exit(52);
    }
    if (num != -1 && pid != info->pid[num]) {
	printf("Got wrong PID back.  expected %d; got %d\n",
	       info->pid[num], pid);
	exit(53);
    }
    if (flags & WAIT_WANTEXIT) {
	if (!WIFEXITED(status) || 
	    ((flags &WAIT_EXITZERO) && WEXITSTATUS(status)!=0) ||
	    (!(flags&WAIT_EXITZERO) && WEXITSTATUS(status)!=WAIT_EXITSTATUS)){
	    printf("Got wrong status: 0x%0x  (expecting exit w/ %d)\n",
		   status, WAIT_EXITSTATUS);
	    exit(54);
	}
    } else {
	if (!WIFSTOPPED(status)) {
	    printf("Got wrong status: 0x%0x  (expecting stop)\n", status);
	    exit(55);
	}
    }
    /* Clear out the PID entry */
    if (!WIFSTOPPED(status)) {
	for (i=1; i < info->nprocs; i++) {
	    if (info->pid[i] == pid) {
		info->pid[i] = 0;
		break;
	    }
	}
	if (i == info->nprocs) {
	    printf("Got unknown pid back from wait... (%d)\n", pid);
	    exit(56);
	}
    }
}

/* test_wait_1
 *
 * Description:
 *   
 */
char desc_wait1[] =
"    Wait for all children using waitpid() on a specific process ID.\n";
int test_wait1(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	/* Parent process */
	int i;
	for (i=1; i < info->nprocs; i++)
	    wait_on_child1(info, i, WAIT_WANTEXIT);
	return 0;
    } else {
	/* One of the children */
	check_tree();
	exit(WAIT_EXITSTATUS);
    }
}

/* test_wait_2
 *
 * Description:
 *   Wait for all children using waitpid() for any process.
 */
char desc_wait2[] =
"    Wait for all children using waitpid() for any process.\n";
int test_wait2(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	/* Parent process */
	int i;
	for (i=1; i < info->nprocs; i++)
	    wait_on_child1(info, -1, WAIT_WANTEXIT);
	return 0;
    } else {
	/* One of the children */
	check_tree();
	exit(WAIT_EXITSTATUS);
    }
}

/* test_wait_3
 *
 * Description:
 *   Child will stop once and then exit.  The parent waits looking for
 *   a stopped status.  Once that is received, a SIGCONT is sent and
 *   the parent waits again looking for a normal exit.
 */
char desc_wait3[] =
"    Child will stop once and then exit.  The parent waits looking for\n"
"    a stopped status.  Once that is received, a SIGCONT is sent and\n"
"    the parent waits again looking for a normal exit.\n";
int test_wait3(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	/* Parent process */
	int i;
	/* look for stops */
	for (i=1; i < info->nprocs; i++) {
	    wait_on_child1(info, i, 0);
	    printf(" W");
	    kill(info->pid[i], SIGCONT);
	    printf(" K");
	}
	/* look for exits */
	for (i=1; i < info->nprocs; i++) {
	    wait_on_child1(info, i, WAIT_WANTEXIT);
	    printf(" W");
	}
	return 0;
    } else {
	check_tree();
	kill(getpid(), SIGSTOP); /* stop self */
	check_tree();
	exit(WAIT_EXITSTATUS);
    }
}

/*-------------------------------------------------------------------------
 * parent process ID tests
 *-----------------------------------------------------------------------*/
/* test_getppid_1
 *
 * Description:
 *    The parent exits and the child waits for its parent process ID
 *    to change.
 */
char desc_getppid1[] =
"    The parent exits and the child waits for its parent process ID\n"
"    to change.\n";
int test_getppid1(int idx, struct bproc_test_info_t *info) {
    if (idx == 0) {
	exit(0);
    } else {
	int i;
	for (i=0; i < 30; i++) {
	    if (getppid() == 1)
		exit(WAIT_EXITSTATUS);
	    usleep(100000);
	}

	fprintf(stderr,
		"getppid didn't change: pid=%d ppid=%d\n",
		getpid(), getppid());
	exit(1);
    }
}

/*-------------------------------------------------------------------------
 * clone() tests
 *-----------------------------------------------------------------------*/
static
int cfunc(void *foo) {
    usleep(DELAY);
    exit(0);
}

char desc_rfork1[] =
"    Process 0 is the parent.  It creates the children one by one using\n"
"    bproc_rfork().\n";
static
int test_rfork1(int idx, struct bproc_test_info_t *inf) {
    int err, i;
#if 0
    int cc, ncc, lw;		/* ACTUAL values */
    int c_cc, c_ncc, c_lw;	/* CORRECT values */
#endif

    printf(" ppid=%d(%d)", getpid(), bproc_currnode()); fflush(stdout);
    for (i=1; i < inf->nprocs; i++) {
	inf->pid[i] = bproc_rfork(inf->node[i]);
	if (inf->pid[i] < 0) {
	    fprintf(stderr, "bproc_rfork(%d): %s\n", inf->pid[i],
		    bproc_strerror(errno));
	    exit(1);
	}
	if (inf->pid[i] == 0) {
	    /* CHILD */
	    exit(0);
	}
	printf(" pid=%d", inf->pid[i]); fflush(stdout);
    }

#if 0
    /* This sanity check is broken */

    /* Sanity check our process tree */
    cc  = child_count();
    ncc = nlchild_count();
    lw  = local_wait(0);
    
    c_cc  = 2;
    c_ncc = (inf->pid[0] == inf->pid[1] || inf->pid[0] == -1) ? 0 : 2;
    c_lw  = (inf->pid[0] == inf->pid[1] || inf->pid[0] == -1) ? 1 : 0;
    

    if ((cc != c_cc) || (ncc != c_ncc) || (lw != c_lw)) {
	printf("\nProcess State:\n");
	printf("                  kern  mine\n"); 
	printf("  child_count   = %-4d  %d%s\n", cc, c_cc,
	       cc != c_cc ? "  ** MISMATCH **":"");
	printf("  nlchild_count = %-4d  %d%s\n", ncc, c_ncc,
	       ncc != c_ncc ? "  ** MISMATCH **":"");
	printf("  local_wait    = %-4d  %d%s\n", lw, c_lw,
	       lw != c_lw ? "  ** MISMATCH **":"");
	for (i=1; i < inf->nprocs; i++)
	    printf("  ch[%d]=%d(%s)", i,
		   inf->pid[i], proc_str(proc_arr(inf->arr,i)));
	printf("\n");
    }
#endif
    err = 0;
    for (i=1; i < inf->nprocs; i++) {
	if (wait(0) < 0) {
	    printf("wait: %s", strerror(errno));
	    err = 1;
	}
    }
    exit(err);
}


/* test_clone_1:
 *  num procs = 2
 *  description:
 *   Process 0 is the parent.  It creates a single child.  The child
 *   then creates another child for process 0 using clone() with
 *   CLONE_PARENT.  The parent then attempts to wait on both children.
 */
char desc_clone1[] =
"    Process 0 is the parent.  It creates a single child.  The child\n"
"    then creates another child for process 0 using clone() with\n"
"    CLONE_PARENT.  The parent then attempts to wait on both children.\n";
int test_clone1(int idx, struct bproc_test_info_t *inf) {
    int pid;
    int err = 0, i;
    int cc, ncc, lw;		/* ACTUAL values */
    int c_cc, c_ncc, c_lw;	/* CORRECT values */
    
    pid = bproc_rfork(inf->node[1]);
    if (pid < 0) {
	perror("bproc_rfork");
	exit(1);
    }
    if (pid == 0) {
	void *stack;
	/* Child #1 */
	stack = malloc(8192);
	pid = clone(cfunc, stack+4096, CLONE_PARENT|SIGCHLD, 0);
	if (pid < 0) {
	    fprintf(stderr, "clone: %s", bproc_strerror(errno));
	    exit(1);
	}
	usleep(DELAY);
	exit(0);
    }
    usleep(DELAY);

    /* Sanity check our process tree */
    cc  = child_count();
    ncc = nlchild_count();
    lw  = local_wait(0);
    
    c_cc  = 2;
    c_ncc = (inf->node[0] == inf->node[1] || inf->node[0] == -1) ? 0 : 2;
    c_lw  = (inf->node[0] == inf->node[1] || inf->node[0] == -1) ? 1 : 0;
    
    /* Print status */
    printf("%d%c %d%c %c%c ",
	   cc,  cc == c_cc ? ' ':'!',
	   ncc, ncc== c_ncc? ' ':'!',
	   lw ? 'L':'R', lw == c_lw ? ' ':'!');
    fflush(stdout);
    
    /* Parent */
    /* Two waits */
    for (i=0; i < 2; i++) {
	if (wait(0) < 0) {
	    printf("wait: %s", strerror(errno));
	    err = 1;
	}
    }
    
    if (err) exit(err);
    
    err = (cc != c_cc) || (ncc != c_ncc) || (lw != c_lw);
    if (err) {
	printf("mypid=%d", getpid()); fflush(stdout);
	sleep(1000);
    }
    exit(err);
}


/*-------------------------------------------------------------------------
 * ptrace tests
 *-----------------------------------------------------------------------*/
/* test_ptrace1
 *
 * */
char desc_ptrace1[] =
"    The parent attaches to the child, the child may be attached or\n"
"    detached.  The parent looks for the magic value with a peek.\n"
"    The parent then changes it with a poke.  The child is basically\n"
"    spinning looking at that value.  Once it is changed externally,\n"
"    the child exits.  If the child is attached, exit status is\n"
"    retrieved after the detach.\n";
#include <sys/ptrace.h>
int test_ptrace1(int idx, struct bproc_test_info_t *info) {
    int i;
    long val;
    static volatile long magicflag = 0x32124312;

    if (idx == 0) {
	setvbuf(stdout, 0, _IONBF, 0); /* fflush every time is ugly */

	/* Parent process */
	for (i=1; i < info->nprocs; i++) {
	    if (ptrace(PTRACE_ATTACH, info->pid[i])) {
		perror("ptrace");
		exit(1);
	    }
	    printf(" A");
	    info->scratch |= (1 << i);

	    wait_on_child1(info, i, 0); /* wait for the stop */
	    printf(" S");

	    val = ptrace(PTRACE_PEEKDATA, info->pid[i], &magicflag);
	    if (val != magicflag) {
		fprintf(stderr, "PE: expected 0x%lx; got 0x%lx\n",
			magicflag, val);
	    }
	    printf(" PE");
	    
	    if (ptrace(PTRACE_POKEDATA, info->pid[i], &magicflag, 0)) {
		perror("ptrace(pokedata)");
	    }
	    printf(" PO");

	    wait_data_check(info, -1);
	    if (ptrace(PTRACE_DETACH, info->pid[i], 0, 0)) {
		perror("ptrace(detach)");
	    }
	    printf(" D");
	    info->scratch &= ~(1 << i);

	    if (proc_isattach(proc_arr(info->arr,i))) {
		wait_on_child1(info, i, WAIT_WANTEXIT);
		printf(" W");
	    }
	}
	return 0;
    } else {
	/* child process */
	check_tree();
	while (magicflag) { usleep(100000); }
	check_tree();
	exit(WAIT_EXITSTATUS);
    }
}

/* test_ptrace2
 *
 * */
char desc_ptrace2[] =
"    The parent forks a child process.  The child calls PTRACE_TRACEME\n"
"    and the parent waits to see a stopped process.\n";
int test_ptrace2(int idx, struct bproc_test_info_t *info) {
    int i;
    if (idx == 0) {
	/* Parent process */
	setvbuf(stdout, 0, _IONBF, 0); /* fflush every time is ugly */

	for (i=1; i < info->nprocs; i++) {
	    info->scratch |= (1 << i);	/* Due to traceme below... ?? */

	    wait_on_child1(info, i, 0);
	    printf(" S");

	    if (ptrace(PTRACE_DETACH, info->pid[i], 0, 0)) {
		perror("ptrace(detach)");
	    }
	    printf(" D");
	    info->scratch &= ~(1 << i);

	    wait_on_child1(info, i, WAIT_WANTEXIT);
	    printf(" W");
	}
	return 0;
    } else {
	if (ptrace(PTRACE_TRACEME)) {
	    perror("ptrace");
	    exit(1);
	}
	check_tree();
	kill(getpid(), SIGSTOP); /* stop self, like with exec */
	check_tree();
	exit(WAIT_EXITSTATUS);	/* wake up and exit */
    }
}

/* test_ptrace3
 *
 * */
char desc_ptrace3[] =
"    The parent forks a child process.  The child calls PTRACE_TRACEME\n"
"    and then execves a binary.  The parent waits to see a stopped process.\n"
"  NOTE: This REQUIRES the binary /tmp/pt3 to be presend on all nodes.\n";
int test_ptrace3(int idx, struct bproc_test_info_t *info) {
    int i;
    if (idx == 0) {
	/* Parent process */
	setvbuf(stdout, 0, _IONBF, 0); /* fflush every time is ugly */

	for (i=1; i < info->nprocs; i++) {
	    info->scratch |= (1 << i);	/* Due to traceme below... ?? */

	    wait_on_child1(info, i, 0);
	    printf(" S");

	    if (ptrace(PTRACE_DETACH, info->pid[i], 0, 0)) {
		perror("ptrace(detach)");
	    }
	    printf(" D");
	    info->scratch &= ~(1 << i);

	    wait_on_child1(info, i, WAIT_WANTEXIT|WAIT_EXITZERO);
	    printf(" W");
	}
	return 0;
    } else {
	if (ptrace(PTRACE_TRACEME)) {
	    perror("ptrace");
	    exit(1);
	}
	check_tree();
	execl("/tmp/pt3", "/tmp/pt3", 0);
	perror("/tmp/pt3");
	exit(1);	/* wake up and exit */
    }
}

/* test_ptrace4
 *
 * */
char desc_ptrace4[] =
"    The parent forks a child process.  The child calls PTRACE_TRACEME.\n"
"    and the parent waits to see a stopped process and exits without.\n"
"    explicitly doing a detach.  The child then waits to see if it can\n"
"    perform PTRACE_TRACEME again.\n";
int test_ptrace4(int idx, struct bproc_test_info_t *info) {
    int i;
    if (idx == 0) {
	/* Parent process */
	setvbuf(stdout, 0, _IONBF, 0); /* fflush every time is ugly */

	for (i=1; i < info->nprocs; i++) {
	    info->scratch |= (1 << i);	/* Due to traceme below... ?? */

	    wait_on_child1(info, i, 0);
	    printf(" S");

	    ptrace(PTRACE_CONT, info->pid[i], 0, 0);
	    printf(" C");
	}
	return 0;
    } else {
	/* Child process */
	if (ptrace(PTRACE_TRACEME)) {
	    perror("ptrace");
	    exit(1);
	}
	kill(getpid(), SIGSTOP);

	for (i=0; i < 5000000/RETRY_DELAY; i++) {
	    if (ptrace(PTRACE_TRACEME) == 0)
		exit(WAIT_EXITSTATUS);
	    usleep(RETRY_DELAY);
	}
	fprintf(stderr,
		"Couldn't redo TRACEME after 5 seconds.  pid=%d ppid=%d\n", 
		getpid(), getppid());
	exit(1);
    }
}

/* test_ptrace5
 *
 * */
static
char desc_ptrace5[] =
"    The parent forks a child process.  The parent attempts to read a\n"
"    sequential chunk of memory from the child.  This is intented to test\n"
"    ptrace peek read-ahead.\n";
#define PT5_NRAND  64
static
void pt5_check_long(int pid, unsigned long addr, long val) {
    long data;

    /* Do an aligned PEEK */
    errno = 0;
    data = ptrace(PTRACE_PEEKTEXT, pid, addr);
    if (errno)
	exit(2);
    if (data != val) {
	printf(" addr %lx: got %ld; expected %ld\n", addr, data, val);
	exit(3);
    }
}

static
int test_ptrace5(int idx, struct bproc_test_info_t *info) {
    int i, j, k;
    int page_size;
    static volatile long memaddr;
    static volatile long crap;

    page_size = getpagesize();
    
    if (idx == 0) {
	/* Parent process */
	setvbuf(stdout, 0, _IONBF, 0); /* fflush every time is ugly */

	for (i=1; i < info->nprocs; i++) {
	    info->scratch |= (1 << i);	/* Due to traceme below... ?? */

	    wait_on_child1(info, i, 0);
	    printf(" S");

	    errno = 0;
	    memaddr = ptrace(PTRACE_PEEKTEXT, info->pid[i], &memaddr);
	    if (errno)
		exit(1);

	    /* Sequential */
	    for (j=0; j < page_size / sizeof(long); j++)
		pt5_check_long(info->pid[i], memaddr+j*sizeof(long), j);
	    printf(" SQ");

	    /* Sequential with flush */
	    for (j=0; j < page_size / sizeof(long); j++) {
		pt5_check_long(info->pid[i], memaddr+j*sizeof(long), j);
		/* Flush */
		ptrace(PTRACE_POKETEXT, info->pid[i], &crap, 0);
	    }
	    printf(" SQF");

	    /* Backwards */
	    for (j = page_size / sizeof(long) - 1; j >=0; j--) {
		pt5_check_long(info->pid[i], memaddr+j*sizeof(long), j);
	    }
	    printf(" SQB");

	    /* Random */
	    srand(0);		/* "random" but reproducable. */
	    for (j=0; j < PT5_NRAND; j++) {
		k = rand() % (page_size / sizeof(long));
		pt5_check_long(info->pid[i], memaddr+k*sizeof(long), k);
	    }
	    printf(" SR");

	    /* All done */
	    ptrace(PTRACE_CONT, info->pid[i], 0, 0);
	}
	return 0;
    } else {
	/* Child process */

	/* Get a hunk of memory that's likely to have edges. */

	memaddr = (long) mmap(0, page_size * 3, PROT_READ|PROT_WRITE,
			      MAP_ANONYMOUS|MAP_SHARED, -1, 0);
	if (memaddr == (long) MAP_FAILED)
	    exit(10);

	memset((void*) memaddr, 0xff, page_size * 3);

	/* Put a landmine before and after */
	if (munmap((void *) memaddr, page_size))
	    exit(11);
	if (munmap((void *) (memaddr + page_size*2), page_size))
	    exit(12);

	memaddr += page_size;

	/* setup our region of memory */
	for (i=0; i < page_size / sizeof(long); i++)
	    ((long *)memaddr)[i] = i;

	/* ... and prepare to be probed. */
	if (ptrace(PTRACE_TRACEME)) {
	    perror("ptrace");
	    exit(13);
	}
	kill(getpid(), SIGSTOP);

	exit(WAIT_EXITSTATUS);
    }
}


/*-------------------------------------------------------------------------
 * test driver
 *-----------------------------------------------------------------------*/
#define T(x) #x, desc_ ## x, test_ ## x
struct bproc_test_t testlist[] = {
    BPROC_TEST(wait1,  2, 3, 0),
    BPROC_TEST(wait2,  2, 3, 0),
    BPROC_TEST(wait3,  2, 3, 0),

    {T(rfork1),   2, 2, bproc_test_no_auto_create},
    {T(clone1),   2, 2, bproc_test_no_auto_create},
    {T(getppid1), 2, 3, 0 },
    {T(ptrace1),  2, 3, bproc_test_detach},
    {T(ptrace2),  2, 3, 0},
    {T(ptrace3),  2, 3, 0},
    {T(ptrace4),  2, 3, 0},
    {T(ptrace5),  2, 3, 0},
    {0}
};

#define MAXTESTS 100

void Usage(char *arg0) {
    struct bproc_test_t *t;
    printf("Usage: %s [--help] [--all] [--arr arrangement] [--<testname>]\n",
	   arg0);
    for (t = testlist; t->name; t++)
	printf("%s:\n%s\n", t->name, t->desc);
}

int main(int argc, char *argv[]) {
    struct bproc_test_t *t;
    int error;
    int c, i, arr=-1, nproc = 0;
    struct option long_opts[MAXTESTS];

    setvbuf(stdout, 0, _IONBF, 0);
    /*setlinebuf(stdout);*/
    /*fill_node_list(nodes, &nnodes, 3);*/

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
	    nproc = strlen(optarg);
	    arr   = strtol(optarg, 0, 8);
	    break;
	case 'h':
	    Usage(argv[0]);
	    exit(0);
	default:
	    exit(1);
	}
    }

    bproc_test_init(0);

    for (t = testlist; t->name; t++) {
	if (t->runflag) {
	    if (arr != -1) {
		/* Run a particular arrangement */
		/* sanity check nproc... */
		error = __bproc_test_run(t, nproc, arr);
	    } else {
		/* Run all arrangements */
		error = bproc_test_run(t);
	    }
	    if (error) exit(error);
	}
    }
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
