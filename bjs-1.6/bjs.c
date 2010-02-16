/*------------------------------------------------------------ -*- C -*-
 * BJS:  a simple scheduler for BProc based environments.
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * bjs.c: the core scheduler
 *
 * Copyright(C) 2002 University of California.
 *
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * Additionally, this program is free software; you can distribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software foundation; either version 2 of
 * the License, or any later version.  Accordingly, this program is
 * distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANY; without even the implied warranty of MARCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more detail.
 *
 *  $Id: bjs.c,v 1.34 2004/11/03 17:49:02 mkdist Exp $
 *--------------------------------------------------------------------*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <time.h>
#include <dirent.h>
#define  NDEBUG
#include <assert.h>

#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <pwd.h>
#include <grp.h>

#include <bproc.h>
#include <cmconf.h>

#include <sexp.h>

#include <bjs.h>

#define BSIZE 4096
#define DEFAULT_CONFIG_FILE CONFIGDIR "/bjs.conf"

extern char **environ;

/* as long as we're debugging... */
/*#define syslog(x,y ...) do { printf(y); putc('\n', stdout); } while(0)*/

/*--------------------------------------------------------------------
 * Data structures which are internal to BJS
 *------------------------------------------------------------------*/
struct bjs_conf_t {
	char *spooldir;
	char *policypath;
	char *socketpath;
	FILE *acctlog;
	int client_sockfd;
	int npools;
	struct bjs_pool_t *pools;
};

struct node_alloc_t {
	struct bjs_job_t *job;
	int node;		/* Index of node in bjs_nodes */
	struct list_head nodes_list;	/* job's list of nodes */
	struct list_head jobs_list;	/* node's list of jobs */
};

enum client_state { CL_READ,
	CL_WAIT_NODES,
	CL_WAIT_UPDATE,
	CL_FLUSH
};

/* Persistent job sexp structure */
#define PJ_POOL    0
#define PJ_SUBTIME 1
#define PJ_UID     2
#define PJ_GID     3
#define PJ_SHELL   4
#define PJ_CMD     5
#define PJ_DIR     6
#define PJ_UMASK   7
#define PJ_ENV     8
#define PJ_REQS    9

struct client_t {
	struct list_head list;
	int fd;
	int euid;
	int egid;

	/* User I/O stuff */
	enum client_state state;
	time_t time;		/* time stamp used for timesouts */
	struct sexp_parser_state_t *parser;

	/* Buffer for output to the client */
	int bsize, bptr;	/* size and current offset in output buffer */
	char *buf;

	struct bjs_job_t *job;	/* interactive job for this client */
};

/* Global vars for use by the scheduler only */
static int nclients = 0;
static LIST_HEAD(clients);
static struct bjs_conf_t conf = { 0, 0, 0, 0, -1, 0, 0 };

static struct bjs_conf_t tc;
static int bproc_notify_fd;
static char *config_file = DEFAULT_CONFIG_FILE;
static long job_id = 0;		/* sequence number for job IDs */

/* Global vars also for use by the policy modules */
int verbose = 0;

/* last time we updated -- we do it at least every 15 seconds. */
time_t lastupdate = 0;

/* Internal list of nodes which includes  */
int bjs_nnodes = 0;
int bjs_nids = 0;
struct bjs_node_t *bjs_nodes = 0;
struct bjs_node_t **bjs_node_idx = 0;

LIST_HEAD(bjs_jobs);

static void bjs_job_free(struct bjs_job_t *j);
static void client_send_sx(struct client_t *c, struct sexp_t *sx);
static int persistent_job_add(struct bjs_job_t *j);
static int persistent_job_remove(struct bjs_job_t *j);
static int persistent_job_load(void);

static int do_status_update = 0;
/*--------------------------------------------------------------------
 * Misc utility crud
 *------------------------------------------------------------------*/
/* Override malloc in the C library so that all our malloc()s -
 * including those in libraries we link against - will be "safe". */
extern void *__libc_malloc(size_t);
void *malloc(size_t size)
{
	void *p;
	p = __libc_malloc(size);
	if (!p) {
		syslog(LOG_ERR, "Out of memory allocating %ld bytes.",
		       (long)size);
		abort();
	}
	return p;
}

#define malloc_chk malloc

extern void *__libc_realloc(void *, size_t);
void *realloc(void *p, size_t size)
{
	p = __libc_realloc(p, size);
	if (!p) {
		syslog(LOG_ERR, "Out of memory allocating %ld bytes.",
		       (long)size);
		abort();
	}
	return p;
}

#define realloc_chk realloc

char *strdup_chk(const char *str)
{
	char *s;
	s = strdup(str);
	if (!str) {
		syslog(LOG_ERR, "Out of memory allocating %ld bytes.",
		       (long)strlen(str) + 1);
		abort();
	}
	return s;
}

#if 0
/* XXX This one is strictly debugging */
void __libc_free(void *);
void free(void *p)
{
	printf("free(%p)\n", p);
	__libc_free(p);
}
#endif

static
void set_non_block(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

/*--------------------------------------------------------------------
 *
 *------------------------------------------------------------------*/
int bjs_job_flag(struct bjs_job_t *j, const char *key)
{
	struct sexp_t *sx;
	sx = sexp_find_list(j->reqs, key, NULL);
	if (!sx || sx->list->next)
		return 0;
	return 1;
}

const char *bjs_job_req(struct bjs_job_t *j, const char *key, const char *dfl)
{
	struct sexp_t *sx;
	sx = sexp_find_list(j->reqs, key, NULL);
	if (!sx || !sx->list->next || !sexp_is_value(sx->list->next))
		return dfl;
	return sx->list->next->val;
}

/* this function checks generic policy-independent requirements like
 * job dependencies */
int bjs_job_runnable(struct bjs_job_t *j)
{
	/* Check that there are enough available nodes to ever run this thing */
	{
		int i, upcount;
		int nodes, n;

		upcount = 0;
		for (i = 0; i < j->pool->nnodes; i++) {
			n = j->pool->nodes[i];
			if (n < bjs_nids && bjs_node_idx[n]->up)
				upcount++;
		}

		/* Check if there are enough "up" nodes in this pool to ever
		 * run this job.  This requirement string got sanity checked
		 * at submit time. */
		nodes = strtol(bjs_job_req(j, "nodes", "1"), 0, 0);
		if (nodes > upcount)
			return 0;
	}

	/* Check for job dependencies */
	{
		int id;
		struct sexp_t *sx;
		char *check;
		struct list_head *l;
		struct bjs_job_t *j2;

		sx = sexp_find_list(j->reqs, "job", NULL);
		if (sx) {
			for (sx = sx->next; sx; sx = sx->next) {
				id = strtol(sx->val, &check, 0);
				if (*check == 0) {
					/* Look for this job ID in the system */
					for (l = bjs_jobs.next; l != &bjs_jobs;
					     l = l->next) {
						j2 = list_entry(j,
								struct
								bjs_job_t,
								list);
						if (j2->job_id == id)
							return 0;
					}
				}
			}
		}
	}
	return 1;
}

/*--------------------------------------------------------------------
 *  Node allocation routines
 *------------------------------------------------------------------*/
void bjs_node_allocate(struct bjs_job_t *j, int node, int exclusive)
{
	struct node_alloc_t *n;
	struct bjs_node_t *bjsnode;

	if (node < 0 || node >= bjs_nids || !bjs_node_idx[node]) {
		syslog(LOG_ERR, "bjs_node_allocate: Invalide node number: %d",
		       node);
		return;
	}

	bjsnode = bjs_node_idx[node];

	if (!bjsnode->up) {
		syslog(LOG_ERR, "bjs_node_allocate: Allocating down node: %d",
		       node);
		return;
	}

	n = malloc_chk(sizeof(*n));
	n->node = node;
	n->job = j;
	list_add_tail(&n->jobs_list, &bjsnode->jobs);
	list_add_tail(&n->nodes_list, &j->nodes);

	if (exclusive) {
		bproc_chown(node, j->uid);
		bproc_chgrp(node, j->gid);
		bproc_chmod(node, 0100);
	} else {
		/* non-exclusive: just open it up... */
		bproc_chown(node, 0);
		bproc_chgrp(node, 0);
		bproc_chmod(node, 0111);
	}
}

/*--------------------------------------------------------------------
 *  Node deallocation routines
 *------------------------------------------------------------------*/

static struct bproc_node_set_t clean_set = BPROC_EMPTY_NODESET;
void bjs_do_clean(void)
{
	/* the way we will be cleaning a node is rebooting it, in future */
#if 0
	int i, j, nprocs, killed_one;
	struct bproc_proc_info_t *plist;

	/* XXX It would be much better if we had the option of killing
	 * only the processes related to the job.  We're going to end up
	 * killing off mon, etc. here.  */
	do {
		nprocs = bproc_proclist(BPROC_NODE_ANY, &plist);

		killed_one = 0;
		for (i = 0; i < clean_set.size; i++) {
			for (j = 0; j < nprocs; j++) {
				if (clean_set.node[i].node == plist[j].node) {
#if 0
					struct stat statbuf;
					char procname[50];
					/* Hack to not try to kill root-owned */
					sprintf(procname, "/proc/%d",
						plist[j].pid);
					if (stat(procname, &statbuf) == 0) {
						if (statbuf.st_uid != 0) {
							kill(plist[j].pid,
							     SIGKILL);
							killed_one = 1;
						}
					}
#else
					kill(plist[j].pid, SIGKILL);
					killed_one = 1;
#endif
				}
			}
		}

		if (nprocs > 0)
			free(plist);
	} while (killed_one);
#endif

	bproc_nodeset_free(&clean_set);
}

void bjs_clean_node(int node)
{
	struct bproc_node_info_t n;
	bproc_chown(node, 0);
	bproc_chgrp(node, 0);
	bproc_chmod(node, 0100);

	n.node = node;
	if (bproc_nodeset_add(&clean_set, &n)) {
		syslog(LOG_ERR, "Out of memory.");
		exit(1);
	}
}

static
void bjs_node_deallocate(struct node_alloc_t *n)
{
	list_del(&n->jobs_list);
	list_del(&n->nodes_list);

	if (list_empty(&bjs_node_idx[n->node]->jobs))
		bjs_clean_node(n->node);
	free(n);
}

/* This one kills all the jobs running on a particular node and then
 * cleans the node. */
void bjs_kill_node(int node)
{
	struct list_head *l, *next;
	struct bjs_node_t *n;

	n = bjs_get_node(node);
	if (!n)
		return;

	for (l = n->jobs.next; l != &n->jobs; l = next) {
		struct node_alloc_t *n =
		    list_entry(l, struct node_alloc_t, jobs_list);
		next = l->next;

		bjs_job_remove(n->job);
	}
}

int bjs_node_idle(int node)
{
	struct bjs_node_t *n;
	n = bjs_get_node(node);
	return n && n->up && list_empty(&n->jobs);
}

int bjs_node_up(int node)
{
	struct bjs_node_t *n;
	n = bjs_get_node(node);
	return n && n->up;
}

int bjs_node_usable(int node, long pri)
{
	struct list_head *l;
	struct bjs_node_t *n;

	n = bjs_get_node(node);
	if (!n)
		return 0;

	/* See if there are any unkillable jobs on this node */
	for (l = n->jobs.next; l != &n->jobs; l = l->next) {
		struct node_alloc_t *na =
		    list_entry(l, struct node_alloc_t, jobs_list);
		if (na->job->priority >= pri)
			return 0;
	}
	return 1;
}

/*--------------------------------------------------------------------
 *  Job startup routines
 *------------------------------------------------------------------*/
static
void bjs_job_environment(struct bjs_job_t *j)
{
	int ct, len = 0;
	char *tmp;
	struct list_head *l;
	environ = j->envp;
	ct = 0;
	for (l = j->nodes.next; l != &j->nodes; l = l->next)
		ct++;

	printf("NODE COUNT=%d\n", ct);
	tmp = alloca(10 * ct);

	for (l = j->nodes.next; l != &j->nodes; l = l->next) {
		struct node_alloc_t *n;
		n = list_entry(l, struct node_alloc_t, nodes_list);
		len += sprintf(tmp + len, "%d,", bjs_node_idx[n->node]->node);
	}
	tmp[len - 1] = 0;
	printf("NODES=\"%s\"\n", tmp);
	fflush(0);
	setenv("NODES", tmp, 1);

	sprintf(tmp, "%d", j->job_id);
	setenv("JOBID", tmp, 1);
}

static
int set_job_ids(struct bjs_job_t *j)
{
	struct passwd *pwd;
	struct group *grp;
	int ngroups = 0, i;
	gid_t groups[NGROUPS_MAX];

	/* Try and find all the supplementary groups for this uid */
	pwd = getpwuid(j->uid);
	if (pwd) {
		groups[ngroups++] = pwd->pw_gid;
		/* Find all the supplementary groups that go with this login */
		setgrent();
		grp = getgrent();
		while (grp && ngroups < NGROUPS_MAX) {
			for (i = 0; grp->gr_mem[i] && ngroups < NGROUPS_MAX;
			     i++) {
				if (strcmp(grp->gr_mem[i], pwd->pw_name) == 0)
					groups[ngroups++] = grp->gr_gid;
			}
			grp = getgrent();
		}
		endgrent();
	}

	if (setgroups(ngroups, groups)) {
		syslog(LOG_ERR, "setgroups: %s", strerror(errno));
		return -1;
	}

	if (setregid(j->gid, j->gid)) {
		syslog(LOG_ERR, "setregid(%d, %d): %s",
		       j->gid, j->gid, strerror(errno));
		return -1;
	}

	if (setreuid(j->uid, j->uid)) {
		syslog(LOG_ERR, "setreuid(%d, %d): %s",
		       j->uid, j->uid, strerror(errno));
		return -1;
	}
	return 0;
}

static
int set_job_io(struct bjs_job_t *j)
{
	int fd;
	const char *outfile;

	/* note, we're presuming that there's already something on fds 0,1,2 */
	fd = open("/dev/null", O_RDONLY);
	dup2(fd, STDIN_FILENO);
	close(fd);

	outfile = bjs_job_req(j, "output", "/dev/null");
	printf("outfile=%s\n", outfile);
	if (outfile[0] == '|') {
		/* This is a little hack to allow pipes as output commands */
		FILE *f;
		if (!(f = popen(outfile + 1, "w"))) {
			syslog(LOG_INFO,
			       "Failed to run user pipe command: %s\n",
			       outfile);
			return -1;
		}
		fd = fileno(f);
	} else {
		fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (fd == -1) {
			syslog(LOG_INFO,
			       "Failed to open user output file: %s\n",
			       outfile);
			return -1;
		}

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
	return 0;
}

static
int start_job_batch(struct bjs_job_t *j)
{
	int pid;

	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		struct list_head *l;
		sigset_t sset;

		/* Restore signal handling defaults */
		signal(SIGCHLD, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGPIPE, SIG_IGN);

		sigfillset(&sset);
		sigprocmask(SIG_UNBLOCK, &sset, 0);

		/* Close file descriptors for clients */
		for (l = clients.next; l != &clients; l = l->next) {
			struct client_t *c;
			c = list_entry(l, struct client_t, list);
			close(c->fd);
		}
		close(conf.client_sockfd);
		close(bproc_notify_fd);
		if (conf.acctlog)
			fclose(conf.acctlog);
		setsid();
		if (set_job_ids(j))
			exit(1);

		/* I'm a little torn on what order to do things in here....
		 * The output file is the only mechanism we have to report
		 * errors.  It can't be created till after the chdir since it
		 * should affect the open to create the output file.  However,
		 * the chdir is one of the calls most likely to fail.  How do
		 * we report what the error is back to the user in that case?
		 * No.  I refuse to use the mail system for this.
		 */
		umask(j->umask);
		bjs_job_environment(j);

		chdir("/");	/* sane starting point for chdir */
		if (chdir(j->dir)) {
			fprintf(stderr, "chdir(\"%s\"): %s\n", j->dir,
				strerror(errno));
			exit(1);
		}

		if (set_job_io(j))
			exit(1);
		execl(j->shell, j->shell, "-c", j->cmdline, NULL);
		exit(1);
	}
	/* Parent */
	j->pid = pid;
	return 0;
}

static
int start_job_interactive(struct bjs_job_t *j)
{
	struct sexp_t *sx;
	struct list_head *l;
	char tmp[20];

	sx = sexp_create_list("nodes", NULL);
	sprintf(tmp, "%d", j->job_id);
	sexp_append_atom(sx, tmp);
	for (l = j->nodes.next; l != &j->nodes; l = l->next) {
		struct node_alloc_t *n =
		    list_entry(l, struct node_alloc_t, nodes_list);
		sprintf(tmp, "%d", bjs_node_idx[n->node]->node);
		sexp_append_atom(sx, tmp);
	}
	client_send_sx(j->client, sx);
	return 0;
}

int bjs_start_job(struct bjs_job_t *j)
{
	if (verbose > 0)
		syslog(LOG_DEBUG, "Starting job %d", j->job_id);
	j->start_time = time(0);

	if (!bjs_job_is_interactive(j) && !bjs_job_flag(j, "restartable"))
		persistent_job_remove(j);

	if (j->cmdline)
		return start_job_batch(j);
	else
		return start_job_interactive(j);
}

static
void bjs_job_free(struct bjs_job_t *j)
{
	int i;

	list_del(&j->list);

	if (j->client)
		j->client->job = 0;
	if (j->cmdline)
		free(j->cmdline);
	if (j->shell)
		free(j->shell);
	if (j->dir)
		free(j->dir);
	if (j->envp) {
		for (i = 0; j->envp[i]; i++)
			free(j->envp[i]);
		free(j->envp);
	}
	if (j->reqs)
		sexp_free(j->reqs);
	assert(!list_empty(&j->nodes));
	free(j);
}

static
int sexp_check_format(struct sexp_t *sx, const char *fmt)
{
	int i;
	sx = sx->list;
	if (!sx)
		return -1;
	for (i = 0; fmt[i] && sx; i++, sx = sx->next) {
		if (fmt[i] == 'V' && !sexp_is_value(sx))
			return -1;
		if (fmt[i] == 'L' && !sexp_is_list(sx))
			return -1;
	}
	if (fmt[i] || sx)
		return -1;
	return 0;
}

static
struct bjs_job_t *mkjob(struct client_t *c, struct sexp_t *jobsx)
{
	int i, inter;
	struct bjs_job_t *j;
	struct sexp_t *sx;

	inter = strcmp(jobsx->list->val, "job") == 0 ? 0 : 1;

	/* malloc up a new job and add it to our list */
	j = malloc_chk(sizeof(*j));
	memset(j, 0, sizeof(*j));
	INIT_LIST_HEAD(&j->nodes);
	list_add_tail(&j->list, &bjs_jobs);
	j->job_id = job_id++;	/* we should probably wait till
				 * successful submit to assign
				 * this. */
	if (inter) {
		j->client = c;
		c->job = j;
	}
	j->uid = c->euid;
	j->gid = c->egid;
	j->submit_time = time(0);

	if (!inter) {
		/* Note that we sanity checked the job sexp format at
		 * submission time */
		j->shell = strdup_chk(sexp_nth(jobsx, JX_SHELL)->val);
		j->cmdline = strdup_chk(sexp_nth(jobsx, JX_CMD)->val);
		j->dir = strdup_chk(sexp_nth(jobsx, JX_DIR)->val);
		j->umask = strtol(sexp_nth(jobsx, JX_UMASK)->val, 0, 0);

		/* Suck out the environment */
		j->envp = malloc_chk(sizeof(char *) *
				     (sexp_length(sexp_nth(jobsx, JX_ENV)) +
				      1));
		for (i = 0, sx = sexp_nth(jobsx, JX_ENV)->list; sx;
		     sx = sx->next)
			j->envp[i++] = strdup_chk(sx->val);
		j->envp[i] = 0;
	}

	j->reqs = sexp_copy(sexp_nth(jobsx, inter ? JIX_REQS : JX_REQS));
	return j;
}

static
void bjs_job_kill(struct bjs_job_t *j)
{
	/* Release any nodes allocated to this job */
	while (!list_empty(&j->nodes)) {
		struct node_alloc_t *n;
		n = list_entry(j->nodes.next, struct node_alloc_t, nodes_list);
		/* bjs_node_deallocate takes care of killing junk left on the
		 * node. */
		bjs_node_deallocate(n);
	}
	bjs_do_clean();
}

/* bjs_job_remove should be used on a job after it has successfully
 * been added to a pool */
void bjs_job_remove(struct bjs_job_t *j)
{
	time_t now;
	time(&now);

	do_status_update = 1;

	if (conf.acctlog && bjs_job_is_running(j)) {
		int nodes = 0;
		struct list_head *l;
		char tmp[50];

		/* Count the nodes used */
		for (l = j->nodes.next; l != &j->nodes; l = l->next)
			nodes++;

		strftime(tmp, sizeof(tmp), "%Y %m %d %H %M %S",
			 localtime(&now));
		fprintf(conf.acctlog, "%s\t%s\t%d\t%d\t%d\t%ld\n",
			tmp, j->pool->name, j->uid, j->gid,
			nodes, (long)now - j->start_time);
		fflush(conf.acctlog);
	}

	/* We do the accounting before killing because killing deallocates
	 * the nodes */
	bjs_job_kill(j);

	/* Done with this one... */
	if (j->pool->policy->remove)
		j->pool->policy->remove(j->pool, j);
	persistent_job_remove(j);
	bjs_job_free(j);
}

static
void wait_on_children(void)
{
	int pid, status;
	struct list_head *l;
	time_t now;

	pid = waitpid(-1, &status, WNOHANG);
	while (pid > 0) {
		/* Find the job for this PID */
		now = time(0);
		for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
			struct bjs_job_t *j;
			j = list_entry(l, struct bjs_job_t, list);
			if (j->pid == pid) {
				if (verbose > 1)
					syslog(LOG_DEBUG, "job %d exited.",
					       j->job_id);
				bjs_job_remove(j);
				break;
			}
		}
		pid = waitpid(-1, &status, WNOHANG);
	}
}

/*--------------------------------------------------------------------
 *  Persistent Job Storage Routines
 *------------------------------------------------------------------*/
static
int persistent_job_add(struct bjs_job_t *j)
{
	int i, fd;
	FILE *f;
	char uidstr[10];
	char gidstr[10];
	char umstr[10];
	char substr[20];
	struct sexp_t *jobsx, *environ;
	char path[PATH_MAX + 1];
	/* Save the job in a file */

	sprintf(uidstr, "%d", j->uid);
	sprintf(gidstr, "%d", j->gid);
	sprintf(umstr, "0%o", j->umask);
	sprintf(substr, "%ld", (long)j->submit_time);

	jobsx = sexp_create_list(j->pool->name, substr, uidstr, gidstr,
				 j->shell, j->cmdline, j->dir, umstr, NULL);
	environ = sexp_create(NULL);
	sexp_append_sx(jobsx, environ);
	for (i = 0; j->envp[i]; i++)
		sexp_append_sx(environ, sexp_create(j->envp[i]));
	sexp_append_sx(jobsx, sexp_copy(j->reqs));

	/*
	   printf("JOBSX:");
	   sexp_print(stdout, jobsx);
	   printf("\n");
	 */

	sprintf(path, "%s/%d", conf.spooldir, j->job_id);
	/* Use normal open for better control over file creation. */
	fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (fd == -1) {
		syslog(LOG_ERR, "job_save: %s: %s\n", path, strerror(errno));
		sexp_free(jobsx);
		return -1;
	}
	f = fdopen(fd, "w");
	if (!f) {
		syslog(LOG_ERR, "fdopen: %s", strerror(errno));
		close(fd);
		sexp_free(jobsx);
		return -1;
	}

	sexp_print(f, jobsx);
	fflush(f);
	fsync(fileno(f));
	fclose(f);

	/* XXX write it to a file */
	sexp_free(jobsx);
	return 0;
}

static
struct sexp_t *sexp_read_f(FILE * f)
{
	int r, u;
	char buf[BSIZE];
	struct sexp_t *sx = 0;
	struct sexp_parser_state_t *s;
	s = sexp_parser_new();

	r = fread(buf, 1, BSIZE, f);
	while (r > 0 && !sx) {
		u = sexp_parser_parse(buf, r, &sx, s);
		if (u == -1) {
			syslog(LOG_ERR, "sexp parse error.\n");
			break;
		}
		r = fread(buf, 1, BSIZE, f);
	}
	sexp_parser_destroy(s);
	return sx;
}

static
int persistent_job_load_single(int id)
{
	int i;
	FILE *f;
	char path[PATH_MAX + 1], *pool;
	struct bjs_job_t *j;
	struct sexp_t *sx, *sx2;
	struct bjs_pool_t *p;

	sprintf(path, "%s/%d", conf.spooldir, id);
	if (!(f = fopen(path, "r"))) {
		syslog(LOG_ERR, "%s: %s", path, strerror(errno));
		return 0;
	}
	sx = sexp_read_f(f);
	fclose(f);
	if (!sx) {
		syslog(LOG_ERR, "No S-expresssion found in %s", path);
		return 0;
	}

	/* Try and find a pool that this will go with? */
	pool = sexp_nth(sx, PJ_POOL)->val;

	/* Create a job structure out of this thing */
	j = malloc_chk(sizeof(*j));
	memset(j, 0, sizeof(*j));
	INIT_LIST_HEAD(&j->nodes);
	list_add_tail(&j->list, &bjs_jobs);

	/* Not much error checking here since we trust these files and I'm
	 * under time pressure. */
	j->job_id = id;
	j->submit_time = strtol(sexp_nth(sx, PJ_SUBTIME)->val, 0, 0);
	j->uid = strtol(sexp_nth(sx, PJ_UID)->val, 0, 0);
	j->gid = strtol(sexp_nth(sx, PJ_GID)->val, 0, 0);
	j->shell = strdup_chk(sexp_nth(sx, PJ_SHELL)->val);
	j->cmdline = strdup_chk(sexp_nth(sx, PJ_CMD)->val);
	j->dir = strdup_chk(sexp_nth(sx, PJ_DIR)->val);
	j->umask = strtol(sexp_nth(sx, PJ_UMASK)->val, 0, 0);
	sx2 = sexp_nth(sx, PJ_ENV);
	j->envp = malloc_chk(sizeof(char *) * (sexp_length(sx2) + 1));
	for (i = 0, sx2 = sx2->list; sx2; sx2 = sx2->next)
		j->envp[i++] = strdup_chk(sx2->val);
	j->envp[i] = 0;
	j->reqs = sexp_copy_list(sexp_nth(sx, PJ_REQS));

	/* Find the pool for this job */
	for (i = 0; i < conf.npools; i++) {
		p = &conf.pools[i];
		if (strcmp(p->name, pool) == 0)
			break;
	}
	if (i == conf.npools) {
		syslog(LOG_ERR, "No pool named %s found for job %d",
		       pool, j->job_id);
		bjs_job_free(j);
		return -1;
	}

	/* XXX FIX ME...  we should at least check the built-ins before
	 * re-submitting */
#if 0
	if (submit_check_perm(j, p)) {
		syslog(LOG_ERR, "Permission denied for submit to pool %s during"
		       "restore for job %d.", pool, j->job_id);
		bjs_job_free(j);
		return -1;
	}
#endif

#if 0
	/* XXX FIX ME.. */
	if (submit_check_builtin(c, p, j)) {
		/* The check function emits the error message... */
		bjs_job_free(j);
		return -1;
	}
#endif

	/* Try and actually do it. */
	if (p->policy->submit(p, j) != 0) {
		/* Policy module generates the error message to the client in
		 * this case. */
		syslog(LOG_ERR, "Submission failure while restoring job %d.",
		       j->job_id);
		bjs_job_free(j);
		return -1;
	}
	j->pool = p;
	return 0;
}

static
int scandir_select(const struct dirent *de)
{
	char *check;
	strtol(de->d_name, &check, 0);
	return *check == 0;
}

static
int scandir_compare(const struct dirent **a, const struct dirent **b)
{
	int ida, idb;
	ida = strtol((*a)->d_name, 0, 0);
	idb = strtol((*b)->d_name, 0, 0);
	return ida > idb;
}

static
int persistent_job_load(void)
{
	int nents, i;
	struct dirent **de;
	int id;

	nents = scandir(conf.spooldir, &de, scandir_select, scandir_compare);

	for (i = 0; i < nents; i++) {
		id = strtol(de[i]->d_name, 0, 0);
		printf("Restoring job %d\n", id);
		persistent_job_load_single(id);
		if (id >= job_id)
			job_id = id + 1;
	}

	/* free this mess */
	for (i = 0; i < nents; i++)
		free(de[i]);
	free(de);
	return 0;
}

static
int persistent_job_remove(struct bjs_job_t *j)
{
	char path[PATH_MAX + 1];
	sprintf(path, "%s/%d", conf.spooldir, j->job_id);
	if (unlink(path)) {
		if (errno == ENOENT)
			return 0;	/* ok - already removed */
		syslog(LOG_ERR, "%s: %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

/*--------------------------------------------------------------------
 * Client interface code
 *------------------------------------------------------------------*/
static
int client_setup_socket(char *path)
{
	int fd, u;
	struct sockaddr_un addr;

	if (strlen(path) + 1 > sizeof(addr.sun_path)) {
		syslog(LOG_ERR,
		       "Listen socket path too long.  Max length is %d",
		       (int)sizeof(addr.sun_path) - 1);
		return -1;
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "socket(AF_UNIX, SOCK_STREAM, 0): %s",
		       strerror(errno));
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	u = umask(0);
	unlink(path);		/* blindly try to clean up before listening */
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		syslog(LOG_ERR, "bind(\"%s\"): %s:", path, strerror(errno));
		umask(u);
		close(fd);
		return -1;
	}
	umask(u);

	listen(fd, 50);
	return fd;
}

static
int client_accept(void)
{
	int fd;
	socklen_t size;
	struct sockaddr_un addr;
	struct client_t *c;
	struct ucred cred;

	size = sizeof(addr);
	fd = accept(conf.client_sockfd, (struct sockaddr *)&addr, &size);
	if (fd == -1) {
		syslog(LOG_ERR, "accept: %s", strerror(errno));
		return -1;
	}
	set_non_block(fd);

	size = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) == -1) {
		syslog(LOG_ERR, "getsockopt(SO_PEERCRED): %s", strerror(errno));
	}

	c = malloc_chk(sizeof(*c));
	memset(c, 0, sizeof(*c));
	c->fd = fd;
	c->euid = cred.uid;
	c->egid = cred.gid;
	c->state = CL_READ;
	c->time = time(0);	/* for I/O timeouts */
	c->job = 0;

	c->parser = sexp_parser_new();
	if (!c->parser) {
		syslog(LOG_ERR, "Out of memory.");
		abort();
	}
	sexp_parser_limit(c->parser, 10 * 1024);

	list_add_tail(&c->list, &clients);
	nclients++;
	//printf("CLIENT ADD: %p (%d)\n", c, nclients);
	return 0;
}

/* client I/O helpers */

static
void client_destroy(struct client_t *c)
{
	//printf("DESTROY---------- (%p) --------\n", c);
	if (c->job)
		bjs_job_remove(c->job);
	if (c->buf)
		free(c->buf);
	close(c->fd);
	sexp_parser_destroy(c->parser);

	list_del(&c->list);
	nclients--;
	memset(c, 1, sizeof(c));	/* XXX debugging paranoia */
	free(c);
}

static
void client_send(struct client_t *c, char *buf, int len)
{
	if (!c->buf) {
		c->buf = malloc_chk(len);
		memcpy(c->buf, buf, len);
		c->bsize = len;
		c->bptr = 0;
		return;
	}

	/* Shift everything down */
	if (c->bptr > 0) {
		memmove(c->buf, c->buf + c->bptr, c->bsize - c->bptr);
		c->bsize -= c->bptr;
		c->bptr = 0;
	}

	c->buf = realloc_chk(c->buf, c->bsize + len);
	memcpy(c->buf + c->bsize, buf, len);
	c->bsize += len;
}

static
void client_send_sx(struct client_t *c, struct sexp_t *sx)
{
	char *buf;
	buf = sexp_string(sx);
	client_send(c, buf, strlen(buf));
	free(buf);
}

static
int submit_check_perm(struct client_t *c, struct bjs_pool_t *p)
{
	int i;
	if (c->euid == 0)
		return 0;	/* root = ok :) */
	if (p->users) {
		for (i = 0; p->users[i] != -1; i++)
			if (p->users[i] == c->euid)
				break;
		if (p->users[i] == -1)
			return -1;
	}

	if (p->groups) {
		/* FIX ME: We have no way to check a user's supplementary
		 * groups here. */
		for (i = 0; p->groups[i] != -1; i++)
			if (p->groups[i] == c->egid)
				break;
		if (p->groups[i] == -1)
			return -1;
	}
	return 0;
}

static
int submit_check_builtin(struct client_t *c, struct bjs_pool_t *p,
			 struct bjs_job_t *j)
{
	int nodes, secs;
	const char *str;
	char *check;

    /*--- Check number of nodes requested ---*/
	str = bjs_job_req(j, "nodes", "1");
	nodes = strtol(str, &check, 0);
	if (*check || nodes < 1) {
		bjs_client_error(c, "Invalid number of nodes: %s", str);
		return -1;
	}

	if (p->min_nodes != -1 && nodes < p->min_nodes) {
		bjs_client_error(c, "The minimum number of nodes for pool"
				 " %s is %d.", p->name, p->min_nodes);
		return -1;
	}

	if (p->max_nodes != -1) {
		if (nodes > p->max_nodes) {
			bjs_client_error(c,
					 "The maximum number of nodes for pool"
					 " %s is %d.", p->name, p->max_nodes);
			return -1;
		}
	} else {
		if (nodes > p->nnodes) {
			bjs_client_error(c,
					 "The maximum number of nodes for pool"
					 " %s is %d.", p->name, p->nnodes);
			return -1;
		}
	}

    /*--- Check number of seconds requested ---*/
	str = bjs_job_req(j, "secs", "0");	/* XXX FIX ME: default # of secs? */
	secs = strtol(str, &check, 0);
	if (*check || secs <= 0) {
		bjs_client_error(c, "Invalid number of seconds: %s", str);
		return -1;
	}

	if (p->min_secs != -1 && secs < p->min_secs) {
		bjs_client_error(c, "The minimum number of seconds for pool"
				 " %s is %d.", p->name, p->min_secs);
		return -1;
	}

	if (p->max_secs != -1 && secs > p->max_secs) {
		bjs_client_error(c, "The maximum number of seconds for pool"
				 " %s is %d.", p->name, p->max_secs);
		return -1;
	}
	return 0;
}

static
int client_submit_job(struct client_t *c, struct sexp_t *jobsx)
{
	int i, inter;
	char *str;
	struct bjs_pool_t *p;
	struct bjs_job_t *j;
	struct sexp_t *sx, *sx2;

	/* "job" == batch job,  "jobi" == interactive job */
	inter = strcmp(jobsx->list->val, "job") == 0 ? 0 : 1;

	/* First do a basic sanity check on what was submitted. */
	if (sexp_check_format(jobsx, inter ? "VVL" : "VVVVVVLL")) {
		bjs_client_error(c, "Invalid job submission");
		return -1;
	}
	if (!inter) {
		/* Check formatting of the environment */
		for (sx = sexp_nth(jobsx, JX_ENV)->list; sx; sx = sx->next) {
			if (!sexp_is_value(sx)) {
				bjs_client_error(c, "Invalid job submission");
				return -1;
			}
		}
	}

	/* Check formatting of the requirements */
	for (sx = sexp_nth(jobsx, inter ? JIX_REQS : JX_REQS)->list;
	     sx; sx = sx->next) {
		if (!sexp_is_list(sx)) {
			bjs_client_error(c, "Invalid job submission");
			return -1;
		}
		for (sx2 = sx->list; sx2; sx2 = sx2->next)
			if (!sexp_is_value(sx2)) {
				bjs_client_error(c, "Invalid job submission");
				return -1;
			}
	}

	/* Figure out what pool to submit this to */
	str = sexp_nth(jobsx, inter ? JIX_POOL : JX_POOL)->val;
	for (i = 0; i < conf.npools; i++) {
		p = &conf.pools[i];
		if (strcmp(p->name, str) == 0)
			break;
	}
	if (i == conf.npools) {
		bjs_client_error(c, "No pool named: %s", str);
		return -1;
	}

	/* Permission check on this pool */
	if (submit_check_perm(c, p)) {
		bjs_client_error(c, "You don't have permission to submit to %s",
				 p->name);
		return -1;
	}

	j = mkjob(c, jobsx);

	if (submit_check_builtin(c, p, j)) {
		/* The check function emits the error message... */
		bjs_job_free(j);
		return -1;
	}

	printf("Adding JOB: %p\n", j);

	if (verbose > 2)
		syslog(LOG_DEBUG, "Calling %s submit.\n", p->policy->name);
	if (p->policy->submit(p, j) != 0) {
		/* Policy module generates the error message to the client in
		 * this case. */
		printf("Calling job destroy.\n");
		bjs_job_free(j);
		return -1;
	}
	j->pool = p;
	if (!bjs_job_is_interactive(j))
		persistent_job_add(j);

	/* Send a message to the client indicating a successful submission */
	{
		char tmp[20];
		sprintf(tmp, "(ok %d)", j->job_id);
		client_send(c, tmp, strlen(tmp));
	}

	if (bjs_job_is_interactive(j))
		c->state = CL_WAIT_NODES;

	do_status_update = 1;
	return 0;
}

/* Create the sexp to show status for a single pool */
static
struct sexp_t *pool_sexp(struct bjs_pool_t *p)
{
	int i;
	struct list_head *l;
	struct sexp_t *top, *sx, *sx2, *sx3;
	struct bjs_node_t *node;
	int nodes_total, nodes_up, nodes_free;
	char totstr[10], upstr[10], freestr[10];

	top = sexp_create_list(p->name, NULL);

	/* Create the list of nodes */
	nodes_total = nodes_up = nodes_free = 0;
	for (i = 0; i < p->nnodes; i++) {
		if (p->nodes[i] < bjs_nids && bjs_node_idx[p->nodes[i]]) {
			node = bjs_node_idx[p->nodes[i]];
			nodes_total++;
			if (node->up) {
				nodes_up++;
				if (list_empty(&node->jobs))
					nodes_free++;
			}
		}
	}
	sprintf(totstr, "%d", nodes_total);
	sprintf(upstr, "%d", nodes_up);
	sprintf(freestr, "%d", nodes_free);
	sexp_append_sx(top, sexp_create_list(totstr, upstr, freestr, NULL));

	/* Create list of jobs */
	sx = sexp_create(NULL);
	sexp_append_sx(top, sx);
	for (l = p->jobs.next; l != &p->jobs; l = l->next) {
		char jid[10], uid[10], subtime[20], starttime[20];
		struct bjs_job_t *j = list_entry(l, struct bjs_job_t, plist);
		sprintf(jid, "%d", j->job_id);
		sprintf(uid, "%d", j->uid);
		sprintf(subtime, "%ld", (long)j->submit_time);
		sprintf(starttime, "%ld", (long)j->start_time);
		sx3 = sexp_copy(j->reqs);
		sx2 = sexp_create_list(jid, uid,
				       j->cmdline ? j->
				       cmdline : "(interactive)", subtime,
				       starttime, NULL);
		sexp_append_sx(sx2, sx3);
		sexp_append_sx(sx, sx2);
	}

	/*sexp_print(stdout, top);
	   fflush(0); */
	return top;
}

static
struct sexp_t *mk_status_sx(void)
{
	int i;
	struct sexp_t *top, *poolsx;
	struct bjs_pool_t *p;

	top = sexp_create_list("status", NULL);

	for (i = 0; i < conf.npools; i++) {
		p = &conf.pools[i];
		poolsx = pool_sexp(p);
		sexp_append_sx(top, poolsx);
	}
	return top;
}

static
void client_get_status(struct client_t *c, struct sexp_t *req_sx)
{
	struct sexp_t *sx;

	sx = mk_status_sx();
	client_send_sx(c, sx);
	sexp_free(sx);
}

static
void client_status_update(void)
{
	struct list_head *l;
	struct client_t *c;
	struct sexp_t *status_sx = 0;

	for (l = clients.next; l != &clients; l = l->next) {
		c = list_entry(l, struct client_t, list);
		if (c->state == CL_WAIT_UPDATE) {
			if (!status_sx)
				status_sx = mk_status_sx();
			client_send_sx(c, status_sx);
		}
	}
	if (status_sx)
		sexp_free(status_sx);
	do_status_update = 0;
}

static
void client_remove_job(struct client_t *c, struct sexp_t *removesx)
{
	char *check;
	int jobid;
	struct bjs_job_t *j;
	struct list_head *l;
	struct sexp_t *sx;

	for (sx = removesx->list->next; sx; sx = sx->next) {
		if (!sexp_is_value(sx))
			continue;
		jobid = strtol(sx->val, &check, 0);
		if (*check) {
			bjs_client_error(c, "Invalid job ID: %s", sx->val);
			continue;
		}

		/* Look for a job with this ID.. */
		for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
			j = list_entry(l, struct bjs_job_t, list);
			if (j->job_id == jobid)
				break;
		}
		if (l == &bjs_jobs) {
			bjs_client_error(c, "No job %s found.", sx->val);
			continue;
		}

		/* Permission check */
		if (c->euid != 0 && c->euid != j->uid) {
			bjs_client_error(c, "Permission denied.");
			continue;
		}

		/* Do the remove */
		bjs_job_remove(j);
		client_send(c, "(ok)", 4);
	}
}

static
int client_process_sexp(struct client_t *c, struct sexp_t *sx)
{
	struct sexp_t *elt;
	c->state = CL_FLUSH;	/* Default state after receiving a sexp */

	elt = sx->list;
	if (!elt || !sexp_is_value(elt)) {
		syslog(LOG_INFO, "Invalild request from client.");
		return -1;
	}
	if (strcmp(elt->val, "job") == 0 || strcmp(elt->val, "jobi") == 0) {
		if (verbose)
			syslog(LOG_DEBUG, "Received job submission.");
		client_submit_job(c, sx);
	}
	if (strcmp(elt->val, "status") == 0) {
		client_get_status(c, sx);
	}
	if (strcmp(elt->val, "statusupdate") == 0) {
		client_get_status(c, sx);
		c->state = CL_WAIT_UPDATE;
	}
	if (strcmp(elt->val, "remove") == 0) {
		client_remove_job(c, sx);
	}
	return 0;
}

static
int client_read(struct client_t *c)
{
	int r;
	char buf[BSIZE];
	struct sexp_t *sx;

	/* We're basically interested in getting a single s-expession from
	 * the client. */
	r = read(c->fd, buf, BSIZE);
	while (r > 0) {
		if (sexp_parser_parse(buf, r, &sx, c->parser) == -1) {
			/* Parse error or something */
			return -1;
		}
		if (sx) {
			fprintf(stderr, "Got sexp: \n");
			sexp_print(stderr, sx);
			fprintf(stderr, "\n");

			client_process_sexp(c, sx);
			sexp_free(sx);
			return 1;
		}
		r = read(c->fd, buf, BSIZE);
	}
	/* This is the case where we hit EOF *BEFORE* getting a full sexp */
	if (r <= 0) {
		client_destroy(c);
		return -1;
	}
	return 0;
}

static
int client_write(struct client_t *c)
{
	int w;
	w = write(c->fd, c->buf + c->bptr, c->bsize - c->bptr);
	if (w < 0) {
		/* We don't really want to bitch about client write errors
		   fprintf(stderr, "write error: %s\n", strerror(errno));
		 */
		client_destroy(c);
		return -1;
	}
	c->bptr += w;
	if (c->bptr == c->bsize) {
		if (c->state == CL_FLUSH) {
			client_destroy(c);
		} else {
			free(c->buf);
			c->bptr = c->bsize = 0;
			c->buf = 0;
		}
	}
	return 0;
}

#define MAX_MSG 1023
void bjs_client_error(struct client_t *cl, char *fmt, ...)
{
	char msg[MAX_MSG + 1], *buf;
	struct sexp_t *sx;
	va_list va;

	va_start(va, fmt);
	vsnprintf(msg, MAX_MSG, fmt, va);
	va_end(va);

	sx = sexp_create_list("error", msg, NULL);
	buf = sexp_string(sx);
	if (verbose > 2)
		syslog(LOG_DEBUG, "MSG to client: %s\n", buf);
	client_send(cl, buf, strlen(buf));
}

/*--------------------------------------------------------------------
 * Configuration Load and Update code
 *------------------------------------------------------------------*/
/* Crud for the option processor */
static int current_pool_pass = -1;
static struct bjs_pool_t *current_pool;

static
int config_spooldir_callback(struct cmconf *cnf, char **args)
{
	struct stat buf;
	if (tc.spooldir)
		free(tc.spooldir);
	tc.spooldir = strdup_chk(args[1]);

	/* Check that this directory exists */
	if (stat(tc.spooldir, &buf)) {
		syslog(LOG_ERR, "spooldir %s: %s", tc.spooldir,
		       strerror(errno));
		return -1;
	}
	if (!S_ISDIR(buf.st_mode)) {
		syslog(LOG_ERR, "spooldir %s exists but is not a directory.",
		       tc.spooldir);
		return -1;
	}
	if (buf.st_uid != 0) {
		syslog(LOG_ERR, "spooldir %s should be owned by root.",
		       tc.spooldir);
		return -1;
	}
	if (buf.st_mode & 022) {
		syslog(LOG_ERR,
		       "spooldir %s should should not be writable to anybody"
		       " other than root.", tc.spooldir);
		return -1;
	}

	return 0;
}

static
int config_policypath_callback(struct cmconf *cnf, char **args)
{
	free(tc.policypath);
	tc.policypath = strdup_chk(args[1]);
	return 0;
}

static
int config_socketpath_callback(struct cmconf *cnf, char **args)
{
	if (tc.socketpath)
		free(tc.socketpath);
	tc.socketpath = strdup_chk(args[1]);
	return 0;
}

static
int config_acctlog_callback(struct cmconf *cnf, char **args)
{
	int fd;
	if (tc.acctlog) {
		fclose(tc.acctlog);
		tc.acctlog = 0;
	}

	/* Use normal open for better control over file creation. */
	fd = open(args[1], O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd == -1) {
		syslog(LOG_ERR, "%s:%d: %s: %s\n", cmconf_file(cnf),
		       cmconf_lineno(cnf), args[1], strerror(errno));
		return -1;
	}
	tc.acctlog = fdopen(fd, "a");
	if (!tc.acctlog) {
		syslog(LOG_ERR, "fdopen: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static
int config_pool_callback(struct cmconf *cnf, char **args)
{
	int i;
	struct bjs_pool_t *p;

	/* Look through the list of pools to make sure we don't alread
	 * have one by this name */
	if (strlen(args[1]) > MAX_POOL_NAME) {
		syslog(LOG_ERR,
		       "%s:%d: Node pool names are limited to %d characters.",
		       cmconf_file(cnf), cmconf_lineno(cnf), MAX_POOL_NAME);
		return -1;
	}
	for (i = 0; i < tc.npools; i++) {
		if (strcmp(tc.pools[i].name, args[1]) == 0) {
			syslog(LOG_ERR,
			       "%s:%d: A pool named %s already exists!",
			       cmconf_file(cnf), cmconf_lineno(cnf), args[1]);
			return -1;
		}
	}

	/* Add a new pool */
	tc.npools++;
	tc.pools = realloc_chk(tc.pools, sizeof(*tc.pools) * tc.npools);
	p = &tc.pools[tc.npools - 1];

	memset(p, 0, sizeof(*p));
	strcpy(p->name, args[1]);

	p->min_secs = p->max_secs = -1;
	p->min_nodes = p->max_nodes = -1;

	current_pool = p;
	current_pool_pass = cmconf_pass(cnf);
	return 0;
}

static
struct bjs_pool_t *get_current_pool(struct cmconf *cnf, char *arg)
{
	/* This pass thing is to make sure that we don't use a stale
	 * pointer from a previous pass through the configuration file. */
	if (current_pool_pass != cmconf_pass(cnf)) {
		syslog(LOG_ERR, "%s:%d: %s only allowed inside a pool.",
		       cmconf_file(cnf), cmconf_lineno(cnf), arg);
		return 0;
	}
	return current_pool;
}

static
int config_nodes_callback(struct cmconf *cnf, char **args)
{
	int i, j;
	struct bjs_pool_t *p;
	struct bproc_node_set_t ns, ns2;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	for (i = 1; args[i]; i++) {
		if (bproc_nodelist(&ns) == -1) {
			syslog(LOG_ERR, "Failed to get BProc node set");
			return -1;
		}

		if (bproc_nodefilter(&ns2, &ns, args[i]) == -1) {
			syslog(LOG_ERR, "%s:%d: Invalid node specification: %s",
			       cmconf_file(cnf), cmconf_lineno(cnf), args[i]);
			return -1;
		}

		p->nodes =
		    realloc_chk(p->nodes, sizeof(int) * (p->nnodes + ns2.size));
		for (j = 0; j < ns2.size; j++) {
			/* XXX Do we want to sanity check node numbers at this
			 * point?  It seems that we need to be able to handle
			 * bogus node numbers. */
			p->nodes[p->nnodes++] = ns2.node[j].node;
			/* We handle machine setup inside config_xfer */
		}
		bproc_nodeset_free(&ns);
		bproc_nodeset_free(&ns2);
	}
	return 0;
}

static
int config_secs_callback(struct cmconf *cnf, char **args)
{
	char *check;
	int secs;
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	secs = strtol(args[1], &check, 0);
	if (*check || secs < 0) {
		syslog(LOG_ERR, "%s:%d: invalid number of seconds: %s",
		       cmconf_file(cnf), cmconf_lineno(cnf), args[1]);
		return -1;
	}

	if (strcmp(args[0], "minsecs") == 0) {
		if (p->max_secs != -1 && secs > p->max_secs) {
			syslog(LOG_ERR, "%s:%d: maxsecs < minsecs",
			       cmconf_file(cnf), cmconf_lineno(cnf));
			return -1;
		}
		p->min_secs = secs;
	} else {
		if (p->min_secs != -1 && secs < p->min_secs) {
			syslog(LOG_ERR, "%s:%d: maxsecs < minsecs",
			       cmconf_file(cnf), cmconf_lineno(cnf));
			return -1;
		}
		p->max_secs = secs;
	}
	return 0;
}

static
int config_mmnodes_callback(struct cmconf *cnf, char **args)
{
	char *check;
	int nodes;
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	nodes = strtol(args[1], &check, 0);
	if (*check || nodes < 1) {
		syslog(LOG_ERR, "%s:%d: invalid number of nodes: %s",
		       cmconf_file(cnf), cmconf_lineno(cnf), args[1]);
		return -1;
	}

	if (strcmp(args[0], "minnodes") == 0) {
		if (p->max_nodes != -1 && nodes > p->max_nodes) {
			syslog(LOG_ERR, "%s:%d: maxnodes < minnodes",
			       cmconf_file(cnf), cmconf_lineno(cnf));
			return -1;
		}
		p->min_nodes = nodes;
	} else {
		if (p->min_nodes != -1 && nodes < p->min_nodes) {
			syslog(LOG_ERR, "%s:%d: maxnodes < minnodes",
			       cmconf_file(cnf), cmconf_lineno(cnf));
			return -1;
		}
		p->max_nodes = nodes;
	}
	return 0;
}

static
void add_id(int **id_list, int new_id)
{
	int ct = 0;
	int *p = *id_list;
	if (p)			/* count IDs so far */
		for (ct = 0; p[ct] != -1; ct++) ;

	p = realloc_chk(p, sizeof(*p) * (ct + 2));

	p[ct] = new_id;
	p[ct + 1] = -1;
	*id_list = p;
	return;
}

static
int config_users_callback(struct cmconf *cnf, char **args)
{
	int i, id;
	char *check;
	struct passwd *pwd;
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	for (i = 1; args[i]; i++) {
		/* First try to treat it like a number... */

		id = strtol(args[i], &check, 0);
		if (*check) {
			if (!(pwd = getpwnam(args[i]))) {
				syslog(LOG_ERR, "%s:%d: Unknown user: %s",
				       cmconf_file(cnf), cmconf_lineno(cnf),
				       args[i]);
				return -1;
			}
			id = pwd->pw_uid;
		}
		add_id(&p->users, id);
	}
	return 0;
}

static
int config_groups_callback(struct cmconf *cnf, char **args)
{
	int i, id;
	char *check;
	struct group *grp;
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	for (i = 1; args[i]; i++) {
		/* First try to treat it like a number... */

		id = strtol(args[i], &check, 0);
		if (*check) {
			if (!(grp = getgrnam(args[i]))) {
				syslog(LOG_ERR, "%s:%d: Unknown group: %s",
				       cmconf_file(cnf), cmconf_lineno(cnf),
				       args[i]);
				return -1;
			}
			id = grp->gr_gid;
		}
		add_id(&p->users, id);
	}
	return 0;
}

static
void *policy_load(const char *policy)
{
	void *handle;
	char *mypath, *ptr, *end, tmpfile[PATH_MAX + 1];
	/* Do a path-walk type thing to find the .so file we're looking
	 * for. */
	mypath = policy[0] == '/' ? "/" : tc.policypath;

	ptr = mypath;
	while (*ptr) {
		end = strchr(ptr, ':');
		if (!end)
			end = ptr + strlen(ptr);
		strncpy(tmpfile, ptr, end - ptr);
		tmpfile[end - ptr] = 0;
		strcat(tmpfile, "/");
		strcat(tmpfile, policy);

		if (access(tmpfile, R_OK | X_OK) == 0)
			break;

		strcat(tmpfile, ".so");	/* try it with another .so on the end */
		if (access(tmpfile, R_OK | X_OK) == 0)
			break;

		/* Advance to next path element */
		ptr = *end ? end + 1 : end;
	}

	handle = dlopen(tmpfile, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		syslog(LOG_ERR, "Failed to open %s: %s", tmpfile, dlerror());
	}
	return handle;
}

static
int config_policy_callback(struct cmconf *cnf, char **args)
{
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	if (p->policy) {
		syslog(LOG_ERR, "%s:%d: Pool %s already has a policy (%s).",
		       cmconf_file(cnf), cmconf_lineno(cnf),
		       p->name, p->policy->name);
		return -1;
	}

	p->handle = policy_load(args[1]);
	if (!p->handle) {
		syslog(LOG_ERR, "%s:%d: %s", cmconf_file(cnf),
		       cmconf_lineno(cnf), dlerror());
		return -1;
	}
	p->policy = dlsym(p->handle, "policy");
	if (!p->policy) {
		syslog(LOG_ERR, "%s:%d: %s: missing symbol \"policy\"",
		       cmconf_file(cnf), cmconf_lineno(cnf), args[1]);
		dlclose(p->handle);
		p->handle = 0;
		return -1;
	}
	if (p->policy->init && p->policy->init(p) != 0) {	/* Initialize policy */
		syslog(LOG_ERR,
		       "%s:%d: Policy initialization failed for pool %s"
		       "(policy %s)\n", cmconf_file(cnf), cmconf_lineno(cnf),
		       p->name, p->policy->name);
		return -1;
	}

	if (verbose)
		syslog(LOG_INFO, "Assigned policy %s to pool %s.",
		       p->policy->name, p->name);
	return 0;
}

/* This is a little crutch to select pools on the second configuration
 * pass. */
static
int config_pool_select(struct cmconf *cnf, char **args)
{
	int i;
	struct bjs_pool_t *p;
	for (i = 0; i < tc.npools; i++) {
		p = &tc.pools[i];
		if (strcmp(p->name, args[1]) == 0) {
			current_pool = p;
			current_pool_pass = cmconf_pass(cnf);
			return 0;
		}
	}
	/* This won't happen */
	return -1;
}

static
int config_pool_option(struct cmconf *cnf, char **args)
{
	struct bjs_pool_t *p;

	p = get_current_pool(cnf, args[0]);
	if (!p)
		return -1;

	if (p->policy->config) {
		return p->policy->config(p, args);
	} else {
		syslog(LOG_ERR,
		       "%s:%d: pool policy (%s) does not take any options.\n",
		       cmconf_file(cnf), cmconf_lineno(cnf), p->policy->name);
		return -1;
	}
}

static
struct cmconf_option config_opts[] =
    { {"spooldir", 1, 1, 0, config_spooldir_callback},
{"policypath", 1, 1, 0, config_policypath_callback},
{"socketpath", 1, 1, 0, config_socketpath_callback},
{"acctlog", 1, 1, 0, config_acctlog_callback},

     /* Built-in pool configuration */
{"pool", 1, 1, 0, config_pool_callback},
{"nodes", 1, 1, 0, config_nodes_callback},
{"maxsecs", 1, 1, 0, config_secs_callback},
{"minsecs", 1, 1, 0, config_secs_callback},
{"maxnodes", 1, 1, 0, config_mmnodes_callback},
{"minnodes", 1, 1, 0, config_mmnodes_callback},
{"users", 1, 99, 0, config_users_callback},
{"groups", 1, 99, 0, config_groups_callback},

     /* Second pass for configuring the pool policies - this is where
      * we call init for every policy. */
{"pool", 1, 1, 1, config_pool_select},
{"policy", 1, 1, 1, config_policy_callback},

     /* Third pass - configure policy specific options */
{"pool", 1, 1, 2, config_pool_select},
{"*", 0, 99, 2, config_pool_option},
{0}
};

static
void config_free(struct bjs_conf_t *c)
{
	int i;
	struct bjs_pool_t *p;
	/* Strings */
	if (c->spooldir)
		free(c->spooldir);
	if (c->policypath)
		free(c->policypath);
	if (c->socketpath)
		free(c->socketpath);

	/* Pools */
	for (i = 0; i < c->npools; i++) {
		p = &c->pools[i];
		if (p->policy && p->policy->destroy)
			p->policy->destroy(p);

		if (p->handle)
			dlclose(p->handle);
		if (p->nodes)
			free(p->nodes);
		if (p->users)
			free(p->users);
		if (p->groups)
			free(p->groups);
	}
	if (c->pools)
		free(c->pools);

	/* Files */
	if (c->client_sockfd != -1)
		close(c->client_sockfd);
	if (c->acctlog)
		fclose(c->acctlog);
}

/* This function takes a newly (re)loaded configuration and transfers
 * information to it from an existing configuration. */
static
int config_xfer(void)
{
	int i, j, do_store = 0;
	char *poolname;
	struct list_head *l;
	struct bjs_pool_t *p;
	struct bjs_node_t *node;

	/* Final initialization step for new pools */
	for (i = 0; i < tc.npools; i++)
		INIT_LIST_HEAD(&tc.pools[i].jobs);

    /*---------------------------------------------------------------------
     *  Transfer jobs from old configuration to new configuration
     *-------------------------------------------------------------------*/
	/* Take every job out of its existing pool and re-submit it to the
	 * new pool with the same name.  */
	/* FIXME:  What do we do with "lost" jobs? */
	for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
		struct bjs_job_t *j = list_entry(l, struct bjs_job_t, list);
		poolname = j->pool->name;
		if (j->pool->policy->remove)
			j->pool->policy->remove(j->pool, j);

		for (i = 0; i < tc.npools; i++) {
			if (strcmp(poolname, tc.pools[i].name) == 0) {
				if (tc.pools[i].policy->submit)
					tc.pools[i].policy->submit(&tc.pools[i],
								   j);
				break;
			}
		}
		if (i == tc.npools) {
			/* No pool found for this job */
			/* XXX We need to do something reasonable more here */
			syslog(LOG_ERR,
			       "Job %d has no home after reconfiguration.",
			       j->job_id);

			/* XXX this seems kinda busted....  Accounting here? */
			bjs_job_kill(j);
			bjs_job_free(j);
		}
	}

    /*---------------------------------------------------------------------
     * Add and return nodes from our configuration
     *-------------------------------------------------------------------*/
	/* The new configuration may have a different node set from the
	 * old one.  We have to grab new nodes at this point and release
	 * nodes that we're not using anymore. */
	for (i = 0; i < bjs_nnodes; i++)
		bjs_nodes[i].owned = 0;

	/* Mark all the ones we had */
	for (i = 0; i < conf.npools; i++) {
		p = &conf.pools[i];
		for (j = 0; j < p->nnodes; j++) {
			node = bjs_get_node(p->nodes[j]);
			if (node)
				node->owned = 1;
		}
	}

	/* ... now the ones we have now */
	for (i = 0; i < tc.npools; i++) {
		p = &tc.pools[i];
		for (j = 0; j < p->nnodes; j++) {
			node = bjs_get_node(p->nodes[j]);
			if (node) {
				if (!node->owned && node->up)
					bjs_clean_node(node->node);
				node->owned = 2;
			}
		}
	}
	/* Now release the ones which belonged in the old configuration
	 * but not the new one. */
	for (i = 0; i < bjs_nnodes; i++) {
		if (bjs_nodes[i].owned == 1) {
			/* XXX Do we want to kill jobs on these nodes at this point ? */
			/* Release node... */
			bproc_chown(bjs_nodes[i].node, 0);
			bproc_chgrp(bjs_nodes[i].node, 0);
			bproc_chmod(bjs_nodes[i].node, 0111);
		}
	}

    /*-------------------------------------------------------------------*/
	/* If the new configuration has the same listen path for the
	 * client socket, steal the file descriptor from the old
	 * configuration.  Otherwise we need to setup a new one */
	if (conf.client_sockfd != -1 &&
	    strcmp(conf.socketpath, tc.socketpath) == 0) {
		tc.client_sockfd = conf.client_sockfd;
		conf.client_sockfd = -1;
	} else {
		tc.client_sockfd = client_setup_socket(tc.socketpath);
		if (tc.client_sockfd == -1)
			return -1;
	}

	/* If we changed the spool dir, we have to re-create our spool
	 * files in a new location.  Doing it in two phases like this
	 * isn't strictly safe but somebody else can fix that later... - Erik */
	if (conf.spooldir && strcmp(tc.spooldir, conf.spooldir) != 0) {
		do_store = 1;
		for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
			struct bjs_job_t *j =
			    list_entry(l, struct bjs_job_t, list);
			persistent_job_remove(j);
		}
	}

	config_free(&conf);
	conf = tc;

	if (do_store) {
		for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
			struct bjs_job_t *j =
			    list_entry(l, struct bjs_job_t, list);
			persistent_job_add(j);
		}
	}
	return 0;
}

static
int config_load(void)
{
	current_pool = 0;
	memset(&tc, 0, sizeof(tc));
	tc.spooldir = strdup_chk(DEFAULT_SPOOL_DIR);
	tc.policypath = strdup_chk(DEFAULT_POLICY_PATH);
	tc.socketpath = strdup_chk(DEFAULT_SOCKET_PATH);
	tc.client_sockfd = -1;
	if (cmconf_process_file(config_file, config_opts)) {
		/* Config load failure */
		config_free(&tc);
		return -1;
	}

	/* Switch over to new configuration */
	return config_xfer();
}

/*--------------------------------------------------------------------
 * BProc / Machine interface routines
 *------------------------------------------------------------------*/

static
void bproc_nodeset_to_bjs_nodes(struct bjs_node_t **nodes_, int *nnodes_,
				struct bjs_node_t ***node_idx_, int *nids_,
				struct bproc_node_set_t *ns)
{
	int i, nnodes, nids;
	struct bjs_node_t *nodes, **node_idx;

	/* Count how many IDs */
	nnodes = ns->size;

	nids = -1;
	for (i = 0; i < ns->size; i++)
		if (ns->node[i].node > nids)
			nids = ns->node[i].node;
	nids++;

	/* Build an index for the node set. */
	nodes = malloc_chk(sizeof(*nodes) * nnodes);
	node_idx = malloc_chk(sizeof(*node_idx) * nids);
	memset(node_idx, 0, sizeof(*node_idx) * nids);

	/* Initialize the node set (job lists and node indexes) */
	for (i = 0; i < nnodes; i++) {
		nodes[i].node = ns->node[i].node;
		INIT_LIST_HEAD(&nodes[i].jobs);
	}

	/* Build the index */
	for (i = 0; i < nnodes; i++)
		node_idx[nodes[i].node] = &nodes[i];

	*nodes_ = nodes;
	*nnodes_ = nnodes;
	*node_idx_ = node_idx;
	*nids_ = nids;
}

/* A nice accessor for our node set */
struct bjs_node_t *bjs_get_node(int node_id)
{
	if (node_id < 0 || node_id >= bjs_nids)
		return 0;
	return bjs_node_idx[node_id];
}

time_t now(void)
{
	struct timeval t;
	gettimeofday(&t, NULL);
	return t.tv_sec;
}


/* This routine updates the internal node list data structures when
 * there's a machine state change in the system. */
static
int update_machine_status(int status_fd)
{
	int nnodes, nids, i, j, k, status;
	int change = 0;
	struct bjs_node_t *new_nodes, *newn;
	struct bjs_node_t **new_node_idx;
	struct node_alloc_t *a;
	struct bproc_node_set_t ns;

	/* Clear update status.  Do this first so that no updates slip
	 * through between the node list call and clearing the status. We
	 * should really have a short delay in here to allow lots of quick
	 * updates to pile up. */
	read(bproc_notify_fd, 0, 0);

	if (bproc_nodelist_(&ns, status_fd) == -1) {
		syslog(LOG_ERR, "bproc_nodelist: fail");
		return -1;
	}
	lastupdate = now();
	/* BIG PRESUMPTION - nodes which are not up aren't getting
	 * re-numbered.  We basically have no reasonable mechanism for
	 * detecting that.  That should also be extremely rare. */

	/* Check if this nodeset is the same as the last one.  Then we
	 * don't need to re-do the node lists */
	if (ns.size != bjs_nnodes) {
		change = 1;
	} else {
		for (i = 0; i < ns.size; i++) {
			if (ns.node[i].node != bjs_nodes[i].node) {
				change = 1;
				break;
			}
		}
	}
	if (change) {
		bproc_nodeset_to_bjs_nodes(&new_nodes, &nnodes, &new_node_idx,
					   &nids, &ns);

		/* Transfer old running jobs to the new configuration */
		for (i = 0; i < bjs_nnodes; i++) {
			if (!list_empty(&bjs_nodes[i].jobs) &&
			    bjs_nodes[i].node < nids) {
				newn = new_node_idx[bjs_nodes[i].node];
				/* Transfer the list of jobs to the new node.  Note
				 * that we're adding and removing the list heads here,
				 * not elements. */
				list_add(&newn->jobs, &bjs_nodes[i].jobs);
				list_del(&bjs_nodes[i].jobs);
				INIT_LIST_HEAD(&bjs_nodes[i].jobs);
			}
		}

		/* Remove old jobs that aren't in the new configuration */
		for (i = 0; i < bjs_nnodes; i++) {
			while (!list_empty(&bjs_nodes[i].jobs)) {
				a = list_entry(bjs_nodes[i].jobs.next,
					       struct node_alloc_t, jobs_list);
				bjs_node_deallocate(a);
				/* XXX maybe check here for nodeless jobs? */
			}
		}

		/* Switch to new machine configuration */
		change = 1;
		if (bjs_nodes)
			free(bjs_nodes);
		bjs_nnodes = nnodes;
		bjs_nodes = new_nodes;
		bjs_nids = nids;
		bjs_node_idx = new_node_idx;
	}

	/* Update status on all the nodes */
	for (i = 0; i < bjs_nnodes; i++) {
		status = (strcmp(ns.node[i].status, "up") == 0) ? 1 : 0;
		if (bjs_nodes[i].up != status) {
			bjs_nodes[i].up = status;

			if (bjs_nodes[i].up) {
				/* check if this node is allocated to a pool.  If so
				 * grab the node. */
				for (j = 0; j < conf.npools; j++)
					for (k = 0; k < conf.pools[j].nnodes;
					     k++)
						if (conf.pools[j].nodes[k] ==
						    bjs_nodes[i].node) {
							bjs_clean_node(bjs_nodes
								       [i].
								       node);
							break;
						}
				change = 1;
			}
		}
	}
	bproc_nodeset_free(&ns);
	bjs_do_clean();		/* node wipes actually happen here... */
	return change;
}

/* clean_node */

/* kill job , etc */

int bjs_grab_node(int node)
{

	return 0;
}

int bjs_release_node(int node)
{
	return 0;
}

/*--------------------------------------------------------------------
 * Debugging aids
 *------------------------------------------------------------------*/

static
void print_status(void)
{
	struct list_head *l, *l2;

	printf
	    ("Status -------------------------------------------------------\n");
	printf("BRK: 0x%lx\n", (long)sbrk(0));
	printf("Spooldir = %s\n", tc.spooldir);
#if 0
	{
		int i, j;
		for (i = 0; i < tc.npools; i++) {
			struct bjs_pool_t *p = &tc.pools[i];
			printf("  Pool: %s\n", p->name);
			for (j = 0; j < p->nnodes; j++) {
				printf("    node %4d %4s\n", p->nodes[j],
				       p->nodes[j] < bjs_nnodes ?
				       (bjs_nodes[p->nodes[j]].
					up ? "up" : "down") : "INV");
			}
		}
	}
#endif

	printf("  Clients:\n");
	for (l = clients.next; l != &clients; l = l->next) {
		struct client_t *c = list_entry(l, struct client_t, list);
		printf("    %p fd=%d state=%d\n", c, c->fd, c->state);
	}
	printf("  Jobs:\n");
	for (l = bjs_jobs.next; l != &bjs_jobs; l = l->next) {
		struct bjs_job_t *j = list_entry(l, struct bjs_job_t, list);
		printf("    %p id=%-3d pool=%s running=%s pri=%ld",
		       j, j->job_id, j->pool->name,
		       list_empty(&j->nodes) ? "NO " : "YES", j->priority);
		for (l2 = j->nodes.next; l2 != &j->nodes; l2 = l2->next) {
			struct node_alloc_t *n =
			    list_entry(l2, struct node_alloc_t, nodes_list);
			printf(" %d", bjs_node_idx[n->node]->node);
		}
		printf("\n");
	}
	printf
	    ("--------------------------------------------------------------\n");
}

/*------------------------------------------------------------------*/
static
void daemonize(void)
{
	int fd, pid;
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	}
	if (pid != 0)
		exit(0);

	fd = open("/dev/null", O_RDWR);
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
	if (fd > 2)
		close(fd);
	chdir("/");
	umask(0);
	setsid();
}

static struct timeval tmo;	/* select timeout */
static int do_config_reload = 0;
static
void signal_handler(int sig)
{
	tmo.tv_sec = tmo.tv_usec = 0;	/* hack to because pselect() doesn't work */
	if (sig == SIGHUP)
		do_config_reload = 1;
}

void Usage(char *arg0)
{
	printf("Usage: %s [options...]\n"
	       "       -h      Print this message and exit.\n"
	       "       -V      Print version information and exit.\n"
	       "       -v      Increase verbose level.\n"
	       "       -C file   Read configuration from file (default=%s)\n",
	       arg0, DEFAULT_CONFIG_FILE);
}

int main(int argc, char *argv[])
{
	int c;
	sigset_t sset;

	/* setup for logging since ALL error messages get spit out via the
	 * syslog.  We'll most likely turn off LOG_PERROR after initialization */
	openlog(argv[0], LOG_PERROR, LOG_DAEMON);

	while ((c = getopt(argc, argv, "hVvC:")) != EOF) {
		switch (c) {
		case 'h':
			Usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'v':
			verbose++;
			break;
		case 'C':
			config_file = optarg;
			break;
		default:
			exit(1);
		}
	}

	if (geteuid()) {
		syslog(LOG_ERR, "bjs needs to be run as r00T!");
		exit(1);
	}

	bproc_notify_fd = bproc_notifier();
	if (bproc_notify_fd == -1) {
		syslog(LOG_ERR, "bproc_notifier: %s", strerror(errno));
		exit(1);
	}
	/* Load configuration */
	if (update_machine_status(bproc_notify_fd) == -1) {
		syslog(LOG_ERR, "Failed to read machine status.");
		exit(1);
	}
	/*syslog(LOG_INFO, "Loading configuration from %s", config_file); */
	if (config_file[0] != '/') {
		syslog(LOG_WARNING,
		       "Configuration reload will likely fail because"
		       " \"%s\" is not an absolute path.", config_file);
	}
	if (config_load()) {
		syslog(LOG_ERR, "Configuration load failed.  Exiting.");
		exit(1);
	}

	if (persistent_job_load()) {
		syslog(LOG_ERR, "Failed to load stored job state.");
		exit(1);
	}

	/* Go into daemon mode here.... */
	if (verbose == 0) {
		openlog(argv[0], 0, LOG_DAEMON);
		daemonize();
	}

	/* Setup my signal situation */
	sigemptyset(&sset);
	sigaddset(&sset, SIGHUP);
	sigaddset(&sset, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sset, 0);
	signal(SIGCHLD, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGPIPE, SIG_IGN);

    /*-- main select loop ------------------------------------------*/
	while (1) {
		int i;
		int r, maxfd = -1;
		int chng;
		struct bjs_pool_t *p;
		struct client_t *c;
		struct list_head *l, *next;
		fd_set rset, wset;

		do_status_update = 0;

		FD_ZERO(&rset);
		FD_ZERO(&wset);
		/* we can't poll a FUSE file descriptor. So ... */
		tmo.tv_sec = 15;	/* we poll the notifier fd every 15 seconds.  */
		tmo.tv_usec = 0;

		if (nclients < DEFAULT_MAX_CLIENTS) {
			FD_SET(conf.client_sockfd, &rset);
			if (maxfd < conf.client_sockfd)
				maxfd = conf.client_sockfd;
		}

		for (l = clients.next; l != &clients; l = l->next) {
			c = list_entry(l, struct client_t, list);
			FD_SET(c->fd, &rset);
			if (maxfd < c->fd)
				maxfd = c->fd;
			if (c->buf) {
				FD_SET(c->fd, &wset);
				if (maxfd < c->fd)
					maxfd = c->fd;
			}
		}

		/* Get the timeout for each pool */
		for (i = 0; i < conf.npools; i++) {
			long policy_tmo;
			p = &conf.pools[i];
			if (p->policy->timeout) {
				if (p->policy->timeout(p, &policy_tmo)) {
					if (policy_tmo < tmo.tv_sec)
						tmo.tv_sec = policy_tmo;
				}
			}
		}

		sigprocmask(SIG_UNBLOCK, &sset, 0);
		//printf("*** S 1 *** %d %d\n", list_empty(&clients), nclients);
		r = select(maxfd + 1, &rset, &wset, 0, &tmo);
		//printf("*** S 2 *** %d %d\n", list_empty(&clients), nclients);
		sigprocmask(SIG_BLOCK, &sset, 0);

		if (r > 0) {
			/* Check for machine status changes */
			if ((now()-lastupdate) > 15) {
				if (verbose)
					syslog(LOG_INFO,
					       "Check BProc machine status change.");
				chng = update_machine_status(bproc_notify_fd);
				if (chng) {
					if (verbose)
						syslog(LOG_INFO,
						       "Scheduler status change.");
					for (i = 0; i < conf.npools; i++) {
						p = &conf.pools[i];
						if (p->policy->state_change)
							p->policy->
							    state_change(p);
					}
				}
			}

			/* Check for new clients */
			if (FD_ISSET(conf.client_sockfd, &rset))
				client_accept();

			/* Check for I/O from clients */

			/* These loops are separated out to avoid problems that
			 * can arise from deleting clients in the middle of
			 * client_read or client_write */
			for (l = clients.next; l != &clients; l = next) {
				next = l->next;
				c = list_entry(l, struct client_t, list);
				if (FD_ISSET(c->fd, &rset)) {
					if (c->state == CL_READ)
						client_read(c);
					else {
						/* Coming ready for reading at any point after
						 * the initial request is an error.  We use
						 * this to detect EOF too. */
						client_destroy(c);
					}
				}
			}

			for (l = clients.next; l != &clients; l = next) {
				next = l->next;
				c = list_entry(l, struct client_t, list);
				if (c->buf && FD_ISSET(c->fd, &wset))
					client_write(c);
			}
		}

		wait_on_children();

		/* Configuration reloads need to happen before scheduling
		 * since they will likely affect what the policies do. */
		if (do_config_reload) {
			syslog(LOG_ERR, "Rereading configuration from %s",
			       config_file);
			if (config_load())
				syslog(LOG_ERR, "Configuration load failed.");
			do_config_reload = 0;
			do_status_update = 1;
		}

		/* Give all the policies a chance to do something */
		/* Since what one policy does might affect the decisions of
		 * another, we really need to keep re-running these modules
		 * until each one does nothing. */
		do {
			chng = 0;
			for (i = 0; i < conf.npools; i++) {
				p = &conf.pools[i];
				if (p->policy->schedule)
					chng |= p->policy->schedule(p);
			}
			if (chng)
				do_status_update = 1;
		} while (chng);

		if (do_status_update) {
			client_status_update();
			do_status_update = 0;
		}

		if (verbose > 1)
			print_status();
	}
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
