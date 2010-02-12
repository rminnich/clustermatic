/*------------------------------------------------------------ -*- C -*-
 * BJS: a simple scheduler for BProc based environments.
 *
 * bjs.h: This file contains definitions required for user
 * interactions with the scheduler.
 *
 * Erik Arjan Hendriks <hendriks@lanl.gov>
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
 *  $Id: bjs.h,v 1.19 2003/11/10 19:40:22 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _BJS_H
#define _BJS_H

#include <sexp.h>
#include <bjs_list.h>

#define MAX_POOL_NAME 31
#define MAX_REQ_NAME  31
#define MAX_REQ_VAL   31

struct timeval;

struct bjs_job_req_t {
	char key[MAX_REQ_NAME + 1];
	char val[MAX_REQ_VAL + 1];
};

struct bjs_node_t {
	int node;
	int up;
	int owned;		/* Flag whether this node is owned by
				 * a BJS policy. */
	struct list_head jobs;
};

struct bjs_job_t {
	struct list_head list;	/* Global list of jobs */
	int job_id;		/* some kind of job identifier */

	/* Vitals needed to create the job */
	int uid, gid;		/* This is all we can get from PEERCRED */
	char *cmdline;
	char *shell;
	char *dir;
	int umask;
	char **envp;
	struct sexp_t *reqs;

	/* Job accounting type stuff */
	long priority;
	time_t submit_time;
	time_t start_time;

	int pid;		/* PID of child process */
	struct list_head nodes;
	struct client_t *client;	/* client for this  */

	struct bjs_pool_t *pool;	/*  */

	struct list_head plist;	/* For use by policy modules */
	void *private;		/* For use by policy modules */
};

#define bjs_job_is_running(j)     ((j)->start_time != 0)
#define bjs_job_is_interactive(j) ((j)->cmdline == 0)

struct bjs_pool_t {
	char name[MAX_POOL_NAME + 1];	/* Name of the pool */

	int nnodes;		/* number of nodes in this pool */
	int *nodes;		/* array of nodes for this pool */

	struct list_head jobs;	/* List of jobs in this pool */

	/* Policy stuff */
	void *handle;		/* handle for policy module */
	struct policy_ops_t *policy;

	/* Misc configuration stuff  */
	int *users;		/* handled by BJS */
	int *groups;		/* handled by BJS */

	int max_secs, min_secs;	/* conf by BJS, handled by policy */
	int max_nodes, min_nodes;	/* conf by BJS, handled by policy */

	void *private;		/* For use by policy modules */
};

/**
 * \brief this is the brief desctription
 * Every policy module must contain an instance of policy_ops_t named
 * policy in order to work.
 */
struct policy_ops_t {
    /**
     * name is the policy name.  This is used to print policy related
     * error messages.
     */
	char *name;
    /**
     * BJS calls the init callback when a new pool is being created.
     * The init callback should return 0 if initialization is
     * successful.
     */
	int (*init) (struct bjs_pool_t *);
    /**
     * The destroy callback is called when a pool is being destroyed
     * during a scheduler reconfiguration.  All jobs will be removed
     * from the pool before destroy is called.
     */
	int (*destroy) (struct bjs_pool_t *);
    /**
     * The config callback is used for policy specific configuration
     * options.  This will be called after the init callback and
     * before submitting any jobs to the queue.  The args argument is
     * a null terminated list of strings from the config file.
     *
     */
	int (*config) (struct bjs_pool_t *, char **args);

	/* These are the two functions called to submit remove jobs
	 * to/from a pool.  submit should return zero on success and zeron
	 * on error.  NOTE THAT A RUNNING JOB MAY BE PASSED TO SUBMIT AT A
	 * CONFIGURATION RELOAD. */
	int (*submit) (struct bjs_pool_t *, struct bjs_job_t * j);
	int (*remove) (struct bjs_pool_t *, struct bjs_job_t * j);

	/* called when there's a machine state change.  e.g. when a node
	 * goes up or comes down */
	void (*state_change) (struct bjs_pool_t *);

	/* This one is called every time the scheduler goes through its
	 * main loop.  the scheduler should run things in here */
	int (*schedule) (struct bjs_pool_t * p);

	/* timeout is called before calling select.  This gives the policy
	 * module a way to tell the scheduler how long it wants to sleep
	 * before waking up and doing something again.  The actual timeout
	 * will be the minimum of all the loaded policies.  Timeout should
	 * return non-zero if the policy wants a timeout. */
	int (*timeout) (struct bjs_pool_t *, long *);
};

#define DEFAULT_SPOOL_DIR   "/var/bjs"
#define DEFAULT_POLICY_PATH "/usr/lib64/bjs:/usr/lib/bjs"
#define DEFAULT_SOCKET_PATH "/tmp/.bjs"

#define DEFAULT_MAX_CLIENTS 100

//struct job_t * sexp_to_job(struct sexp_t *);
#ifdef __cplusplus
extern "C" {
#endif

	extern int verbose;
	extern int bjs_nnodes, bjs_nids;
	extern struct bjs_node_t *bjs_nodes, **bjs_node_idx;

    /** @file */
/**
 * A policy module can use bjs_client_error to send and error message
 * to an attached client.  cl is the client to send the error message
 * to.  fmt and remaining arguments are passed to printf to generate
 * the error message.
 */
	extern void bjs_client_error(struct client_t *cl, char *fmt, ...);
/**
 * bjs_job_flag will return true if a requirement flag is set on a job.
 */
	extern int bjs_job_flag(struct bjs_job_t *j, const char *key);
/**
 * bjs_job_req gets a job requirement string for a particular job.
 * key is the name of the requirement to fetch.  If the job does not
 * contain a value for that requirement, bjs_job_req will return
 * default.
 */
	extern const char *bjs_job_req(struct bjs_job_t *job, const char *key,
				       const char *dfl);

	extern struct bjs_node_t *bjs_get_node(int node);

/**
 * bjs_node_idle returns true if the node is both up and nothing is
 * running on that node.
 */
	extern int bjs_node_up(int node);
	extern int bjs_node_idle(int node);

/**
 * bjs_node_usable returns true if a node is up and either idle or the
 * things running on it are killable.  (job->priority == -1)
 */
	extern int bjs_node_usable(int node, long pri);

/**
 * bjs_node_allocate allocates a node to a job.  A policy should not
 * allocate nodes unless it is actually ready to run something on it.
 */
	extern void bjs_node_allocate(struct bjs_job_t *j, int node,
				      int set_owner);

/*!
 \fn bjs_job_runnable(struct bjs_job_t *j)
\brief bjs_job_runnable returns true if the job passes all the built-in
 requirements for running at some point in the future in whatever
 pool it is in.  Currently, these requirements include having at
 least as many nodes as the job requires and having all job
 dependencies satisfied.
 \param j The job to be checked.
*/
	extern int bjs_job_runnable(struct bjs_job_t *j);
	extern int bjs_start_job(struct bjs_job_t *j);
	extern void bjs_job_remove(struct bjs_job_t *j);
	extern void bjs_kill_node(int node);

/* Routines for clients */
	extern int bjs_connect(char *path);
	extern void bjs_close(void);
	extern int bjs_send_str(const char *str);
	extern int bjs_send_sx(struct sexp_t *sx);
	extern int bjs_recv(struct sexp_t **sx);
#ifdef __cplusplus
}
#endif
/* Some defines for the S-expressions we use */
#define JX_POOL  1
#define JX_SHELL 2
#define JX_CMD   3
#define JX_DIR   4
#define JX_UMASK 5
#define JX_ENV   6
#define JX_REQS  7
#define JIX_POOL 1
#define JIX_REQS 2
#define SJX_JID    0
#define SJX_UID    1
#define SJX_CMD    2
#define SJX_SUBMIT 3
#define SJX_START  4
#define SJX_REQS   5
#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
