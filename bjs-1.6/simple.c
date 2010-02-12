/*------------------------------------------------------------ -*- C -*-
 * BJS:  a simple scheduler for BProc based environments.
 *
 * simple.c: a simple BJS policy module.
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
 *  $Id: simple.c,v 1.13 2002/09/19 20:28:20 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <bjs.h>
#include <time.h>

static
int simple_submit(struct bjs_pool_t *p, struct bjs_job_t *j)
{
	const char *str;
	char *check;
	int nodes;
	/* Anything is ok in this pool */
	j->pool = p;

	str = bjs_job_req(j, "nodes", "1");
	if (!str) {
		bjs_client_error(j->client, "Missing requirement nodes.");
		return -1;
	}
	nodes = strtol(str, &check, 0);
	if (*check || nodes <= 0) {
		bjs_client_error(j->client, "Invalid number of nodes: %s.",
				 str);
		return -1;
	}
	if (nodes > p->nnodes) {
		bjs_client_error(j->client, "Requested number of nodes exceeds"
				 "the number allocated to this pool.");
		return -1;
	}
	list_add_tail(&j->plist, &p->jobs);
	return 0;
}

static
int simple_remove(struct bjs_pool_t *p, struct bjs_job_t *j)
{
	/* Perhaps the scheduler should do this?  Probably not since we're
	 * involved in adding this to the queue ourselves.
	 */
	list_del(&j->plist);
	return 0;
}

static
int count_free_nodes(struct bjs_pool_t *p)
{
	int i, ct = 0;
	for (i = 0; i < p->nnodes; i++)
		if (bjs_node_usable(p->nodes[i], 0))
			ct++;
	return ct;
}

static
int simple_timeout(struct bjs_pool_t *p, long *tmo)
{
	struct list_head *l;
	long now, time_left, time_used;
	long time_reqd;
	int retval = 0;

	now = time(0);

	*tmo = -1;
	for (l = p->jobs.next; l != &p->jobs; l = l->next) {
		struct bjs_job_t *j = list_entry(l, struct bjs_job_t, plist);
		if (j->start_time && j->priority >= 0) {
			time_reqd = strtol(bjs_job_req(j, "secs", "0"), 0, 0);
			time_used = now - j->start_time;
			time_left = time_reqd - time_used;
			if (time_left < 0)
				time_left = 0;
			if (*tmo == -1 || *tmo > time_left)
				*tmo = time_left;
			retval = 1;
		}
	}
	return retval;
}

static
struct bjs_job_t *find_first_runable(struct bjs_pool_t *p)
{
	struct list_head *l;
	struct bjs_job_t *j;
	for (l = p->jobs.next; l != &p->jobs; l = l->next) {
		j = list_entry(l, struct bjs_job_t, plist);

		/* Check basic requirements */
		if (!bjs_job_runnable(j))
			continue;
		if (!bjs_job_is_running(j))
			return j;
	}
	return 0;
}

static
int simple_schedule(struct bjs_pool_t *p)
{
	int i, n;
	int did_something = 0;
	struct bjs_job_t *j;
	struct list_head *l, *next;
	int reqd_nodes, free_nodes;
	long time_reqd, now;

	//printf("simple_schedule on %s\n", p->name);
	//printf("  free nodes = %d\n", count_free_nodes(p));

	/* Look through my job list for jobs that have exceeded their time */
	now = time(0);

	for (l = p->jobs.next; l != &p->jobs; l = next) {
		next = l->next;
		j = list_entry(l, struct bjs_job_t, plist);
		if (j->start_time && j->priority >= 0) {
			time_reqd = strtol(bjs_job_req(j, "secs", "0"), 0, 0);
			if (now - j->start_time >= time_reqd) {
#if 0
				printf("JOB KILLABLE %d %ld %ld %ld\n",
				       j->job_id, time_reqd, now,
				       j->start_time);
				j->priority = -1;	/* mark as killable */
#else
				/* Keep it really simple.  Kill it after its time is up */
				bjs_job_remove(j);
#endif
				did_something = 1;
			}
		}
	}

	j = find_first_runable(p);
	while (j) {
		free_nodes = count_free_nodes(p);
		reqd_nodes = strtol(bjs_job_req(j, "nodes", "1"), 0, 0);

		if (reqd_nodes > free_nodes)
			return did_something;

		/* Try to find nodes to use - start with idle nodes, then look for
		 * nodes used by killable jobs. */
		for (i = 0; i < p->nnodes && reqd_nodes; i++) {
			n = p->nodes[i];
			if (bjs_node_idle(n)) {
				bjs_node_allocate(j, n, 1);
				reqd_nodes--;
			}
		}

		for (i = 0; i < p->nnodes && reqd_nodes; i++) {
			n = p->nodes[i];
			if (bjs_node_usable(n, 0)) {
				bjs_kill_node(n);	/* Make sure this node is cleaned up. */
				bjs_node_allocate(j, n, 1);
				reqd_nodes--;
			}
		}
		bjs_start_job(j);

		j = find_first_runable(p);
	}
	return did_something;
}

struct policy_ops_t policy = {
      name:"simple",
      submit:simple_submit,
      remove:simple_remove,
      timeout:simple_timeout,
      schedule:simple_schedule
};

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
