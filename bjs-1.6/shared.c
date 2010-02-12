/*------------------------------------------------------------ -*- C -*-
 * BJS: a shared scheduler for BProc based environments.
 *
 * shared.c: a shared BJS policy module.
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
 *  $Id: shared.c,v 1.7 2004/11/03 17:49:02 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <bjs.h>

static
int shared_submit(struct bjs_pool_t *p, struct bjs_job_t *j)
{
	/* Anything is ok in this pool */
	list_add_tail(&j->plist, &p->jobs);
	return 0;
}

static
int shared_remove(struct bjs_pool_t *p, struct bjs_job_t *j)
{
	/* Perhaps the scheduler should do this?  Probably not since we're
	 * involved in adding this to the queue ourselves.
	 */
	list_del(&j->plist);
	return 0;
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

struct jc_t {
	int node;
	int count;
};

static
int sort_compare(struct jc_t *a, struct jc_t *b)
{
	return a->count > b->count;
}

static
int shared_schedule(struct bjs_pool_t *p)
{
	int i, node_count;
	struct bjs_job_t *j;
	struct bjs_node_t *node;
	struct list_head *l;
	int reqd_nodes;
	int idx;
	struct jc_t *job_counts;

	/* Check this early so we don't go through a lot of work if we
	 * have nothing to do. */
	j = find_first_runable(p);
	if (!j)
		return 0;

	/* Figure out how many jobs I have per node */
	job_counts = alloca(sizeof(*job_counts) * p->nnodes);
	for (i = 0; i < p->nnodes; i++) {
		job_counts[node_count].node = node->node;
		job_counts[node_count].count = 0;

		if (bjs_node_up(p->nodes[i])) {
			node = bjs_get_node(p->nodes[i]);
			for (l = node->jobs.next; l != &node->jobs; l = l->next)
				job_counts[node_count].count++;
			node_count++;
		}
	}
	/* Sort it so I can go for the least loaded nodes... */
	qsort(job_counts, node_count, sizeof(*job_counts),
	      (int (*)(const void *, const void *))sort_compare);

	/* Start scheduling jobs */
	idx = 0;
	while (j) {
		reqd_nodes = strtol(bjs_job_req(j, "nodes", "1"), 0, 0);

		/* Allocate nodes to this job and start it */
		for (i = 0; i < reqd_nodes; i++) {
			bjs_node_allocate(j, job_counts[idx].node, 0);
			idx = (idx + 1) % node_count;
		}
		bjs_start_job(j);

		j = find_first_runable(p);
	}
	return 1;
}

struct policy_ops_t policy = {
      name:"shared",
      submit:shared_submit,
      remove:shared_remove,
      schedule:shared_schedule
};

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
