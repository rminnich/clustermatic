/*------------------------------------------------------------ -*- C -*-
 * BJS:  a filler scheduler for BProc based environments.
 *
 * filler.c: a filler BJS policy module.
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
 *  $Id: filler.c,v 1.3 2003/10/23 22:38:04 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <bjs.h>
#include <time.h>

static
int filler_submit(struct bjs_pool_t *p, struct bjs_job_t *j) {
    const char *str;
    char *check;
    int  nodes;
    /* Anything is ok in this pool */
    j->pool = p;

    str = bjs_job_req(j, "nodes", "1");
    if (!str) {
	bjs_client_error(j->client, "Missing requirement nodes.");
	return -1;
    }
    nodes = strtol(str, &check, 0);
    if (*check || nodes <= 0) {
	bjs_client_error(j->client, "Invalid number of nodes: %s.", str);
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
int filler_remove(struct bjs_pool_t *p, struct bjs_job_t *j) {
    /* Perhaps the scheduler should do this?  Probably not since we're
     * involved in adding this to the queue ourselves.
     */
    list_del(&j->plist);
    return 0;
}

static
int filler_timeout(struct bjs_pool_t *p, long *tmo) {
    struct list_head *l;
    long now, time_left, time_used;
    long time_reqd;
    int retval = 0;

    now = time(0);

    *tmo = -1;
    for (l=p->jobs.next; l != &p->jobs; l = l->next) {
	struct bjs_job_t *j = list_entry(l, struct bjs_job_t, plist);
	if (j->start_time && j->priority >= 0) {
	    time_reqd = strtol(bjs_job_req(j, "secs", "0"), 0, 0);
	    time_used = now - j->start_time;
	    time_left = time_reqd - time_used;
	    if (time_left < 0) time_left = 0;
	    if (*tmo == -1 || *tmo > time_left) *tmo = time_left;
	    retval = 1;
	}
    }
    return retval;
}

struct sched_event_t {
    struct sched_event_t *next, *prev;
    long time;			/* when */
    int  nodes;			/* number of nodes available. */
};

static
void add_sched_event(struct sched_event_t *head, long time, int adj) {
    struct sched_event_t *new_se, *se;

    /* Scan forward and look for the node to insert after */
    for (se = head; se->next; se = se->next)
	if (se->next->time > time) break;

    if (se->time == time) {
	/* Easy case, we found a match */
	new_se = se;
    } else {
	/* Otherwise, allocate a new element */

	new_se = malloc(sizeof(*new_se));
	new_se->time  = time;
	new_se->nodes = se->nodes;

	new_se->prev = se;
	new_se->next = se->next;
	if (new_se->next) new_se->next->prev = new_se;
	new_se->prev->next = new_se;
    }

    /* Adjust everything after this point */
    for (se = new_se; se; se = se->next)
	se->nodes += adj;
}

static
long find_hole(struct sched_event_t *head, long time, int nodes) {
    long start = -1;
    struct sched_event_t *se;
    /* Find a hole in our schedule to stick this job in */
    for (se = head; se; se = se->next) {
	/* If we're in a hole and it's big enough, return the start */
	if (start != -1 && se->time > start + time)
	    return start;
	if (se->nodes >= nodes) {
	    if (start == -1) start = se->time;
	} else {
	    start = -1;
	}
    }
    return start;
}

static
void print_schedule(struct sched_event_t *head) {
    struct sched_event_t *se;
    printf("-----------------\n");
    for (se = head; se; se = se->next)
	printf("t=%6ld n=%6d\n", se->time, se->nodes);
}

static
int filler_schedule(struct bjs_pool_t *p) {
    int i;
    struct list_head *l, *next;
    struct bjs_job_t *j;
    struct sched_event_t selist;
    int total_nodes, nodes;
    int did_something = 0;
    long time_rem, time_reqd, now, start;

    now = time(0);

    /* Kill off jobs who's time has expired */
    for (l = p->jobs.next; l != &p->jobs; l = next) {
	next = l->next;
	j = list_entry(l, struct bjs_job_t, plist);
	if (j->start_time && j->priority >= 0) {
	    time_reqd = strtol(bjs_job_req(j, "secs", "0"), 0, 0);
	    if (now - j->start_time >= time_reqd) {
		/* Keep it really simple.  Kill it after its time is up */
		bjs_job_remove(j);
		did_something = 1;
	    }
	}
    }

    /* Count how many nodes in my pool are up */
    total_nodes = 0;
    for (i=0; i < p->nnodes; i++) {
	if (bjs_node_up(p->nodes[i]))
	    total_nodes++;
    }

    /* Initialize the schedule */
    selist.next = selist.prev = 0;
    selist.time = 0;
    selist.nodes = total_nodes;

    /* Add all the running jobs */
    for (l = p->jobs.next; l != &p->jobs; l = l->next) {
	j = list_entry(l, struct bjs_job_t, plist);
	if (!bjs_job_is_running(j)) continue;

	time_reqd = strtol(bjs_job_req(j, "secs", "0"), 0, 0);
	time_rem = time_reqd - (now - j->start_time);
	if (time_rem <= 0) time_rem = 1;

	nodes = strtol(bjs_job_req(j, "nodes", "1"), 0, 0);

	/* Add these nodes to the schedule */
	add_sched_event(&selist, 0, -nodes);
	add_sched_event(&selist, time_rem, nodes);
    }

    print_schedule(&selist);

    /* Start scheduling the waiting jobs... */
    for (l = p->jobs.next; l != &p->jobs; l = l->next) {
	j = list_entry(l, struct bjs_job_t, plist);
	if (bjs_job_is_running(j)) continue;
	if (!bjs_job_runnable(j))  continue;

	nodes     = strtol(bjs_job_req(j, "nodes", "1"), 0, 0);
	time_reqd = strtol(bjs_job_req(j, "secs",  "1"), 0, 0);

	start = find_hole(&selist, time_reqd, nodes);

	if (start == -1) continue; /* no room for this thing */

	add_sched_event(&selist, start, -nodes);
	add_sched_event(&selist, start + time_reqd, nodes);
	if (start == 0) {
	    /* Find nodes and start it now */
	    for (i=0; i < p->nnodes && nodes; i++) {
		if (bjs_node_idle(p->nodes[i])) {
		    bjs_node_allocate(j, p->nodes[i], 1);
		    nodes--;
		}
	    }

	    bjs_start_job(j);
	    did_something=1;
	}
    }

    print_schedule(&selist);

    /* Free the schedule */
    while (selist.next) {
	struct sched_event_t *tmp;
	tmp = selist.next;
	selist.next = tmp->next;
	free(tmp);
    }
    return did_something;
}

struct policy_ops_t policy = {
    name     : "filler",
    submit   : filler_submit,
    remove   : filler_remove,
    timeout  : filler_timeout,
    schedule : filler_schedule
};

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
