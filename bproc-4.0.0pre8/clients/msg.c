/*-------------------------------------------------------------------------
 *  msg.c:  msg functions taken from Beowulf distributed PID space master daemon
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: master.c,v 1.156 2004/10/18 20:02:24 mkdist Exp $
 *-----------------------------------------------------------------------*/

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <sys/un.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#define SYSLOG_NAMES 1
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sched.h>

#include "bproc.h"

static
struct bproc_message_hdr_t *req_get(int size)
{
	struct bproc_message_hdr_t *req;
	req = malloc(sizeof(*req) + size);
	memset(req, 0, sizeof(*req) + size);
	req->size = sizeof(*req) + size;
	return req;
}

static
struct bproc_message_hdr_t *req_clone(struct bproc_message_hdr_t *msg)
{
	struct bproc_message_hdr_t *req;
	/* use req_get in case the free list comes back */
	req = req_get(msg->size);
	memcpy(req, msg, msg->size + sizeof(*req));
	return req;
}

static
void req_free(struct bproc_message_hdr_t *req)
{
	free(req);
}

static
struct bproc_message_hdr_t *bproc_new_req(int type, int size)
{
	struct bproc_message_hdr_t *msg;
	msg = req_get(size);
	msg->req = type;
	msg->id = 0;
	msg->result = 0;	/* cosmetic for debugging */
	/* Zero out the routing stuff for paranoia  XXX DEBUGGING */
	msg->totype = msg->fromtype = 0;
	msg->to = msg->from = 0;
	return msg;
}

static
struct bproc_message_hdr_t *bproc_new_resp(struct bproc_message_hdr_t *req_msg, int size)
{
	struct bproc_message_hdr_t *resp_msg;

	resp_msg = req_get(size);
	resp_msg->req = BPROC_RESPONSE(req_msg->req);
	resp_msg->id = req_msg->id;
	resp_msg->size = size;
	resp_msg->result = 0;
	resp_msg->totype = req_msg->fromtype;
	resp_msg->to = req_msg->from;
	resp_msg->fromtype = req_msg->totype;
	resp_msg->from = req_msg->to;
	return resp_msg;
}

struct bproc_message_hdr_t *
read_req(int fd)
{
	struct bproc_message_hdr_t m;
	struct bproc_message_hdr_t *msg;
	int left;

	if (read(fd, &m, sizeof(m)) < sizeof(m))
		return NULL;

	msg = req_get(m.size);

	if (! msg)
		return;
	*msg = m;

	left = msg->size - sizeof(m);
	if (suck_it_in(fd, &msg[1], left) < left) {
		req_free(msg);
		return NULL;
	}
	return msg;
}
/* testing for same */
int
bproc_nodelist_uds(struct bproc_node_set_t *ns, int fd)
{
	/* create a request, send to bpmaster, get response. how much easier could it be? */

	struct bproc_message_hdr_t *req;
	struct bproc_nodestatus_resp_t *resp;

	bproc_nodeset_init(ns, 0);	/* make this safe to use grow */

	req = bproc_new_req(BPROC_GET_STATUS, 0);
	if (! req)
		return -1;

	if (push_it_out(fd, req, sizeof(*req)) < sizeof(*req))
		return -1;

	resp = (struct bproc_nodestatus_resp_t *)read_req(fd);
	if (! resp)
		return -1;

	if (bproc_nodeset_grow(ns, resp->numnodes)) {
		bproc_nodeset_free(ns);	/* we may have allocated stuff earlier */
		return -1;
	}

	memcpy(ns->node, resp->node, resp->numnodes*sizeof(*ns->node));
	ns->size = resp->numnodes;

	return resp->numnodes;
}
