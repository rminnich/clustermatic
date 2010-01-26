/*-------------------------------------------------------------------------
 *  db.c:  A request pretty printer for debugging purposes.
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
 * $Id: db.c,v 1.43 2003/11/03 21:44:10 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include "bproc.h"
#include <sys/bproc.h>

#include <netinet/in.h>		/* for htonl,etc */
#include <arpa/inet.h>

static FILE *tracefile = 0;

#define D_(x) #x
#define D(x) { x, D_(x) }
struct desc_t {
	int req;
	char *name;
};

static
struct desc_t descs[] = {
	D(BPROC_MOVE),
	D(BPROC_MOVE_COMPLETE),
	D(BPROC_EXEC),

	D(BPROC_FWD_SIG),
	D(BPROC_GET_STATUS),

	D(BPROC_SYS_FORK),
	D(BPROC_SYS_KILL),
	D(BPROC_SYS_WAIT),
	D(BPROC_SYS_GETSID),
	D(BPROC_SYS_SETSID),
	D(BPROC_SYS_GETPGID),
	D(BPROC_SYS_SETPGID),

	D(BPROC_STOP),
	D(BPROC_WAIT),
	D(BPROC_CONT),
	D(BPROC_EXIT),

	D(BPROC_PARENT_EXIT),
	D(BPROC_CHILD_ADD),
	D(BPROC_CHILD_DEL),
	D(BPROC_PGRP_CHANGE),
	D(BPROC_PTRACE),
	D(BPROC_SET_CREDS),
	D(BPROC_ISORPHANEDPGRP),

	D(BPROC_NODE_PING),
	D(BPROC_NODE_DOWN),
	D(BPROC_NODE_EOF),
	D(BPROC_NODE_RECONNECT),

	D(BPROC_NODE_CHROOT),

	D(BPROC_NODE_REBOOT),
	D(BPROC_NODE_HALT),
	D(BPROC_NODE_PWROFF),
	{0,}
};

static char *ptrace_types[] = {
	"traceme",		/* 0 */
	"peektext",
	"peekdata",
	"peekuser",
	"poketext",

	"pokedata",		/* 5 */
	"pokeuser",
	"cont",
	"kill",
	"step",

	"10",			/* 10 */
	"11",
#ifdef __i386__
	"getregs",
	"setregs",
	"getfpregs",

	"setfpregs",		/* 15 */
#else
	"12",
	"13",
	"14",

	"15",			/* 15 */
#endif
	"attach",
	"detach",
	"18",
	"19",

	"20",			/* 20 */
	"21",
	"22",
	"23",
	"syscall"
};

void msgtrace_on(int fd)
{
	tracefile = fdopen(fd, "w");
}

static time_t start = 0;

static
const char *msg_name(int req)
{
	int i;
	static char unknown[20];
	req = BPROC_REQUEST(req);
	for (i = 0; descs[i].req; i++) {
		if (descs[i].req == req)
			return descs[i].name + 6;	/* remove BPROC_ */
	}
	sprintf(unknown, "?? (%d)", req);
	return unknown;
}

void msgtrace(struct bproc_request_t *req, char *src)
{
	if (!tracefile)
		return;

	if (start == 0)
		start = time(0);

	fprintf(tracefile, "%ld: %s: %c%5d->%c%5d %p %5ld ",
		time(0) - start, src,
		(req->fromtype == BPROC_ROUTE_REAL) ? 'R' :
		(req->fromtype == BPROC_ROUTE_NODE) ? 'N' :
		(req->fromtype == BPROC_ROUTE_GHOST) ? 'G' : '?',
		req->from,
		(req->totype == BPROC_ROUTE_REAL) ? 'R' :
		(req->totype == BPROC_ROUTE_NODE) ? 'N' :
		(req->totype == BPROC_ROUTE_GHOST) ? 'G' : '?',
		req->to, req->id, req->result);
	fprintf(tracefile, "%-10s %c", msg_name(req->req),
		BPROC_ISRESPONSE(req->req) ? 'R' : ' ');

	switch (req->req) {
	case BPROC_MOVE:
	case BPROC_EXEC:
		fprintf(tracefile, "addr=%d.%d.%d.%d:%d chld=%d o/ppid=%d/%d",
			(htonl(req->bpr_move_addr) >> 24) & 0xFF,
			(htonl(req->bpr_move_addr) >> 16) & 0xFF,
			(htonl(req->bpr_move_addr) >> 8) & 0xFF,
			ntohl(req->bpr_move_addr) & 0xFF,
			(int)ntohs(req->bpr_move_port), req->bpr_move_children,
			req->bpr_move_ppid, req->bpr_move_oppid);
		break;
	case BPROC_SYS_FORK:
		fprintf(tracefile, "flags=0x%lx", req->bpr_rsyscall_arg[0]);
		break;
	case BPROC_RESPONSE(BPROC_SYS_FORK):
		fprintf(tracefile, "oppid=%d ppid=%d",
			req->bpr_move_oppid, req->bpr_move_ppid);
		break;
	case BPROC_STOP:
		fprintf(tracefile, "exit code=%d", req->bpr_status_exit_code);
		break;
	case BPROC_WAIT:
		fprintf(tracefile, "pid=%ld", req->bpr_rsyscall_arg[0]);
		break;
	case BPROC_SYS_WAIT:
		fprintf(tracefile, "pid=%ld options=0x%lx",
			req->bpr_rsyscall_arg[0], req->bpr_rsyscall_arg[1]);
		break;
	case BPROC_FWD_SIG:
		fprintf(tracefile, "sig=%d", req->bpr_sig_info.si_signo);
		break;
	case BPROC_NODE_RECONNECT:{
			struct in_addr addr;
			addr.s_addr = req->bpr_conn.raddr;
			fprintf(tracefile, "r%s:%d", inet_ntoa(addr),
				htons(req->bpr_conn.rport));
			addr.s_addr = req->bpr_conn.laddr;
			fprintf(tracefile, ",l%s:%d", inet_ntoa(addr),
				htons(req->bpr_conn.lport));
		} break;
#if 0
	case BPROC_NODE_INFO:
		fprintf(tracefile, "node=%d", req->bpr_node);
		break;
#endif
#if 0
	case BPROC_PROC_INFO:
		fprintf(tracefile, "first=%d node=%d", req->bpr_proc[0].pid,
			req->bpr_proc[0].node);
		break;
#endif
	case BPROC_SYS_KILL:
		fprintf(tracefile, "pid=%d sig=%d", req->bpr_sig_pid,
			req->bpr_sig_info.si_signo);
		break;
	case BPROC_PTRACE:
		fprintf(tracefile, "%-8.8s pid=%d %08lx %08lx",
			ptrace_types[req->bpr_ptrace_req],
			(int)req->bpr_ptrace_pid, req->bpr_ptrace_addr,
			req->bpr_ptrace_data);
		break;
	}
	fprintf(tracefile, "\n");
	fflush(tracefile);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
