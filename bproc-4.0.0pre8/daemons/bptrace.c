#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <sys/ptrace.h>
#if 0
#include <linux/ptrace.h>	/* sys/ptrace.h is incomplete... */
#endif

#include "list.h"
#include "debug.h"
#include "bproc.h"

#include "messages.h"		/* daemon-only messages */

static int errs = 0;		/* error counter for exit status */
static int verbose_moves = 0;	/* print lots of guts on move messages */
static int no_strings = 0;	/* control string lookups */


static
long read_all(int fd, void *buf, long count) {
    long r, bytes = count;
    while (bytes) {
	r = read(fd, buf, bytes);
	if (r < 0)  return r;
	if (r == 0) return count - bytes;
	bytes -= r; buf += r;
    }
    return count;
}

/**-------------------------------------------------------------------
 **  Request pretty printer
 **-----------------------------------------------------------------*/
#include <arpa/inet.h>
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
    D(BPROC_PGRP_CHANGE),
    D(BPROC_PTRACE),
    D(BPROC_REPARENT),
    D(BPROC_SET_CREDS),
    D(BPROC_ISORPHANEDPGRP),

    D(BPROC_VERSION),
    D(BPROC_NODE_CONF),
    D(BPROC_NODE_PING),
    D(BPROC_NODE_DOWN),
    D(BPROC_NODE_EOF),
    D(BPROC_NODE_RECONNECT),
    
    D(BPROC_NODE_CHROOT),

    D(BPROC_NODE_REBOOT),
    D(BPROC_NODE_HALT),
    D(BPROC_NODE_PWROFF),
    {-1,}
};

static
struct desc_t descs_ptrace[] = {
    D(PTRACE_TRACEME),
    D(PTRACE_PEEKTEXT),
    D(PTRACE_PEEKDATA),
    D(PTRACE_PEEKUSER),
    D(PTRACE_POKETEXT),
    D(PTRACE_POKEDATA),
    D(PTRACE_POKEUSER),
    D(PTRACE_CONT),
    D(PTRACE_KILL),
    /*D(PTRACE_STEP),*/
#if defined(__i386__) || defined(__x86_64__)
    D(PTRACE_GETREGS),
    D(PTRACE_SETREGS),
    D(PTRACE_GETFPREGS),
    D(PTRACE_SETFPREGS),
    D(PTRACE_GETFPXREGS),
    D(PTRACE_SETFPXREGS),
#endif
    D(PTRACE_ATTACH),
    D(PTRACE_DETACH),
    D(PTRACE_SYSCALL),
#if 0
    D(PTRACE_SETOPTIONS),
    D(PTRACE_GETEVENTMSG),
    D(PTRACE_GETSIGINFO),
    D(PTRACE_SETSIGINFO),
#endif
    {-1,}
};

static
char *msg_dst_names[] = { ">K", "K>", ">S", "S>", ">M", "M>", "--"};

static
const char *desc_lookup(struct desc_t *list, int key) {
    char *p;
    static char unknown[20];
    if (!no_strings) {
	while (list->req != -1) {
	    if (list->req == key) {
		p = strchr(list->name, '_');
		return p ? p + 1 : list->name;
	    }
	    list++;
	}
    }
    sprintf(unknown, "0x%x", key);
    return unknown;
}

static inline
struct bproc_credentials_t *creds_ptr(void *ptr, int offset) {
    return (struct bproc_credentials_t *)(ptr + offset);
}
#define ROUND_UP(x,y) (((x)+(y)-1) & ~((y)-1))
int creds_struct_size(struct bproc_credentials_t *creds) {
    int s;
    s = sizeof(*creds) + creds->ngroups * sizeof(creds->groups[0]);
    return ROUND_UP(s, sizeof(void*));
}

static
void print_creds(struct bproc_message_hdr_t *msg, int offset) {
    void *end;
    struct bproc_credentials_t *creds;

    if (offset == 0) {
	printf("	    (not present)\n");
	return;
    }

    end = ((void *)msg) + msg->size;
    creds = creds_ptr(msg, offset);
    if (((void *)creds) <= ((void *)msg) ||
	((void *)(creds+1)) > end ||
	(((void *)creds)+ creds_struct_size(creds)) > end) {
	fprintf(stderr, "Invalid/truncated credential pointer\n");
	return;
    }
    printf("		 r/e/s/fuid=%d/%d/%d/%d\n",
	   creds->uid, creds->euid, creds->suid, creds->fsuid);
    printf("		 r/e/s/fgid=%d/%d/%d/%d\n",
	   creds->gid, creds->egid, creds->sgid, creds->fsgid);
    printf("		 cap_effective=0x%x  dumpable=%d\n",
	   creds->cap_effective, creds->dumpable);
}


static
void print_message(struct debug_hdr_t *req) {
    struct in_addr in_addr;
    struct bproc_message_hdr_t *hdr;

    hdr = bproc_debug_msg(req);
    printf("  %d.%03d:%4d: ",(int) req->time.tv_sec,
	   (int) req->time.tv_usec/1000, hdr->size);

    if (req->tofrom == BPROC_DEBUG_OTHER) {
	switch(hdr->req) {
	case 1000: {
	    struct bproc_debug_1000_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("Process move %d  %d -> %d",msg->pid,msg->last,msg->node);
	    } break;
	default:
	    printf(" ???? ");
	}
    } else {
	/* Routing */
	printf("%8p %s %4d %c%5d->%c%5d\t",
	       hdr->id, msg_dst_names[req->tofrom], req->node,
	       (hdr->fromtype == BPROC_ROUTE_REAL) ? 'R' :
	       (hdr->fromtype == BPROC_ROUTE_NODE) ? 'N' : 
	       (hdr->fromtype == BPROC_ROUTE_GHOST)? 'G' : '?',
	       hdr->from,
	       (hdr->totype == BPROC_ROUTE_REAL) ? 'R' :
	       (hdr->totype == BPROC_ROUTE_NODE) ? 'N' : 
	       (hdr->totype == BPROC_ROUTE_GHOST)? 'G' : '?',
	       hdr->to);

	printf("%-13s %c %4ld\t",
	       desc_lookup(descs, BPROC_REQUEST(hdr->req)),
	       BPROC_ISRESPONSE(hdr->req) ? 'R' : ' ', hdr->result);

	/* Misc message details */
	switch(hdr->req) {
	case BPROC_VERSION: {
	    struct bproc_version_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("%s-%u-%d  %Ld", msg->vers.version_string,
		   (int) msg->vers.magic, (int) msg->vers.arch,
		   (long long) msg->cookie);
	    } break;
	case BPROC_NODE_CONF: {
	    struct bproc_conf_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("time=%ld.%06ld ping=%d masters=%d@%d",
		   msg->time_sec, msg->time_usec,
		   msg->ping_timeout, msg->masters_size, msg->masters);
	    } break;
	case BPROC_NODE_PING: {
	    struct bproc_ping_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("time=%ld.%06ld", msg->time_sec, msg->time_usec);
	    } break;

	case BPROC_MOVE: {
	    struct bproc_move_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    in_addr.s_addr = msg->addr;
	    printf("pid=%d ppid=%d addr=%s:%d chld=%d o/ppid=%d/%d",
		   msg->pid, msg->ppid, inet_ntoa(in_addr),
		   (int) ntohs(msg->port),
		   msg->children, msg->ppid, msg->oppid);
	    if (verbose_moves) {
		printf("	  exit signal = %d\n", msg->exit_signal);
		printf("\n");
		printf("	  call_creds (@%d)\n", msg->call_creds);
		print_creds(hdr, msg->call_creds);
		printf("	  proc_creds (@%d)\n", msg->proc_creds);
		print_creds(hdr, msg->proc_creds);
	    }
	    } break;
	case BPROC_EXEC: {
#if 0
	    in_addr.s_addr = req->req.bpr_move_addr;
	    printf("addr=%s:%d chld=%d o/ppid=%d/%d",
		   inet_ntoa(in_addr), (int) ntohs(req->req.bpr_move_port),
		   req->req.bpr_move_children,
		   req->req.bpr_move_ppid, req->req.bpr_move_oppid);
#endif
	    } break;
	case BPROC_RESPONSE(BPROC_MOVE): {
	    struct bproc_move_msg_t *msg;
	    msg = bproc_debug_msg(req);

	    /* Move responses can be small... */
	    if (msg->hdr.size >= sizeof(*msg)) {
		in_addr.s_addr = msg->addr;
		printf("addr=%s:%d",
		       inet_ntoa(in_addr), (int) ntohs(msg->port));
		
		if (verbose_moves) {
		    printf("\n");
		    printf("	      call_creds (@%d)\n", msg->call_creds);
		    print_creds(hdr, msg->call_creds);
		    printf("	      proc_creds (@%d)\n", msg->proc_creds);
		    print_creds(hdr, msg->proc_creds);
		}
	    }
	    } break;
	case BPROC_SYS_FORK: {
	    struct bproc_rsyscall_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("flags=0x%lx", msg->arg[0]);
	    } break;
	case BPROC_RESPONSE(BPROC_SYS_FORK): {
	    struct bproc_fork_resp_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("oppid=%d ppid=%d", msg->oppid, msg->ppid);
	    } break;

	case BPROC_SYS_WAIT: {
	    struct bproc_rsyscall_msg_t *msg;
	    msg = bproc_debug_msg(req);
	    printf("pid=%ld options=0x%lx", msg->arg[0], msg->arg[1]);
	    } break;

	case BPROC_PTRACE: {
	    struct bproc_ptrace_msg_t *msg = bproc_debug_msg(req);
	    printf("%-8.8s pid=%d addr=0x%lx data=0x%lx",
		   desc_lookup(descs_ptrace, msg->request),
		   msg->hdr.to, msg->addr, msg->data.data[0]);
	    if (msg->request == PTRACE_ATTACH) {
		printf(" uid=%d gid=%d ce=0x%x", msg->uid, msg->gid,
		       msg->cap_effective);
	    }
	    } break;
	case BPROC_RESPONSE(BPROC_PTRACE): {
	    struct bproc_ptrace_msg_t *msg = bproc_debug_msg(req);
	    printf("%-8.8s",
		   desc_lookup(descs_ptrace, msg->request));
	    if (msg->request == PTRACE_ATTACH) {
		printf(" nlchild_adj=%d", msg->data.data ? 1 : 0);
	    }
	    if (msg->request == PTRACE_PEEKDATA ||
		msg->request == PTRACE_PEEKTEXT) {
		int i;
		printf(" addr=0x%0*lx bytes=%d",
		       (int) sizeof(long) * 2, msg->addr, msg->bytes);
		for (i=0; i < msg->bytes / sizeof(int) ; i++) 
		    printf(" %0*lx", (int)sizeof(int)*2,
			   ((int *)msg->data.data)[i]);
	    }
	    } break;
	case BPROC_REPARENT: {
	    struct bproc_reparent_msg_t *msg = bproc_debug_msg(req);
	    printf("ptrace=0x%x new_parent=%d", msg->ptrace, msg->new_parent);
	    } break;

	case BPROC_FWD_SIG: {
	    struct bproc_signal_msg_t *sig = bproc_debug_msg(req);
	    printf("sig = %d   kill: pid=%d uid=%d",
		   sig->info.si_signo, sig->info._sifields._kill._pid,
		   sig->info._sifields._kill._uid);
	    } break;
	case BPROC_SYS_SETPGID: {
	    struct bproc_rsyscall_msg_t *msg = bproc_debug_msg(req);
	    printf("pid=%ld pgid=%ld", msg->arg[0], msg->arg[1]);
	    } break;
	case BPROC_SYS_GETPGID: {
	    struct bproc_rsyscall_msg_t *msg = bproc_debug_msg(req);
	    printf("pid=%ld", msg->arg[0]);
	    } break;
	case BPROC_PGRP_CHANGE: {
	    struct bproc_pgrp_msg_t *msg = bproc_debug_msg(req);
	    printf("pgid=%d", msg->pgid);
	    } break;
	case BPROC_SYS_KILL: {
	    struct bproc_signal_msg_t *msg = bproc_debug_msg(req);
	    printf("pid=%d sig=%d", msg->pid, msg->info.si_signo);
	    } break;
        case BPROC_STOP:
	case BPROC_CONT:
	case BPROC_RESPONSE(BPROC_GET_STATUS): {
	    struct bproc_status_msg_t *msg = bproc_debug_msg(req);
	    printf("state=%d exit_code=0x%x (vm=%ld %ld)",
		   msg->state, msg->exit_code,
		   msg->vm.statm.size, msg->vm.status.total_vm);
	    } break;
	}
    }
    printf("\n");
    fflush(stdout);
}

/**-------------------------------------------------------------------
 **  Move status checking code.
 **-----------------------------------------------------------------*/
struct move_t {
    struct list_head list;
    void *id;
    struct debug_hdr_t *move_req;
    struct debug_hdr_t *move_resp;
};

static LIST_HEAD(moves);

static
struct move_t *move_find(void *id) {
    struct move_t *mv;
    struct list_head *l;
    for (l = moves.next; l != &moves; l = l->next) {
	mv = list_entry(l, struct move_t, list);
	if (mv->id == id)
	    return mv;
    }
    return 0;
}

static
struct debug_hdr_t * msgdup(struct debug_hdr_t *dbg) {
    struct debug_hdr_t *new;
    struct bproc_message_hdr_t *msg;

    msg = bproc_debug_msg(dbg);

    new = malloc(sizeof(*new) + msg->size);
    if (!new) {
	fprintf(stderr, "Out of memory allocating %d bytes.\n",
		(int) (sizeof(*new) + msg->size));
	exit(1);
    }
    memcpy(new, dbg, sizeof(*new) + msg->size);
    return new;
}

static
void move_msg(struct debug_hdr_t *req) {
    struct move_t *mv;
    struct bproc_message_hdr_t *hdr, *hdr2;

    /* only look at the outgoing messages for this */
    if (req->tofrom == BPROC_DEBUG_MSG_FROM_KERNEL ||
	req->tofrom == BPROC_DEBUG_MSG_FROM_SLAVE)
	return;

    switch (hdr->req) {
    case BPROC_MOVE:
	mv = malloc(sizeof(*mv));
	memset(mv, 0, sizeof(*mv));

	mv->id = hdr->id;
	mv->move_req = msgdup(req);
	list_add(&mv->list, &moves);
	break;
    case BPROC_RESPONSE(BPROC_MOVE):
	mv = move_find(hdr->id);
	if (!mv) {
	    printf("No move request for move response id=%p\n", hdr->id);
	    print_message(req);
	    errs++;
	    return;
	}
	hdr2 = bproc_debug_msg(mv->move_resp);
	if (hdr2->id != 0) {
	    printf("Two move responses for move id=%p\n", hdr->id);
	    print_message(req);
	    errs++;
	    return;
	}

	if (hdr->result != 0) {
	    printf("Failed move.  Error code %d\n", (int) hdr->result);
	    print_message(req);
	    errs++;
	    return;
	}
	mv->move_resp = msgdup(req);
	break;
    case BPROC_RESPONSE(BPROC_MOVE_COMPLETE):
	mv = move_find(hdr->id);
	if (!mv) {
	    printf("No move request for move complete id=%p:\n", hdr->id);
	    print_message(req);
	    errs++;
	    return;
	}

	/* Toss this one since it's done and happy */
	list_del(&mv->list);
	if (mv->move_req) free(mv->move_req);
	if (mv->move_resp) free(mv->move_resp);
	free(mv);
	break;
    default:			/* ignore */
	break;
    }
}

static
void move_find_data_src(struct move_t *mv1) {
    struct move_t *mv;
    struct list_head *l;
    struct bproc_move_msg_t *mv1_msg, *msg;

    mv1_msg = bproc_debug_msg(mv1);
    /* Look *back* for a move response that fits the bill */
    for (l = mv1->list.prev; l != &mv1->list && l != &moves; l = l->prev) {
	mv = list_entry(l, struct move_t, list);

	msg = bproc_debug_msg(mv);

	if (msg->addr == mv1_msg->addr &&
	    msg->port == mv1_msg->port) {
	    print_message(mv->move_resp);
	    break;
	}
    }
}

static
void move_finished(void) {
    struct move_t *mv;
    struct list_head *l;
    for (l = moves.next; l != &moves; l = l->next) {
	mv = list_entry(l, struct move_t, list);

	if (!mv->move_resp) {
	    printf("Unfinished move:\n");
	    print_message(mv->move_req);
	    move_find_data_src(mv);
	}
    }
}

/**-------------------------------------------------------------------
 **  Loop finding code
 **    NOTE: this can get very memory intensive...
 **-----------------------------------------------------------------*/
struct loopctr_t {
    struct list_head list;
    void *	     id;
    unsigned char    fromtype;
    int		     from;
    int		     count;
    
    struct debug_hdr_t *msg;
};

static LIST_HEAD(loopctrs);

static
struct loopctr_t *loop_findctr(void *id, unsigned char fromtype, int from) {
    struct list_head *l;
    struct loopctr_t *lc;
    for (l = loopctrs.next; l != &loopctrs; l = l->next) {
	lc = list_entry(l, struct loopctr_t, list);
	if (lc->id == id && lc->fromtype == fromtype && lc->from == from)
	    return lc;
    }
    return 0;
}

static
void loop_check(struct debug_hdr_t *req) {
    struct loopctr_t *lc;
    struct bproc_message_hdr_t *hdr;
    if (req->tofrom == BPROC_DEBUG_OTHER) return; /* ignore these */

    lc = loop_findctr(hdr->id, hdr->fromtype, hdr->from);
    if (!lc) {
	lc = malloc(sizeof(*lc));
	lc->id	     = hdr->id;
	lc->fromtype = hdr->fromtype;
	lc->from     = hdr->from;
	lc->msg	     = msgdup(req);
	lc->count    = 0;
	list_add(&lc->list, &loopctrs);
    }
    lc->count++;
}

static
void loop_report(void) {
    struct list_head *l;
    struct loopctr_t *lc;
    for (l = loopctrs.next; l != &loopctrs; l = l->next) {
	lc = list_entry(l, struct loopctr_t, list);
	if (lc->count > 2) {
	    printf("Looping message:  (count=%d)\n", lc->count);
	    print_message(lc->msg);
	}
    }
}


struct debug_hdr_t *read_msg(int fileno) {
    int r;
    struct debug_hdr_t *dbg;
    struct bproc_message_hdr_t *hdr;
    char buffer[sizeof(*dbg) + sizeof(*hdr)];

    r = read_all(fileno, buffer, sizeof(buffer));
    if (r == 0) return 0;	/* End of file - ok. */
    if (r < 0) {
	fprintf(stderr, "read error: %s\n", strerror(errno));
	exit(1);
    }
    if (r != sizeof(buffer)) {
	fprintf(stderr, "Short read reading message header "
		"(expected %d; got %d).\n", (int) sizeof(buffer), r);
	exit(1);
    }

    dbg = (struct debug_hdr_t *)buffer;
    hdr = bproc_debug_msg(dbg);

    dbg = malloc(sizeof(*dbg) + hdr->size);
    if (!dbg) {
	fprintf(stderr, "Failed to allocate %d bytes for message.\n",
		(int)(sizeof(*dbg) + hdr->size));
	exit(1);
    }
    memcpy(dbg, buffer, sizeof(buffer));

    hdr = bproc_debug_msg(dbg);
    r = read_all(fileno, ((void*)dbg) + sizeof(buffer),
		 hdr->size - sizeof(*hdr));
    if (r < 0) {
	fprintf(stderr, "read error: %s\n", strerror(errno));
	exit(1);
    }
    if (r != hdr->size - sizeof(*hdr)) {
	fprintf(stderr, "Short read reading message body "
		"(expected %d; got %d).\n",(int)(hdr->size - sizeof(*hdr)),r);
	exit(1);
    }
    return dbg;
}

#define SHOW_SENDS 1
#define SHOW_RECVS 2
#define SHOW_NOISE 4
int main(int argc, char *argv[]) {
    int c;
    struct debug_hdr_t *dbg;
    int check_moves = 0;
    int print_all = 0;
    int find_loops = 0;
    int show = SHOW_NOISE | SHOW_SENDS | SHOW_RECVS;
    static struct option long_options[] = {
	{"help",  0, 0, 'h'},
	{"print", 0, 0, 'p'},

	{"verbose-moves", 0, 0, 1},
	{0,0,0,0}
    };

    while ((c = getopt_long(argc, argv, "hnmplis",
			    long_options, 0)) != -1) {
	switch (c) {
	case 'h':
	    printf(
"Usage: %s [options] < tracefile\n"
"    -h		  Display this message and exit.\n"
"    -p		  Print all messages.\n"
"    -n		  No string lookups.\n"
"    -m		  Find unfinished moves.\n"
"    -l		  Find messages in a loop.\n"
"    -i		  Ignore \"noise\" messages (ping, status, etc.)\n"
"    -s		  Show only message sends.\n"
,argv[0]);
	    exit(0);
	case 'n':
	    no_strings = 1;
	    break;
	case 'm':
	    check_moves = 1;
	    break;
	case 'p':
	    print_all = 1;
	    break;
	case 'l':
	    find_loops = 1;
	    break;
	case 'i':
	    show &= ~SHOW_NOISE;
	    break;
	case 's':
	    show &= ~SHOW_RECVS;
	    break;

	case 1:
	    verbose_moves = 1;
	    break;
	default:
	    exit(1);
	}
    }

    dbg = read_msg(STDIN_FILENO);
    while (dbg) {
	struct bproc_message_hdr_t *hdr;
	hdr = bproc_debug_msg(dbg);
	if (print_all) {
	    /* Printing filters */
	    if (!(show & SHOW_NOISE) &&
		(hdr->req == BPROC_GET_STATUS ||
		 hdr->req == BPROC_RESPONSE(BPROC_GET_STATUS) ||
		 hdr->req == BPROC_NODE_PING ||
		 hdr->req == BPROC_RESPONSE(BPROC_NODE_PING))) {
		goto skip_it;
	    }
	    if (!(show & SHOW_SENDS) &&
		(dbg->tofrom == BPROC_DEBUG_MSG_TO_KERNEL ||
		 dbg->tofrom == BPROC_DEBUG_MSG_TO_SLAVE  ||
		 dbg->tofrom == BPROC_DEBUG_MSG_TO_MASTER)) {
		goto skip_it;
	    }
	    
	    if (!(show & SHOW_RECVS) &&
		(dbg->tofrom == BPROC_DEBUG_MSG_FROM_KERNEL ||
		 dbg->tofrom == BPROC_DEBUG_MSG_FROM_SLAVE  ||
		 dbg->tofrom == BPROC_DEBUG_MSG_FROM_MASTER)) {
		goto skip_it;
	    }

	    print_message(dbg);
	}

	/* Analysis stuff */
	if (check_moves) move_msg(dbg);
	if (find_loops)	 loop_check(dbg);

	free(dbg);
    skip_it:
	dbg = read_msg(STDIN_FILENO);
    }

    if (check_moves) { move_finished(); }
    if (find_loops)  loop_report();
    exit(errs == 0 ? 0 : 1);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
