/*-------------------------------------------------------------------------
 *  master.c:  Beowulf distributed PID space master daemon
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: bpctl.c,v 1.25 2003/09/11 19:02:18 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <netdb.h>
#include <sys/bproc.h>

static struct bproc_node_set_t node_list = BPROC_EMPTY_NODESET;

static
void Usage(char *arg0) {
    printf(
"Usage: %s [options]\n"
"  -h,--help              Print this message and exit\n"
"  -v,--version           Print version information and exit\n"
"  -M,--master            Send a command to the master node\n"
"  -S num,--slave num     Send a command to slave node num\n"
"\n"
"  -s state,--state state Set the state of the node to state\n"
"  -r dir,--chroot dir    Cause slave daemon to chroot to dir\n"
"  -R,--reboot            Reboot the slave node\n"
"  -H,--halt              Halt the slave node\n"
"  -P,--pwroff            Power off the slave node\n"
"  --reconnect master[:port[,local[:port]]] \n"
"                         Reconnect to front end.\n"
"\n"
"  -m mode,--mode mode    Set the permission bits of a node\n"
"  -u user,--user user    Set the user ID of a node\n"
"  -g group,--group group Set the group ID of a node\n"
,arg0);
}

static int slave_chroot(int node, void *path) {
    return bproc_nodechroot(node, (char *) path);
}

static int slave_set_status(int node, void *arg) {
    return bproc_nodesetstatus(node, arg);
}

static int slave_reboot(int node, void *arg) {
    return bproc_nodereboot(node);
}

static int slave_halt(int node, void *arg) {
    return bproc_nodehalt(node);
}

static int slave_pwroff(int node, void *arg) {
    return bproc_nodepwroff(node);
}

static int slave_set_mode(int node, void *arg) {
    return bproc_chmod(node, (long) arg);
}

static int slave_set_user_id(int node, void *arg) {
    return bproc_chown(node, (long) arg);
}

static int slave_set_group_id(int node, void *arg) {
    return bproc_chgrp(node, (long) arg);
}

struct addr_struct {
    struct sockaddr_in rem;
    struct sockaddr_in loc;
} addr;

static
int slave_reconnect_argprocess(char *arg) {
    char remhost[100], lochost[100];
    int remport=0, locport=0;
    struct hostent *h;

    remhost[0] = lochost[0] = 0;
    addr.rem.sin_family = addr.loc.sin_family = AF_INET;

    sscanf(arg, "%[^:, ]:%d,%[^:, ]:%d",
	   remhost, &remport, lochost, &locport);
    /* Conververt host names to IP addresses */
    if (remhost[0]) {
	if (!(h = gethostbyname(remhost))) {
	    fprintf(stderr, "%s: %s\n", remhost, hstrerror(h_errno));
	    return -1;
	}
	memcpy(&addr.rem.sin_addr, h->h_addr_list[0], h->h_length);
    } else
	addr.rem.sin_addr.s_addr = INADDR_NONE;
    /* I may want to do a services lookup here if I'm feeling really anal. */
    addr.rem.sin_port = htons(remport);

    if (lochost[0]) {
	if (!(h = gethostbyname(lochost))) {
	    fprintf(stderr, "%s: %s\n", remhost, hstrerror(h_errno));
	    return -1;
	}
	memcpy(&addr.loc.sin_addr, h->h_addr_list[0], h->h_length);
    } else
	addr.loc.sin_addr.s_addr = INADDR_NONE;
    addr.loc.sin_port = htons((uint16_t)locport);
    return 0;
}

static int slave_reconnect(int node, void *_arg) {
    struct addr_struct *arg = _arg;
    return bproc_nodereconnect(node,
			       (struct sockaddr *)&arg->rem, sizeof(arg->rem),
			       (struct sockaddr *)&arg->loc, sizeof(arg->loc));
}

static
int do_func(int (*func)(int node, void *arg), void *arg) {
    int i, node, err = 0;
    for (i=0; i < node_list.size; i++) {
	node = node_list.node[i].node;
	if (func(node, arg)) {
	    fprintf(stderr, "%d: %s\n", node, bproc_strerror(errno));
	    err = -1;
	}
    }
    return err;
}

static
long check_strtol(const char *str, int base) {
    long result;
    char *check;
    result = strtol(str, &check, base);
    if (*check) {
	fprintf(stderr, "Invalid number: %s\n", str);
	exit(1);
    }
    return result;
}



int main(int argc, char *argv[]) {
    int c,id,mode, err=0;
    char *check;
    struct passwd *pw;
    struct group  *gr;

    static struct option long_options[] = {
	{"help",    0, 0, 'h'},
	{"version", 0, 0, 'v'},

	{"master",  0, 0, 'M'},
	{"slave",   1, 0, 'S'},

	{"state",   1, 0, 's'},
	{"chroot",  1, 0, 'r'},

	{"reboot",  0, 0, 'R'},
	{"halt",    0, 0, 'H'},
	{"pwroff",  0, 0, 'P'},

	{"mode",    1, 0, 'm'},
	{"user",    1, 0, 'u'},
	{"group",   1, 0, 'g'},

	{"reconnect", 1, 0, 3},
	{ 0, 0, 0, 0}
    };

    while ((c=getopt_long(argc, argv, "hvVMS:r:s:RHPm:u:g:f",
			  long_options, 0)) != EOF) {
	switch(c) {
	case 'h':
	    Usage(argv[0]);
	    exit(0);
	case 'V':
	case 'v':
	    printf("%s version %s\n", argv[0], PACKAGE_VERSION);
	    exit(0);
	case 'M':
	    if (bproc_nodespec(&node_list, "master"))
		exit(1);
	    break;
	case 'S':
	    if (bproc_nodespec(&node_list, optarg))
		exit(1);
	    break;
	    
	case 'r':
	    err |= do_func(slave_chroot, optarg);
	    break;
	case 's':
	    err |= do_func(slave_set_status, (void *)optarg);
	    break;
	case 'R':
 	    err |= do_func(slave_reboot, 0);
	    break;
	case 'H':
 	    err |= do_func(slave_halt, 0);
	    break;
	case 'P':
	    err |= do_func(slave_pwroff, 0);
	    break;
	case 'm':
	    mode = check_strtol(optarg, 8);
	    err |= do_func(slave_set_mode, (void*)(long)mode);
	    break;
	case 'u':
	    pw = getpwnam(optarg);
	    if (pw) {
		id = pw->pw_uid;
	    } else {
		id = strtol(optarg, &check, 0);
		if (*check) {
		    fprintf(stderr, "Invalid user id: %s\n", optarg);
		    exit(1);
		}
	    }
	    err |= do_func(slave_set_user_id, (void *) (long) id);
	    break;
	case 'g':
	    gr = getgrnam(optarg);
	    if (gr) {
		id = gr->gr_gid;
	    } else {
		id = strtol(optarg, &check, 0);
		if (*check) {
		    fprintf(stderr, "Invalid user id: %s\n", optarg);
		    exit(1);
		}
	    }
	    err |= do_func(slave_set_group_id, (void*)(long)id);
	    break;
	case 3:
	    if (slave_reconnect_argprocess(optarg)) {
		fprintf(stderr, "Invalid argument: %s\n", optarg);
		exit(1);
	    }
	    err |= do_func(slave_reconnect, &addr);
	    break;
	case 'f':     /* ignore silently for backward compatibility */
	    break;
	default:
	    exit(1);
	}
    }
    exit( err ? 1 : 0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
