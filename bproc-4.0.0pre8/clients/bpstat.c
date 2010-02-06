/*-------------------------------------------------------------------------
 *  bpstat.c:  bproc status viewer
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: bpstat.c,v 1.27 2003/08/29 21:46:57 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>

#include "bproc.h"

static
char *ip2str(struct sockaddr_in *addr)
{
	static char buf[30];
	uint32_t laddr;
	laddr = ntohl(addr->sin_addr.s_addr);
	sprintf(buf, "%d.%d.%d.%d",
		(int)(laddr >> 24) & 0xFF, (int)(laddr >> 16) & 0xFF,
		(int)(laddr >> 8) & 0xFF, (int)(laddr) & 0xFF);
	return buf;
}

static
void print_nodes_long(struct bproc_node_info_t *ni, int num)
{
	int i;
	struct passwd *pwd;
	struct group *grp;
	char *user, *group, usernum[10], groupnum[10], mode[11];

	printf("Node Address         Status       Mode          "
	       "User       Group\n");
	for (i = 0; i < num; i++) {
		sprintf(mode, "---%c--%c--%c",
			ni[i].mode & S_IXUSR ? 'x' : '-',
			ni[i].mode & S_IXGRP ? 'x' : '-',
			ni[i].mode & S_IXOTH ? 'x' : '-');
		if ((pwd = getpwuid(ni[i].user))) {
			user = pwd->pw_name;
		} else {
			user = usernum;
			sprintf(usernum, "#%d", ni[i].user);
		}
		if ((grp = getgrgid(ni[i].group))) {
			group = grp->gr_name;
		} else {
			group = groupnum;
			sprintf(groupnum, "#%d", ni[i].group);
		}
		printf("%4d %-15s %-12s %s\t%-10.10s %-10.10s\n", ni[i].node,
		       ip2str((struct sockaddr_in *)&ni[i].addr),
		       ni[i].status, mode, user, group);
	}
	return;
}

static
int node_same_conf(struct bproc_node_info_t *a, struct bproc_node_info_t *b)
{
	return (strcmp(a->status, b->status) == 0 &&
		a->user == b->user &&
		a->group == b->group && a->mode == b->mode);
}

#define MODELEN 10		/* make it wide enough for the label */
#define USERLEN 8

static
void print_nodes_compact(struct bproc_node_info_t *node, int num)
{
	int i, j, k, first;
	char *nodes_str, *p, *orig;
	struct winsize sz;
	struct passwd *pwd;
	struct group *grp;
	char *user, *group, usernum[10], groupnum[10];
	char modestr[20];

	/* Column widths */
	static int cw[] = { 0, BPROC_STATE_LEN, MODELEN, USERLEN, USERLEN };

	/* Adjust column widths based on window size */
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &sz) != 0) {
		sz.ws_col = 80;
	}
	cw[0] = sz.ws_col - (cw[1] + cw[2] + cw[3] + cw[4] + 5);
	if (cw[0] < 11) {
		fprintf(stderr, "Window to small.\n");
		return;
	}

	if (cw[0] < 0)
		cw[0] = 0;
	nodes_str = alloca(cw[0] + 100);

	/* Print a nice header */
	printf("%-*s %-*s %-*s %-*s %-*s\n",
	       cw[0], "Node(s)", cw[1], "Status", cw[2], "Mode",
	       cw[3], "User", cw[4], "Group");

	/* Assumption: nodes numbered sequentially when all other features
	 * are the same. */
	for (i = 0; i < num;) {
		first = 1;
		nodes_str[0] = 0;
		p = nodes_str;
		/* Start a line with node state the same as node i */
		for (j = i; j < num && node_same_conf(&node[i], &node[j]); j++) {
			orig = p;
			/* This is the first node that's "equal" */
			p += sprintf(p, "%s%d", first ? "" : ",", node[j].node);
			first = 0;

			/* overflowed */
			if (p - nodes_str > cw[0]) {
				*orig = 0;
				break;
			}

			/* scan forward to see if we have a contiguous group */
			for (k = j + 1;
			     k < num && node_same_conf(&node[j], &node[k])
			     && node[k].node == node[k - 1].node + 1; k++) ;
			k--;	/* k points at last same node */
			if (k > j) {
				/* Runs of 2 or more are printed w/ dashes */
				p += sprintf(p, "-%d", node[k].node);
				if (p - nodes_str > cw[0]) {
					*orig = 0;
					break;
				}
				j = k;
			}
		}

		sprintf(modestr, "---%c--%c--%c",
			node[i].mode & S_IXUSR ? 'x' : '-',
			node[i].mode & S_IXGRP ? 'x' : '-',
			node[i].mode & S_IXOTH ? 'x' : '-');

		if ((pwd = getpwuid(node[i].user))) {
			user = pwd->pw_name;
		} else {
			user = usernum;
			sprintf(usernum, "#%d", node[i].user);
		}
		if ((grp = getgrgid(node[i].group))) {
			group = grp->gr_name;
		} else {
			group = groupnum;
			sprintf(groupnum, "#%d", node[i].group);
		}

		/* Print the node information */
		printf("%-*.*s %-*.*s %-*.*s %-*.*s %-*.*s",
		       cw[0], cw[0], nodes_str,
		       cw[1], cw[1], node[i].status,
		       cw[2], cw[2], modestr,
		       cw[3], cw[3], user, cw[4], cw[4], group);
		printf("\n");
		i = j;
	}
}

static
void print_nodes_address(struct bproc_node_info_t *ni, int num)
{
	int i;
	for (i = 0; i < num; i++)
		puts(ip2str((struct sockaddr_in *)&ni[i].addr));
}

static
void print_nodes_state(struct bproc_node_info_t *ni, int num)
{
	int i;
	for (i = 0; i < num; i++)
		puts(ni[i].status);
}

static
void print_nodes_number(struct bproc_node_info_t *ni, int num)
{
	int i;
	for (i = 0; i < num; i++)
		printf("%d\n", ni[i].node);
}

static
void print_nodes_total(struct bproc_node_info_t *ni, int num)
{
	printf("%d\n", num);
}

#if 0
/* get_node_info - get node information on the nodes that we're
 * interested in */
static
struct bproc_node_info_t *get_node_info(int *nodes, int len, int *ni_size)
{
	int i, j, k;
	struct bproc_node_info_t *info, *ni, fe;
	int nnodes;

	/* Info for all nodes.  Note that this may be sparse */
	nnodes = bproc_nodelist(&info);
	if (nnodes == -1) {
		perror("bproc_nodelist");
		exit(1);
	}
	bproc_nodeinfo(-1, &fe);	/* Info for the front end. */

	ni = malloc(sizeof(*ni) * len);
	if (!ni)
		return 0;

	k = 0;
	for (i = 0; i < len; i++) {
		if (nodes[i] == -1) {
			ni[k++] = fe;	/* special case for front end */
		} else {
			/* Search for this node number in our info */
			for (j = 0; j < nnodes; j++)
				if (nodes[i] == info[j].node) {
					ni[k++] = info[j];
					break;
				}
		}
	}
	free(info);
	*ni_size = k;
	return ni;
}
#endif

#if 0
/*--------------------------------------------------------------------
 * Short tid-bits good for scripts
 */

static
void print_process_state(void)
{
	int i, r;
	struct bproc_proc_info_t *procmap = 0;
	/*procmap = bproc_proclist(BPROC_NODE_ANY); */
	r = bproc_proclist(BPROC_NODE_ANY, &procmap);
	if (r == -1) {
		perror("bproc_proclist");
		return;
	}
	printf("PID\tNode\n");
	if (!procmap)
		return;
	for (i = 0; i < r; i++)
		printf("%d\t%d\n", procmap[i].pid, procmap[i].node);
	free(procmap);
}
static
void print_node_number(char *_arg)
{
	int i, nn, sz;
	struct hostent *h;
	struct sockaddr_in addr;
	h = gethostbyname(_arg);
	if (!h) {
		fprintf(stderr, "Unknown host: %s\n", _arg);
		exit(1);
	}

	nn = bproc_numnodes();
	for (i = -1; i < nn; i++) {
#if 0
		sz = sizeof(addr);
		if (bproc_nodeaddr(i, (struct sockaddr *)&addr, &sz)) {
			fprintf(stderr,
				"Error getting node address for node %d: %s\n",
				i, strerror(errno));
			exit(1);
		}
		if (memcmp(&addr.sin_addr, h->h_addr_list[0],
			   sizeof(addr.sin_addr)) == 0) {
			printf("%d\n", i);
			break;
		}
#else
	printf("print node number is busted\n");
#endif

	}
	if (i == nn) {
		fprintf(stderr, "No node with address %s\n", _arg);
		exit(1);
	}
}

static
void grok_ps()
{
	int pid, i, nproc;
	char line[10000], *check;
	int pidoffset;
	struct bproc_proc_info_t *pmap;

	nproc = bproc_proclist(BPROC_NODE_ANY, &pmap);
	if (nproc == -1) {
		perror("bproc_proclist");
		return;
	}

	if (!fgets(line, 10000, stdin))
		return;
	/* This is the header line... we need to find "PID" */
	check = strstr(line, "PID");
	while (check) {
		if (check == line || *(check - 1) == ' '
		    || *(check - 1) == '\t')
			break;
		check = strstr(check + 1, "PID");
	}
	if (!check) {
		fprintf(stderr, "Didn't find \"PID\" in ps header line.\n");
		exit(1);
	}
	pidoffset = (check - line) - 2;

	/* Output the header */
	fputs("NODE\t", stdout);
	fputs(line, stdout);

	while (fgets(line, 10000, stdin)) {
		pid = strtol(line + pidoffset, &check, 10);
		if (check == line) {
			fprintf(stderr, "punting on: %s", line);
			continue;
		}
		if (pmap) {
			for (i = 0; i < nproc; i++)
				if (pmap[i].pid == pid) {
					printf("%d\t", pmap[i].node);
					break;
				}
			if (i == nproc)
				fputs("\t", stdout);
		} else
			fputs("\t", stdout);
		fputs(line, stdout);
	}
	if (pmap)
		free(pmap);
}
#endif

void Usage(char *arg0)
{
	printf("Usage: %s [options] [nodes ...]\n"
	       "  -h,--help     Display this message and exit.\n"
	       "  -v,--version  Display version information and exit.\n"
	       "\n"
	       " The nodes argument is a comma delimited list of the following: \n"
	       "   Single node numbers - \"4\"    means node number 4\n"
	       "   Node ranges         - \"5-8\"  means node numbers 5,6,7,8\n"
	       "   Node classes        - \"allX\" means all slave nodes with status X\n"
	       "                         \"all\"  means all slave nodes\n"
	       " More than one nodes argument can be given.\n"
	       "\n\n"
	       " Node list display flags:\n"
	       "  -c,--compact      Print compacted listing of nodes. (default)\n"
	       "  -l,--long         Print long listing of nodes.\n"
	       "  -a,--address      Print node addresses.\n"
	       "  -s,--status       Print node status.\n"
	       "  -n,--number       Print node numbers.\n"
	       "  -t,--total        Print total number of nodes.\n"
	       "\n"
	       " Node list sorting flags:\n"
	       "  -R,--sort-reverse Reverse sort order.\n"
	       "  -N,--sort-number  Sort by node number.\n"
	       "  -S,--sort-status  Sort by node status.\n"
	       "  -O,--keep-order   Don't sort node list.\n"
	       "\n"
	       " Misc options:\n"
	       "  -U,--update   Continuously update status\n"
	       "  -L,--lock     \"locked\" mode for running on an unattended terminal\n"
	       "  -A hostname   Print the node number that corresponds to a\n"
	       "                host name or IP address.\n"
	       "  -p            Display process state.\n"
	       "  -P            Eat \"ps\" output and augment. (doesn't work well.)\n",
	       arg0);
}

static int sort_reverse = 0;
static
int node_sort_id(const void *_a, const void *_b)
{
	const struct bproc_node_info_t *a = _a, *b = _b;
	if (a->node == b->node)
		return 0;
	if (sort_reverse)
		return a->node < b->node ? 1 : -1;
	else
		return a->node > b->node ? 1 : -1;
}

static
int node_sort_status(const void *_a, const void *_b)
{
	const struct bproc_node_info_t *a = _a, *b = _b;
	if (strcmp(a->status, b->status) == 0)
		return a->node > b->node ? 1 : -1;
	if (sort_reverse)
		return -strcmp(a->status, b->status);
	/*return a->status < b->status ? 1 : -1; */
	else
		return strcmp(a->status, b->status);
	/*return a->status > b->status ? 1 : -1; */
}

#define node_sort_none ((int (*)(const void *, const void *))-1L)

int main(int argc, char *argv[])
{
	int c, i;
	int did_something = 0;
	int orig_optind, status_fd = -1;
	int continuous = 0;

	/* These are the node sets we'll be munging together */
	struct bproc_node_set_t ns_all = BPROC_EMPTY_NODESET;
	struct bproc_node_set_t ns_tmp = BPROC_EMPTY_NODESET;
	struct bproc_node_set_t ns_final = BPROC_EMPTY_NODESET;

	int (*sort_func) (const void *, const void *);
	void (*print_func) (struct bproc_node_info_t * ni, int num);

	static struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},

		{"long", 0, 0, 'l'},	/* printing options */
		{"compact", 0, 0, 'c'},
		{"address", 0, 0, 'a'},
		{"status", 0, 0, 's'},
		{"number", 0, 0, 'n'},
		{"total", 0, 0, 't'},

		{"sort-reverse", 0, 0, 'R'},	/* sort options */
		{"sort-number", 0, 0, 'N'},
		{"sort-status", 0, 0, 'S'},
		{"keep-order", 0, 0, 'O'},

		{"update", 0, 0, 'U'},
		{"lock", 0, 0, 'L'},
		{0, 0, 0, 0}
	};

	sort_func = 0;
	print_func = print_nodes_compact;

	while ((c = getopt_long(argc, argv, "hvVlcasntRNSOA:pPUL",
				long_options, 0)) != EOF) {
		did_something = 1;
		switch (c) {
		case 'h':
			Usage(argv[0]);
			exit(0);
		case 'V':
		case 'v':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'l':
			print_func = print_nodes_long;
			break;
		case 'c':
			print_func = print_nodes_compact;
			break;
		case 'a':
			print_func = print_nodes_address;
			break;
		case 's':
			print_func = print_nodes_state;
			break;
		case 'n':
			print_func = print_nodes_number;
			break;
		case 't':
			print_func = print_nodes_total;
			break;

			/* Sorting flags */
		case 'R':
			sort_reverse = 1;
			break;
		case 'N':
			sort_func = node_sort_id;
			break;
		case 'S':
			sort_func = node_sort_status;
			break;
		case 'O':
			sort_func = node_sort_none;
			break;

			/* Misc stuff */
#if 0
		case 'A':
			print_node_number(optarg);
			exit(0);
		case 'p':
			print_process_state();
			exit(0);
		case 'P':
			grok_ps();
			exit(0);
#endif

		case 'U':
			continuous = 1;
			break;
		case 'L':
			signal(SIGINT, SIG_IGN);
			signal(SIGTSTP, SIG_IGN);
			break;
		default:
			exit(1);
		}
	}

	/* Pick a default sort */
	if (!sort_func) {
		if (print_func == print_nodes_compact)
			sort_func = node_sort_status;
		else
			sort_func = node_sort_id;
	}

	orig_optind = optind;

	status_fd = bproc_notifier();
	if (status_fd == -1) {
		fprintf(stderr, "bproc_notifier fails\n");
		exit(1);
	}

      again:
	if (bproc_nodelist_(&ns_all, status_fd) == -1) {
		fprintf(stderr, "bproc_nodelist_: \n");
		exit(1);
	}

	/* Filter out the nodes that we're interested in */
	/* Grab node ranges */
	if (optind == argc) {
		bproc_nodefilter(&ns_final, &ns_all, "all");
	} else {
		for (i = optind; i < argc; i++) {
			if (bproc_nodefilter(&ns_tmp, &ns_all, argv[i])) {
				fprintf(stderr,
					"Invalid node specification \"%s\"\n",
					argv[1]);
				exit(1);
			}
			if (bproc_nodeset_append(&ns_final, &ns_tmp)) {
				fprintf(stderr, "Out of memory.\n");
				exit(1);
			}
			bproc_nodeset_free(&ns_tmp);
		}
	}

	if (sort_func != node_sort_none)
		qsort(ns_final.node, ns_final.size,
		      sizeof(*ns_final.node), sort_func);

	if (continuous)
		printf("\33[H\33[J");	/* Clear the screen */
	print_func(ns_final.node, ns_final.size);

	/* Clean up */
	bproc_nodeset_free(&ns_all);
	bproc_nodeset_free(&ns_final);

	if (continuous) {
		/* Wait for next machine state change */
		fflush(0);
		optind = orig_optind;

		{
			struct pollfd pfd;
			pfd.fd = status_fd;
			pfd.events = POLLIN;
			poll(&pfd, 1, -1);
		}

		goto again;
	}
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
