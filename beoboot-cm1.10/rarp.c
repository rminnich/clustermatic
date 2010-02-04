/*------------------------------------------------------------ -*- C -*-
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * This is a derivative version of the original RARP code which is:
 *
 *  Copyright (C) 2000 Scyld Computing Corporation
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  $Id: rarp.c,v 1.30 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/bproc.h>
#include <dirent.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netpacket/packet.h>	/* AF_PACKET stuff. */
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cmconf.h"

#include "boot.h"
#include "beoboot_boothooks.h"

#define arpdata arpdata_eth_ip

/* Argument structure for RARP client */
struct rarp_arg_t {
	int initial_delay;
	int max_delay;
	float backoff;
	int max_time;
	float rand;
};

static
struct rarp_arg_t rarp_args = {
      initial_delay:RARP_INITIAL_DELAY,
      max_delay:RARP_MAX_DELAY,
      backoff:RARP_BACKOFF,
      max_time:RARP_MAX_TIME,
      rand:RARP_RAND
};

/*--------------------------------------------------------------------
 * RARP sending stuff
 */
static
int mk_rarp_request(char *my_hwaddr, char *bfr)
{
	int r;
	struct arphdr *arp = (struct arphdr *)bfr;
	struct arpdata *data = (struct arpdata *)(bfr + sizeof(*arp));

	/* Build ARP Packet */
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_RREQUEST);

	/* This junk is potentially viariable in size so no nice struct. */
	memcpy(data->src_eth, my_hwaddr, ETH_ALEN);
	memset(data->src_ip, 0, 4);
	memcpy(data->tgt_eth, my_hwaddr, ETH_ALEN);
	memset(data->tgt_ip, 0, 4);
	memset(data->netmask, 0, 4);

	/* This is the version stuff. */
	r = bproc_version(&data->version);
	if (r == -1) {
		if (errno == ENOSYS) {
			/* no BProc module loaded... zero except for arch */
			memset(&data->version, 0, sizeof(data->version));
			data->version.arch = BPROC_ARCH;
		} else
			fprintf(stderr, "Error retrieving BProc version: %s\n",
				strerror(errno));
	}

	return sizeof(*arp) + sizeof(*data);	/* Return length of packet */
}

/* this is some crud to keep track of the interfaces we've seen so
 * that we don't keep printing out the same MAC addresses over and
 * over again. */
struct iflist_t {
	struct iflist_t *next;
	char ifname[0];
};

static
int rarp_seen(const char *interface)
{
	static struct iflist_t *iflist = 0;
	struct iflist_t *ifc;

	for (ifc = iflist; ifc; ifc = ifc->next)
		if (strcmp(interface, ifc->ifname) == 0)
			return 1;

	ifc = malloc(sizeof(*ifc) + strlen(interface) + 1);
	if (!ifc)
		fatal("Out of memory.");
	strcpy(ifc->ifname, interface);
	ifc->next = iflist;
	iflist = ifc;
	return 0;
}

static
int rarp_send(int sockfd, const char *interface)
{
	int r, len, index;
	struct ifreq ifr;
	char packet[1500];
	unsigned char hwaddr[ETH_ALEN];
	struct sockaddr_ll addr;	/* ll = link layer (?) */

	/* Get interface index */
	strcpy(ifr.ifr_name, interface);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		console_log("SIOCGIFINDEX %s: %s\n",
			    interface, strerror(errno));
		return -1;
	}
	index = ifr.ifr_ifindex;

	/* Get the hardare address */
	strcpy(ifr.ifr_name, interface);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
		console_log("SIOCGIFHWADDR %s: %s\n",
			    interface, strerror(errno));
		return -1;
	}
	memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (!rarp_seen(interface)) {
		console_log
		    ("RARP: interface: %-8s %02x:%02x:%02x:%02x:%02x:%02x\n",
		     interface, (int)hwaddr[0], (int)hwaddr[1], (int)hwaddr[2],
		     (int)hwaddr[3], (int)hwaddr[4], (int)hwaddr[5]);
	}

	/* Make sure interface is up */
	strcpy(ifr.ifr_name, interface);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		console_log("SIOCGIFFLAGS %s: %s\n", interface,
			    strerror(errno));
		return -1;
	}
	if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
			console_log("SIOCSIFFLAGS %s: %s\n", interface,
				    strerror(errno));
			return -1;
		}
	}

	len = mk_rarp_request(hwaddr, packet);

	/* This is a nasty ethernet specific mess... */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_RARP);	/* Ethernet proto for packet. */
	addr.sll_ifindex = index;	/* interface to send to */
	memset(&addr.sll_addr, 0xff, ETH_ALEN);	/* send to broadcast */

	r = sendto(sockfd, packet, len, 0, (struct sockaddr *)&addr,
		   sizeof(addr));
	/* Some ethernet drivers return ENOBUFS after a while if there's
	 * no link beat.  Ignore this. */
	if (r == -1 && errno != ENOBUFS && errno != EAGAIN) {
		perror("sendto");
		console_log("sendto %s: %s\n", interface, strerror(errno));
		return -1;
	}
	return 0;
}

static
int rarp_send_all(int sockfd)
{
	/* Look through /sys/class/net for a list of network devices */
	int result = 0;
	DIR *dir;
	struct dirent *de;
	struct ifreq ifr;

	dir = opendir("/sys/class/net");
	if (!dir) {
		console_log("/sys/class/net: %s", strerror(errno));
		return -1;
	}

	while ((de = readdir(dir))) {
		strcpy(ifr.ifr_name, de->d_name);
		/* Grab the flags */
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
			if (errno != ENODEV) {
				console_log("SIOCGIFFLAGS %s: %s\n",
					    de->d_name, strerror(errno));
				result = -1;
				break;
			}
			continue;
		}
		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;	/* Skip loop backs... */

		if ((result = rarp_send(sockfd, de->d_name)))
			break;
	}
	closedir(dir);
	return result;
}

/*--------------------------------------------------------------------
 * RARP receiving stuff
 */
static
int rarp_recv(int sockfd, struct rarp_data_t *user)
{
	int r, result = 0;
	char packet[1500];
	struct arphdr *arp = (struct arphdr *)packet;
	struct arpdata *data = (struct arpdata *)(packet + sizeof(*arp));

	DIR *dir;
	struct dirent *de;
	struct ifreq ifr;

	/* Sanity checking on this RARP packet ? */
	r = recv(sockfd, packet, 1500, 0);
	if (r == -1) {
		console_log("recv: %s\n", strerror(errno));
		return -1;
	}

	/* Sanity checking:
	 *  - Is the packet big enough?
	 *  - Is it an ARP reverse reply?
	 */
	if (r < sizeof(*arp) + 20)
		return 0;
	if (arp->ar_op != htons(ARPOP_RREPLY))
		return 0;

	/* Find the interface that this response goes with. */

	dir = opendir("/sys/class/net");
	if (!dir) {
		console_log("/sys/class/net: %s", strerror(errno));
		return -1;
	}

	while ((de = readdir(dir))) {
		strcpy(ifr.ifr_name, de->d_name);
		if (ioctl(sockfd, SIOCGIFHWADDR, &ifr)) {
			if (errno != ENODEV) {
				console_log("SIOCGIFFWADDR %s: %s\n",
					    de->d_name, strerror(errno));
				result = -1;
				break;
			}
			continue;
		}

		if (memcmp(data->tgt_eth, &ifr.ifr_hwaddr.sa_data, ETH_ALEN) ==
		    0) {
			console_log
			    ("RARP: %-8s %02X:%02X:%02X:%02X:%02X:%02X ->"
			     " %d.%d.%d.%d/%d.%d.%d.%d\n", de->d_name,
			     (int)data->tgt_eth[0], (int)data->tgt_eth[1],
			     (int)data->tgt_eth[2], (int)data->tgt_eth[3],
			     (int)data->tgt_eth[4], (int)data->tgt_eth[5],
			     (int)data->tgt_ip[0], (int)data->tgt_ip[1],
			     (int)data->tgt_ip[2], (int)data->tgt_ip[3],
			     (int)data->netmask[0], (int)data->netmask[1],
			     (int)data->netmask[2], (int)data->netmask[3]);

			/* Fill in data for caller */
			strcpy(user->interface, de->d_name);
			memcpy(&user->server_ip, data->src_ip,
			       sizeof(user->server_ip));
			memcpy(&user->my_ip, data->tgt_ip, sizeof(user->my_ip));
			memcpy(&user->netmask, data->netmask,
			       sizeof(user->netmask));
			user->bproc_port = ntohs(data->bproc_port);
			user->file_port = ntohs(data->file_port);
			strcpy(user->boot_file, data->boot_file);
			console_log("RARP: bproc=%d; file=%d; file=%s\n",
				    user->bproc_port, user->file_port,
				    user->boot_file);
			result = 1;
			break;
		}

	}
	closedir(dir);
	return result;
}

/* XXX WARNING: This code could break if you set the initial delay too
 * low or RARP_RAND too high... */
static
int update_delay(struct rarp_arg_t *args, int delay)
{
	float factor;
	delay = delay * args->backoff;

	/* Constrain delay to be within our bounds */
	if (delay > args->max_delay)
		delay = args->max_delay;
	if (delay < args->initial_delay)
		delay = args->initial_delay;

	/* Add some randomness to the delay */
	factor =
	    1.0 - args->rand + (rand() / ((float)RAND_MAX)) * args->rand * 2;
	delay = delay * factor;

	/* Constrain again */
	if (delay > args->max_delay)
		delay = args->max_delay;
	if (delay < args->initial_delay)
		delay = args->initial_delay;

	return delay;
}

int rarp(struct rarp_data_t *data)
{
	static struct timeval start = { 0, 0 }, last_send;
	static char *spinner = "/-\\|";
	static char *spinner_ptr = 0;
	static int delay;

	int sockfd, r, elapsed;
	struct timeval now, tmo;
	fd_set rset;
	int result = 0;

	if (spinner_ptr == 0) {
		/* Initialize everything on the first call */
		spinner_ptr = spinner;
		gettimeofday(&start, 0);
		console_log("RARP: delay=%.1fs -> %.1fs backoff=%.2f"
			    " max=%ds rand=%.2f\n",
			    rarp_args.initial_delay / 1000000.0,
			    rarp_args.max_delay / 1000000.0,
			    rarp_args.backoff, rarp_args.max_time,
			    rarp_args.rand);
		delay = 0;
	}

	sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
	if (sockfd == -1)
		fatal("socket(AF_PACKET: %s", strerror(errno));

	if (rarp_send_all(sockfd)) {
		close(sockfd);
		return -1;
	}
	gettimeofday(&last_send, 0);

	/* Show one spinner element per request ... */
	printf("%c\b", *spinner_ptr);
	fflush(stdout);
	spinner_ptr++;
	if (!*spinner_ptr)
		spinner_ptr = spinner;

	/* Wait for the response to show up. */
	delay = update_delay(&rarp_args, delay);

	/* Cap the delay so that we don't go over our total time. */
	if ((last_send.tv_sec - start.tv_sec) * 1000000 +
	    last_send.tv_usec - start.tv_usec + delay >
	    rarp_args.max_time * 1000000) {
		delay = rarp_args.max_time * 1000000 -
		    ((last_send.tv_sec - start.tv_sec) * 1000000 +
		     last_send.tv_usec - start.tv_usec);
		if (delay <= 0)
			result = -1;
	}

	gettimeofday(&now, 0);
	elapsed = (now.tv_sec - last_send.tv_sec) * 1000000 +
	    now.tv_usec - last_send.tv_usec;
	while (result == 0 && elapsed < delay) {
		tmo.tv_sec = (delay - elapsed) / 1000000;
		tmo.tv_usec = (delay - elapsed) % 1000000;

		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		r = select(sockfd + 1, &rset, 0, 0, &tmo);
		if (r == -1)
			fatal("select: %s", strerror(errno));
		if (r == 1)
			result = rarp_recv(sockfd, data);

		gettimeofday(&now, 0);
		elapsed = (now.tv_sec - last_send.tv_sec) * 1000000 +
		    now.tv_usec - last_send.tv_usec;
	}

	close(sockfd);
	return result;
}

/*--- RARP configuration code --------------------------------------*/
static
int rarp_initial_delay(struct cmconf *conf, char **args)
{
	char *check;
	int usec;
	usec = strtod(args[1], &check) * 1000000;
	if (*check || usec <= 0) {
		console_log("rarp initial_delay invalid: %s (ignoring)\n",
			    args[1]);
		return 0;
	}
	rarp_args.initial_delay = usec;
	return 0;
}

static
int rarp_max_delay(struct cmconf *conf, char **args)
{
	char *check;
	int usec;
	usec = strtod(args[1], &check) * 1000000;
	if (*check || usec <= 0) {
		console_log("rarp max_delay invalid: %s  (ignoring)\n",
			    args[1]);
		return 0;
	}
	rarp_args.max_delay = usec;
	return 0;
}

static
int rarp_backoff(struct cmconf *conf, char **args)
{
	char *check;
	float backoff;
	backoff = strtod(args[1], &check);
	if (*check || backoff < 1.0) {
		console_log("rarp backoff invalid: %s  (ignoring)\n", args[1]);
		return 0;
	}
	rarp_args.backoff = backoff;
	return 0;
}

static
int rarp_max_time(struct cmconf *conf, char **args)
{
	char *check;
	int sec;
	sec = strtod(args[1], &check);
	if (*check || sec <= 0) {
		console_log("rarp max_time invalid: %s\n", args[1]);
		return 0;
	}
	rarp_args.max_time = sec;
	return 0;
}

static
int rarp_rand(struct cmconf *conf, char **args)
{
	char *check;
	float rnd;
	rnd = strtod(args[1], &check);
	if (*check || rnd < 0.0 || rnd > 1.0) {
		console_log("rarp rand invalid: %s\n", args[1]);
		return 0;
	}
	rarp_args.rand = rnd;
	return 0;
}

static
int rarp_unknown(struct cmconf *conf, char **args)
{
	console_log("%s:%d unknown RARP configuration option: %s\n",
		    cmconf_file(conf), cmconf_lineno(conf), args[0]);
	return 0;
}

static
struct cmconf_option rarp_configoptions[] = {
	{"initial_delay", 1, 1, 0, rarp_initial_delay},
	{"max_delay", 1, 1, 0, rarp_max_delay},
	{"backoff", 1, 1, 0, rarp_backoff},
	{"max_time", 1, 1, 0, rarp_max_time},
	{"rand", 1, 1, 0, rarp_rand},
	{"*", 0, -1, 0, rarp_unknown},
	{0,}
};

BOOT_ADD_CONFIG(0, "rarp", rarp_configoptions);

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
