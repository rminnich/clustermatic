/*------------------------------------------------------------ -*- C -*-
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *  Copyright(C) 2002 University of California.  LA-CC Number 01-67.
 *
 *  This is a modified version of the original beoboot RARP code which is:
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
 *  $Id: rarp.c,v 1.4 2003/04/08 22:27:22 mkdist Exp $
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

#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>
#include <netpacket/packet.h>	/* AF_PACKET stuff. */
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rarp.h"
#include "node_up.h"

MODULE_DESC("Interface RARP module.");
#define MAX_IFS 20

#define arpdata arpdata_eth_ip

#define PROC_TMP "/.rarp.proc.tmp"

/* This data is available to external people. */
int rarp_if_list_len = 0;
struct rarp_if_t rarp_if_list[MAX_IFS];
struct rarp_if_t *rarp_response = 0;

static int sockfd = -1;

/*--------------------------------------------------------------------
 * get_if_list - get basic information about all the network
 * interfaces in the system.
 */
static
int rarp_prepare_interface(struct rarp_if_t *ifc)
{
	struct ifreq ifr;

	strcpy(ifr.ifr_name, ifc->name);
	/* Grab the flags */
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		log_print(LOG_ERROR, "ioctl(SIOCGIFFLAGS, %s): %s\n", ifc->name,
			  strerror(errno));
		return -1;
	}
	if (ifr.ifr_flags & IFF_LOOPBACK)
		return 0;	/* Skip loop backs... */
	ifc->flags = ifr.ifr_flags;	/* save original flags */

	/* Up the interface isn't up, put it up. */
	if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
			log_print(LOG_ERROR, "ioctl(SIOCSIFFLAGS, %s): %s\n",
				  ifc->name, strerror(errno));
			return -1;
		}
	}

	/* Store some intformation about the interface  */
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {	/* save index */
		log_print(LOG_ERROR, "ioctl(\"SIOCGIFINDEX\", %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}
	ifc->index = ifr.ifr_ifindex;

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {	/* save HW addr */
		log_print(LOG_ERROR, "ioctl(\"SIOCGIFHWADDR\", %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}
	memcpy(ifc->hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* Clear out the results section */
	memset(&ifc->server_ip, 0, sizeof(ifc->server_ip));
	memset(&ifc->my_ip, 0, sizeof(ifc->my_ip));
	memset(&ifc->netmask, 0, sizeof(ifc->netmask));
	memset(ifc->boot_file, 0, sizeof(ifc->boot_file));
	ifc->bproc_port = ifc->mcast_port = 0;
	return 0;
}

static
void restore_interfaces(void)
{
	int i;
	struct ifreq ifr;
	struct rarp_if_t *ifc;

	/* Restore interface flags on all interfaces */
	for (i = 0; i < rarp_if_list_len; i++) {
		ifc = &rarp_if_list[i];
		strcpy(ifr.ifr_name, ifc->name);
		ifr.ifr_flags = ifc->flags;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
			log_print(LOG_ERROR, "ioctl(SIOCSIFFLAGS, %s): %s",
				  ifc->name, strerror(errno));
		}
	}
}

int rarp_add_interface(const char *ifname)
{
	int i;
	/* check to see that we don't already have this one */
	for (i = 0; i < rarp_if_list_len; i++) {
		if (strcmp(rarp_if_list[i].name, ifname) == 0)
			return rarp_prepare_interface(&rarp_if_list[i]);
	}

	if (i >= MAX_IFS) {
		log_print(LOG_ERROR, "Too many network interfaces.\n");
		return -1;
	}

	strcpy(rarp_if_list[i].name, ifname);
	rarp_if_list_len++;
	return rarp_prepare_interface(&rarp_if_list[i]);
}

/* This function just does the prepare interface step on everything in
 * PROC_TMP/net/dev */
int rarp_add_all(void)
{
	char line[1000], *p;
	FILE *f;

	/* This sucks... it seems like the only reliable place to get a
	 * list of interfaces is PROC_TMP/net/dev.  Interfaces don't show up
	 * on SIOCGIFCONF unless they've had an address assigned to them
	 * at some point in time. */
	f = fopen(PROC_TMP "/net/dev", "r");
	if (!f) {
		log_print(LOG_ERROR, "Couln't open %s/net/dev!\n", PROC_TMP);
		return -1;
	}

	rarp_if_list_len = 0;
	while (fgets(line, 1000, f) && (rarp_if_list_len < MAX_IFS)) {
		/* Cut off the line at the last colon.  This should allow us
		 * to work on IP aliases as well... */
		if (!(p = strrchr(line, ':')))
			continue;
		*p = 0;
		for (p = line; isspace(*p); p++) ;	/* Ditch leading space.. */

		if (rarp_add_interface(p)) {
			log_print(LOG_ERROR, "Failed to prep interface: %s\n",
				  p);
			return -1;
		}
	}
	fclose(f);
	return 0;
}

int rarp_down_all(void)
{
	int i;
	struct ifreq ifr;

	/* Down all interfaces we've touched */

	for (i = 0; i < rarp_if_list_len; i++) {
		strcpy(ifr.ifr_name, rarp_if_list[i].name);
		/* Grab the flags */
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
			log_print(LOG_ERROR, "ioctl(SIOCGIFFLAGS, %s): %s",
				  rarp_if_list[i].name, strerror(errno));
			return -1;
		}
		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;	/* Skip loop backs... */

		/* If the interface is up, put it down. */
		if (ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) {
			ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
			if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
				log_print(LOG_ERROR,
					  "ioctl(SIOCSIFFLAGS, %s): %s",
					  rarp_if_list[i].name,
					  strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

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
		} else {
			log_print(LOG_ERROR,
				  "Error retrieving BProc version: %s\n",
				  strerror(errno));
		}
	}

	return sizeof(*arp) + sizeof(*data);	/* Return length of packet */
}

static
void rarp_send(struct rarp_if_t *ifc)
{
	int r, len;
	char packet[1500];
	struct sockaddr_ll addr;	/* ll = link layer (?) */

	len = mk_rarp_request(ifc->hwaddr, packet);

	/* This is a nasty ethernet specific mess... */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_RARP);	/* Ethernet protocol number */
	addr.sll_ifindex = ifc->index;	/* interface to send to */
	memset(&addr.sll_addr, 0xff, ETH_ALEN);	/* broadcast */

	r = sendto(sockfd, packet, len, 0, (struct sockaddr *)&addr,
		   sizeof(addr));
	if (r == -1)
		perror("sendto");
}

/*--------------------------------------------------------------------
 * RARP receiving stuff
 */
static
int rarp_recv(int fd)
{
	int i, r;
	char packet[1500];
	struct arphdr *arp = (struct arphdr *)packet;
	struct arpdata *data = (struct arpdata *)(packet + sizeof(*arp));
	struct rarp_if_t *ifc;

	/* Sanity checking on this RARP packet ? */
	r = recv(fd, packet, 1500, 0);
	if (r == -1) {
		perror("recv");
		exit(1);
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
	for (i = 0; i < rarp_if_list_len; i++) {
		ifc = &rarp_if_list[i];
		if (memcmp(data->tgt_eth, ifc->hwaddr, ETH_ALEN) == 0) {
			log_print(LOG_INFO,
				  "response: %s %02X:%02X:%02X:%02X:%02X:%02X ->"
				  " %d.%d.%d.%d/%d.%d.%d.%d\n", ifc->name,
				  (int)data->tgt_eth[0], (int)data->tgt_eth[1],
				  (int)data->tgt_eth[2], (int)data->tgt_eth[3],
				  (int)data->tgt_eth[4], (int)data->tgt_eth[5],
				  (int)data->tgt_ip[0], (int)data->tgt_ip[1],
				  (int)data->tgt_ip[2], (int)data->tgt_ip[3],
				  (int)data->netmask[0], (int)data->netmask[1],
				  (int)data->netmask[2], (int)data->netmask[3]);
			/* Store information in this RARP response */
			memcpy(&ifc->server_ip, &data->src_ip,
			       sizeof(ifc->server_ip));
			memcpy(&ifc->my_ip, &data->tgt_ip, sizeof(ifc->my_ip));
			memcpy(&ifc->netmask, &data->netmask,
			       sizeof(ifc->netmask));

			ifc->bproc_port = ntohs(data->bproc_port);
			ifc->mcast_port = ntohs(data->mcast_port);
			memcpy(ifc->boot_file, data->boot_file,
			       BOOTFILE_MAXLEN);
			ifc->boot_file[BOOTFILE_MAXLEN] = 0;
			log_print(LOG_INFO,
				  "response: bproc=%d; mcast=%d; file=%s\n",
				  ifc->bproc_port, ifc->mcast_port,
				  ifc->boot_file);
			return -1;
		}
	}
	return 0;
}

/* This one does a RARP request on all interfaces which have been
 * configured... */
int rarp_do_rarp(int delay, int timeout)
{
	int r, i, ntries;
	fd_set rset;
	struct timeval tmo;

	ntries = timeout / delay;
	for (i = 0; i < ntries; i++) {
		/* Send on all preped interfaces */
		for (i = 0; i < rarp_if_list_len; i++)
			rarp_send(&rarp_if_list[i]);
		/* XXX bogosity alert: Linux-specific presumption about the
		 * value of timeout after select. */
		tmo.tv_sec = delay;
		tmo.tv_usec = 0;
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);
		r = select(sockfd + 1, &rset, 0, 0, &tmo);
		while (r != 0) {
			if (r == -1) {
				log_print(LOG_ERROR, "select: %s",
					  strerror(errno));
				return -1;
			}

			/* XXX we need to think a little more about indicating
			 * which interface actually got a response */
			if (rarp_recv(sockfd))
				return 0;

			FD_ZERO(&rset);
			FD_SET(sockfd, &rset);
			r = select(sockfd + 1, &rset, 0, 0, &tmo);
		}
	}

	/* Failure to receive a response */
	return -1;
}

/*----------------------------------------------------------------------
 * Post-RARP interface configuration
 */
int rarp_configure(struct rarp_if_t *ifc)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	/*struct sockaddr_in addr; */
	/*struct sockaddr_in bcast; */
	struct rtentry route;

	/* Down the interface */
	strcpy(ifr.ifr_name, ifc->name);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCGIFFLAGS, %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}
	ifr.ifr_flags &= ~IFF_UP | IFF_RUNNING;
	strcpy(ifr.ifr_name, ifc->name);
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFFLAGS, %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}

	/* Set interface address */
	strcpy(ifr.ifr_name, ifc->name);
	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ifc->my_ip;
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFADDR, %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}

	/* Set interface netmask to 0.0.0.0 */
	strcpy(ifr.ifr_name, ifc->name);
	addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = ifc->netmask;
	if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFNETMASK, %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}

	/* Set broadcast addr */
	strcpy(ifr.ifr_name, ifc->name);
	addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr =
	    ifc->my_ip.s_addr | (0xffffffff & ~ifc->netmask.s_addr);
	if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFBRDADDR, %s): %s\n",
			  ifc->name, strerror(errno));
		return -1;
	}

	/* Enable this interface */
	strcpy(ifr.ifr_name, ifc->name);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("SIOCGIFFLAGS");
		exit(1);
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("SIOCSIFFLAGS");
		exit(1);
	}

	/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
	/* HACK HERE: so many ethernet drivers are broken with
	 * multicast that we just turn on allmulti here for
	 * everybody...  */
	strcpy(ifr.ifr_name, ifc->name);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("SIOCGIFFLAGS");
		exit(1);
	}
	ifr.ifr_flags |= IFF_ALLMULTI;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
		perror("SIOCSIFFLAGS");
		exit(1);
	}
	/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

	/* Add the default route... */
	memset(&route, 0, sizeof(route));
	/* dst, mask, gw are all zeros for this route... easy :) */
	route.rt_dst.sa_family = AF_INET;
	route.rt_gateway.sa_family = AF_INET;
	route.rt_genmask.sa_family = AF_INET;
	route.rt_flags = RTF_UP;
	route.rt_dev = ifc->name;
	if (ioctl(sockfd, SIOCADDRT, &route) == -1) {
		fprintf(stderr, "%s: SIOCADDRT: %s\n",
			ifc->name, strerror(errno));
		exit(1);
	}
	return 0;
}

int rarp_configure_all(void)
{
	int i;
	for (i = 0; i < rarp_if_list_len; i++) {
		if (rarp_if_list[i].my_ip.s_addr) {
			if (rarp_configure(&rarp_if_list[i]))
				return -1;
		}
	}
	return 0;
}

int rarp_init(void)
{
	if (sockfd == -1) {
		sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
		if (sockfd == -1) {
			log_print(LOG_ERROR,
				  "socket(AF_PACKET, SOCK_DGRAM, 0x%x): %s",
				  (int)htons(ETH_P_RARP), strerror(errno));
			return -1;
		}
	}
	restore_interfaces();
	rarp_if_list_len = 0;
	return 0;
}

#if 0

int rarp_all(int configure, int delay, struct rarp_data_t *data)
{
	int r;

	sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
	if (sockfd == -1)
		fatal("socket: %s", strerror(errno));

	rarp_prepare_all_interfaces();
	if (rarp_if_list_len == 0) {
		fprintf(stderr, "No usable network interfaces found.\n");
		return -1;
	}

	log_print(LOG_INFO, "Sending RARP requests...\n");

	r = do_rarp_request(delay, data);
	restore_interfaces();
	if (r == -1)
		return -1;

	if (configure)
		configure_all_interfaces();	/* Configure interfaces
						 * according to RARP
						 * results. */
	return 0;
}
#endif

/* RARP on a single interface */
int rarp(const char *ifname, int delay, int timeout)
{
	int r;

	rarp_init();
	if (rarp_add_interface(ifname)) {
		log_print(LOG_ERROR, "Prepare interface on %s failed.\n",
			  ifname);
		return -1;
	}

	r = rarp_do_rarp(delay, timeout);
	restore_interfaces();

	if (r == -1) {
		log_print(LOG_INFO, "RARP failed.\n");
		return -1;
	}
	if (rarp_configure_all())
		return -1;
	return 0;
}

int nodeup_postmove(int argc, char *argv[])
{
	int c, i;

	if (nodeup_mnt_proc(PROC_TMP))
		return -1;

	while ((c = getopt(argc, argv, "")) != -1) {
		switch (c) {

		default:
			return -1;
		}
	}

	for (i = optind; i < argc; i++) {
		log_print(LOG_INFO, "performing RARP on %s\n", argv[i]);
		if (rarp(argv[i], 1, 5 * 60))
			return -1;
	}
	return 0;
}

#if 0
int main(int argc, char *argv[]) __attribute__ ((weak));
int main(int argc, char *argv[])
{
	struct rarp_data_t data;
	if (rarp_all(0, 1, &data)) {
		fprintf(stderr, "RARP failed\n");
		return -1;
	}
	printf("me    : %s\n", inet_ntoa(data.my_ip));
	printf("server: %s\n", inet_ntoa(data.server_ip));
	return 0;
}
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
