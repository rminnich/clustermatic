/*------------------------------------------------------------ -*- C -*-
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *
 *
 * This code is derived from rarpserv.c:
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
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
 *  $Id: rarpserv.c,v 1.30 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_BPROC
#include <sys/bproc.h>
#endif

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/ethernet.h>

#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cmconf.h"

#include "boot.h"
#define arpdata arpdata_eth_ip

int verbose __attribute__ ((weak)) = 0;
int ignore_version __attribute__ ((weak)) = 0;

/* Entry type for ethernet.... */
struct ethaddr_t {
	char addr[ETH_ALEN];
};
struct rarp_entry_eth_ip {
	int id;			/* BProc node number */
	int nipaddr, nethaddr;
	struct in_addr *ipaddr;
	struct ethaddr_t *ethaddr;
	char *boot_file;
};
#define rarp_entry rarp_entry_eth_ip

struct interface_t {
	char *name;		/* necessary? */
	int fd;
	unsigned char ethaddr[6];	/* interface ethernet address */
	struct sockaddr_in addr;
	struct sockaddr_in netmask;
};

/* This structure just bundles the configuration stuff together */
struct config_t {
	int rarp_list_size;
	struct rarp_entry *rarp_list;

	int if_list_size;
	struct interface_t *if_list;
	struct bproc_version_t version;
	int bproc_port;
};
static struct config_t conf = { 0, 0, 0, 0 };

static
char *mac_to_str(char *mac)
{
	static char buf[20];
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		(int)(unsigned char)mac[0], (int)(unsigned char)mac[1],
		(int)(unsigned char)mac[2], (int)(unsigned char)mac[3],
		(int)(unsigned char)mac[4], (int)(unsigned char)mac[5]);
	return buf;
}

/*------------------------------------------------------------------*
 * Config file stuff                                                *
 *------------------------------------------------------------------*/
static int next_node_n;
static int next_node_ip;
static struct config_t tc;	/* tc = temporary config */

static
int get_if_index(int sock, char *ifname)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		syslog(LOG_ERR, "%s: %s", ifname, strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}

static
int setup_socket(struct interface_t *ifc)
{
	int sock, flag;
	struct sockaddr_ll addr;
	struct ifreq ifr;

	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
	if (sock == -1) {
		syslog(LOG_ERR, "socket(AF_PACKET, ...): %s", strerror(errno));
		return -1;
	}

	/* ... the ethernet address. */
	strncpy(ifr.ifr_name, ifc->name, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		syslog(LOG_ERR, "ioctl(SIOCGIFHWADDR,%s): %s", ifc->name,
		       strerror(errno));
		close(sock);
		return -1;
	}
	memcpy(ifc->ethaddr, ifr.ifr_addr.sa_data, ETH_ALEN);

	/* ... the IP address.  (Why does "ADDR" always mean IP?) */
	strncpy(ifr.ifr_name, ifc->name, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
		syslog(LOG_ERR, "ioctl(SIOCGIFADDR,%s): %s", ifc->name,
		       strerror(errno));
		close(sock);
		return -1;
	}
	memcpy(&ifc->addr.sin_addr,
	       &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);

	/* ... the netmask.  (Why does "ADDR" always mean IP?) */
	strncpy(ifr.ifr_name, ifc->name, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFNETMASK, &ifr) == -1) {
		syslog(LOG_ERR, "ioctl(SIOCGIFNETMASK,%s): %s", ifc->name,
		       strerror(errno));
		close(sock);
		return -1;
	}
	memcpy(&ifc->netmask.sin_addr,
	       &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);

	/* Add this to allow address to be reused */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)))
		syslog(LOG_WARNING, "%s: %s", ifc->name, strerror(errno));

	/* Bind the socket to the interface we're interested in. */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_RARP);
	addr.sll_ifindex = get_if_index(sock, ifc->name);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		syslog(LOG_ERR, "%s: %s", ifc->name, strerror(errno));
		close(sock);
		return -1;
	}
	ifc->fd = sock;
	return 0;
}

static
int rarp_serv_config_interface(struct cmconf *conf, char **args)
{
	struct interface_t *tmp;
	/* create a new interface entry */
	if (!
	    (tmp =
	     realloc(tc.if_list,
		     sizeof(*tc.if_list) * (tc.if_list_size + 1)))) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	tc.if_list = tmp;
	tmp = &tc.if_list[tc.if_list_size];
	memset(tmp, 0, sizeof(*tc.if_list));
	if (!(tmp->name = strdup(args[1]))) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	if (setup_socket(tmp)) {
		free(tmp->name);
		syslog(LOG_ERR, "Failed to setup socket on %s", args[1]);
		return -1;
	}
	tc.if_list_size++;
	/* We got the address, netmask and stuff off the interface */
	return 0;
}

#define ALLOC_CHUNK 32
static
struct rarp_entry *add_node(int node_num)
{
	struct rarp_entry *rarp_tmp, *ent;
	int curr_size, new_size;

	curr_size = (tc.rarp_list_size + ALLOC_CHUNK - 1) / ALLOC_CHUNK;
	new_size = (tc.rarp_list_size + ALLOC_CHUNK) / ALLOC_CHUNK;
	if (curr_size != new_size) {
		rarp_tmp = realloc(tc.rarp_list,
				   new_size * sizeof(*tc.rarp_list) *
				   ALLOC_CHUNK);
		if (!rarp_tmp) {
			syslog(LOG_ERR, "Out of memory allocating RARP list.");
			return 0;
		}
		tc.rarp_list = rarp_tmp;
	}
	ent = &tc.rarp_list[tc.rarp_list_size];
	tc.rarp_list_size++;

	memset(ent, 0, sizeof(*ent));
	ent->id = node_num;
	return ent;
}

static
struct rarp_entry *find_node(int node_num)
{
	int i;
	for (i = 0; i < tc.rarp_list_size; i++) {
		if (tc.rarp_list[i].id == node_num)
			return &tc.rarp_list[i];
	}
	return 0;
}

static
int add_node_ip(int node_num, struct in_addr addr)
{
	struct rarp_entry *ent;
	struct in_addr *tmp;

	ent = find_node(node_num);
	if (!ent)
		ent = add_node(node_num);
	if (!ent)
		return -1;

	/* Allocate room for another IP address */
	if (!
	    (tmp =
	     realloc(ent->ipaddr, (ent->nipaddr + 1) * sizeof(*ent->ipaddr)))) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	ent->ipaddr = tmp;
	ent->ipaddr[ent->nipaddr] = addr;
	ent->nipaddr++;
	return 0;
}

static
int add_node_eth(int node_num, unsigned char *mac)
{
	struct ethaddr_t *tmp;
	struct rarp_entry *ent;
	char mac_tmp[18];

	ent = find_node(node_num);
	if (!ent) {
		sprintf(mac_tmp, "%02x:%02x:%02x:%02x:%02x:%02x",
			(int)mac[0], (int)mac[1], (int)mac[2],
			(int)mac[3], (int)mac[4], (int)mac[5]);
		syslog(LOG_WARNING, "No IP address for node.  node=%d mac=%s",
		       node_num, mac_tmp);
		ent = add_node(node_num);
	}
	if (!ent)
		return -1;

	/* Allocate another MAC for this node */
	if (!
	    (tmp =
	     realloc(ent->ethaddr,
		     sizeof(*ent->ethaddr) * (ent->nethaddr + 1)))) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	ent->ethaddr = tmp;
	memcpy(ent->ethaddr + ent->nethaddr, mac, ETH_ALEN);
	ent->nethaddr++;
	return 0;
}

static
int get_node_num(char ***args, int *num, int defl)
{
	char *check;

	if (!(*args)[1]) {
		*num = defl;
		(*args) += 1;
		return 0;
	}

	*num = strtol((*args)[1], &check, 0);
	if (*check) {
		/* No node number */
		*num = defl;
		(*args) += 1;	/* move args past node args */
	} else {
		/* Got a node number */
		if (*num < 0) {
			syslog(LOG_ERR, "Invalid node number: %s", (*args)[1]);
			*num = -1;	/* error value... */
			return -1;
		}
		(*args) += 2;	/* move args past node number */
	}
	return 0;
}

static
int rarp_serv_config_ip(struct cmconf *conf, char **args)
{
	int node_num;
	struct in_addr addr;

	if (get_node_num(&args, &node_num, next_node_ip))
		return -1;

	next_node_ip = node_num + 1;

	while (*args) {
		if (inet_aton(*args, &addr) == 0) {
			syslog(LOG_ERR, "Invalid IP address: %s", *args);
			return -1;
		}
		if (add_node_ip(node_num, addr))
			return -1;
		args++;
	}
	return 0;
}

static
int check_ip(struct in_addr _ip1, struct in_addr _ip2)
{
	int i, j;
	struct rarp_entry *r;
	unsigned long ip1, ip2, ip;

	ip1 = ntohl(_ip1.s_addr);
	ip2 = ntohl(_ip2.s_addr);
	for (i = 0; i < tc.rarp_list_size; i++) {
		r = &tc.rarp_list[i];
		for (j = 0; j < r->nipaddr; j++) {
			ip = ntohl(r->ipaddr[j].s_addr);
			if (ip >= ip1 && ip <= ip2)
				return -1;	/* This IP range includes an allocated IP */
		}
	}
	return 0;
}

static
int rarp_serv_config_ip_range(struct cmconf *conf, char **args)
{
	int i;
	int node_num;
	unsigned long ip;
	struct in_addr addr[2];
	unsigned long ip1, ip2;

	if (get_node_num(&args, &node_num, next_node_ip))
		return -1;

	for (i = 0; i < 2; i++) {
		if (inet_aton(args[i], &addr[i]) == 0) {
			syslog(LOG_ERR, "Invalid IP address: %s", args[i]);
			return -1;
		}
	}

	/* check that these aren't already assigned somewhere */
	if (check_ip(addr[0], addr[1])) {
		syslog(LOG_ERR,
		       "IP range overlaps allocated IP addresses: %s %s",
		       args[0], args[1]);
		return -1;
	}
	ip1 = ntohl(addr[0].s_addr);
	ip2 = ntohl(addr[1].s_addr);
	for (ip = ip1; ip <= ip2; ip++) {
		struct in_addr addr;
		addr.s_addr = htonl(ip);
		if (add_node_ip(node_num, addr))
			return -1;
		node_num++;
	}
	next_node_ip = node_num;
	return 0;
}

static
int rarp_serv_config_node(struct cmconf *conf, char **args)
{
	int i, val, bytes;
	unsigned char mac[ETH_ALEN], *p;
	int node_num;

	if (get_node_num(&args, &node_num, next_node_n))
		return -1;

	next_node_n = node_num + 1;

	while (*args) {
		/* Convert the MAC address to binary. */
		p = *args;
		for (i = 0; i < ETH_ALEN; i++) {
			if (sscanf(p, "%2x%n%*[ :.]%n", &val, &bytes, &bytes) <
			    1) {
				syslog(LOG_ERR,
				       "Invalid hardware address: %s\n", *args);
				return -1;
			}
			p += bytes;
			mac[i] = val;
		}
		if (add_node_eth(node_num, mac))
			return -1;
		args++;
	}
	return 0;
}

static
int get_port(char *arg)
{
	char *check;
	int portno;
	struct servent *s;

	s = getservbyname(arg, "tcp");
	if (s) {
		return ntohs(s->s_port);
	} else {
		portno = strtol(arg, &check, 0);
		if (*check || portno < 0 || portno >= 65536) {
			syslog(LOG_ERR, "unknown service/invalid port: %s",
			       arg);
			return -1;
		}
		return portno;
	}
}

static
int rarp_serv_config_bprocport(struct cmconf *conf, char **args)
{
	tc.bproc_port = get_port(args[1]);
	if (tc.bproc_port == 0) {
		syslog(LOG_ERR, "Invalid BProc port: %d\n", tc.bproc_port);
		return -1;
	}
	if (tc.bproc_port == -1)
		return -1;
	return 0;
}

static
int do_nodelist(char *str, int (*callback) (int, void *), void *data)
{
	int i, r;
	struct bproc_node_set_t ns;

	bproc_nodeset_init(&ns, 0);
	if (bproc_nodespec(&ns, str) == -1) {
		syslog(LOG_ERR, "Invalid node set: %s", str);
		bproc_nodeset_free(&ns);
		return -1;
	}

	for (i = 0; i < ns.size; i++) {
		r = callback(ns.node[i].node, data);
		if (r != 0)
			return r;
	}
	bproc_nodeset_free(&ns);
	return 0;
}

static
int rarp_serv_config_bootfile_callback(int node, void *data)
{
	struct rarp_entry *rarp;

	rarp = find_node(node);
	if (!rarp) {
		syslog(LOG_WARNING, "bootfile node number (%d): no such node.",
		       node);
		return 0;
	}

	if (rarp->boot_file)
		free(rarp->boot_file);
	rarp->boot_file = strdup((char *)data);
	if (!rarp->boot_file) {
		syslog(LOG_ERR, "Out of memory.");
		return -1;
	}
	return 0;
}

static
int rarp_serv_config_bootfile(struct cmconf *conf, char **args)
{
	char *node;
	char *filename;
	struct rarp_entry_eth_ip *rarp;
	if (args[2]) {
		node = args[1];
		filename = args[2];
	} else {
		node = 0;
		filename = args[1];
	}
	if (strlen(filename) > BOOTFILE_MAXLEN) {
		syslog(LOG_ERR, "bootfile filename too long (max %d)",
		       BOOTFILE_MAXLEN);
		return 0;
	}
	if (node == 0) {
		int i;
		for (i = 0; i < tc.rarp_list_size; i++) {
			rarp = &tc.rarp_list[i];
			if (!rarp->boot_file) {
				rarp->boot_file = strdup(filename);
				if (!rarp->boot_file) {
					syslog(LOG_ERR, "Out of memory.");
					return -1;
				}
			}
		}
	} else {
		/* set for particular nodes */
		do_nodelist(node, rarp_serv_config_bootfile_callback, filename);
	}
	return 0;
}

static
struct cmconf_option configopts[] = {
	/* tag          min args, max args, pass, function */
	{"interface", 1, 3, 0, rarp_serv_config_interface},
	{"ip", 0, -1, 1, rarp_serv_config_ip},
	{"iprange", 2, 3, 1, rarp_serv_config_ip_range},
	{"node", 0, -1, 2, rarp_serv_config_node},

	{"bprocport", 1, 1, 0, rarp_serv_config_bprocport},
	{"bootfile", 1, 2, 1, rarp_serv_config_bootfile},
	{0,}
};

static
void config_free(struct config_t *c)
{
	int i;
	for (i = 0; i < c->rarp_list_size; i++) {
		if (c->rarp_list[i].ethaddr)
			free(c->rarp_list[i].ethaddr);
		if (c->rarp_list[i].boot_file)
			free(c->rarp_list[i].boot_file);
	}
	free(c->rarp_list);
	c->rarp_list_size = 0;
	c->rarp_list = 0;

	for (i = 0; i < c->if_list_size; i++) {
		close(c->if_list[i].fd);
		free(c->if_list[i].name);
	}
	free(c->if_list);
	c->if_list_size = 0;
	c->if_list = 0;
}

int rarp_setup(char *configfile, char *new_node_file)
{
	int r;
	static int first = 1;

	next_node_n = 0;
	next_node_ip = 0;
	memset(&tc, 0, sizeof(tc));
	tc.bproc_port = BPROC_PORT;	/* defaults */

#if 0
	/* Retrieve Version Data */
	if ((r = bproc_version(&tc.version)) != 0)
		syslog(LOG_ERR, "Cannot retrieve BProc version.");
#endif

	if (cmconf_process_file(configfile, configopts)) {
		if (first)
			syslog(LOG_ERR, "Config load failed.");
		else
			syslog(LOG_ERR,
			       "Config reload failed; keeping old config.");
		return -1;
	}
	first = 0;

	/* Switch to new configuration */
	config_free(&conf);
	conf = tc;
	return 0;
}

/*------------------------------------------------------------------*/
/* RARP                                                             */
/*------------------------------------------------------------------*/

static
void send_response(struct interface_t *ifc, struct rarp_entry *entry,
		   int ip_idx, int mac_idx)
{
	int r;
	struct sockaddr_ll addr;
	char packet[1500];
	struct arphdr *arp = (struct arphdr *)packet;
	struct arpdata *data =
	    (struct arpdata *)(packet + sizeof(struct arphdr));
	extern int send_file_port;	/* File request port defined in send.c */

	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_RREPLY);

	/* Fill in my info.. */
	memcpy(data->src_eth, ifc->ethaddr, ETH_ALEN);
	memcpy(data->src_ip, &ifc->addr.sin_addr, 4);

	memcpy(data->tgt_eth, entry->ethaddr + mac_idx, ETH_ALEN);
	memcpy(data->tgt_ip, entry->ipaddr + ip_idx, 4);
	memcpy(data->netmask, &ifc->netmask.sin_addr, 4);

	/* Not necessary for response but what the hell... */
	memcpy(&(data->version), &conf.version, sizeof(data->version));

	data->bproc_port = htons(conf.bproc_port);
	data->file_port = htons(send_file_port);	/*htons(conf.file_port); */
	if (entry->boot_file)
		strcpy(data->boot_file, entry->boot_file);
	else
		strcpy(data->boot_file, BOOT_FILE);

	if (verbose >= 1)
		syslog(LOG_NOTICE, "RARP: %s == %d.%d.%d.%d  node %d",
		       mac_to_str(data->tgt_eth),
		       (int)data->tgt_ip[0], (int)data->tgt_ip[1],
		       (int)data->tgt_ip[2], (int)data->tgt_ip[3], entry->id);

	/* This is yucky... one would hope that doing the bind() would
	 * render all of this unnecessary...*/
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_RARP);
	addr.sll_ifindex = get_if_index(ifc->fd, ifc->name);
	memcpy(&addr.sll_addr, entry->ethaddr + mac_idx, ETH_ALEN);
	r = sendto(ifc->fd, packet, sizeof(*arp) + sizeof(*data), 0,
		   (struct sockaddr *)&addr, sizeof(addr));
	if (r == -1) {
		if (errno == ENOBUFS)
			return;	/* Ignore this... */
		syslog(LOG_ERR, "sendto(%s): %s", ifc->name, strerror(errno));
	}
}

static
void rarp_recv(struct interface_t *ifc)
{
	int i, j, k, r;
	struct rarp_entry *entry;
	char packet[1500];
	struct arphdr *arp = (struct arphdr *)packet;
	struct arpdata *data =
	    (struct arpdata *)(packet + sizeof(struct arphdr));

	r = recv(ifc->fd, packet, 1500, 0);
	if (r == -1) {
		syslog(LOG_ERR, "recv(%s): %s", ifc->name, strerror(errno));
		return;
	}
	if (r < sizeof(*arp) + 20)
		return;
	if (arp->ar_op != htons(ARPOP_RREQUEST))
		return;

	/* FIX ME: This check should happen after we figure out if it's a
	 * node that we want to respond to ourselves. */
	if (!ignore_version) {
		if (memcmp(&data->version.bproc_magic, conf.version.bproc_magic,
			   sizeof(conf.version.bproc_magic)) == 0) {
			/* BProc vesrion present */
			if (memcmp
			    (&data->version, &conf.version,
			     sizeof(conf.version))) {
				/* Better to complain to much than too little here.
				 * We should throttle this or something */
				if (verbose) {
					syslog(LOG_ERR,
					       "Ignoring %02X:%02X:%02X:"
					       "%02X:%02X:%02X due to version mismatch.  "
					       "me=%s-%u-%d  remote=%s-%u-%d",
					       (int)data->tgt_eth[0],
					       (int)data->tgt_eth[1],
					       (int)data->tgt_eth[2],
					       (int)data->tgt_eth[3],
					       (int)data->tgt_eth[4],
					       (int)data->tgt_eth[5],
					       conf.version.version_string,
					       conf.version.magic,
					       conf.version.arch,
					       data->version.version_string,
					       data->version.magic,
					       data->version.arch);
				}
				return;	/* mismatch */
			}
		} else {
			/* No bproc version... just look at arch flag */
			if (data->version.arch != BEOBOOT_ARCH) {	/* mismatch */
				if (verbose) {
					printf
					    ("Ignoring %02X:%02X:%02X:%02X:%02X:%02X due to "
					     " architecture mismatch.  me=%d  remote=%d\n",
					     (int)data->tgt_eth[0],
					     (int)data->tgt_eth[1],
					     (int)data->tgt_eth[2],
					     (int)data->tgt_eth[3],
					     (int)data->tgt_eth[4],
					     (int)data->tgt_eth[5],
					     conf.version.arch,
					     data->version.arch);
				}
				return;
			}
		}
	}

	/* Look through the RARP list for a match */
	for (i = 0; i < conf.rarp_list_size; i++) {
		entry = &conf.rarp_list[i];
		for (j = 0; j < entry->nethaddr; j++)
			if (memcmp(entry->ethaddr + j, data->tgt_eth, ETH_ALEN)
			    == 0) {
				/* Check address / netmask out to find the address
				 * that will match the network */
				unsigned long if_netaddr;
				if_netaddr = ifc->addr.sin_addr.s_addr &
				    ifc->netmask.sin_addr.s_addr;
				for (k = 0; k < entry->nipaddr; k++) {
					if ((entry->ipaddr[k].s_addr &
					     ifc->netmask.sin_addr.s_addr) ==
					    if_netaddr)
						break;
				}
				if (k == entry->nipaddr) {
					syslog(LOG_ERR,
					       "RARP:  MAC address match but no netmask"
					       " match for node %s",
					       mac_to_str(data->tgt_eth));
					break;	/* punt... */
				}
				send_response(ifc, entry, k, j);
				return;
			}
	}

	if (verbose >= 2)
		syslog(LOG_NOTICE, "RARP: Unknown MAC address: %s",
		       mac_to_str(data->tgt_eth));
}

/*--- External Interface ------------------------------------------------*/
void rarp_select_1(int *fdmax, fd_set * rset, fd_set * wset, fd_set * eset,
		   struct timeval *tmo)
{
	int i;
	for (i = 0; i < conf.if_list_size; i++) {
		FD_SET(conf.if_list[i].fd, rset);
		if (conf.if_list[i].fd > *fdmax)
			*fdmax = conf.if_list[i].fd;
	}
}

void rarp_select_2(fd_set * rset, fd_set * wset, fd_set * eset)
{
	int i;
	for (i = 0; i < conf.if_list_size; i++)
		if (FD_ISSET(conf.if_list[i].fd, rset))
			rarp_recv(&conf.if_list[i]);
}

int send_file_port __attribute__ ((weak)) = 0;

/* A main() for stand-alone testing. */
int main(int argc, char *argv[]) __attribute__ ((weak));
int main(int argc, char *argv[])
{
	int r, fdmax;
	fd_set rset;
	openlog(argv[0], LOG_PERROR, LOG_DAEMON);

	if (rarp_setup(CONFIGDIR "/config", "/dev/null"))
		exit(1);

	/* Would daemonize here */
	openlog(argv[0], 0, LOG_DAEMON);

	while (1) {
		fdmax = -1;
		FD_ZERO(&rset);
		rarp_select_1(&fdmax, &rset, 0, 0, 0);
		r = select(fdmax + 1, &rset, 0, 0, 0);
		if (r > 0)
			rarp_select_2(&rset, 0, 0);
	}
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
