/*------------------------------------------------------------ -*- C -*-
 * beoserv.c:
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2001 University of California.  LA-CC Number 01-67.
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference to
 * http://www.gnu.org/licenses/gpl.html.
 *
 * This software is provided by the author(s) "as is" and any express
 * or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose
 * are disclaimed.  In no event shall the author(s) be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability,
 * whether in contract, strict liability, or tort (including
 * negligence or otherwise) arising in any way out of the use of this
 * software, even if advised of the possibility of such damage.
 *
 *  $Id: nodeadd.c,v 1.3 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <getopt.h>
#include "cmconf.h"

#include "boot.h"
#define arpdata arpdata_eth_ip

#define DEFAULT_CONFIG_FILE (CONFIGDIR "/config")

#define MAX_MACS 10000

struct macaddr {
	unsigned char addr[ETH_ALEN];
};

static int nmacs = 0;
static struct macaddr macs[MAX_MACS];
static char *configfile = DEFAULT_CONFIG_FILE;
static int first_node = -1;	/* First node number */
static int every_node = 0;	/* number every node? */
static int auto_reload = 0;

/*--------------------------------------------------------------------
 * Configuration file processesing goop
 */
static
int get_if_index(int sock, char *ifname)
{
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		fprintf(stderr, "%s: %s", ifname, strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}

static int currnode;
static
int config_node(struct cmconf *conf, char **args)
{
	int i, j, val, bytes, node;
	char *check, *p;
	struct macaddr mac;

	node = strtol(args[1], &check, 0);	/* check if first is a node number */
	if (*check)
		node = currnode + 1;

	currnode = node;
	for (i = *check ? 1 : 2; args[i]; i++) {
		p = args[i];
		for (j = 0; j < ETH_ALEN; j++) {
			if (sscanf(p, "%2x%n%*[ :.]%n", &val, &bytes, &bytes) <
			    1) {
				fprintf(stderr,
					"Invalid hardware address: %s\n",
					args[i]);
				return -1;
			}
			p += bytes;
			mac.addr[j] = val;
		}
		memcpy(&macs[nmacs], &mac, sizeof(mac));
		nmacs++;
	}
	return 0;
}

static
struct cmconf_option configopts[] = {
	{"node", 0, -1, 0, config_node},
	{0,}
};

static
void daemon_reload(void)
{
	/* This could be neater */
	printf("Sending SIGHUP to beoserv.\n");
	(void) system("killall -HUP beoserv");
}

static
void config_file_add_mac(struct macaddr *mac, int node)
{
	struct cmconf *conf;
	char newline[100];

	if (node == -1) {
		sprintf(newline, "node      %02X:%02X:%02X:%02X:%02X:%02X",
			(int)mac->addr[0], (int)mac->addr[1],
			(int)mac->addr[2], (int)mac->addr[3],
			(int)mac->addr[4], (int)mac->addr[5]);
	} else {
		sprintf(newline, "node %4d %02X:%02X:%02X:%02X:%02X:%02X", node,
			(int)mac->addr[0], (int)mac->addr[1],
			(int)mac->addr[2], (int)mac->addr[3],
			(int)mac->addr[4], (int)mac->addr[5]);
	}

	conf = cmconf_read(configfile, 1);
	if (!conf) {
		fprintf(stderr, "Failed to open %s for writing.\n", configfile);
		exit(1);
	}

	cmconf_append(conf, newline);
	cmconf_write(conf);
	cmconf_free(conf);
}

static
void do_packet(char *packet, int size)
{
	int i;
	struct arphdr *arp = (struct arphdr *)packet;
	struct arpdata *data =
	    (struct arpdata *)(packet + sizeof(struct arphdr));

	if (size < sizeof(*arp) + 20)
		return;
	if (arp->ar_op != htons(ARPOP_RREQUEST))
		return;
	if (data->version.arch != BEOBOOT_ARCH) {
		printf("Ignoring RARP due to architecture mismatch.\n");
		return;
	}

	/* Check if we've already seen this one */
	for (i = 0; i < nmacs; i++) {
		if (memcmp(macs[i].addr, data->tgt_eth, ETH_ALEN) == 0)
			return;
	}

	/* Add it to our list */
	memcpy(&macs[nmacs++].addr, &data->tgt_eth, ETH_ALEN);

	/* And now do something with it */
	printf("New MAC:");
	for (i = 0; i < ETH_ALEN; i++)
		printf(" %02X", (int)data->tgt_eth[i]);
	printf("\n");

	config_file_add_mac(&macs[nmacs - 1], first_node);
	if (every_node)
		first_node++;
	else
		first_node = -1;

	if (auto_reload)
		daemon_reload();
}

static
void Usage(char *arg0)
{

	printf("Usage: %s interfacename\n"
	       "       -h,--help            Display this message and exit.\n"
	       "       -V,--version         Display version information and exit.\n"
	       "       -n ###, --node ###   Start node numbering at ###.\n"
	       "       -a,--auto            Automatically cause daemon reloads when new\n"
	       "                            MAC addresses are added.\n"
	       "       -e,--every           Write a node number for every node.\n",
	       arg0);
};

int main(int argc, char *argv[])
{
	int c, sock;

	char *interface;
	struct sockaddr_ll addr;

	struct option longopts[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{"config", 1, 0, 'C'},
		{"node", 1, 0, 'n'},
		{"auto", 0, 0, 'a'},
		{"every", 0, 0, 'e'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "hVC:n:ae", longopts, 0)) != -1) {
		switch (c) {
		case 'h':
			Usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'C':
			configfile = optarg;
			break;
		case 'a':
			auto_reload = 1;
			printf("Automatic daemon reload enabled.\n");
			break;
		case 'n':
			first_node = strtol(optarg, 0, 0);
			printf("Starting node numbering at node %d\n",
			       first_node);
			break;
		case 'e':
			every_node = 1;
			printf("Numbering every node entry.\n");
			break;
		default:
			exit(1);
		}
	}

	if (argc - optind != 1) {
		Usage(argv[0]);
		exit(1);
	}

	if (cmconf_process_file(configfile, configopts)) {
		fprintf(stderr,
			"Failed to load existing mac addresses from %s\n",
			configfile);
		exit(1);
	}

	interface = argv[optind];

    /*--- Setup a new socket to listen on --------------------------*/
	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_RARP));
	if (sock == -1) {
		fprintf(stderr, "socket(AF_PACKET, ...): %s\n",
			strerror(errno));
		return -1;
	}

	/* Bind to the interface we're interested in */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_RARP);
	addr.sll_ifindex = get_if_index(sock, interface);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "%s: %s\n", interface, strerror(errno));
		close(sock);
		return -1;
	}
	printf("Listening on interface: %s\n", interface);

	/* Now listen for RARP traffic that we don't know about */
	{
		int r;
		char packet[1500];

		while (1) {
			r = recv(sock, packet, sizeof(packet), 0);
			if (r < 0) {
				fprintf(stderr, "recv: %s\n", strerror(errno));
				exit(1);
			}
			do_packet(packet, r);
		}
	}

	return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
