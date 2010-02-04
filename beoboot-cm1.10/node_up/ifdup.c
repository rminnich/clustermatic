/*------------------------------------------------------------ -*- C -*-
 * ifdup: network device configuration by grabbing part of the ip
 *         address from an already configured interface.
 * Joshua Aune <luken@linuxnetworx.com>
 *
 * Based on ifconfig.c from beoboot-cm-1.5
 * Erik Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2003 Linux Networx
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
 * $Id: ifdup.c,v 1.1 2003/06/04 21:29:31 mkdist Exp $
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* useful if compiling outside of node_up for testing */
#if NO_NODEUP
#define LOG_INFO 1
#define LOG_ERROR 1

#include <stdarg.h>
void log_print(int level, char *fmt, ...)
{
	va_list valist;
	int len;
	char buffer[1024];

	va_start(valist, fmt);
	len = vsnprintf(buffer, 1024, fmt, valist);
	write(STDOUT_FILENO, buffer, len);
	va_end(valist);
}

#else				/* NO_NODEUP */
#include "node_up.h"
#endif				/* NO_NODEUP */

/* Used for ioctls, but why? */
static int sockfd = -1;

static
int do_simple_ifconfig(const char *interface,
		       struct in_addr addr, struct in_addr nm)
{
	struct ifreq ifr;
	struct sockaddr_in *a = (struct sockaddr_in *)&ifr.ifr_addr;

	/* Set interface IP address */
	strncpy(ifr.ifr_name, interface, IF_NAMESIZE);
	a->sin_family = AF_INET;
	a->sin_addr = addr;
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFADDR): %s\n",
			  strerror(errno));
		return 1;
	}

	/* Set interface netmask address */
	strncpy(ifr.ifr_name, interface, IF_NAMESIZE);
	a->sin_family = AF_INET;
	a->sin_addr = nm;
	if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFADDR): %s\n",
			  strerror(errno));
		return 1;
	}

	/* Set interface broadcast address */
	strncpy(ifr.ifr_name, interface, IF_NAMESIZE);
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = addr.s_addr | (0xffffffff & ~nm.s_addr);
	if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCSIFBRDADDR): %s\n",
			  strerror(errno));
		return 1;
	}

	/* Turn on the interface */
	strncpy(ifr.ifr_name, interface, IF_NAMESIZE);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		log_print(LOG_ERROR, "ioctl(SIOCGIFFLAGS): %s",
			  strerror(errno));
		return 1;
	}

	/* Up the interface isn't up, put it up. */
	if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
			log_print(LOG_ERROR, "ioctl(SIOCSIFFLAGS): %s",
				  strerror(errno));
			return 1;
		}
	}
	return 0;
}

static
int do_ifdup(char *base_ifname, char *clone_ifname,
	     struct in_addr clone_mask,
	     struct in_addr clone_addr, struct in_addr nm)
{
	struct ifreq base_ifr;
	struct sockaddr_in *base_sa = (struct sockaddr_in *)&base_ifr.ifr_addr;
	char ipaddr[16];

	/* Get ip from base interface so we can calculate the ip for clone */
	memset(&base_ifr, 0, sizeof(base_ifr));
	strncpy(base_ifr.ifr_name, base_ifname, IF_NAMESIZE);
	base_sa->sin_family = AF_INET;
	if (ioctl(sockfd, SIOCGIFADDR, &base_ifr) == -1) {
		log_print(LOG_ERROR, "ioctl(SIOCGIFADDR) %s: %s\n",
			  strerror(errno));
		return 1;
	}

	/* Use the passed mask, base interface addr, and the passed new addr
	 * to generate the new ip address */
	clone_addr.s_addr = (clone_addr.s_addr & clone_mask.s_addr) |
	    (base_sa->sin_addr.s_addr & ~clone_mask.s_addr);

	/* For some reason, printf isnt working, so put the nm into a string */
	snprintf(ipaddr, sizeof(ipaddr), "%s", inet_ntoa(nm));
	log_print(LOG_INFO, "ifdup: ifconfig %s %s %s\n", clone_ifname,
		  inet_ntoa(clone_addr), ipaddr);

	if (do_simple_ifconfig(clone_ifname, clone_addr, nm)) {
		return 1;
	}

	return 0;
}

int nodeup_postmove(int argc, char *argv[])
{
	int i;
	struct in_addr clone_mask, clone_addr, clone_nm;

	if (sockfd == -1) {
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			log_print(LOG_ERROR,
				  "socket(AF_INET, SOCK_DGRAM, 0): %s\n",
				  strerror(errno));
			return 1;
		}
	}

	for (i = 1; i + 4 < argc; i += 5) {
		log_print(LOG_INFO, "ifdup: %s based on %s\n", argv[i],
			  argv[i + 1]);

		if (inet_aton(argv[i + 2], &clone_mask) == 0) {
			log_print(LOG_ERROR, "Invalid address mask: %s\n",
				  argv[i + 2]);
			return 1;
		}
		if (inet_aton(argv[i + 3], &clone_addr) == 0) {
			log_print(LOG_ERROR, "Invalid clone base address: %s\n",
				  argv[i + 3]);
			return 1;
		}
		if (inet_aton(argv[i + 4], &clone_nm) == 0) {
			log_print(LOG_ERROR, "Invalid clone netmask: %s\n",
				  argv[i + 4]);
			return 1;
		}
	}

	if (do_ifdup(argv[1], argv[2], clone_mask, clone_addr, clone_nm))
		return 1;

	return 0;
}

#if NO_NODEUP
int main(int argc, char *argv[])
{
	char *args[9];

	printf("Good Run\n");
	args[0] = "ifdup";
	args[1] = "eth0";
	args[2] = "eth1";
	args[3] = "255.255.255.0";
	args[4] = "10.0.1.0";
	args[5] = "255.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	printf("Bad base iface\n");
	args[0] = "ifdup";
	args[1] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
	args[2] = "eth1";
	args[3] = "255.255.255.0";
	args[4] = "10.0.1.0";
	args[5] = "255.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	printf("Bad dup iface\n");
	args[0] = "ifdup";
	args[1] = "eth0";
	args[2] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
	args[3] = "255.255.255.0";
	args[4] = "10.0.1.0";
	args[5] = "255.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	printf("bad mask\n");
	args[0] = "ifdup";
	args[1] = "myri0";
	args[2] = "eth2";
	args[3] = "655.295.225.1";
	args[4] = "10.0.1.0";
	args[5] = "255.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	printf("bad ip\n");
	args[0] = "ifdup";
	args[1] = "myri0";
	args[2] = "eth2";
	args[3] = "255.255.255.0";
	args[4] = "333.0.1.0";
	args[5] = "255.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	printf("bad nm\n");
	args[0] = "ifdup";
	args[1] = "myri0";
	args[2] = "eth2";
	args[3] = "255.255.255.0";
	args[4] = "333.0.1.0";
	args[5] = "256.255.255.0";
	args[6] = (char *)NULL;
	if (nodeup_postmove(6, args)) {
		perror("postmove failed: ");
	}

	return 0;
}
#endif				/* NO_NODEUP */

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
