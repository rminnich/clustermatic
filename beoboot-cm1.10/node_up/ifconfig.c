/*------------------------------------------------------------ -*- C -*-
 * ifconfig:  network configuration
 * Erik Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.  LA-CC Number 01-67.
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
 * $Id: ifconfig.c,v 1.1 2002/05/28 23:08:10 mkdist Exp $
 *--------------------------------------------------------------------*/

/* This module should be expanded to do things like copy
 * configurations from other interfaces */
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "node_up.h"

static int sockfd = -1;

static
int do_simple_ifconfig(const char *interface,
		       struct in_addr addr, struct in_addr nm) {
    struct ifreq ifr;
    struct sockaddr_in *a = (struct sockaddr_in *)&ifr.ifr_addr;

    /* Set interface IP address */
    strcpy(ifr.ifr_name, interface);
    a->sin_family = AF_INET;
    a->sin_addr = addr;
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) {
	log_print(LOG_ERROR, "ioctl(SIOCSIFADDR): %s\n", strerror(errno));
	return 1;
    }

    /* Set interface netmask address */
    strcpy(ifr.ifr_name, interface);
    a->sin_family = AF_INET;
    a->sin_addr = nm;
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1) {
	log_print(LOG_ERROR, "ioctl(SIOCSIFADDR): %s\n", strerror(errno));
	return 1;
    }

    /* Set interface broadcast address */
    strcpy(ifr.ifr_name, interface);
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = addr.s_addr | (0xffffffff & ~ nm.s_addr);
    if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) == -1) {
	log_print(LOG_ERROR, "ioctl(SIOCSIFBRDADDR): %s\n", strerror(errno));
	return 1;
    }

    /* Turn on the interface */
    strcpy(ifr.ifr_name, interface);
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
	log_print(LOG_ERROR, "ioctl(SIOCGIFFLAGS): %s", strerror(errno));
	return 1;
    }
    
    /* Up the interface isn't up, put it up. */
    if (!(ifr.ifr_flags & (IFF_UP|IFF_RUNNING))) {
	ifr.ifr_flags |= IFF_UP|IFF_RUNNING;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
	    log_print(LOG_ERROR, "ioctl(SIOCSIFFLAGS): %s", strerror(errno));
	    return 1;
	}
    }
    return 0;
}

int nodeup_postmove(int argc, char *argv[]) {
    int i;
    struct in_addr addr, nm;

    if (sockfd == -1) {
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
	    log_print(LOG_ERROR, "socket(AF_INET, SOCK_DGRAM, 0): %s\n",
		      strerror(errno));
	    return 1;
	}
    }

    for (i=1; i+2 < argc; i+=3) {
	log_print(LOG_INFO, "ifconfig %s %s %s\n",
		  argv[i], argv[i+1], argv[i+2]);
	if (inet_aton(argv[i+1], &addr) == 0) {
	    log_print(LOG_ERROR, "Invalid IP address: %s\n", argv[i+1]);
	    return 1;
	}
	if (inet_aton(argv[i+2], &nm) == 0) {
	    log_print(LOG_ERROR, "Invalid IP address: %s\n", argv[i+2]);
	    return 1;
	}
	if (do_simple_ifconfig(argv[i], addr, nm))
	    return 1;
    }
    return 0;
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
