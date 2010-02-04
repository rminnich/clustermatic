/*------------------------------------------------------------ -*- C -*-
 * rarp.h: Definitions for external users of the RARP module.
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
 * $Id: rarp.h,v 1.1 2002/05/31 17:30:52 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _RARP_H_
#define _RARP_H_

#include <net/if.h>		/* for IFNAMSIZ */
#include <net/ethernet.h>	/* for ETH_ALEN */
#include <netinet/in.h>		/* for struct in_addr */

/*--------------------------------------------------------------------
 * Stuff for use by RARP callers
 */
#define BOOTFILE_MAXLEN 100

struct rarp_if_t {
	/* Information about interface */
	char name[IFNAMSIZ];
	int index;
	int flags;
	char hwaddr[ETH_ALEN];

	/* Data from RARP response */
	struct in_addr server_ip;
	struct in_addr my_ip;
	struct in_addr netmask;
	/* XXX Do we want to stick a network gateway in here ? */
	int bproc_port;
	int mcast_port;
	char boot_file[BOOTFILE_MAXLEN + 1];
};

extern struct rarp_if_t rarp_if_list[];
extern int rarp_if_list_len;

/* Functions for external use */
int rarp_init(void);
int rarp_add_interface(const char *ifname);
int rarp_add_all(void);
int rarp_do_rarp(int delay, int timeout);
int rarp_configure(struct rarp_if_t *ifc);
int rarp_configure_all(void);

#if 0
int rarp_prepare_interface(const char *ifname);
int rarp_prepare_all_interfaces(void);
void rarp_down_all(void);
#endif

/*--------------------------------------------------------------------
 * Internal RARP stuff
 */
struct arpdata_eth_ip {
	unsigned char src_eth[6];
	unsigned char src_ip[4];
	unsigned char tgt_eth[6];
	unsigned char tgt_ip[4];
	unsigned char netmask[4];
	struct bproc_version_t version;
	uint16_t bproc_port;
	uint16_t mcast_port;
	char boot_file[BOOTFILE_MAXLEN + 1];
};

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
