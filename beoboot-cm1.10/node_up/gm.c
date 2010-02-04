/*------------------------------------------------------------ -*- C -*-
 * gm: nodeup module to wait for the myrinet mapper to do its thing
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
 * $Id: gm.c,v 1.9 2004/02/10 20:58:19 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <gm.h>
#include <sys/bproc.h>
#include "node_up.h"

MODULE_DESC("GM setup module");

#define MAX_UNITS 10
#define MAX_PORTS 16
struct node_id_t {
	unsigned char mac[6];
};
static struct node_id_t node_ids[MAX_UNITS];
static char *hostname_fmt = "n%d";

static
int get_unique_id(int unit)
{
	int i;
	struct gm_port *gmp;
	gm_status_t res;
	char hostname[GM_MAX_HOST_NAME_LEN + 1];

	for (i = 0; i < MAX_PORTS; i++) {
		res = gm_open(&gmp, unit, i, "node_up: gm", GM_API_VERSION);
		if (res == GM_SUCCESS)
			break;
	}
	if (i == MAX_PORTS)
		return -1;	/* presume this one doesn't exist */

	/* We can't really "wait for the mapper" on GM 2 - every node runs
	 * a mapper.  If you want to guarantee connectivity to some other
	 * place in the network, that's tough at this point. */

	/* Grab the board's unique ID (the mac address) */
	res = gm_get_unique_board_id(gmp, node_ids[unit].mac);
	if (res != GM_SUCCESS) {
		log_print(LOG_ERROR, "gm_get_unique_board_id: %s\n",
			  gm_strerror(res));
		gm_close(gmp);
		return -1;
	}

	log_print(LOG_INFO, "GM Unique ID on unit %d: %02x:%02x:%02x:%02x:"
		  "%02x:%02x\n", unit,
		  (int)node_ids[unit].mac[0], (int)node_ids[unit].mac[1],
		  (int)node_ids[unit].mac[2], (int)node_ids[unit].mac[3],
		  (int)node_ids[unit].mac[4], (int)node_ids[unit].mac[5]);

	/* Also set the host name on this unit while we're at it. */
	snprintf(hostname, GM_MAX_HOST_NAME_LEN, hostname_fmt, nodeup_node());
	{
		/* We have this prototype here so that we don't depend on
		 * headers which are not normally installed. */
		extern gm_status_t _gm_set_host_name(struct gm_port *, char *);
		res = _gm_set_host_name(gmp, hostname);
		if (res != GM_SUCCESS) {
			/* We report this error but don't barf on it */
			log_print(LOG_WARNING,
				  "_gm_set_hostname: %s (ignoring)\n",
				  gm_strerror(res));
		}
	}
	gm_close(gmp);
	return 0;
}

static
int gm_id_callback(void *data, int size, void **a, int *b)
{
	if (bproc_setnodeattr(nodeup_node(), "gm_unique_id", data, size)) {
		log_print(LOG_ERROR,
			  "Failed to set \"gm_unique_id\" on node %d: %s\n",
			  nodeup_node(), bproc_strerror(errno));
		return -1;
	}
	return 0;
}

int nodeup_postmove(int argc, char *argv[])
{
	int i, c;

	while ((c = getopt(argc, argv, "h:")) != -1) {
		switch (c) {
		case 'h':
			hostname_fmt = optarg;
			break;
		default:
			log_print(LOG_ERROR, "Unknown option '%c'\n", c);
			return -1;
		}
	}

	/* most systems will only have one GM unit */
	for (i = 0; i < MAX_UNITS; i++) {
		if (get_unique_id(i) != 0)
			break;
	}

	/* Store info back on the front end */
	return nodeup_rpc(gm_id_callback, node_ids, i * sizeof(node_ids[0]), 0,
			  0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
