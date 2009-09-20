/*------------------------------------------------------------ -*- C -*-
 * switchnet: switch to another subnet
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
 * $Id: switchnet.c,v 1.5 2004/01/26 01:58:28 mkdist Exp $
 *--------------------------------------------------------------------*/

#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/bproc.h>
#include "node_up.h"

#include "rarp.h"

int nodeup_postmove(int argc, char *argv[]) {
    int i, sa_size;
    struct rarp_if_t *ifc;
    struct sockaddr_in remote, local;
    char tmp[30];

    log_print(LOG_DEBUG, "switching to %s\n", argv[1]);

    /* Find RARP information for this interface in the list of RARP
     * responses. */
    for (i=0; i < rarp_if_list_len; i++) {
	ifc = &rarp_if_list[i];
	if (strcmp(argv[1], ifc->name) == 0 &&
	    ifc->bproc_port != 0) {
	    break;
	}
    }
    if (i == rarp_if_list_len) {
	log_print(LOG_ERROR, "No completed RARP for %s found.\n", argv[1]);
	return -1;
    }

    remote.sin_family = AF_INET;
    remote.sin_addr   = ifc->server_ip;
    remote.sin_port   = htons(ifc->bproc_port);
    local.sin_family  = AF_INET;
    local.sin_addr    = ifc->my_ip;
    local.sin_port    = 0;

    strcpy(tmp, inet_ntoa(local.sin_addr));
    log_print(LOG_INFO, "reconnecting %s:%d -> %s:%d\n",
	      tmp, ntohs(local.sin_port), inet_ntoa(remote.sin_addr),
	      ntohs(remote.sin_port));
    if (bproc_nodereconnect(BPROC_NODE_SELF, /*nodeup_node(0),*/
			    (struct sockaddr *) &remote, sizeof(remote),
			    (struct sockaddr *) &local,  sizeof(local)) != 0) {
	log_print(LOG_ERROR, "bproc_nodereconnect: %s\n", strerror(errno));
	return -1;
    }

    log_print(LOG_INFO, "switchnet completed successfully.\n");

    /* Our address and master address are different after this point
     * so re-fetch that information and update what the other node_up
     * modules will see. */
    sa_size = sizeof(nodeup_master);
    if (bproc_nodeaddr(BPROC_NODE_MASTER, (struct sockaddr *)
		       &nodeup_master, &sa_size) == -1) {
	log_print(LOG_ERROR, "Failed to get address of master node: %s\n",
		  strerror(errno));
	return -1;
    }
    
    /* XXX We should reconnect the socket we're using for
     * communication here too since we will may want to down that
     * interface later on. */
    return 0;
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
