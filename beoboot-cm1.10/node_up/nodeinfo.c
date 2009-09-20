/*------------------------------------------------------------ -*- C -*-
 *
 * nodeinfo.c: a crappy little program to make note of some
 * information about the nodes in the system.
 *
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
 *  $Id: nodeinfo.c,v 1.12 2004/11/04 17:27:22 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/bproc.h>

#include "node_up.h"

MODULE_DESC("Node information gathering module");
#define PROC_TMP "/.nodeinfo.proc.tmp"

static
int store_info_callback(void *data, int size, void **a, int *b) {
    int tmpi;
    long long tmpll;

    tmpi = ((long long *)data)[0];
    if (bproc_setnodeattr(nodeup_node(), "cpus", &tmpi, sizeof(tmpi))) {
	log_print(LOG_ERROR, "Failed to set \"cpus\" on node %d: %s\n",
		  nodeup_node(), bproc_strerror(errno));
	return -1;
    }

    tmpll = ((long long *)data)[1];
    if (bproc_setnodeattr(nodeup_node(), "hz", &tmpll, sizeof(tmpll))) {
	log_print(LOG_ERROR, "Failed to set \"hz\" on node %d: %s\n",
		  nodeup_node(), bproc_strerror(errno));
	return -1;
    }

    tmpll = ((long long *)data)[2];
    if (bproc_setnodeattr(nodeup_node(), "mem", &tmpll, sizeof(tmpll))) {
	log_print(LOG_ERROR, "Failed to set \"mem\" on node %d: %s\n",
		  nodeup_node(), bproc_strerror(errno));
	return -1;
    }
    return 0;
}

int nodeup_postmove(int argc, char *argv[]) {
    FILE *f;
    char line[200];
    int i, j;
    long long values[3] = {0,0,0};

    static char *files[] = { PROC_TMP "/cpuinfo", PROC_TMP "/meminfo", 0};
    struct info_t {
	char *fmt;
	long long *value;
	long long scale;
    } info[] = {
#if defined(__alpha__)
	{"cpus active             : %Ld", &values[0], 1},
	{"cycle frequency [Hz]    : %Ld", &values[1], 1},
#endif
#if defined(__i386__) || defined(__x86_64__)
	{"cpu MHz         : %Ld", &values[1], 1000000},
	{"processor\t:", &values[0], 0},
#endif
#if defined(__powerpc64__) || defined(powerpc)
	{"clock\t\t: %Ld", &values[1], 1000000},
	{"processor\t:", &values[0], 0},
#endif
	{"MemTotal: %Ld", &values[2], 1024},
	{0}
    };

    if (nodeup_mnt_proc(PROC_TMP))
	return -1;

    for (i=0; files[i]; i++) {
	if (!(f = fopen(files[i], "r"))) {
	    perror(files[i]);
	    exit(1);
	}
	while (fgets(line, 100, f)) {
	    for (j=0; info[j].fmt; j++) {
		if (info[j].scale &&
		    sscanf(line, info[j].fmt, info[j].value) == 1) {
		    (*info[j].value) *= info[j].scale;
		    break;
		}
		if (!info[j].scale &&
		    strncmp(info[j].fmt, line, strlen(info[j].fmt)) == 0) {
		    (*info[j].value)++;
		    break;
		}
	    }
	}
	fclose(f);
    }

    log_print(LOG_INFO, "cpus=%Ld; hz=%Ld; mem=%Ld\n",
	      values[0], values[1], values[2]);

    nodeup_rpc(store_info_callback, values, sizeof(values), 0, 0);
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
