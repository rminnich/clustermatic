/*------------------------------------------------------------ -*- C -*-
 * sysctl: nodeup module to set sysctl options
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
 * $Id: sysctl.c,v 1.3 2003/04/15 17:54:15 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "node_up.h"

MODULE_DESC("sysctl setup module");
MODULE_INFO(
"Usage: sysctl option value\n"
);

#define PROC_TMP "/.sysctl.proc.tmp"

int nodeup_postmove(int argc, char *argv[]) {
    int i, len, fd;
    char *path, *val;

    if (argc < 3) {
	log_print(LOG_ERROR, "ERROR: Usage: sysctl key value\n");
	return -1;
    }

    if (nodeup_mnt_proc(PROC_TMP))
	return -1;

    /* Arg 1 is the path */
    path = alloca(strlen(argv[1])+strlen(PROC_TMP "/sys/") + 1);
    strcpy(path, PROC_TMP "/sys/");
    strcat(path, argv[1]);

    /* Change dots to slashes in the path */
    for (i=strlen(PROC_TMP "/sys/"); path[i]; i++)
	if (path[i] == '.') path[i] = '/';

    /*log_print(LOG_DEBUG, "PATH: %s\n", path);*/
    
    /* Build the value */
    len = 0;
    for (i=2; i < argc; i++)
	len += strlen(argv[i]) + 1;

    /*log_print(LOG_DEBUG, "VAL LEN: %d\n", len);*/

    val = alloca(len);
    val[0] = 0;
    for (i=2; i+1 < argc; i++) {
	strcat(val, argv[i]);
	strcat(val, " ");
    }
    strcat(val, argv[i]);

    log_print(LOG_INFO, "setting %s = \"%s\"\n", argv[1], val);

    /* Do the sysctl write */
    fd = open(path, O_WRONLY);
    if (fd == -1) {
	log_print(LOG_ERROR, "%s: %s\n", path, strerror(errno));
	return -1;
    }
    if (write(fd, val, strlen(val)) != strlen(val)) {
    	log_print(LOG_ERROR, "write(%s): %s\n", path, strerror(errno));
	close(fd);
	return -1;
    }
    close(fd);
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
