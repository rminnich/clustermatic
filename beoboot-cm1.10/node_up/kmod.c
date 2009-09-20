/*------------------------------------------------------------ -*- C -*-
 * nodeup / modsetup:  Set up necessary modules on the slave nodes.
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
 * $Id: kmod.c,v 1.24 2004/10/19 17:53:21 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#include <sys/utsname.h>

#include "node_up.h"
#include "../module.h"

MODULE_DESC("Kernel Module Loader");
MODULE_INFO(
"Usage: kmod [options] modules ..."
"\n"
"   -r rev      Specify an alternate kernel revision to load.  By default\n"
"               kmod will load modules for the kernel running on the\n"
"               front end.\n"
"   -f          Ignore failures.\n"
"\n"
"kmod is a remote module loader.  It takes kernel modules from the front end\n"
"and installs them on the slave node.  Dependencies will be automatically\n"
"loaded for all the modules listed on the command line.\n"
);

int module_load(const char *krev, char * modname) {
    struct module_t *mod;
    char **deps;
    int i;

    mod = module_get(krev, modname);
    if (!mod) {
	log_print(LOG_ERROR, "Module not found: %s\n", modname);
	return -1;
    }

    /* find dependencies and load those as well */
    deps = module_get_deps(mod->map, mod->size);
    for (i=0; deps[i]; i++) {
	module_load(krev, deps[i]);
	free(deps[i]);
    }
    free(deps);

    return 0;
}

int nodeup_premove(int argc, char *argv[]) {
    int c, i;
    int failok = 0;
    const char *krev = 0;
    struct utsname utsbuf;

    /* Before moving to the remote node, every kmod line is treated as
     * hint for modules to load.  '-r' can also be used to load hints
     * for a different kernel */
    while ((c=getopt(argc, argv, "r:f")) != -1) {
	switch (c) {
	case 'r':
	    krev = optarg;
	    break;
	case 'f':
	    failok = 1;
	    break;
	default:
	    log_print(LOG_ERROR, "Unrecognized flag: %c\n", (char) optopt);
	    return -1;
	}
    }

    if (!krev) {
	if (uname(&utsbuf) != 0) {
	    log_print(LOG_ERROR, "Failed to get kernel revision: %s\n",
		      strerror(errno));
	    return -1;
	}
	krev = utsbuf.release;
    }
    
    for (i=optind; i < argc; i++) {
	log_print(LOG_INFO, "Loading module hint %s %s\n", krev, argv[i]);
	if (module_load(krev, argv[i])) {
	    log_print(LOG_ERROR, "Failed to load module %s %s\n",
		      krev, argv[i]);
	    if (!failok)
		return -1;
	}
    }
    return 0;
}

int nodeup_postmove(int argc, char *argv[]) {
    int c, i;
    struct module_t *mod;
    const char *krev;
    struct utsname utsbuf;

    /* We're really just skipping over options here */
    while ((c=getopt(argc, argv, "r:f")) != -1) {
	switch (c) {
	case 'r': break;
	case 'f': break;
	default:
	    log_print(LOG_ERROR, "Unrecognized flag: %c\n", (char) optopt);
	    return -1;
	}
    }

    if (uname(&utsbuf) != 0) {
	log_print(LOG_ERROR, "Failed to get kernel revision: %s\n",
		  strerror(errno));
	return -1;
    }
    krev = utsbuf.release;

    for (i=optind; i < argc; i++) {
	mod = module_get(krev, argv[i]);
	if (!mod || !mod->map) continue;

	log_print(LOG_INFO, "Loading module %s\n", argv[i]);
	if (modprobe(mod, 0))
	    log_print(LOG_ERROR, "  Insmod failed: %s\n", mod_strerror(errno));
	
    }
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
