/*------------------------------------------------------------ -*- C -*-
 * symdm: nodeup module to set sysctl options
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
 * $Id: symdm.c,v 1.4 2003/04/08 22:27:22 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>

#include "node_up.h"

MODULE_DESC("sysctl setup module");
MODULE_INFO(
"Usage: sysctl option value\n"
);

extern void kmod_modprobe(const char *name);
asm(".weak kmod_modprobe");	/* weak extern */

struct sym_t {
    long addr;
    char type;
};

#define PROC_TMP "/.symdm.proc.tmp"

#define SYMFILE_LINE 200
#define S1(x) #x
#define S(x) S1(x)
#define SYMSIZE_MAX  100
static
int symdm_sym_callback(void *in_data, int in_size,
		       void **out_data, int *out_size) {
    char *kver, *symname;
    char *symfilename;
    FILE *symfile;
    char line[SYMFILE_LINE];

    /* Grab the strings from the slave side */
    kver = in_data;
    symname = kver + strlen(kver)+1;
    
    /* Open the system map for this kernel.  This is presumed to live
     * /boot/System.map-KVER */

    symfilename = alloca(strlen(kver) + 18);
    sprintf(symfilename, "/boot/System.map-%s", kver);
    symfile = fopen(symfilename, "r");
    if (!symfile) {
	log_print(LOG_ERROR, "%s: %s\n", symfilename, strerror(errno));
    }

    /* Find the symbol entry we're looking for... */
    while (fgets(line, SYMFILE_LINE, symfile)) {
	char sym[SYMSIZE_MAX+1], type;
	long addr;
	if (sscanf(line, "%lx %c %" S(SYMSIZE_MAX) "s",&addr,&type,sym) != 3)
	    continue;

	if (strcmp(sym, symname) == 0) {
	    struct sym_t *s;
	    s = malloc(sizeof(*s));
	    s->addr = addr;
	    s->type = type;

	    *out_data = s;
	    *out_size = sizeof(*s);
	    fclose(symfile);
	    return 0;
	}
    }
    fclose(symfile);
    return 1;
}

int nodeup_postmove(int argc, char *argv[]) {
    int i, fd;
    char request[100 + SYMSIZE_MAX];
    char symdmline[20 + SYMSIZE_MAX];
    struct utsname unamebuf;

    if (argc < 3) {
	log_print(LOG_ERROR, "ERROR: Usage: sysctl key value\n");
	return -1;
    }

    if (!kmod_modprobe) {
	log_print(LOG_ERROR, "kmod_modprobe undefined.\nsymdm requires "
		  "kmod plugin.\n");
	return -1;
    }

    if (nodeup_mnt_proc(PROC_TMP))
	return -1;

    uname(&unamebuf);

    /* Start by loading the module */
    kmod_modprobe("symdm");

    /* Open the symdm interface */
    fd = open(PROC_TMP "/symdm", O_WRONLY);
    if (fd == -1) {
	log_print(LOG_ERROR, PROC_TMP "/symdm: %s\n", strerror(errno));
	return 1;
    }
    
    for (i=1; i < argc; i++) {
	struct sym_t *s;
	int out_len = 0;

	/* Make the request */
	strcpy(request, unamebuf.release);
	strcpy(request + strlen(unamebuf.release) + 1, argv[i]);
	if (nodeup_rpc(symdm_sym_callback,
		       request, strlen(unamebuf.release) + strlen(argv[i]) + 2,
		       (void **) &s, &out_len) != 0) {
	    log_print(LOG_WARNING, "WARNING: Failed to find symbol \"%s\"\n",
		      argv[i]);
	    continue;
	}

	sprintf(symdmline, "%lx %c %s", s->addr, s->type, argv[i]);
	log_print(LOG_DEBUG,"Loading symbol \"%s\" = 0x%lx\n",argv[i],s->addr);
	free(s);

	/* Do the write to PROC_TMP/symdm */
	lseek(fd, 0, SEEK_SET);
	if (write(fd, symdmline, strlen(symdmline)) != strlen(symdmline)) {
	    log_print(LOG_ERROR, "write(%s/symdm,\"%s\"): %s\n",
		      PROC_TMP, symdmline, strerror(errno));
	    close(fd);
	    return 1;
	}
    }

    close(fd);
    return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
