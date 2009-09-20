/*------------------------------------------------------------ -*- C -*-
 * nodeup / vmadlib:  library list transfer module for nodeup
 * Erik Arjan Hendriks <hendriks@lanl.gov>
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
 * $Id: vmadlib.c,v 1.11 2004/11/04 16:42:33 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <sys/bproc.h>

#include "node_up.h"

MODULE_DESC("Library transfer module.");
MODULE_INFO(
"Usage: vmadlib\n"
"    vmadlib transfers shared libraries to the slave node.  It looks at the\n"
"    kernel library list (bplib -l) to get a list of libraries to transfer.\n"
"    Once on the slave node, the slave's library list is setup and those\n"
"    libraries are written out.  vmadlib will also create symlinks for the\n"
"    sonames for the libraries which are transfered - just like ldconfig.\n"
"\n"
"Dependencies:\n"
"    This plugin requires the miscfiles plugin to be loaded for transfer\n"
"    of the library files.\n"
);


static int    liblist_size;
static char **liblist;

/*--------------------------------------------------------------------
 *   ldconfig
 *------------------------------------------------------------------*/
/*--------------------------------------------------------------------
 *  This is a quick 'n' dirty ldconfig that doesn't create the cache
 *  file.... although it probably should.
 */

/* This code is borrowed from the GNU C Library */
static int
_dl_cache_libcmp (const char *p1, const char *p2)
{
  while (*p1 != '\0')
    {
      if (*p1 >= '0' && *p1 <= '9')
        {
          if (*p2 >= '0' && *p2 <= '9')
            {
              /* Must compare this numerically.  */
              int val1;
              int val2;

              val1 = *p1++ - '0';
              val2 = *p2++ - '0';
              while (*p1 >= '0' && *p1 <= '9')
                val1 = val1 * 10 + *p1++ - '0';
              while (*p2 >= '0' && *p2 <= '9')
                val2 = val2 * 10 + *p2++ - '0';
              if (val1 != val2)
                return val1 - val2;
            }
          else
            return 1;
        }
      else if (*p2 >= '0' && *p2 <= '9')
        return -1;
      else if (*p1 != *p2)
        return *p1 - *p2;
      else
        {
          ++p1;
          ++p2;
        }
    }
  return *p1 - *p2;
}

/* This is a macro to try and avoid bad data in the ELF file.  We
 * still need to be a bit more careful about the dynamic entries and
 * strings. */
#define CHECK_PTR(val, extent) \
    if (((void*)(val)) < data || \
        ((void*)(val)) >= data + statbuf.st_size - (extent)) { \
        goto out_no_soname; \
    }

static
char *get_soname(const char *filename) {
    int fd, i;
    struct stat statbuf;
    void *data;
    char *soname = 0, *dyn_strings = 0;
    Elf32_Ehdr *ehdr_;

    /* Step 1: Load the library into memory. */
    if ((fd = open(filename, O_RDONLY)) == -1) {
	log_print(LOG_ERROR, "%s: %s\n", filename, strerror(errno));
	return 0;
    }

    if (fstat(fd, &statbuf)) {
	log_print(LOG_ERROR, "fstat(%s): %s\n", filename, strerror(errno));
	close(fd);
	return 0;
    }

    data = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (data == MAP_FAILED) {
	log_print(LOG_ERROR, "mmap(%s): %s\n", filename, strerror(errno));
	return 0;
    }

    ehdr_ = data;

    if (strncmp(ehdr_->e_ident, ELFMAG, SELFMAG) != 0) {
	log_print(LOG_WARNING, "%s: Not an ELF object!\n", filename);
	goto out_no_soname;
    }

    if (ehdr_->e_ident[EI_CLASS] == ELFCLASS32) {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Dyn  *dyn = 0;
	Elf32_Addr loadaddr = -1;

	/*------------------------------------------------*/
	/* THIS CHUNK IS THE SAME FOR 32-bit and 64-bit */
	ehdr = data;
	if (ehdr->e_type != ET_DYN) {
	    log_print(LOG_WARNING,"%s: Not an ELF Dynamic object!\n",filename);
	    goto out_no_soname;
	}

	/* Find the program headers using the ELF header */
	phdr = data + ehdr->e_phoff;
	CHECK_PTR(phdr, sizeof(*phdr) * ehdr->e_phnum);

	/* Look through the program header entries */
	for (i=0; i < ehdr->e_phnum; i++) {
	    switch(phdr[i].p_type) {
	    case PT_LOAD:
		if (loadaddr == -1) 
		    loadaddr = phdr[i].p_vaddr - phdr[i].p_offset;
		break;
	    case PT_DYNAMIC:
		dyn = data + phdr[i].p_offset;
		CHECK_PTR(dyn, phdr[i].p_filesz);
		break;
	    }
	}
	if (loadaddr == -1) loadaddr = 0;
	if (!dyn) goto out_no_soname;
	
	/* One pass to find the string table */
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
	    CHECK_PTR(&dyn[i], sizeof(*dyn)*2);
	    if (dyn[i].d_tag == DT_STRTAB) {
		dyn_strings = data + (dyn[i].d_un.d_val - loadaddr);
		CHECK_PTR(dyn_strings, 0);
		break;
	    }
	}
	if (!dyn_strings) goto out_no_soname;
	
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
	    if (dyn[i].d_tag == DT_SONAME) {
		soname = dyn_strings + dyn[i].d_un.d_val;
		CHECK_PTR(soname, 0);
		break;
	    }
	}
	/*------------------------------------------------*/
    } else if (ehdr_->e_ident[EI_CLASS] == ELFCLASS64) {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Dyn  *dyn = 0;
	Elf64_Addr loadaddr = (Elf64_Addr) -1;

	/*------------------------------------------------*/
	/* THIS CHUNK IS THE SAME FOR 32-bit and 64-bit */
	ehdr = data;
	if (ehdr->e_type != ET_DYN) {
	    log_print(LOG_WARNING,"%s: Not an ELF Dynamic object!\n",filename);
	    goto out_no_soname;
	}

	/* Find the program headers using the ELF header */
	phdr = data + ehdr->e_phoff;
	CHECK_PTR(phdr, sizeof(*phdr) * ehdr->e_phnum);

	/* Look through the program header entries */
	for (i=0; i < ehdr->e_phnum; i++) {
	    switch(phdr[i].p_type) {
	    case PT_LOAD:
		if (loadaddr == -1) 
		    loadaddr = phdr[i].p_vaddr - phdr[i].p_offset;
		break;
	    case PT_DYNAMIC:
		dyn = data + phdr[i].p_offset;
		CHECK_PTR(dyn, phdr[i].p_filesz);
		break;
	    }
	}
	if (loadaddr == -1) loadaddr = 0;
	if (!dyn) goto out_no_soname;
	
	/* One pass to find the string table */
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
	    CHECK_PTR(&dyn[i], sizeof(*dyn)*2);
	    if (dyn[i].d_tag == DT_STRTAB) {
		dyn_strings = data + (dyn[i].d_un.d_val - loadaddr);
		CHECK_PTR(dyn_strings, 0);
		break;
	    }
	}
	if (!dyn_strings) goto out_no_soname;
	
	for (i=0; dyn[i].d_tag != DT_NULL; i++) {
	    if (dyn[i].d_tag == DT_SONAME) {
		soname = dyn_strings + dyn[i].d_un.d_val;
		CHECK_PTR(soname, 0);
		break;
	    }
	}
	/*------------------------------------------------*/
    } else {
	log_print(LOG_WARNING, "%s: Bad ELF class!\n", filename);
	goto out_no_soname;
    }
    if (soname)
	soname = strdup(soname);
 out_no_soname:
    munmap(data, statbuf.st_size);
    return soname;
}

static
int link_library(const char *libpath) {
    int r;
    char *file_name, *soname;
    char *link_path;
    struct stat statbuf;
    char existing_link[PATH_MAX+1];

    /* Sanity checking */
    if (libpath[0] != '/') {
	log_print(LOG_ERROR, "%s: link_library only works for "
		  "absolute paths.\n", libpath);
	return -1;
    }

    soname = get_soname(libpath);
    if (!soname) {
	log_print(LOG_INFO, "%s no SONAME.  Not and ELF object?\n", libpath);
	return 0;
    }

    /* allocate some memory for the string */
    link_path  = alloca(strlen(libpath) + strlen(soname) + 1);
    file_name  = strrchr(libpath, '/') + 1;
    sprintf(link_path, "%.*s%s", (int) (file_name - libpath),
	    libpath, soname);
    free(soname);

    log_print(LOG_DEBUG, "%s: SONAME is %s\n", link_path, file_name);

    if (lstat(link_path, &statbuf) == 0) {
	if (!S_ISLNK(statbuf.st_mode)) {
	    /* This is not a link, skip over it */
	    log_print(LOG_INFO, "%s exists and is not a link. (ignoring)\n",
		      link_path);
	    return 0;
	}

	r = readlink(link_path, existing_link, PATH_MAX);
	if (r == -1) {
	    log_print(LOG_ERROR, "readlink(%s): %s\n", link_path,
		      strerror(errno));
	    return -1;
	}
	existing_link[r] = 0;	/* readlink doesn't null terminate */

	if (_dl_cache_libcmp(file_name, existing_link) > 0) {
	    /* This library is newer - replace the link */
	    log_print(LOG_INFO, "Re-linking %s -> %s\n", link_path, file_name);
	    unlink(link_path);
	} else {
	    /* This library is older - don't replace the link */
	    return 0;
	}
    } else {
	log_print(LOG_INFO, "Linking %s -> %s\n", link_path, file_name);
    }

    /* Create the link */
    if (symlink(file_name, link_path)) {
	log_print(LOG_ERROR, "symlink(\"%s\", \"%s\"): %s\n",
		  file_name, link_path, strerror(errno));
	return -1;
    }
    return 0;
}

/*--------------------------------------------------------------------
 *   vmadlib library management main
 *------------------------------------------------------------------*/
extern int miscfiles_premove(int argc, char *argv[]);
extern int miscfiles_postmove(int argc, char *argv[]);

/* We need some kind of auto-magic dependency system. */
/*asm(".weak miscfiles_premove");*/
/*asm(".weak miscfiles_postmove");*/

int vmadlib_premove(int argc, char *argv[]) {
    int i;
    char *p;
    char *libs;

#if 0
    if (!miscfiles_premove) {
	if (nodeup_require_module("miscfiles")) {

	}
    }
#endif

    /* Grab the lib list from the kernel */
    if (bproc_liblist(&libs) == -1) {
	log_print(LOG_ERROR, "bproc_liblist failed: %s\n", strerror(errno));
	return -1;
    }

    /* Create an argv style list of strings out of this list */
    liblist_size = 0;
    for (p = libs; *p; p = p+strlen(p)+1) liblist_size++;
    log_print(LOG_INFO, "library list contains %d libraries\n", liblist_size);

    if (!(liblist = malloc(sizeof(*liblist) * (liblist_size+1)))) {
	log_print(LOG_ERROR, "out of memory\n");
	return -1;
    }

    /* Convert it */
    for (p = libs, i=0; *p; p = p+strlen(p)+1)
	liblist[i++] = p;
    liblist[i] = 0;

    if (!miscfiles_premove) {
	log_print(LOG_ERROR, "vmadlib requires \n");
    }

    /* Load the libraries into RAM */
    return miscfiles_premove(liblist_size+1, liblist - 1);
}

int vmadlib_postmove(int argc, char *argv[]) {
    int i, ret;

    if (bproc_libclear() != 0) {
	log_print(LOG_ERROR, "bproc_libclear failed: %s\n", strerror(errno));
	return -1;
    }
    log_print(LOG_DEBUG, "cleared library list on node %d\n", nodeup_node);

    log_print(LOG_DEBUG, "liblist_size = %d;\n", liblist_size);
    for (i=0; i < liblist_size; i++) {
	if (bproc_libadd(liblist[i]) != 0) {
	    log_print(LOG_ERROR, "bproc_libadd(\"%s\") failed: %s\n",
		      liblist[i], strerror(errno));
	    return -1;
	}
	log_print(LOG_DEBUG, "added library \"%s\"\n", liblist[i]);
    }

    /* Write out the files and do the ldconfig stuff. */
    ret = miscfiles_postmove(liblist_size+1, liblist - 1);
    if (ret) return ret;

    for (i=0; i < liblist_size; i++)
	if (link_library(liblist[i]))
	    ret = -1;
    return ret;
}

int nodeup_premove(int argc, char *argv[])
  __attribute__((alias ("vmadlib_premove")));
int nodeup_postmove(int argc, char *argv[])
  __attribute__((alias ("vmadlib_postmove")));

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
