/*------------------------------------------------------------ -*- C -*-
 * module lib:  Set up necessary modules on the slave nodes.
 * Erik Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2004 University of California.  LA-CC Number 01-67.
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
 * $Id: module.c,v 1.1 2004/08/09 18:46:08 mkdist Exp $
 *--------------------------------------------------------------------*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <sys/utsname.h>

#include <link.h>

#include "module.h"

/* Printing functions that can be defined / redirected at compile time. */
#ifndef modinfo_print
#define modinfo_print(x ...) printf(x)
#endif
#ifndef moderr_print
#define moderr_print(x ...) fprintf(stderr, x)
#endif 

/*--------------------------------------------------------------------
 * Module installation and dependency handling.
 *------------------------------------------------------------------*/
int              install_seq=1;
struct module_t *modlist = 0;

const char *module_path = "/lib/modules/%s";

/*--------------------------------------------------------------------
 *  Module handling code
 *------------------------------------------------------------------*/
extern long init_module(void *, unsigned long, const char *);
extern long delete_module(const char *, unsigned int);

#include <link.h>		/* for Elf stuff... */
/* This is a hack to get the ELF class thing with the ElfW macro */
#define Elf32_CLASS ELFCLASS32
#define Elf64_CLASS ELFCLASS64

/*
 *  module_find_sec - get the section header for a particular section.
 */
static
const ElfW(Shdr) *module_find_sec(const void *module, int len,
				  const char *name) {
    int i;
    const ElfW(Ehdr) *ehdr;		/* ELF Header */
    const ElfW(Shdr) *sechdrs;
    const char *secstrings;

    /*--- ELF frobbing ---*/
    ehdr = module;
    if (ehdr->e_ident[EI_CLASS] != ElfW(CLASS)) {
	moderr_print("Incorrect ELF class.\n");
	return 0;
    }
    sechdrs    = module + ehdr->e_shoff;
    secstrings = module + sechdrs[ehdr->e_shstrndx].sh_offset;
    for (i=0; i < ehdr->e_shnum; i++) {
	if (strcmp(secstrings+sechdrs[i].sh_name, name) == 0)
	    return sechdrs+i;
    }
    return 0;
}

/*
 *  module_find_modinfo - find the .modinfo section of the module (which
 *                        is where the modinfo strings are.)
 */
static
int module_find_modinfo(const void *base, int len,
			const char ** strs_out, int *len_out) {
    const ElfW(Shdr) *sechdr;
    const char *start, *end;

    sechdr = module_find_sec(base, len, ".modinfo");
    if (!sechdr) {
	moderr_print("Error:Didn't find a section named \".modinfo\"\n");
	return 0;
    }

    start = base  + sechdr->sh_offset;
    end   = start + sechdr->sh_size;

    /* Sanity checking... */
    if (((void *) start) < base || ((void*)start) > (base + len) ||
	((void *) end)   < base || ((void*)end)   > (base + len)) {
	moderr_print("Invalid range.\n");
	return -1;
    }

    * strs_out = start;
    * len_out  = sechdr->sh_size;
    return 0;
}

/*
 *  module_modinfo_first
 */
const char *module_modinfo_first(const void *module, int modlen) {
    int len;
    const char *start, *end, *p;

    if (module_find_modinfo(module, modlen, &start, &len))
	return 0;

    end = start + len;

    for (p = start; p < end && !*p; p++); /* skip over nulls */
    return (p < end) ? p : 0;
}

/*
 *  module_modinfo_next
 */
const char *module_modinfo_next(const void *module, int modlen, const char *p){
    int len;
    const char *start, *end;

    if (module_find_modinfo(module, modlen, &start, &len))
	return 0;

    end = start + len;
    for (; p < end &&  *p; p++); /* skip over string */
    for (; p < end && !*p; p++); /* skip over nulls */
    
    return (p < end) ? p : 0;
}

/*
 *  module_get_string - get a pointer to a modinfo string.
 */
static
const char *module_modinfo_get(const void *base, int modlen, const char *key) {
    int klen;
    const char *p;
    klen = strlen(key);
    p = module_modinfo_first(base, modlen);
    while (p) {
	if (strncmp(key, p, klen) == 0 && p[klen] == '=')
	    return p+klen+1;
	p = module_modinfo_next(base, modlen, p);
    }
    return 0;
}

/*
 *  module_get_deps - get a string list of module dependencies
 */
char **module_get_deps(void *module, int len) {
    int count;
    const char *p, *end;
    const char *deps;
    char **deps_out;

    deps = module_modinfo_get(module, len, "depends");
    if (!deps) {
	moderr_print("No dependency information\n");
	return 0;
    }

    /* Count the number of dependencies */
    for (p = deps, count = 0; p && *p; 	p = strchr(p+1, ','))
	 count++;

    deps_out = malloc(sizeof(*deps_out) * (count+1));
    if (!deps_out) {
	moderr_print("Out of memory.\n");
	return 0;
    }

    /* Second pass, copy the strings */
    for (p = deps, count = 0; p && *p;) {
	end = strchr(p, ',');
	if (!end) end = strchr(p, 0);

	deps_out[count] = strndup(p, end-p);
	if (!deps_out[count]) {
	    while (--count >= 0)
		free(deps_out[count]);
	    free(deps_out);
	    moderr_print("Out of memory.\n");
	    return 0;
	}
	count++;
	p = *end ? end+1 : end;
    }
    deps_out[count] = 0;
    return deps_out;
}

/*
 *  module_get_modname - get the internal modname of a module
 */
const char *module_get_modname(const void *module, int len) {
    const ElfW(Shdr) *sechdr;
    const char *start, *end, *p;
    sechdr = module_find_sec(module, len, ".gnu.linkonce.this_module");
    if (!sechdr)
	return 0;

    start = module + sechdr->sh_offset;
    end   = start  + sechdr->sh_size;

    /* Big-ish presumption here: The module's name will be the first
     * string we come across in this section.  This depends on the
     * layout of 'struct module' to some degree. */

    for (p = start; p < end && !*p; p++); /* skip over nulls */
    return p;
}

/* reasonable strerror strings for insmod */
const char *mod_strerror(int err) {
    switch (err) {
    case ENOEXEC:
	return "Invalid module format";
    case ENOENT:
	return "Unknown symbol in module";
    case ESRCH:
	return "Module has wrong symbol version";
    case EINVAL:
	return "Invalid parameters";
    default:
	return strerror(err);
    }
}

int module_map(const char *pathname, void **module_, int *modlen_) {
    int fd;
    int modlen;
    void *module;
    struct stat st;

    /* Map the module into memory */
    fd = open(pathname, O_RDONLY);
    if (fd == -1) {
	moderr_print("%s: %s\n", pathname, strerror(errno));
	return -1;
    }

    fstat(fd, &st);
    modlen = st.st_size;

    module = mmap(0, modlen, PROT_READ, MAP_SHARED, fd, 0);
    if (module == MAP_FAILED) {
	moderr_print("mmap: %s\n", strerror(errno));
	close(fd);
	return -1;
    }
    close(fd);

    *module_ = module;
    *modlen_ = modlen;
    return 0;
}

/*--------------------------------------------------------------------
 *  Stuff for dealing with a bunch of modules
 *
 *------------------------------------------------------------------*/
static
char *find(const char *path, const char *name) {
    DIR *dir;
    struct dirent *de;
    struct stat statbuf;
    char *fullname;
    char *result = 0;

    dir = opendir(path);
    if (!dir) {
	moderr_print("%s: %s\n", path, strerror(errno));
	return 0;
    }
    while ((de = readdir(dir))) {
	/* Ignore these two */
	if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
	    continue;

	fullname = malloc(strlen(path) + strlen(de->d_name) + 2);
	sprintf(fullname, "%s/%s", path, de->d_name);

	if (strcmp(de->d_name, name) == 0) {
	    closedir(dir);
	    return fullname;
	}
	if (lstat(fullname, &statbuf) == 0) {
	    /* recurse into directories */
	    if (S_ISDIR(statbuf.st_mode)) {
		result = find(fullname, name);
		if (result) {
		    free(fullname);
		    closedir(dir);
		    return result;
		}
	    }
	} else {
	    moderr_print("%s: %s\n", fullname, strerror(errno));
	}
	free(fullname);
    }
    closedir(dir);
    return 0;
}

static
char *module_find(const char *path, const char *modname) {
    char * modname_;
    modname_ = alloca(strlen(modname) + 4);
    sprintf(modname_, "%s.ko", modname);

    return find(path, modname_);
}

struct module_t *module_get(const char *krev, const char *name) {
    struct module_t *mod;
    struct utsname utsbuf;
    char *modfile, *modpath;

    if (!krev) {
	uname(&utsbuf);
	krev = utsbuf.release;
    }

    /* See if we have this module somewhere. */
    for (mod = modlist; mod; mod=mod->next)
	if (strcmp(mod->name, name)==0 &&
	    strcmp(mod->krev, krev)==0)
	    return mod;

    /* Allocate a new one. */
    mod = malloc(sizeof(*mod));
    if (!mod)
	return 0;

    memset(mod, 0, sizeof(*mod));

    /* Find + map the module */
    modpath = alloca(strlen(module_path) + strlen(krev) + 10);
    sprintf(modpath, module_path, krev);
    modfile = module_find(modpath, name);
    if (!modfile) {
	free(mod);
	return 0;
    }
    if (module_map(modfile, &mod->map, &mod->size) != 0) {
	free(mod);
	return 0;
    }

    mod->krev = strdup(krev);
    mod->name = strdup(name);
    mod->args = strdup("");

    /* insert in global list of modules */
    mod->next = modlist;
    modlist = mod;
    return mod;
}

int modprobe(struct module_t *mod, char *args) {
    int i;
    /*void *module;*/
    char **deps;
    /*int   modlen;*/
    const char *mn;

    if (mod->installed) return 0;
    mod->installed=-1;		/* Set this here to avoid loops */

    /* XXX This needs to happen for removal to work... */
    /* Make note of this module's modname */
    mn = module_get_modname(mod->map, mod->size);

    /* Get dependency information */
    deps = module_get_deps(mod->map, mod->size);
    if (deps) {
	for (i=0; deps[i]; i++) {
	    struct module_t *mod_dep;
	    mod_dep = module_get(mod->krev, deps[i]);
	    if (modprobe(mod_dep,0)) {
		moderr_print("Failed to load dependency for "
			    "module \"%s\"\n", mod->name);
		/* XXX Free/unmap */
		return -1;
	    }
	    
	    free(deps[i]);
	}
	free(deps);
    }

    if (!args)
	args = mod->args;

    modinfo_print("Installing module \"%s\"\n", mod->name);
    if (init_module(mod->map, mod->size, args) != 0) {
	if (errno == EEXIST) {
	    modinfo_print("  module already installed.\n");
	    mod->installed = -1; /* Don't try to uninstall */
	} else {
	    moderr_print("  *** MODULE INSTALL FAILED: %s\n",
			 mod_strerror(errno));
	    mod->installed = 0;	/* Failed */
	}
    } else {
	/* Make note of this module's loaded name */
	const char *modname;
	modname = module_get_modname(mod->map, mod->size);
	mod->loaded_name = strdup(modname);

	mod->installed=install_seq++;	/* Set this here to avoid loops */
    }
    return 0;
}
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
