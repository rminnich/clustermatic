/*------------------------------------------------------------ -*- C -*-
 * modhelper:  A linux 2.6 module helper thing
 * Erik Arjan Hendriks <hendriks@lanl.gov>
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
 *  $Id: modhelper.c,v 1.5 2004/08/16 20:38:21 mkdist Exp $
 *--------------------------------------------------------------------*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <link.h>		/* for ELF stuff... */
/* This is a hack to get the ELF class thing with the ElfW macro */
#define Elf32_CLASS ELFCLASS32
#define Elf64_CLASS ELFCLASS64

static int verbose = 0;

/*
 *  module_map - map a module into memory.
 */
static
int module_map(const char *name, const void **module_, int *modlen_)
{
	int fd;
	int modlen;
	void *module;
	struct stat st;

	/* Map the module into memory */
	fd = open(name, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Couldn't find module: %s\n", name);
		return -1;
	}

	fstat(fd, &st);
	modlen = st.st_size;

	module = mmap(0, modlen, PROT_READ, MAP_SHARED, fd, 0);
	if (module == MAP_FAILED) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	*module_ = module;
	*modlen_ = modlen;
	return 0;
}

/*
 *  module_find_sec - get the section header for a particular section.
 */
static
const ElfW(Shdr) * module_find_sec(const void *module, int len,
				   const char *name)
{
	int i;
	const ElfW(Ehdr) * ehdr;	/* ELF Header */
	const ElfW(Shdr) * sechdrs;
	const char *secstrings;

    /*--- ELF frobbing ---*/
	ehdr = module;
	if (ehdr->e_ident[EI_CLASS] != ElfW(CLASS)) {
		fprintf(stderr, "Incorrect ELF class.\n");
		return 0;
	}
	sechdrs = module + ehdr->e_shoff;
	secstrings = module + sechdrs[ehdr->e_shstrndx].sh_offset;
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (strcmp(secstrings + sechdrs[i].sh_name, name) == 0)
			return sechdrs + i;
	}
	return 0;
}

/*
 *  module_find_modinfo - find the .modinfo section of the module (which
 *                        is where the modinfo strings are.)
 */
static
int module_find_modinfo(const void *base, int len,
			const char **strs_out, int *len_out)
{
	const ElfW(Shdr) * sechdr;
	const char *start, *end;

	sechdr = module_find_sec(base, len, ".modinfo");
	if (!sechdr) {
		fprintf(stderr,
			"Error: Didn't find a section named \".modinfo\"\n");
		return 0;
	}

	start = base + sechdr->sh_offset;
	end = start + sechdr->sh_size;

	/* Sanity checking... */
	if (((void *)start) < base || ((void *)start) > (base + len) ||
	    ((void *)end) < base || ((void *)end) > (base + len)) {
		fprintf(stderr, "Invalid range.\n");
		return -1;
	}

	*strs_out = start;
	*len_out = sechdr->sh_size;
	return 0;
}

/*
 *  module_modinfo_first
 */
const char *module_modinfo_first(const void *module, int modlen)
{
	int len;
	const char *start, *end, *p;

	if (module_find_modinfo(module, modlen, &start, &len))
		return 0;

	end = start + len;

	for (p = start; p < end && !*p; p++) ;	/* skip over nulls */
	return (p < end) ? p : 0;
}

/*
 *  module_modinfo_next
 */
const char *module_modinfo_next(const void *module, int modlen, const char *p)
{
	int len;
	const char *start, *end;

	if (module_find_modinfo(module, modlen, &start, &len))
		return 0;

	end = start + len;
	for (; p < end && *p; p++) ;	/* skip over string */
	for (; p < end && !*p; p++) ;	/* skip over nulls */

	return (p < end) ? p : 0;
}

/*
 *  module_get_string - get a pointer to a modinfo string.
 */
static
const char *module_modinfo_get(const void *base, int modlen, const char *key)
{
	int klen;
	const char *p;
	klen = strlen(key);
	p = module_modinfo_first(base, modlen);
	while (p) {
		if (strncmp(key, p, klen) == 0 && p[klen] == '=')
			return p + klen + 1;
		p = module_modinfo_next(base, modlen, p);
	}
	return 0;
}

static
int module_show_deps(const void *modmap, int modlen)
{
	const char *p, *np;
	const char *deps;

	deps = module_modinfo_get(modmap, modlen, "depends");
	if (!deps) {
		fprintf(stderr, "No dependency information\n");
		return -1;
	}

	p = deps;
	while (p && *p) {
		np = strchr(p, ',');
		if (np) {
			printf("%.*s ", (int)(np - p), p);
			np++;
		} else {
			printf("%s", p);
		}
		p = np;
	}
	printf("\n");
	return 0;
}

static
int modinfo_prefix(const void *modmap, int modlen, const char *str)
{
	const char *modinfo;

	modinfo = module_modinfo_first(modmap, modlen);
	while (modinfo) {
		if (strncmp(modinfo, str, strlen(str)) == 0) {
			if (verbose)
				fprintf(stderr, "Module contains %s.\n", str);
			return 1;
		}
		modinfo = module_modinfo_next(modmap, modlen, modinfo);
	}

	if (verbose)
		fprintf(stderr, "Module does not contain %s\n", str);
	return 0;
}

void usage(char *arg0)
{
	printf("Usage: %s [options] module\n"
	       "    -h         Display this message and exit.\n"
	       "    -V         Display version information and exit.\n"
	       "    -v         Increase verbose level.\n"
	       "\n"
	       "    -d         Show module dependencies.\n"
	       "\n"
	       "  These flags are logically ORed together if more than one is given.\n"
	       "    -p         Return true if the module contains a PCI alias.\n"
	       "    -u         Return true if the module contains a USB alias.\n",
	       arg0);

}

int main(int argc, char *argv[])
{
	int c, result;
	int check_pci = 0;
	int check_usb = 0;
	int show_deps = 0;
	const void *modmap;
	int modlen;

	while ((c = getopt(argc, argv, "hVvdpu")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'v':
			verbose++;
			break;
		case 'd':
			show_deps = 1;
			break;
		case 'p':
			check_pci = 1;
			break;
		case 'u':
			check_usb = 1;
			break;
		default:
			exit(1);
		}
	}

	if (argc - optind != 1) {
		if (argc - optind == 0)
			usage(argv[0]);
		exit(1);
	}

	/* Map this module */
	if (module_map(argv[optind], &modmap, &modlen) != 0) {
		fprintf(stderr, "Failed to load module %s\n", argv[optind]);
		exit(1);
	}

	if (show_deps) {
		if (module_show_deps(modmap, modlen))
			exit(1);
		exit(0);
	}

	if (check_pci || check_usb) {
		result = 0;
		if (check_pci)
			result |= modinfo_prefix(modmap, modlen, "alias=pci:");
		if (check_usb)
			result |= modinfo_prefix(modmap, modlen, "alias=usb:");

		exit(result == 0 ? 1 : 0);	/* reverse true/false for shell land */
	}

	fprintf(stderr, "Please specify at least one of '-d', '-p' or '-u'\n");
	exit(1);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
