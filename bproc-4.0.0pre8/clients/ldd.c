/*
 * Copyright (C) 2006 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <libelf.h>
#include <gelf.h>
#include <limits.h>
#include <glob.h>

#define LD_SO_CONF "/etc/ld.so.conf"

int xp_ldd_support = 1;

typedef struct Dep Dep;
typedef struct Deplist Deplist;

struct Dep {
	char*		name;
	char*		path;
	char*		rpath;
	Dep*		next;
};

struct Deplist {
	Dep*		deps;
	Dep*		deplast;
	int		elfclass;
	char*		sysroot;
	char*		interp;
	char**		ldsoconf;
	char**		ldlibpath;
};

static char *dfltpaths[] = {
	"/lib",
	"/lib64",
	"/usr/lib",
	"/usr/lib64",
	NULL,
};

static Elf_Scn *
find_dyn_section(Elf *elf)
{
	GElf_Shdr shdr;
	Elf_Scn *scn;

	for(scn = elf_getscn(elf, 0); scn != NULL; scn = elf_nextscn(elf, scn)) {
		if (!gelf_getshdr(scn, &shdr))
			continue;

		if (shdr.sh_type == SHT_DYNAMIC)
			return scn;
	}

	return NULL;
}

static char *
find_dyn_type(Elf *elf, Elf_Scn *dynscn, int dtype)
{
	int n;
	GElf_Shdr shdr;
	GElf_Dyn dyn;
	Elf_Data *data;

	if (!gelf_getshdr(dynscn, &shdr)) {
		fprintf(stderr, (char *) elf_errmsg(elf_errno()), EIO);
		return NULL;
	}

	data = NULL;
	for(data = elf_getdata(dynscn, NULL); data != NULL; data = elf_getdata(dynscn, data)) {
		for(n = 0; n < shdr.sh_size / shdr.sh_entsize; n++) {
			if (!gelf_getdyn(data, n, &dyn))
				break;

			if (dyn.d_tag == dtype)
				return elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
		}
	}

	return NULL;
}

static char *
find_interp(Elf *elf)
{
	int i;
	size_t n;
	char *data;
	GElf_Phdr phdr;

	for(i = 0; gelf_getphdr(elf, i, &phdr) != NULL; i++) {
		if (phdr.p_type == PT_INTERP) {
			data = elf_rawfile(elf, &n);
			if (data!=NULL && phdr.p_offset<n)
				return strdup(data + phdr.p_offset);
			break;
		}
	}

	return NULL;
}

static int
add_dep(Deplist *dl, char *name, char *rpath)
{
	Dep *d;

	for(d = dl->deps; d != NULL; d = d->next)
		if (strcmp(d->name, name) == 0)
			break;

	if (d != NULL)
		return 0;

	d = malloc(sizeof(*d));
	d->name = strdup(name);
	d->path = NULL;
	d->rpath = rpath?strdup(rpath):NULL;
	d->next = NULL;

	if (!dl->deps)
		dl->deps = d;

	if (dl->deplast)
		dl->deplast->next = d;

	dl->deplast = d;
	return 0;
}

static int
find_deps(Deplist *dl, const char *pathname)
{
	int fd, n;
	char *rpath;
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Scn *scn;
	GElf_Dyn dyn;
	Elf_Data *data;

	if ((fd = open(pathname, O_RDONLY)) == -1) {
		perror(pathname);
		return -1;
	}

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, (char *) elf_errmsg(elf_errno()), EIO);
		return -1;
	}

	if (!dl->interp)
		dl->interp = find_interp(elf);

	if (!gelf_getehdr(elf, &ehdr)) {
		fprintf(stderr, (char *) elf_errmsg(elf_errno()), EIO);
		return -1;
	}

	if (dl->elfclass < 0)
		dl->elfclass = ehdr.e_ident[EI_CLASS];

	scn = find_dyn_section(elf);
	if (!scn)
		goto done;

	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, (char *) elf_errmsg(elf_errno()), EIO);
		return -1;
	}

	data = NULL;
	rpath = find_dyn_type(elf, scn, DT_RPATH);
	for(data = elf_getdata(scn, NULL); data != NULL; data = elf_getdata(scn, data)) {
		for(n = 0; n < shdr.sh_size / shdr.sh_entsize; n++) {
			if (!gelf_getdyn(data, n, &dyn))
				break;

			if (dyn.d_tag != DT_NEEDED)
				continue;

			add_dep(dl, elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val), rpath);
		}
	}

done:
	elf_end(elf);
	close(fd);
	return 0;
}

static char **
parse_conf(char *file)
{
	char *line = NULL, *end = NULL;
	char **ret = NULL, **temp;
	FILE *fp;

	int n = 0, i, result;
	glob_t libglob;

	line = malloc(PATH_MAX);
	if(!line)
		return NULL;

	if ((fp = fopen(file, "r")) == NULL)
		return NULL;

	while(fgets(line, PATH_MAX, fp)) {

		/* Skip the initial whitespace */
		while(*line==' ' || *line=='\t')
			line++;

		/* Strip comments */
		if ((end = strchr(line, '#')) != NULL)
			*end = '\0';

		/* Strip newline character */
		if ((end = strchr(line, '\n')) != NULL)
			*end = '\0';

		if (*line == '\0')
			continue;

		/* Strip trailing whitespaces and tabs */
		end = line + strlen(line) - 1;
		while(*end == ' ' || *end == '\t')
			end--;

		*(end+1) = '\0';

		if (!strncmp(line, "include" , 7)) {
			line += 8;
			result = glob(line, GLOB_NOSORT, NULL, &libglob);

			switch(result) {
			case 0:
				for(i = 0; i < libglob.gl_pathc; i++) {
					if ((temp = parse_conf(libglob.gl_pathv[i]))) {
						while(*temp != NULL) {
							ret = realloc(ret, (n+1)*sizeof(char *));
							if (!ret)
								return NULL;

							ret[n] = malloc(PATH_MAX);
							strcpy(ret[n], *temp);
							n++;
							temp++;
						}
					}
				}

				globfree(&libglob);
				break;

			case GLOB_NOMATCH:
				break;

			case GLOB_NOSPACE:
				fprintf(stderr, "Out of memory at %s\n", line);
				break;

			case GLOB_ABORTED:
				fprintf(stderr, "%s: Cannot read directory: %s\n", file, line);
				break;
			}

		} else {
			ret = realloc(ret, (n+1)*sizeof(char *));
			if (!ret)
				return NULL;
			ret[n] = malloc(PATH_MAX);
			strcpy(ret[n], line);
			n++;
		}

	}

	fclose(fp);

	ret = realloc(ret, (n+1)*sizeof(char *));
	ret[n] = NULL;
	return ret;
}

static char **
parse_path(char *path)
{
	int n;
	char *s;
	char **ret;

	n = 2;
	s = path;
	while ((s = strchr(s, ':')) != NULL) {
		n++;
		s++;
	}

	ret = malloc(n*sizeof(char *) + strlen(path));
	if (!ret)
		return NULL;

	s = (char *)ret + n*sizeof(char *);
	strcpy(s, path);
	ret[0] = s;
	n = 1;
	while ((s = strchr(s, ':')) != NULL) {
		*s = '\0';
		s++;
		ret[n] = s;
		n++;
	}

	ret[n] = NULL;

	return ret;
}

static int
locate_dep_pathlist(Deplist *dl, Dep *d, char **plist)
{
	int i, fd, elfclass;
	char buf[1024];
	struct stat st;
	Elf *elf;
	GElf_Ehdr ehdr;

	for(i = 0; plist[i] != NULL; i++) {
		if (dl->sysroot)
			snprintf(buf, sizeof(buf), "%s/%s/%s", dl->sysroot, plist[i], d->name);
		else
			snprintf(buf, sizeof(buf), "%s/%s", plist[i], d->name);

		if (stat(buf, &st) < 0)
			continue;

		if ((fd = open(buf, O_RDONLY)) < 0)
			continue;

		if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
			close(fd);
			continue;
		}

		if (!gelf_getehdr(elf, &ehdr)) {
			elf_end(elf);
			close(fd);
			continue;
		}

		elfclass = ehdr.e_ident[EI_CLASS];
		elf_end(elf);
		close(fd);

		if (elfclass != dl->elfclass)
			continue;

		d->path = strdup(buf);
		return 1;
	}

	return 0;
}

static int
locate_dep(Deplist *dl, Dep *d)
{
	int n;
	char **ps;

	/* first try the rpath */
	if (d->rpath) {
		ps = parse_path(d->rpath);
		n = locate_dep_pathlist(dl, d, ps);
		free(ps);
		if (n != 0)
			return n>0?0:-1;
	}

	/* next check the LD_LIBRARY_PATH list */
	if (dl->ldlibpath) {
		n = locate_dep_pathlist(dl, d, dl->ldlibpath);
		if (n != 0)
			return n>0?0:-1;
	}

	/* next check the ld.so.conf list */
	if (dl->ldsoconf) {
		n = locate_dep_pathlist(dl, d, dl->ldsoconf);
		if (n != 0)
			return n>0?0:-1;
	}

	/* last the list of default paths */
	n = locate_dep_pathlist(dl, d, dfltpaths);
	if (n != 0)
		return n>0?0:-1;

	return -1;
}

static void
init_paths(Deplist *dl)
{
	char *s;

	elf_version(EV_CURRENT);

	/* LD_LIBRARY_PATH */
	s = getenv("XCPU_LD_LIBRARY_PATH");
	if (s)
		dl->ldlibpath = parse_path(s);

	/* ld.so.conf */
	dl->ldsoconf = parse_conf(LD_SO_CONF);
}

int
xp_ldd(const char *binary, char *sysroot, char ***deps)
{
	int i, n, len;
	char **ret, *s;
	Deplist dl;
	Dep *cdep, *d, *d1;

	n = -1;
	dl.elfclass = -1;
	dl.deps = NULL;
	dl.deplast = NULL;
	dl.sysroot = sysroot;
	dl.interp = NULL;
	dl.ldsoconf = NULL;
	dl.ldlibpath = NULL;
	init_paths(&dl);

	if (find_deps(&dl, binary) < 0) {
		fprintf(stderr, "cannot parse file %s", binary);
		goto done;
	}

	cdep = dl.deps;
	while (cdep != NULL) {
		if (locate_dep(&dl, cdep) < 0) {
			fprintf(stderr, "cannot find %s", cdep->name);
			goto done;
		}

		if (find_deps(&dl, cdep->path) < 0) {
			fprintf(stderr, "cannot parse file %s", cdep->path);
			goto done;
		}

		cdep = cdep->next;
	}

	n = 1;
	len = strlen(binary) + 1;
	for(d = dl.deps; d != NULL; d = d->next) {
		if (dl.interp && !strcmp(d->path, dl.interp))
			continue;
		len += strlen(d->path) + 1;
		n++;
	}

	ret = malloc((n+1) * sizeof(char *) + len);
	if (!ret) {
		n = -1;
		goto done;
	}

	s = (char *) ret + (n+1)*sizeof(char *);

	/* first one is the binary */
	ret[0] = s;
	strcpy(s, binary);
	s += strlen(binary) + 1;
	for(i = 1, d = dl.deps; d != NULL; d = d->next) {
		if (dl.interp && !strcmp(d->path, dl.interp))
			continue;

		ret[i] = s;
		strcpy(s, d->path);
		s += strlen(d->path) + 1;
		i++;
	}

	ret[i] = NULL;
	*deps = ret;
done:
	d = dl.deps;
	while (d != NULL) {
		d1 = d->next;
		free(d->name);
		free(d->path);
		free(d->rpath);
		free(d);
		d = d1;
	}

	free(dl.interp);

	for(i=0; dl.ldsoconf[i] != NULL; i++)
		free(dl.ldsoconf[i]);
	free(dl.ldlibpath);
	return n;
}
