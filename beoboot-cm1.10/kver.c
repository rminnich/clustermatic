/*------------------------------------------------------------ -*- C -*-
 *  kver.c: prints the version a kernel module was built against.
 *  Copyright (C) 2000 Scyld Computing Corporation
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  $Id: kver.c,v 1.3 2004/08/19 21:06:17 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <errno.h>
#include <bfd.h>

static
long get_sym_offset(char *filename, char *sym)
{
	bfd *objfile;
	size_t symtabsize, numsyms, i;
	long offset = -1;
	asymbol **symtab = 0;

	objfile = bfd_openr(filename, 0);
	if (!objfile)
		goto bail;
	if (!bfd_check_format(objfile, bfd_object))
		goto bail;
	/* Get the symbol table */
	symtabsize = bfd_get_symtab_upper_bound(objfile);
	symtab = (asymbol **) malloc(symtabsize);
	if (!symtab) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	numsyms = bfd_canonicalize_symtab(objfile, symtab);
	/* Walk the symbol table */
	for (i = 0; i < numsyms; i++)
		if (strcmp(bfd_asymbol_name(symtab[i]), sym) == 0) {
			offset = symtab[i]->value + symtab[i]->section->filepos;
			break;
		}
      bail:
	if (objfile)
		bfd_close(objfile);
	if (symtab)
		free(symtab);
	return offset;
}

char tempfilename[30];
static
int uncompress_kernel(char *img)
{
	int pid, fd;
	int status;
	sprintf(tempfilename, "/tmp/.kver.%d", getpid());
	if (unlink(tempfilename) == -1 && errno != ENOENT) {
		perror(tempfilename);
		exit(1);
	}
	if ((fd = open(tempfilename, O_WRONLY | O_CREAT | O_EXCL, 0666)) == -1) {
		perror(tempfilename);
		exit(1);
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(1);
	}
	if (pid == 0) {
		dup2(fd, STDOUT_FILENO);
		fd = open("/dev/null", O_WRONLY);
		dup2(fd, STDERR_FILENO);
		execlp("gzip", "gzip", "-cd", img, NULL);
		exit(1);
	}

	close(fd);
	if (wait(&status) != pid) {
		perror("wait");
		unlink(tempfilename);
		exit(1);
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		unlink(tempfilename);
		return -1;
	}
	return 0;
}

#define ZSIG    "HdrS"
#define ZSIGLEN 4
#define ZSIGOFF 0x202
#define ZVEROFF 0x20E
long get_zImage_offset(char *filename)
{
	FILE *file;
	int offset = -1;
	unsigned char buffer[10];

	file = fopen(filename, "r");
	if (!file)
		return -1;
	fseek(file, ZSIGOFF, SEEK_SET);	/* Check signature */
	if (fread(buffer, 1, ZSIGLEN, file) < ZSIGLEN) {
		fprintf(stderr, "read of ZSIGLEN failed\n");
	}
		
	if (memcmp(buffer, ZSIG, ZSIGLEN) != 0)
		goto bail;

	fseek(file, ZVEROFF, SEEK_SET);	/* Read offset of version */
	if (fread(buffer, 1, 2, file) < 2) {
		fprintf(stderr, "read of ZVER failed\n");
	}
	offset = ((int)buffer[0]) + (((int)buffer[1]) << 8) + 0x200;
      bail:
	fclose(file);
	return offset;
}

int main(int argc, char *argv[])
{
	int i;
	FILE *file = 0;
	struct utsname buf;
	long offset;
	char ch;

	bfd_init();
	for (i = 1; i < argc; i++) {
		if (file)
			fclose(file);
		file = fopen(argv[i], "r");
		if (!file) {
			perror(argv[i]);
			continue;
		}

		/* Try it like it's a module */
		offset = get_sym_offset(argv[i], "__module_kernel_version");
		if (offset != -1) {
			fseek(file, offset, SEEK_SET);
			/* lazy lazy strcpy w/o buffers. */
			do {
				ch = fgetc(file);
			} while (ch && ch != '=');	/* Skip to the '=' */
			ch = fgetc(file);
			while (ch) {
				fputc(ch, stdout);
				ch = fgetc(file);
			}
			fputc('\n', stdout);
			continue;
		}

		/* Try it like it's a kernel image */
		offset = get_sym_offset(argv[i], "system_utsname");
		if (offset != -1) {
			/* XXX This will probably barf in the cross-architecture
			 * case... */
			fseek(file, offset, SEEK_SET);
			if (fread(&buf, 1, sizeof(buf), file) < sizeof(buf)) {
				fprintf(stderr, "read of sizeof(buf) failed\n");
			}
			puts(buf.release);
			fclose(file);
			continue;
		}

		/* Try it like it's a compressed kernel image */
		if (uncompress_kernel(argv[i]) == 0) {
			offset = get_sym_offset(tempfilename, "system_utsname");
			if (offset != -1) {
				/* XXX This will probably barf in the cross-architecture
				 * case... */
				fclose(file);
				file = fopen(tempfilename, "r");
				fseek(file, offset, SEEK_SET);
				if (fread(&buf, 1, sizeof(buf), file) < sizeof(buf)) {
					fprintf(stderr, "read of sizeof(buf) failed\n");
				}
				puts(buf.release);
				fclose(file);
				unlink(tempfilename);
				continue;
			}
			unlink(tempfilename);
		}

		/* Try it like it's an i386 zImage */
		offset = get_zImage_offset(argv[i]);
		if (offset != -1) {
			fseek(file, offset, SEEK_SET);
			ch = fgetc(file);
			while (ch && ch != ' ') {
				fputc(ch, stdout);
				ch = fgetc(file);
			}
			fputc('\n', stdout);
			continue;
		}
		fprintf(stderr, "%s: unrecognized file type.\n", argv[i]);
	}
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
