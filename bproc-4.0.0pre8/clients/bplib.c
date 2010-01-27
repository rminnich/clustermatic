/*-------------------------------------------------------------------------
 *  bplib.c: vmadump library management program that works via the BProc
 *  syscall.
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: bplib.c,v 1.2 2001/12/18 21:43:09 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <limits.h>

#include <sys/bproc.h>

void usage(char *arg0)
{
	printf("Usage: %s -c\n"
	       "       %s -a [libs...] \n"
	       "       %s -d [libs...] \n"
	       "       %s -l\n"
	       "\n"
	       "       This program manages the VMAdump in-kernel library list.\n"
	       "       -h            Display this message and exit.\n"
	       "       -v            Display version information and exit.\n"
	       "       -c            Clear kernel library list.\n"
	       "       -a [libs...]  Add to the kernel library list.\n"
	       "       -d [libs...]  Delete from the kernel library list.\n"
	       "       -l            Print the contents of the kernel library list.\n",
	       arg0, arg0, arg0, arg0);
}

enum { MODE_CLEAR, MODE_ADD, MODE_DEL, MODE_LIST };

static
void remove_trailing_newline(char *line)
{
	int len;
	len = strlen(line);
	if (line[len - 1] == '\n')
		line[len - 1] = 0;
}

int main(int argc, char *argv[])
{
	int c, i;
	int mode = -1;
	char buf[PATH_MAX];
	char *listbuf, *p;

	while ((c = getopt(argc, argv, "hvclad")) != EOF) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'v':
			printf("%s version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'c':
			mode = MODE_CLEAR;
			break;
		case 'l':
			mode = MODE_LIST;
			break;
		case 'a':
			mode = MODE_ADD;
			break;
		case 'd':
			mode = MODE_DEL;
			break;
		default:
			exit(1);
		}
	}

	switch (mode) {
	case MODE_CLEAR:
		if (argc - optind != 0) {
			fprintf(stderr, "No library names allowed with -c\n");
			exit(1);
		}
		if (bproc_libclear() == -1) {
			perror("VMAD_LIB_CLEAR");
			exit(1);
		}
		break;
	case MODE_ADD:
		for (i = optind; i < argc; i++) {
			if (strcmp(argv[i], "-") == 0) {
				while (fgets(buf, PATH_MAX, stdin)) {
					remove_trailing_newline(buf);
					if (bproc_libadd(buf) == -1) {
						perror("broc_libadd");
						exit(1);
					}
				}
			} else if (bproc_libadd(argv[i]) == -1) {
				perror("broc_libadd");
				exit(1);
			}
		}
		break;
	case MODE_DEL:
		for (i = optind; i < argc; i++) {
			if (strcmp(argv[i], "-") == 0) {
				while (fgets(buf, PATH_MAX, stdin)) {
					remove_trailing_newline(buf);
					if (bproc_libdel(buf) == -1) {
						perror("bproc_libdel");
						exit(1);
					}
				}
			} else if (bproc_libdel(argv[i]) == -1) {
				perror("bproc_libdel");
				exit(1);
			}
		}
		break;
	case MODE_LIST:
		if (bproc_liblist(&listbuf) == -1) {
			perror("bproc_liblist");
			exit(1);
		}
		/* print out the null delimited list of libraries */
		for (p = listbuf; *p; p += strlen(p) + 1)
			printf("%s\n", p);
		break;
	default:
		usage(argv[0]);
	}
	exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
