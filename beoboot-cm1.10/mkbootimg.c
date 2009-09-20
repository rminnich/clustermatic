/*------------------------------------------------------------ -*- C -*-
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *  This version is derivative from the orignal mkbootimg.c which is
 *  Copyright (C) 2000 Scyld Computing Corporation
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
 *  $Id: mkbootimg.c,v 1.5 2001/10/24 19:05:22 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include "boot.h"

static
char *meld_command_line(char **args) {
    int i, len;
    char *command_line;
    len = 1;
    for (i=0; args[i]; i++)
	len += strlen(args[i])+1;
    command_line = malloc(len);
    if (!command_line) {
	fprintf(stderr, "Out of memory.\n");
	exit(1);
    }
    command_line[0] = 0;
    for (i=0; args[i]; i++) {
	strcat(command_line, args[i]);
	if (args[i+1]) strcat(command_line, " ");
    }
    return command_line;
}

static
void open_file(int *fd, char *filename, int mode, char *msg) {
    if (*fd != -1) {
	fprintf(stderr, "%s", msg);
	exit(1);
    }
    *fd = open(filename, mode, 0666);
    if (*fd == -1) {
	perror(filename);
	exit(1);
    }
}

/*
static
int read_all(int fd,void *buffer, size_t len) {
    int r, bytes = len;
    while (bytes) {
        r = read(fd, buffer, bytes);
        if (r < 0) return r;
        if (r == 0) return len - bytes;
        bytes  -= r;
        buffer += r;
    }
    return len;
}
*/

static
int check_write(int fd, void *buf, int len) {
    int w;
    w = write(fd, buf, len);
    if (w == -1) {
	perror("write");
	exit(1);
    }
    if (w < len) {
	fprintf(stderr, "Short write\n");
	exit(1);
    }
    return w;
}

#define BSIZE 8192
static
void dump_file(int outfd, int infd, int pad) {
    int r;
    int bytes = 0;
    char buffer[BSIZE];

    r = read(infd, buffer, BSIZE);
    while (r > 0) {
	bytes += r;
	check_write(outfd, buffer, r);
	r = read(infd, buffer, BSIZE);
    }
    if (r == -1) {
	perror("read");
	exit(1);
    }

    if (pad > 0) {
	memset(buffer, 0, pad);
	r = (pad - (bytes % pad)) % pad;
	check_write(outfd, buffer, r);
    }
}

static
void write_beoboot_image(int outfile, int kernel, int initrd, char *cmdline) {
    int len;
    struct beoboot_header header;
    struct stat buf, buf2;
    len = strlen(cmdline)+1;

    if (fstat(kernel, &buf)) {
	perror("fstat(kernel)");
	exit(1);
    }
    if (!S_ISREG(buf.st_mode)) {
	fprintf(stderr, "Kernel image is not a regular file!\n");
	exit(1);
    }
    if (initrd != -1) {
	if (fstat(initrd, &buf2)) {
	    perror("fstat(kernel)");
	    exit(1);
	}
	if (!S_ISREG(buf2.st_mode)) {
	    fprintf(stderr, "Kernel image is not a regular file!\n");
	    exit(1);
	}
    } else
	buf2.st_size = 0;

    /* Put together the network boot image header */
    memcpy(header.magic, BEOBOOT_MAGIC, sizeof(header.magic));
    header.arch  = BEOBOOT_ARCH; /* The only one we have for now... */
    header.flags = initrd == -1 ? 0 : BEOBOOT_INITRD_PRESENT;
    header.cmdline_size = htons(len);
    header.kernel_size = buf.st_size;
    header.initrd_size = buf2.st_size;

    check_write(outfile, &header, sizeof(header));
    check_write(outfile, cmdline, len);

    dump_file(outfile, kernel, 0);
    if (initrd != -1)
	dump_file(outfile, initrd, 0);
}

static
void usage(char *arg0) {
    printf(
"Usage: %s [-h] [-v] [-F] [-i initrd] [-f file] imagefile [command line ....]\n"
"       This program creates network boot images for use with beoboot-LANL.\n"
"\n"
"       -h          Display this message and exit.\n"
"       -v          Display the program version number and exit.\n"
"       -i initrd   Load the initial ram disk image stored in initrd.\n"
"       -f file     Write the output to file instead of standard out.\n"
"\n"
"       imagefile is the kernel image file to be loaded.  All remaining\n"
"       options on the command line will be concatenated and passed to\n"
"       the kernel as the kernel command line.\n"
, arg0);
}

int main(int argc, char *argv[]) {
    int c;
    int outfile=-1, kernel=-1, initrd=-1;
    char *cmdline;

    while ((c=getopt(argc, argv, "i:f:hv")) != EOF) {
	switch (c) {
	case 'h': usage(argv[0]); exit(0);
	case 'v':
	    printf("%s version %s\n", argv[0], PACKAGE_VERSION);
	    exit(0);
	case 'i':
	    open_file(&initrd, optarg, O_RDONLY,
		      "Cannot load more than one initrd.\n");
	    break;
	case 'f':
	    open_file(&outfile, optarg, O_WRONLY|O_CREAT,
		      "Can't output to more than one file.\n");
	    break;
	default:
	    exit(1);
	}
    }
    if (outfile == -1) outfile = STDOUT_FILENO;

    if (argc - optind < 1) {
	usage(argv[0]);
	exit(1);
    }

    /* 1st positional arg is the kernel file */
    open_file(&kernel, argv[optind], O_RDONLY, 0);

    /* The rest is kernel command line */

    cmdline = meld_command_line(argv+optind+1);	
    write_beoboot_image(outfile, kernel, initrd, cmdline);
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
