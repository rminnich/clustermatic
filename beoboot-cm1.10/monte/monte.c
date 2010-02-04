/*------------------------------------------------------------ -*- C -*-
 *  2 Kernel Monte a.k.a. Linux loading Linux on x86
 *  monte.c:  Command line utility to use kernel monte.
 *
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 *  This version is a derivative of the original also written by me.
 *
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
 *  $Id: monte.c,v 1.4 2001/10/03 22:31:52 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "monte.h"

static
void usage(char *arg0)
{
	fprintf(stderr,
		"Usage: %s [-h] [-v] [-n] [-d] [-s] [-i initrd] imagefile [command line ....]\n"
		"       This program loads a Linux kernel image and optionally an initial\n"
		"       ramdisk image into memory and restarts the machine using the\n"
		"       new kernel.\n\n"
		"       -h          Display this message and exit.\n"
		"       -v          Display the program version number and exit.\n"
		"       -d          Disable PCI bus masters before rebooting.\n"
		"       -n          Do everything except actually rebooting.\n"
/* Linux specific options */
		"       -s          Skip setup portion of the new kernel.\n"
		"       -i initrd   Load the initial ram disk image stored in initrd.\n\n"
		"       imagefile is the kernel image file to be loaded.  All remaining\n"
		"       options on the command line will be concatenated and passed to\n"
		"       the kernel as the kernel command line.\n", arg0);
}

#define CHUNK 65536
int load_file(int fd, void **data, long *size)
{
	int r;
	long bytes = 0;
	int bsize = 0;
	void *buffer = 0, *tmp;

	r = 0;
	do {
		bytes += r;
		if (bytes == bsize) {
			bsize += CHUNK;
			tmp = realloc(buffer, bsize + CHUNK);
			if (!tmp) {
				fprintf(stderr, "Out of memory.\n");
				if (buffer)
					free(buffer);
				return -1;
			}
			buffer = tmp;
		}
		r = read(fd, buffer + bytes, bsize - bytes);
	} while (r > 0);
	*data = buffer;
	*size = bytes;
	return 0;
}

int main(int argc, char *argv[])
{
	int i, len, c;
	char *initrd_name = 0;
	char *command_line = 0;
	int kernel_fd = -1;
	int initrd_fd = -1;
	struct monte_boot_t *boot;
	int flags = 0;
	void *buffer;
	long buffer_size;

	while ((c = getopt(argc, argv, "i:vhdsn")) != EOF) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'v':
			printf("%s: version %s\n", argv[0], PACKAGE_VERSION);
			exit(0);
		case 'i':
			if (initrd_name) {
				fprintf(stderr,
					"%s: Only one initrd image allowed.\n",
					argv[0]);
				exit(1);
			}
			initrd_name = optarg;
			break;
		case 's':
			flags |= MONTE_PROTECTED;
			break;
		case 'd':
			flags |= MONTE_PCI_DISABLE;
			break;
		case 'n':
			flags |= MONTE_NOT_REALLY;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (argc - optind == 0) {
		usage(argv[0]);
		exit(1);
	}

	boot = monte_new(flags);

	/* Open the kernel image file */
	if (strcmp(argv[optind], "-") == 0) {
		kernel_fd = STDIN_FILENO;
	} else {
		kernel_fd = open(argv[optind], O_RDONLY);
		if (kernel_fd == -1) {
			perror(argv[optind]);
			exit(1);
		}
	}

	/* Open the initrd image file */
	if (initrd_name) {
		if (strcmp(initrd_name, "-") == 0) {
			initrd_fd = STDIN_FILENO;
		} else {
			initrd_fd = open(initrd_name, O_RDONLY);
			if (initrd_fd == -1) {
				perror(initrd_name);
				exit(1);
			}
		}
	}

	/* The rest of the arguments get assembled into the the kernel
	 * command line */
	len = 1;
	for (i = optind + 1; i < argc; i++)
		len += strlen(argv[i]) + 1;
	command_line = malloc(len);
	if (!command_line) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	command_line[0] = 0;
	for (i = optind + 1; i < argc; i++) {
		strcat(command_line, argv[i]);
		if (i + 1 < argc)
			strcat(command_line, " ");
	}

	/* The kernel image must be done first so that we know where to
	 * place arguments and other stuff that comes later */
	if (load_file(kernel_fd, &buffer, &buffer_size))
		exit(1);
	monte_load_linux_kernel(boot, buffer, buffer_size);
	free(buffer);
	close(kernel_fd);

	if (initrd_fd != -1) {
		if (load_file(initrd_fd, &buffer, &buffer_size))
			exit(1);
		monte_load_linux_initrd(boot, buffer, buffer_size);
		free(buffer);
		close(initrd_fd);
	}

	monte_load_linux_command_line(boot, command_line);

	if (monte_boot(boot) == -1) {
		perror("monte");	/* monte reboot failed. */
		exit(1);
	} else
		exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
