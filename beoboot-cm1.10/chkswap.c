/*------------------------------------------------------------ -*- C -*-
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
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
 *  $Id: chkswap.c,v 1.3 2002/01/18 17:34:57 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/page.h>		/* For PAGE_SIZE */
/* Lifted from the linux kernel. */
#define MORE_CHECKS 1
#ifdef MORE_CHECKS
#include <sys/ioctl.h>
#include <sys/mount.h>
#define SWP_OFFSET(entry) ((entry) >> 8)
#define SWP_ENTRY(type,offset) (((type) << 1) | ((offset) << 8))
#define __swapoffset(x) ((unsigned long)&((union swap_header *)0)->x)
#define MAX_SWAP_BADPAGES \
        ((__swapoffset(magic.magic) - __swapoffset(info.badpages)) / sizeof(int))
#endif
union swap_header {
    struct {
	char reserved[PAGE_SIZE - 10];
	char magic[10];
    } magic;
    struct {
	char         bootbits[1024];    /* Space for disklabel etc. */
	unsigned int version;
	unsigned int last_page;
	unsigned int nr_badpages;
	unsigned int padding[125];
	unsigned int badpages[1];
    } info;
};

void usage(char *arg0) {
    printf("Usage: %s <device>\n", arg0);
}

int main(int argc, char *argv[]) {
    int fd, c;
    int version;
#ifdef MORE_CHECKS
    int i, swapfilesize=0, nr_good_pages;
#endif
    union swap_header swap_header;
    while ((c = getopt(argc, argv, "")) != EOF) {
	switch (c) {
	case 'h': usage(argv[0]); exit(0);
	case 'v': printf("chkswap version %s\n", PACKAGE_VERSION); exit(0);
	default:
	    exit(1);
	}
    }

    if (argc-optind != 1) {
	usage(argv[0]);
	exit(0);
    }
	
    /* Read the swap signature off the disk. */
    if ((fd = open(argv[optind], O_RDONLY)) == -1) {
	perror(argv[optind]);
	exit(1);
    }
    if (read(fd, &swap_header, sizeof(swap_header)) != sizeof(swap_header)) {
	perror("read");
	exit(1);
    }

    if (!memcmp("SWAP-SPACE",swap_header.magic.magic,10))
	version = 1;
    else if (!memcmp("SWAPSPACE2",swap_header.magic.magic,10))
	version = 2;
    else {
	fprintf(stderr, "%s: %s: Unable to find swap-space signature\n",
		argv[0], argv[optind]);
	exit(1);
    }

    /* We could do more interesting checks here but this is good
     * enough for our purposes */
#ifdef MORE_CHECKS
    if ( (version == 2) && (swap_header.info.version != 1) ) {
	fprintf(stderr,
	       "Unable to handle swap header version %d\n",
	       swap_header.info.version);
	exit(1);
    }

    if (swap_header.info.nr_badpages > MAX_SWAP_BADPAGES)
	exit(1);
    if (swap_header.info.last_page >= SWP_OFFSET(SWP_ENTRY(0,~0UL)))
	exit(1);

    for (i=0; i<swap_header.info.nr_badpages; i++) {
	int page = swap_header.info.badpages[i];
	if (page <= 0 || page >= swap_header.info.last_page)
	    exit(1);
    }
 
    if (ioctl(fd, BLKGETSIZE, &swapfilesize) < 0) {
	perror("BLKGETSIZE ioctl");
	exit(1);
    }

    swapfilesize = (swapfilesize >> 3) - 1;

    if (swap_header.info.last_page > swapfilesize) {
	fprintf(stderr,
		       "Swap area shorter than signature indicates\n");
	exit(1);
    }
    nr_good_pages = swap_header.info.last_page -
	swap_header.info.nr_badpages - 1;
    if (!nr_good_pages) {
	fprintf(stderr, "Empty swap-file\n");
	exit(1);
    }
#endif
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
