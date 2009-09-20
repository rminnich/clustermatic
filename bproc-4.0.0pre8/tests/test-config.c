/*-------------------------------------------------------------------------
 *  conftest.c: tests configuration stuff
 *
 *  Copyright (C) 2000 by Erik Hendriks <erik@hendriks.cx>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: test-config.c,v 1.6 2003/09/02 20:07:50 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/bproc.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

char *ip_to_str(struct sockaddr_in *_addr) {
    static char str_addr[16];
    long addr = ntohl(_addr->sin_addr.s_addr);
    sprintf(str_addr, "%ld.%ld.%ld.%ld",
	    (addr>>24)&0xff,(addr>>16)&0xff,(addr>>8)&0xff,addr&0xff);
    return str_addr;
}

int main(int argc, char *argv[]) {
    int curr;
    int addrsize;
    struct sockaddr_in addr;

    setlinebuf(stdout);

    curr = bproc_currnode();
    printf("Current node    : %d\n", curr);

    addrsize = sizeof(addr);
    if (bproc_nodeaddr(BPROC_NODE_SELF, (struct sockaddr*)&addr,
		       &addrsize)) {
	fprintf(stderr, "bproc_nodeaddr: %s\n", bproc_strerror(errno));
	exit(1);
    }
    printf("My address      : %s\n", inet_ntoa(addr.sin_addr));
    
    addrsize = sizeof(addr);
    if (bproc_nodeaddr(BPROC_NODE_MASTER, (struct sockaddr*)&addr,
		       &addrsize)) {
	fprintf(stderr, "bproc_nodeaddr: %s\n", bproc_strerror(errno));
	exit(1);
    }
    printf("Master address  : %s\n", inet_ntoa(addr.sin_addr));

    if (curr == BPROC_NODE_MASTER) {
	int num;
	num = bproc_numnodes();
	printf("Number of nodes : %d\n", num);
    }
    exit(0);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
