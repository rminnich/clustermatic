/*------------------------------------------------------------ -*- C -*-
 * BJS:  a simple scheduler for BProc based environments.
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.
 *
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * Additionally, this program is free software; you can distribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software foundation; either version 2 of
 * the License, or any later version.  Accordingly, this program is
 * distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANY; without even the implied warranty of MARCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more detail.
 *
 *  $Id: client.c,v 1.4 2002/09/19 20:28:20 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <sexp.h>
#include <bjs.h>

static int fd = -1;
static struct sexp_parser_state_t *s = 0;
int bjs_connect(char *path) {
    struct sockaddr_un addr;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
	fprintf(stderr, "socket(AF_UNIX, SOCK_STREAM): %s\n", strerror(errno));
	return -1;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
	fprintf(stderr, "connect(\"%s\"): %s\n", path,  strerror(errno));
	close(fd);
	return -1;
    }
    return 0;
}

void bjs_close(void) {
    if (fd != -1) close(fd);
    if (s) sexp_parser_destroy(s);
}

int bjs_send_str(const char *str) {
    int w, len;
    len = strlen(str);

    /* Write it out... */
    w = write(fd, str, len);
    while (w > 0 && len > w)   {
	str += w;
	len -= w;

	w = write(fd, str, len);
    }
    if (w < 0) {
	fprintf(stderr, "write: %s\n", strerror(errno));
	return -1;
    }
    return 0;
}

int bjs_send_sx(struct sexp_t *sx) {
    int len;
    char *str;

    /* First convert sx to a string */
    len = sexp_strlen(sx);
    str = alloca(len);
    len = sexp_snprint(str, -1, sx);

    return bjs_send_str(str);
}


#define BSIZE 4096
int bjs_recv(struct sexp_t **sx) {
    int used;
    /* We have a static buffer since there might be left overs from
     * the last read. */
    static int  r = 0;
    static char buf[BSIZE];
    
    if (!s) s = sexp_parser_new();

    if (r <= 0)
	r = read(fd, buf, BSIZE);
    while (r > 0) {
	used = sexp_parser_parse(buf, r, sx, s);
	if (used == -1) {
	    fprintf(stderr, "Parse error.\n");
	    return -1;
	}
	/* Move remaining data down */
	memmove(buf, buf+used, r - used);
	r -= used;

	if (*sx) return 0;

	if (r == 0) r = read(fd, buf, BSIZE);
    }
    if (r == -1)
	fprintf(stderr, "read: %s\n", strerror(errno));
    return -1;
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
