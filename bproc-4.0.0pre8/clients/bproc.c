/*-------------------------------------------------------------------------
 *  bproc.c: user level library to support bproc
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the
 *  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *  Boston, MA  02111-1307  USA.
 *
 * $Id: bproc.c,v 1.76 2004/08/10 13:54:39 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/param.h>		/* for NGROUPS */
#include <sys/poll.h>
#include <ctype.h>

#include "bproc.h"		/* This is the header from ../kernel */
#include <bproc.h>

#ifdef NO_XATTR
/* A lot of libcs out there don't have the get/setxattr system calls.
 * We have our own implementation here. */
#include "xattr.h"
#define getxattr __bproc_getxattr
#define setxattr __bproc_setxattr
#else
#include <sys/xattr.h>
#endif


/*-------------------------------------------------------------------------
 *  Nodeset manipulation routines
 *-----------------------------------------------------------------------*/

#define ALLOC_CHUNK 128

int bproc_nodeset_init(struct bproc_node_set_t *n, int size)
{
	n->alloc = 0;
	n->size = 0;

	if (size <= 0) {
		n->node = 0;
		return 0;
	}

	n->node = malloc(sizeof(*n->node) * size);
	if (!n->node)
		return -1;
	n->size = size;
	n->alloc = size;
	return 0;
}

void bproc_nodeset_free(struct bproc_node_set_t *n)
{
	if (n->node) {
		free(n->node);
		n->node = 0;
	}
	n->size = 0;
	n->alloc = 0;
}

int bproc_nodeset_grow(struct bproc_node_set_t *ns, int size)
{
	/* Round up to the next chunk size */
	size = (size + ALLOC_CHUNK - 1) & ~(ALLOC_CHUNK - 1);
	if (ns->alloc < size) {
		struct bproc_node_info_t *tmp;
		tmp = realloc(ns->node, sizeof(*tmp) * size);
		if (!tmp)
			return -1;
		ns->alloc = size;
		ns->node = tmp;
	}
	return 0;
}

int bproc_nodeset_add(struct bproc_node_set_t *ns, struct bproc_node_info_t *n)
{
	if (bproc_nodeset_grow(ns, ns->size + 1))
		return -1;
	ns->node[ns->size++] = *n;
	return 0;
}

int bproc_nodeset_append(struct bproc_node_set_t *a, struct bproc_node_set_t *b)
{
	int i;
	if (bproc_nodeset_grow(a, a->size + b->size))
		return -1;
	for (i = 0; i < b->size; i++)
		a->node[a->size++] = b->node[i];
	return 0;
}

/*-------------------------------------------------------------------------
 *  System information functions
 *-----------------------------------------------------------------------*/
#define INT_LEN 30
static
const char *get_bpfs_path(void)
{
	char *bpfs_path;
	bpfs_path = getenv("BPFS_PATH");
	if (!bpfs_path)
		bpfs_path = "/bpfs";
	return bpfs_path;
}

/* This is a gross a macro because I want to use alloca */
#define get_node_path(path,node)          \
do {                                      \
    const char *p1;                       \
    p1 = get_bpfs_path();                 \
    path = alloca(strlen(p1) + INT_LEN);  \
    if (node == BPROC_NODE_SELF)          \
	sprintf(path, "%s/self", p1);     \
    else                                  \
	sprintf(path, "%s/%d", p1, node); \
} while(0)

#define get_status_path(path)       \
do {                                \
    const char *p1;                 \
    p1 = get_bpfs_path();           \
    path = alloca(strlen(p1) + 8);  \
    sprintf(path, "%s/status", p1); \
} while(0)

#define get_self_path(path)         \
do {                                \
    const char *p1;                 \
    p1 = get_bpfs_path();           \
    path = alloca(strlen(p1) + 6);  \
    sprintf(path, "%s/self", p1);   \
} while(0)

int bproc_notifier(void)
{
	const char *bpfs_path;
	char *tmp;

	bpfs_path = get_bpfs_path();
	tmp = alloca(strlen(bpfs_path) + 8);
	sprintf(tmp, "%s/status", bpfs_path);

	return open(tmp, O_RDONLY);
}

int bproc_numnodes(void)
{
	const char *bpfs_path;
	char *tmp;
	struct stat buf;

	bpfs_path = get_bpfs_path();
	tmp = alloca(strlen(bpfs_path) + 8);
	sprintf(tmp, "%s/status", bpfs_path);

	if (stat(tmp, &buf))
		return -1;

	return buf.st_size / sizeof(struct bproc_node_info_t);
}

int bproc_currnode(void)
{
	char *p;
	int r;
	char tmp[INT_LEN];
	get_self_path(p);
	r = readlink(p, tmp, INT_LEN - 1);
	if (r < 0)
		return -1;
	tmp[r] = 0;		/* null terminate */
	return strtol(tmp, 0, 10);
}

int bproc_nodestatus(int num, char *status, int len)
{
	int r;
	char *path;
	get_node_path(path, num);
	r = getxattr(path, BPROC_STATE_XATTR, status, len);
	if (r != -1 && r < len)	/* null terminate if there's room */
		status[r] = 0;
	return r;
}

int bproc_nodeinfo(int node, struct bproc_node_info_t *info)
{
	char *path;
	struct stat buf;

	get_node_path(path, node);

	if (stat(path, &buf) != 0) {
		errno = BE_INVALIDNODE;
		return -1;
	}

	info->node = node;
	info->mode = buf.st_mode & 0111;	/*  */
	info->user = buf.st_uid;
	info->group = buf.st_gid;

	if (getxattr(path, BPROC_STATE_XATTR, info->status,
		     sizeof(info->status)) < 0) {
		errno = BE_INVALIDNODE;
		return -1;
	}

	if (getxattr(path, BPROC_ADDR_XATTR, &info->addr,
		     sizeof(info->addr)) < 0) {
		errno = BE_INVALIDNODE;
		return -1;
	}
	return 0;
}

int bproc_nodelist_(struct bproc_node_set_t *ns, int fd)
{
	int r;
	struct stat statbuf;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;

	/* There's some wackiness possible here.  The machine state might
	   change while we're reading the status file.  To guard against
	   this, we do a read and then check to see if a change has
	   occurred.

	   This might be a bit paranoid.
	 */

	bproc_nodeset_init(ns, 0);	/* make this safe to use grow */

      again:
	if (fstat(fd, &statbuf))
		return -1;

	if (bproc_nodeset_grow(ns, statbuf.st_size / sizeof(*ns->node))) {
		bproc_nodeset_free(ns);	/* we may have allocated stuff earlier */
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	r = read(fd, ns->node, statbuf.st_size);
	if (r == -1) {
		bproc_nodeset_free(ns);
		return -1;
	}
	if (r != statbuf.st_size)
		goto again;

	ns->size = statbuf.st_size / sizeof(*ns->node);
	return ns->size;
}

int bproc_nodelist(struct bproc_node_set_t *ns)
{
	char *pathtmp;
	int r, fd;

	get_status_path(pathtmp);
	fd = open(pathtmp, O_RDONLY);
	if (fd == -1)
		return -1;

	r = bproc_nodelist_(ns, fd);
	close(fd);
	return r;
}

int bproc_nodeaddr(int node, struct sockaddr *s, int *size)
{
	int len;
	char *p;
	get_node_path(p, node);
	len = getxattr(p, BPROC_ADDR_XATTR, s, *size);
	if (len < 0)
		return -1;
	*size = len;
	return 0;
}

int bproc_setnodeattr(int node, char *name, void *value, int size)
{
	char *p;
	char *nametmp;
	get_node_path(p, node);
	nametmp = alloca(strlen(name) + 7);
	sprintf(nametmp, "bproc.%s", name);
	return setxattr(p, nametmp, value, size, 0);
}

int bproc_getnodeattr(int node, char *name, void *value, int size)
{
	char *p;
	char *nametmp;
	get_node_path(p, node);
	nametmp = alloca(strlen(name) + 7);
	sprintf(nametmp, "bproc.%s", name);
	return getxattr(p, nametmp, value, size);
}


int bproc_nodesetstatus(int node, char *status)
{
	char *path;
	get_node_path(path, node);
	if (!path)
		return -1;
	return setxattr(path, BPROC_STATE_XATTR, status, strlen(status), 0);
}

int bproc_chmod(int node, int mode)
{
	char *path;
	get_node_path(path, node);
	if (!path)
		return -1;
	return chmod(path, mode);
}

int bproc_chown(int node, int user)
{
	char *path;
	get_node_path(path, node);
	if (!path)
		return -1;
	return chown(path, user, -1);
}

int bproc_chgrp(int node, int group)
{
	char *path;
	get_node_path(path, node);
	if (!path)
		return -1;
	return chown(path, -1, group);
}

int bproc_access(int node, int mode)
{
	char *path;
	get_node_path(path, node);
	return access(path, mode);
}


/*-------------------------------------------------------------------------
 *  Misc useful utility functions
 *-----------------------------------------------------------------------*/
/* Look for a number in a way that's consistent with our little grammar */
static
int get_number(const char *str_, int *num_)
{
	int num;
	const char *str = str_;
	char *check;
	if (*str == 'n' || *str == '.')
		str++;
	num = strtol(str, &check, 0);
	if (check != str && (*check == ',' || *check == '-' || *check == 0)) {
		*num_ = num;
		return check - str_;	/* return # of bytes consumed. */
	}

	return 0;
}

/* This looks through the string to find a valid state name.  State
 * names are: [a-zA-Z][a-zA-Z0-9_]*  */
static
int get_state_len(const char *str)
{
	int r;
	if (!isalpha(str[0]))
		return 0;

	for (r = 1; str[r]; r++) {
		if (!isalnum(str[r]) && str[r] != '_')
			return r;
	}
	return r;
}

static
int filter_strcmp(const char *str, const char *key)
{
	int len;
	len = strlen(key);
	if (strncmp(str, key, len) == 0 && (str[len] == 0 || str[len] == ','))
		return len;
	return 0;
}

static
int filter_chunk(const char *str,
		 struct bproc_node_info_t **id_map, int max_id,
		 struct bproc_node_set_t *out)
{
	int num1, num2;
	int r, i;
	int invert = 0;
	const char *str1;

	str1 = str;

	/* See if this is a number or a number range */
	r = get_number(str, &num1);
	if (r) {
		str += r;
		/* If we have a dash, get the next number */
		if (*str == '-') {
			str++;
			r = get_number(str, &num2);
			if (!r)
				num2 = max_id;
			str += r;
		} else {
			num2 = num1;
		}

		/* Add this node range */
		for (i = num1; i <= num2; i++) {
			if (i >= 0 && i <= max_id && id_map[i])
				if (bproc_nodeset_add(out, id_map[i]))
					return -1;
		}
		return str - str1;	/* number of bytes consumed */
	}

	/* Check for a magic string or two. */
	r = filter_strcmp(str, "master");
	if (r) {
		struct bproc_node_info_t dummy = { -1, "up", 0111, 0, 0 };
		str += r;

		if (bproc_nodeset_add(out, &dummy))
			return -1;
		return str - str1;	/* number of bytes consumed */
	}
	r = filter_strcmp(str, "all");
	if (r) {
		str += r;
		for (i = 0; i <= max_id; i++) {
			if (id_map[i])
				if (bproc_nodeset_add(out, id_map[i]))
					return -1;
		}
		return str - str1;	/* number of bytes consumed */
	}

	/* Check for a node state */
	r = get_state_len(str);
	if (r) {
		/* Check for the "all" prefix.  This is ignored. */
		if (strncmp(str, "all", 3) == 0) {
			str += 3;
			r -= 3;
		}

		/* Check for the "not" prefix - two styles "not" and "!" */
		if (*str == '!') {
			invert = 1;
			str++;
			r--;
		}
		if (strncmp(str, "not", 3) == 0) {
			invert = 1;
			str += 3;
			r -= 3;
		}

		for (i = 0; i <= max_id; i++) {
			if (id_map[i]) {
				if ((strncmp(str, id_map[i]->status, r) == 0 &&
				     id_map[i]->status[r] == 0) ^ invert)
					if (bproc_nodeset_add(out, id_map[i]))
						return -1;
			}
		}
		str += r;
		return str - str1;
	}
	return 0;
}

int bproc_nodefilter(struct bproc_node_set_t *out,
		     struct bproc_node_set_t *in, const char *str)
{
	int i, r;
	int max_id;
	struct bproc_node_info_t **id_map;

	bproc_nodeset_init(out, 0);

	/* First build an ID map - this will be valuable for node ranges, etc. */
	max_id = -1;
	for (i = 0; i < in->size; i++) {
		if (in->node[i].node > max_id)
			max_id = in->node[i].node;
	}
	if (max_id == -1)	/* no nodes, just bail out now. */
		return 0;

	id_map = malloc(sizeof(*id_map) * (max_id + 1));
	if (!id_map) {
		fprintf(stderr, "out of memory.\n");
		errno = ENOMEM;
		return -1;
	}
	memset(id_map, 0, sizeof(*id_map) * (max_id + 1));
	for (i = 0; i < in->size; i++)
		id_map[in->node[i].node] = &in->node[i];

	while (*str) {
		while (*str == ',')
			str++;
		r = filter_chunk(str, id_map, max_id, out);
		if (r <= 0) {
			bproc_nodeset_free(out);
			free(id_map);
			return -1;
		}
		str += r;
	}
	free(id_map);
	return 0;
}

int bproc_nodefilteraccessible(struct bproc_node_info_t *list, int *ls)
{
	int i, j, size;
	const char *bpfs_path;
	char *pathtmp;

	bpfs_path = get_bpfs_path();
	pathtmp = alloca(strlen(bpfs_path) + 30);

	size = *ls;
	for (i = j = 0; i < size; i++) {
		sprintf(pathtmp, "%s/%u", bpfs_path, list[i].node);
		if (access(pathtmp, X_OK) == 0) {
			if (i != j)
				list[i] = list[j];
			j++;
		}
	}
	*ls = size;
	return 0;
}

int bproc_nodespec(struct bproc_node_set_t *ns, const char *str)
{
	int r;
	struct bproc_node_set_t ns_all;

	r = bproc_nodelist(&ns_all);
	if (r < 0)
		return -1;

	r = bproc_nodefilter(ns, &ns_all, str);
	bproc_nodeset_free(&ns_all);
	return r;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
