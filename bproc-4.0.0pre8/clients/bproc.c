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

#include "../vmadump/vmadump.h"
#include "bproc.h"		/* This is the header from ../kernel */
#include <sys/bproc.h>

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
 *  Machine info routines
 *-----------------------------------------------------------------------*/
#define DEFAULT_FLAGS (BPROC_DUMP_EXEC|BPROC_DUMP_OTHER)

int bproc_version(struct bproc_version_t *vers)
{
	return syscall(__NR_bproc, BPROC_SYS_VERSION, vers);
}

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

	/* explicitly check for changes */
	poll(&pfd, 1, 0);
	if (pfd.revents & POLLIN)
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

/*-------------------------------------------------------------------------
 *  The good stuff: memory space operations + remote process creation
 *-----------------------------------------------------------------------*/
int bproc_rexec_io(int node, struct bproc_io_t *io, int iolen,
		   const char *cmd, char *const argv[], char *const envp[])
{
	struct bproc_move_t req;
	req.arg0 = (char *)cmd;
	req.argv = (char **)argv;
	req.envp = (char **)envp;
	req.iolen = iolen;
	req.io = io;
	req.nodeslen = 0;
	req.nodes = 0;
	req.pids = 0;

	return syscall(__NR_bproc, BPROC_SYS_REXEC, node, &req);
}

int bproc_rexec(int node, const char *cmd, char *const argv[],
		char *const envp[])
{
	return bproc_rexec_io(node, 0, -1, cmd, argv, envp);
}

/*--- move ---------------------------------------------------------*/
int _bproc_move_io(int node, struct bproc_io_t *io, int iolen, int flags)
{
	int ret;
	struct bproc_move_t req;

	req.flags = flags;
	req.io = io;
	req.iolen = iolen;
	req.nodeslen = 0;
	req.nodes = 0;
	req.pids = 0;

	ret = syscall(__NR_bproc, BPROC_SYS_MOVE, node, &req);
	if (ret == -1 && errno == BE_SAMENODE) {	/* moving to current node */
		/* FIX ME - we should do the I/O vector shit locally */
		return 0;
	}
	if (ret == -1 && (errno == ENOSYS || errno == EBUSY) && node == -1)
		return 0;	/* no bproc, move to front end is OK. */
	return ret;
}

int bproc_move_io(int node, struct bproc_io_t *io, int iolen)
{
	return _bproc_move_io(node, io, iolen, DEFAULT_FLAGS);
}

int _bproc_move(int node, int flags)
{
	return _bproc_move_io(node, 0, -1, flags);
}

int bproc_move(int node)
{
	return _bproc_move_io(node, 0, -1, DEFAULT_FLAGS);
}

/*--- rfork --------------------------------------------------------*/

int _bproc_vrfork_io(int nnodes, int *nodes, int *pids,
		     struct bproc_io_t *io, int iolen, int flags)
{
	struct bproc_move_t req;
	req.flags = flags;
	req.iolen = iolen;
	req.io = io;
	req.nodeslen = nnodes;
	req.nodes = nodes;
	req.pids = pids;

	return syscall(__NR_bproc, BPROC_SYS_VRFORK, &req);
}

int bproc_vrfork_io(int nnodes, int *nodes, int *pids,
		    struct bproc_io_t *io, int iolen)
{
	return _bproc_vrfork_io(nnodes, nodes, pids, io, iolen, DEFAULT_FLAGS);
}

/* XXX for the vector versions of these calls, the iolen should
 * probably default to 0 since the default (lame) io forwarding won't
 * work past the first level of processes */
int _bproc_vrfork(int nnodes, int *nodes, int *pids, int flags)
{
	return _bproc_vrfork_io(nnodes, nodes, pids, 0, -1, DEFAULT_FLAGS);
}

int bproc_vrfork(int nnodes, int *nodes, int *pids)
{
	return _bproc_vrfork_io(nnodes, nodes, pids, 0, -1, DEFAULT_FLAGS);
}

int _bproc_rfork_io(int node, struct bproc_io_t *io, int iolen, int flags)
{
#if 0
	int ret;
	struct bproc_move_t req;

	req.flags = flags;
	req.iolen = iolen;
	req.io = io;
	req.nodeslen = 0;
	req.nodes = 0;
	req.pids = 0;

	ret = syscall(__NR_bproc, BPROC_SYS_RFORK, node, &req);
	/* if they're trying to rfork to the local node, do a normal
	 * fork. */
	if (ret == -1 && errno == BE_SAMENODE)
		return fork();
	/* if bproc isn't running and they're trying to rfork to he front
	 * end, do a normal fork. */
	if (ret == -1 && (errno == ENOSYS || errno == EBUSY) && node == -1)
		return fork();
	return ret;
#endif
	int ret, pid;

	ret = _bproc_vrfork_io(1, &node, &pid, io, iolen, flags);
	if (ret != 1)
		return ret;
	return pid;
}

int bproc_rfork_io(int node, struct bproc_io_t *io, int iolen)
{
	return _bproc_rfork_io(node, io, iolen, DEFAULT_FLAGS);
}

int _bproc_rfork(int node, int flags)
{
	return _bproc_rfork_io(node, 0, -1, flags);
}

int bproc_rfork(int node)
{
	return _bproc_rfork_io(node, 0, -1, DEFAULT_FLAGS);
}

/*--- execmove -----------------------------------------------------*/
int bproc_execmove_io(int node, struct bproc_io_t *io, int iolen,
		      const char *cmd, char *const argv[], char *const envp[])
{
	struct bproc_move_t req;

	req.arg0 = (char *)cmd;
	req.argv = (char **)argv;
	req.envp = (char **)envp;
	req.flags = DEFAULT_FLAGS;
	req.iolen = iolen;
	req.io = io;
	req.nodeslen = 0;
	req.nodes = 0;
	req.pids = 0;

	return syscall(__NR_bproc, BPROC_SYS_EXECMOVE, node, &req);
}

int bproc_execmove(int node, const char *cmd, char *const argv[],
		   char *const envp[])
{
	return bproc_execmove_io(node, 0, -1, cmd, argv, envp);
}

int bproc_vexecmove_io(int nnodes, int *nodes, int *pids,
		       struct bproc_io_t *io, int iolen,
		       const char *cmd, char *const argv[], char *const envp[])
{
	struct bproc_move_t req;

	req.arg0 = (char *)cmd;
	req.argv = (char **)argv;
	req.envp = (char **)envp;
	req.flags = DEFAULT_FLAGS;
	req.iolen = iolen;
	req.io = io;
	req.nodeslen = nnodes;
	req.nodes = nodes;
	req.pids = pids;

	return syscall(__NR_bproc, BPROC_SYS_VEXECMOVE, &req);
}

int bproc_vexecmove(int nnodes, int *nodes, int *pids,
		    const char *cmd, char *const argv[], char *const envp[])
{
	return bproc_vexecmove_io(nnodes, nodes, pids, 0, -1, cmd, argv, envp);
}

/*--- exec ---------------------------------------------------------*/
int bproc_execve(const char *cmd, char *const argv[], char *const envp[])
{
	struct bproc_move_t req;
	memset(&req, 0, sizeof(req));
	req.arg0 = (char *)cmd;
	req.argv = (char **)argv;
	req.envp = (char **)envp;
	req.flags = DEFAULT_FLAGS;
	return syscall(__NR_bproc, BPROC_SYS_EXEC, &req);
}

/*------------------------------------------------------------------*/
const char *bproc_strerror(int err)
{
	if (err < 0)
		err = -err;
	switch (err) {
	case BE_INVALIDNODE:
		return "Invalid node number";
	case BE_NODEDOWN:
		return "Node is down";
	case BE_SAMENODE:
		return "Move to same node";
	case BE_SLAVEDIED:
		return "Slave node died";
	case BE_INVALIDPROC:
		return "Invalid process ID";
	default:
		return strerror(err);
	}
}

/*-------------------------------------------------------------------------
 *  PID mapping routines
 *
 *-----------------------------------------------------------------------*/
#define PINFO_CHUNK 64
int bproc_proclist(int node, struct bproc_proc_info_t **_pinfo)
{
	int pid, nodenum;
	char *check;
	DIR *proc;
	struct dirent *de;
	int ninfo = 0;
	struct bproc_proc_info_t *pinfo = 0;

	proc = opendir("/proc");
	if (!proc) {
		errno = EEXIST;
		return -1;
	}
	while ((de = readdir(proc))) {
		pid = strtol(de->d_name, &check, 0);
		if (*check == 0) {
			nodenum = bproc_pidnode(pid);

			if (nodenum != -1
			    && (node == BPROC_NODE_ANY || nodenum == node)) {
				/* Make sure there's enough room for this one on our list */
				int currsize, newsize;
				currsize =
				    (ninfo + PINFO_CHUNK - 1) / PINFO_CHUNK;
				newsize = (ninfo + PINFO_CHUNK) / PINFO_CHUNK;
				if (currsize != newsize) {
					struct bproc_proc_info_t *tmp;
					tmp =
					    realloc(pinfo,
						    newsize * PINFO_CHUNK *
						    sizeof(*pinfo));
					if (!tmp) {
						if (pinfo)
							free(pinfo);
						closedir(proc);
						errno = ENOMEM;
						return -1;
					}
					pinfo = tmp;
				}

				/* Append it to the list */
				pinfo[ninfo].pid = pid;
				pinfo[ninfo].node = nodenum;
				ninfo++;
			}
		}
	}
	closedir(proc);

	*_pinfo = pinfo;
	return ninfo;
}

int bproc_pidnode(int pid)
{
	int fd, r;
	char path[100];
	char buffer[1000], *p;

	/* Suck in the file from /proc */
	sprintf(path, "/proc/%d/status", pid);
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;
	r = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (r < 0)
		return -1;
	buffer[r] = 0;		/* null terminate it */

	/* Look for "BProcNode:" */
	p = strstr(buffer, "BProcNode:");
	if (!p)
		return -1;

	/* Return the number right after it */
	p += 11;
	if (p - buffer > r)
		return -1;

	return strtol(p, 0, 10);
}

/*-------------------------------------------------------------------------
 *  Misc management stuff (not for apps)
 *-----------------------------------------------------------------------*/
int bproc_nodechroot(int node, char *path)
{
	return syscall(__NR_bproc, BPROC_SYS_CHROOT, node, path);
}

int bproc_nodereboot(int node)
{
	return syscall(__NR_bproc, BPROC_SYS_REBOOT, node);
}

int bproc_nodehalt(int node)
{
	return syscall(__NR_bproc, BPROC_SYS_HALT, node);
}

int bproc_nodepwroff(int node)
{
	return syscall(__NR_bproc, BPROC_SYS_PWROFF, node);
}

int bproc_nodereconnect(int node,
			struct sockaddr *_rem, int remsize,
			struct sockaddr *_loc, int locsize)
{
	struct bproc_connect_t conn;
	struct sockaddr_in *rem, *loc;

	if (_rem->sa_family != AF_INET || _loc->sa_family != AF_INET) {
		errno = EINVAL;
		return -1;
	}

	rem = (struct sockaddr_in *)_rem;
	loc = (struct sockaddr_in *)_loc;
	conn.raddr = rem->sin_addr.s_addr;
	conn.rport = rem->sin_port;
	conn.laddr = loc->sin_addr.s_addr;
	conn.lport = loc->sin_port;

	return syscall(__NR_bproc, BPROC_SYS_RECONNECT, node, &conn);
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
 *  VMADump library management stuff
 *-----------------------------------------------------------------------*/
int bproc_dump(int fd, int flags)
{
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_DO_DUMP, fd, flags);
}

int bproc_undump(int fd)
{
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_DO_UNDUMP, fd);
}

int bproc_execdump(int fd, int flags, const char *cmd, char *const argv[],
		   char *const envp[])
{
	struct vmadump_execdump_args args;
	args.fd = fd;
	args.flags = flags;
	args.arg0 = cmd;
	args.argv = argv;
	args.envp = envp;
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_DO_EXECDUMP, &args);
}

int bproc_libclear(void)
{
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_LIB_CLEAR);
}

int bproc_libadd(const char *libname)
{
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_LIB_ADD, libname);
}

int bproc_libdel(const char *libname)
{
	return syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_LIB_DEL, libname);
}

int bproc_liblist(char **list_)
{
	int len, etmp;
	char *list;
	len = syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_LIB_SIZE);
	if (len < 0)
		return len;

	list = malloc(len);
	if (!list) {
		errno = ENOMEM;
		return -1;
	}

	if (syscall(__NR_bproc, BPROC_SYS_VMADUMP + VMAD_LIB_LIST,
		    list, len) == -1) {
		etmp = errno;
		free(list);
		errno = etmp;
		return -1;
	}
	*list_ = list;
	return 0;
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

#if 0
int bproc_nodefilter1(struct bproc_node_info_t **in, int *in_size,
		      const char *str)
{
	int r;
	struct bproc_node_info_t *out;
	int out_size;

	r = bproc_nodefilter(&out, &out_size, *in, *in_size, str);
	if (r == 0) {
		/* If successful, replace the input with the output */
		free(*in);
		*in = out;
		*in_size = out_size;
	}
	return r;
}
#endif

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
