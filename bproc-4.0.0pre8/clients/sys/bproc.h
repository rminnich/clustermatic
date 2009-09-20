/*-------------------------------------------------------------------------
 *  bproc.h: Definitions for libbproc
 *
 *  Copyright (C) 1999-2001 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; version 2 of
 *  the License.
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
 * $Id: bproc.h,v 1.43 2004/09/28 18:58:44 mkdist Exp $
 *-----------------------------------------------------------------------*/
#ifndef _SYS_BPROC_H
#define _SYS_BPROC_H

#define BPROC_API_VERSION 4

/* These need to be the same as the corresponding macros in the
 * vmadump headers. (FIXME) */
#define BPROC_DUMP_LIBS  1
#define BPROC_DUMP_EXEC  2
#define BPROC_DUMP_OTHER 4
#define BPROC_DUMP_ALL   7

/* Special node numbers */
#define BPROC_NODE_MASTER (-1)
#define BPROC_NODE_SELF   (-2)
#define BPROC_NODE_NONE   (-3)
#define BPROC_NODE_ANY    (-4)

#define BPROC_STATUS_NONE (-2)

#define BPROC_X_OK        1

struct sockaddr;

#include <stdint.h>
#include <sys/socket.h>
#include <sys/bproc_common.h>

struct bproc_node_set_t {
    int size, alloc;
    struct bproc_node_info_t *node;
    /* XXX Maybe add ID map stuff in here ? */
};

#define BPROC_EMPTY_NODESET {0, 0, 0}

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------
 * Node information functions
 *------------------------------------------------------------------*/
int  bproc_numnodes(void);
int  bproc_currnode(void);
int  bproc_nodestatus(int node, char *status, int len);
int  bproc_nodeaddr(int node, struct sockaddr *s, int *size);

int  bproc_nodeinfo  (int node, struct bproc_node_info_t *info);
int  bproc_nodelist  (struct bproc_node_set_t *ns);
int  bproc_nodelist_ (struct bproc_node_set_t *ns, int fd);

int  bproc_getnodeattr(int node, char *name, void *value, int size);


/* Node permission / access control stuff */
int  bproc_chmod(int node, int mode);
int  bproc_chown(int node, int user);
int  bproc_chgrp(int node, int group);
int  bproc_access(int node, int mode);

/* Process information functions */
int  bproc_proclist(int node, struct bproc_proc_info_t **list);
int  bproc_pidnode (int pid);


/*--------------------------------------------------------------------
 * Node set functions
 *------------------------------------------------------------------*/
int  bproc_nodeset_init(struct bproc_node_set_t *ns, int size);
int  bproc_nodeset_grow(struct bproc_node_set_t *ns, int size);
void bproc_nodeset_free(struct bproc_node_set_t *ns);
#define bproc_node_set_node(ns,nn) (&(ns)->node[(nn)])
int  bproc_nodeset_add   (struct bproc_node_set_t *ns,
			  struct bproc_node_info_t *n);
int  bproc_nodeset_append(struct bproc_node_set_t *a,
			  struct bproc_node_set_t *b);

int  bproc_nodefilter(struct bproc_node_set_t *out,
		      struct bproc_node_set_t *in, const char *str);

/*--------------------------------------------------------------------
 * Process migration / remote process creation interfaces.
 *------------------------------------------------------------------*/
int  bproc_rexec_io   (int node, struct bproc_io_t *io, int iolen,
		       const char *cmd, char * const argv[],
		       char * const envp[]);
int  bproc_rexec      (int node, const char *cmd, char * const argv[],
		       char * const envp[]);
int _bproc_move_io    (int node, struct bproc_io_t *io, int iolen, int flags);
int  bproc_move_io    (int node, struct bproc_io_t *io, int iolen);
int _bproc_move       (int node, int flags);
int  bproc_move       (int node);

int _bproc_rfork_io   (int node, struct bproc_io_t *io, int iolen, int flags);
int  bproc_rfork_io   (int node, struct bproc_io_t *io, int iolen);
int _bproc_rfork      (int node, int flags);
int  bproc_rfork      (int node);

int _bproc_vrfork_io  (int nnodes, int *nodes, int *pids,
		       struct bproc_io_t *io, int iolen, int flags);
int  bproc_vrfork_io  (int nnodes, int *nodes, int *pids,
		       struct bproc_io_t *io, int iolen);
int _bproc_vrfork     (int nnodes, int *nodes, int *pids, int flags);
int  bproc_vrfork     (int nnodes, int *nodes, int *pids);

int  bproc_execmove_io(int node, struct bproc_io_t *io, int iolen,
		       const char *cmd, char * const argv[],
		       char * const envp[]);
int  bproc_execmove   (int node, const char *cmd, char * const argv[],
		       char * const envp[]);

int  bproc_vexecmove_io(int nnodes, int *nodes, int *pids,
		       struct bproc_io_t *io, int iolen,
		       const char *cmd, char * const argv[],
		       char * const envp[]);
int  bproc_vexecmove  (int nnodes, int *nodes, int *pids,
		       const char *cmd, char * const argv[],
		       char * const envp[]);

int  bproc_execve     (const char *cmd, char * const argv[], 
		       char * const envp[]);

/* Administrative type functions */
int  bproc_nodechroot      (int node, char *path);
int  bproc_nodereboot      (int node);
int  bproc_nodehalt        (int node);
int  bproc_nodepwroff      (int node);
int  bproc_nodereboot_async(int node);
int  bproc_nodehalt_async  (int node);
int  bproc_nodepwroff_async(int node);

int  bproc_nodesetstatus   (int node, char *status);
int  bproc_setnodeattr     (int node, char *name, void *value, int size);

int  bproc_nodereconnect   (int node, struct sockaddr *_rem, int remsize,
			    struct sockaddr *_loc, int locsize);

const char *bproc_strerror(int err);

int  bproc_version(struct bproc_version_t *vers);
int  bproc_notifier(void);

/*--------------------------------------------------------------------
 * VMADump interface exported via BProc *
 *------------------------------------------------------------------*/
int bproc_dump    (int fd, int flags);
int bproc_undump  (int fd);
int bproc_execdump(int fd, int flags, const char *cmd, char * const argv[],
		   char * const envp[]);
int bproc_libclear(void);
int bproc_libadd  (const char *libname);
int bproc_libdel  (const char *libname);
int bproc_liblist (char **list_);



/* Utility functions - this one is going away... */
int bproc_nodespec(struct bproc_node_set_t *ns, const char *str);

#ifdef __cplusplus
}
#endif
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
