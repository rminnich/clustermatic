/*-------------------------------------------------------------------------
 *  ksyscall.c:  Beowulf distributed process space process migration code.
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
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
 * $Id: ksyscall.c,v 1.30 2004/10/27 15:49:36 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/syscalls.h>

#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#include "bproc.h"
#include "bproc_internal.h"

/****-----------------------------------------------------------------
 **** struct file * based operations
 ****---------------------------------------------------------------*/

/*--------------------------------------------------------------------
 * SOCKET OPERATIONS
 *
 *  These look an awful lot like the system calls except that they
 *  operate on file pointers, not file descriptors.
 *------------------------------------------------------------------*/
static
struct file *sock2file(struct socket *sock) {
    struct qstr this;
    char name[32];
    struct file *file = get_empty_filp();

    extern struct vfsmount *sock_mnt;
    extern struct dentry_operations sockfs_dentry_operations;
    extern struct file_operations socket_file_ops;

    /* This code is copied almost verbatim from sock_map_fd in
     * linux/net/socket.c.  The significant difference is that it does
     * not allocate a file descriptor for the file.  */

    if (!file)
	return ERR_PTR(-ENFILE);
    
    sprintf(name, "[%lu]", SOCK_INODE(sock)->i_ino);
    this.name = name;
    this.len = strlen(name);
    this.hash = SOCK_INODE(sock)->i_ino;

    file->f_dentry = d_alloc(sock_mnt->mnt_sb->s_root, &this);
    if (!file->f_dentry) {
	put_filp(file);
	file = ERR_PTR(-ENOMEM);
	goto out;
    }
    file->f_dentry->d_op = &sockfs_dentry_operations;
    d_add(file->f_dentry, SOCK_INODE(sock));
    file->f_vfsmnt = mntget(sock_mnt);
    
    sock->file = file;
    file->f_op = SOCK_INODE(sock)->i_fop = &socket_file_ops;
    file->f_mode = 3;
    file->f_flags = O_RDWR;
    file->f_pos = 0;

 out:
    return file;
}

static
struct socket *file2sock(struct file *file) {
    struct inode *inode;
    inode = file->f_dentry->d_inode;
    if (!inode->i_sock) return 0;
    return SOCKET_I(inode);
}

struct file *
k_socket_f(int family, int type, int protocol) {
    int err;
    struct socket *sock;
    struct file  *file;

    err = sock_create(family, type, protocol, &sock);
    if (err < 0) return ERR_PTR(err);

    file = sock2file(sock);
    if (IS_ERR(file)) {
	sock_release(sock);
	return file;
    }
    
    return file;
}

int k_setsockopt_f(struct file *file, int level,
		   int optname, void *optval, int optlen) {
    int ret;
    mm_segment_t oldfs;
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    if (level == SOL_SOCKET)
	ret = sock_setsockopt(sock,level,optname,optval,optlen);
    else
	ret = sock->ops->setsockopt(sock, level, optname, optval, optlen);
    set_fs(oldfs);
    return ret;
}

int k_bind_f(struct file *file, struct sockaddr *addr, int addrlen) {
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    return sock->ops->bind(sock, addr, addrlen);
}

int k_listen_f(struct file *file, int backlog) {
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    return sock->ops->listen(sock, backlog);
}

int k_getsockname_f(struct file *file, struct sockaddr *addr, int *addrlen) {
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    return sock->ops->getname(sock, addr, addrlen, 0);
}

int k_connect_f(struct file *file, struct sockaddr *addr, int addrlen) {
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    return sock->ops->connect(sock, addr, addrlen, sock->file->f_flags);
}

struct file *k_accept_f(struct file *file,
			struct sockaddr *peeraddr, int *addrlen) {
    struct file   *newfile;
    struct socket *newsock;
    struct socket *sock = file2sock(file);
    if (!sock) return ERR_PTR(-ENOTSOCK);
    
    /* This stuff is copied from linux/net/socket.c */
    if (!(newsock = sock_alloc()))
	return ERR_PTR(-EMFILE);
    
    newsock->type = sock->type;
    newsock->ops  = sock->ops;

    newfile = ERR_PTR(sock->ops->accept(sock, newsock, sock->file->f_flags));
    if (IS_ERR(newfile))
	goto out_release;
    
    if (peeraddr &&
	newsock->ops->getname(newsock, peeraddr, addrlen, 2) < 0) {
	newfile = ERR_PTR(-ECONNABORTED);
	goto out_release;
    }

    newfile = sock2file(newsock);
    if (IS_ERR(newfile))
	goto out_release;

    return newfile;

 out_release:
    sock_release(newsock);
    return newfile;
}

int k_shutdown_f(struct file *file, int how) {
    struct socket *sock = file2sock(file);
    if (!sock) return -ENOTSOCK;
    return sock->ops->shutdown(sock, how);
}


/*--------------------------------------------------------------------
 * GENERIC FILE OPERATIONS
 *------------------------------------------------------------------*/
ssize_t k_read_u_f(struct file *file, void *buf, size_t count) {
    return vfs_read(file, buf, count, &file->f_pos);
}

ssize_t k_read_all_u_f(struct file *file, void *buf, size_t count) {
    ssize_t r, bytes = count;
    while (bytes) {
	r = k_read_u_f(file, buf, bytes);
	if (r < 0)  return r;
	if (r == 0) return count - bytes;
	bytes -= r; buf += r;
    }
    return count;

}

ssize_t k_read_all_f(struct file *file, void *buf, size_t count) {
    ssize_t err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = k_read_all_u_f(file, buf, count);
    set_fs(oldfs);
    return err;
}

ssize_t k_write_u_f(struct file *file, const void *buf, size_t count) {
    return vfs_write(file, buf, count, &file->f_pos);
}

ssize_t k_write_f(struct file *file, const void *buf, size_t count) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = k_write_u_f(file, buf, count);
    set_fs(oldfs);
    return err;
}

/****-----------------------------------------------------------------
 **** Misc syscalls
 ****
 ****  These syscalls require wrappers becaues the arguments are
 ****  coming from kernel space.
 ****---------------------------------------------------------------*/
int k_chdir(const char *path) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS); 
    err = sys_chdir(path);
    set_fs(oldfs);
    return err;
}

int k_execve(char *filename, char **argv, char **envp, struct pt_regs *regs) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = do_execve(filename, argv, envp, regs);
    set_fs(oldfs);
    return err;
}

int k_open(const char *file, int flags, int mode) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS); 
    err = sys_open(file, flags, mode);
    set_fs(oldfs);
    return err;
}


int k_wait4(pid_t pid, int options,  struct siginfo *infop,
	    unsigned int *status, struct rusage *ru) {
    int err;
    mm_segment_t oldfs;
    /* newly exported kernel func w/o prototype */
    long do_wait(pid_t pid, int options, struct siginfo __user *infop,
		 int __user *stat_addr, struct rusage __user *ru);
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = do_wait(pid, options, infop, status, ru);
    set_fs(oldfs);
    return err;
}

#if 0
/* Sometimes we get the prototype, sometimes not...  and it also
 * differs from architecture to architecture...  *grumble* */
#if defined(__i386__)
asmlinkage int sys_ptrace(long, long, long, long);
#endif

#if defined(__i386__) || defined(__x86_64__) || defined(powerpc)
long k_ptrace(long req, long pid, long addr, long data) {
    int err;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    err = sys_ptrace(req, pid, addr, data);
    set_fs(oldfs);
    return err;
}
#endif
#if defined(__alpha__)
/*--------------------------------------------------------------------
 * k_ptrace for alpha....
 *
 * Alpha's ptrace calls returns data in a value parameter so we have
 * to jump through some hoops to get at that and interpet it
 * correctly.  In the end, k_ptrace PEEK* ends up working like the x86
 * version (treating data as a long * for the result) because that's
 * more convenient to us.
 *
 * Also, in the asm snippet below, since ptrace only writes the first
 * long of its pt_regs argument, that's how much space we actually
 * allocate for it.
 */
long __ptrace_caller(long req, long pid, long addr, long data,
		     void *, long *errflag);
__asm__
("    .align 3               \n"
 "    .ent __ptrace_caller   \n"
 "__ptrace_caller:           \n"
 "    subq $30, 24, $30      \n" /* alloc local scratch */
 "    stq  $26,  8($30)      \n" /* save ra */
 "    stq  $21, 16($30)      \n" /* save the address for the second result */
 "    lda  $1,   1($31)      \n" /* init flag value to 1 */
 "    stq  $1,   0($30)      \n"
 "    mov  $20, $27          \n"
 "    jsr  $26, ($27)        \n"
 "    ldq  $1,   0($30)      \n" /* Get the flag */
 "    ldq  $21, 16($30)      \n" /* ... and where to store it */
 "    stq  $1,   0($21)      \n" /* ... and store it. */
 "    ldq  $26,  8($30)      \n" /* restore return address */
 "    addq $30,24,$30        \n" /* pop local off stack */
 "    ret $31, ($26), 1      \n" /* return */
 "    .end __ptrace_caller   \n"
 );

long k_ptrace(long req, long pid, long addr, long data) {
    long ret, err_flag;
    mm_segment_t oldfs;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    ret = __ptrace_caller(req, pid, addr, data,
			  sys_call_table[__NR_ptrace], &err_flag);
    set_fs(oldfs);
    switch (req) {		/* return PEEK data x86-style */
    case PTRACE_PEEKDATA:
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKUSR:
	if (!err_flag) {
	    *((long *)data) = ret;
	    ret = 0;
	}
	break;
    }
    return ret;
}
/*------------------------------------------------------------------*/
#endif
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
