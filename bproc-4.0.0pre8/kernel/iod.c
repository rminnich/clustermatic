/*-------------------------------------------------------------------------
 *  iod.c:  Beowulf distributed process space IO daemon support
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
 * $Id: iod.c,v 1.26 2004/05/25 21:30:13 mkdist Exp $
 *-----------------------------------------------------------------------*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

#include "bproc.h"

struct io_connection_t {
    struct list_head list;
    struct io_connection_t *next, *prev;
    struct file *in;
    struct file *out;
};

static int iods_present = 0;
static LIST_HEAD(ioc_list);
static DECLARE_WAIT_QUEUE_HEAD(ioc_wait);
static spinlock_t ioc_lock = SPIN_LOCK_UNLOCKED;

/*
DEF_INSERT(io_connection, struct io_connection_t, next, prev)
DEF_APPEND(io_connection, struct io_connection_t, next, prev)
DEF_REMOVE(io_connection, struct io_connection_t, next, prev)
*/

static int complained = 0;

int bproc_new_io_connection(struct file *infd, struct file *outfd) {
    int err;
    struct io_connection_t *ioc;

    ioc = kmalloc(sizeof(*ioc), GFP_KERNEL);
    if (!ioc) {
	fput(infd);
	fput(outfd);
	return -ENOMEM;
    }
    ioc->in  = infd;
    ioc->out = outfd;

    err = -EBUSY;
    spin_lock(&ioc_lock);
    if (iods_present == 0) {
	spin_unlock(&ioc_lock);
	if (!complained) {
	    printk("bproc: iod: No daemon present to forward IO.\n");
	    complained = 1;
	}

	fput(ioc->in);
	fput(ioc->out);

	kfree(ioc);
	return -EBUSY;
    }
    list_add_tail(&ioc->list, &ioc_list);
    spin_unlock(&ioc_lock);
    wake_up(&ioc_wait);
    return 0;
}

static
unsigned int bproc_iod_poll(struct file * filp, poll_table * wait) {
    unsigned int mask = 0;
    poll_wait(filp, &ioc_wait, wait);
    if (!list_empty(&ioc_list)) mask |= POLLIN | POLLRDNORM;
    return mask;
}


static int
iod_get_io(int *fd) {
    struct io_connection_t *c;

    spin_lock(&ioc_lock);
    if (list_empty(&ioc_list)) {
	spin_unlock(&ioc_lock);
	return -EAGAIN;
    }
    c = list_entry(ioc_list.next, struct io_connection_t, list);
    list_del(&c->list);
    spin_unlock(&ioc_lock);
    
    /* File pointer games. */
    fd[0] = get_unused_fd();
    if (fd[0] < 0) {
	spin_lock(&ioc_lock);	/* Put back the IO connection */
	list_add(&c->list, &ioc_list);
	spin_unlock(&ioc_lock);
	return fd[0];
    }
    fd[1] = get_unused_fd();
    if (fd[1] < 0) {
	put_unused_fd(fd[0]);
	spin_lock(&ioc_lock);	/* Put back the IO connection */
	list_add(&c->list, &ioc_list);
	spin_unlock(&ioc_lock);
	return fd[1];
    }

    fd_install(fd[0], c->in);
    fd_install(fd[1], c->out);
    kfree(c);
    return 0;
}

static
int bproc_iod_ioctl(struct inode *ino, struct file * filp,
			     unsigned int cmd, unsigned long arg) {
    int fd[2], err;
    switch(cmd) {
    case BPROC_GET_IO:
	err = iod_get_io(fd);
	if (err == 0) {
	    if (copy_to_user((void *)arg, fd, sizeof(int)*2)) {
		/* XXX Might want to clean up the mess here ? */
		return -EFAULT;
	    }
	}
	return err;
    default:
	return -EINVAL;
    }
}

static 
int bproc_iod_open(struct inode *ino, struct file *filp) {
    spin_lock(&ioc_lock);
    iods_present++;
    complained = 0;
    spin_unlock(&ioc_lock);
    return 0;
}

static
int bproc_iod_release(struct inode *ino, struct file *filp) {
    struct io_connection_t *c;
    spin_lock(&ioc_lock);
    iods_present--;
    while (!list_empty(&ioc_list)) {
	c = list_entry(ioc_list.next, struct io_connection_t, list);
	list_del(&c->list);
	printk("bproc: iod: Freeing: 0x%08lx 0x%08lx\n",
	       (long) c->in, (long) c->out);
	fput(c->in);
	fput(c->out);
	kfree(c);
    }
    spin_unlock(&ioc_lock);
    return 0;
}

struct file_operations bproc_iod_fops = {
    open:    bproc_iod_open,
    release: bproc_iod_release,
    poll:    bproc_iod_poll,
    ioctl:   bproc_iod_ioctl,
};

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */

