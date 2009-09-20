/*-------------------------------------------------------------------------
 *  bpfs.c: BProc virtual file system code
 *
 *
 * $Id: bpfs.c,v 1.15 2004/10/18 16:36:04 mkdist Exp $
 *-----------------------------------------------------------------------*/
#define __NO_VERSION__

#include <linux/config.h>
#if defined(CONFIG_SMP) && ! defined(__SMP__)
#define __SMP__
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/xattr.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/mount.h>
#include <linux/statfs.h>

#include <asm/uaccess.h>

/* This snippet is borrowed from the user space xattr header file. */
#ifndef ENOATTR
# define ENOATTR ENODATA        /* No such attribute */
#endif

#include "bproc.h"
#include "bproc_internal.h"

#define BPROCFS_MAGIC 0x1234

static
struct inode *bpfs_get_inode(struct super_block *sb, int ino);
/*-------------------------------------------------------------------------
 * Machine node state representation
 *-----------------------------------------------------------------------*/
struct bproc_node_attr_t {
    struct list_head list;
    char *key;
    int   len;
    void *value;
};

struct bproc_node_attr_set_t {
    struct list_head list;
    int count;
};

/* This is basically the same as the user space bproc_node_info_t but
 * it will deviate at somepoint to hold more file system related details.
 */
struct bproc_knode_t {
    int             node;
    char            status[BPROC_STATE_LEN+1];
    unsigned int    mode;
    unsigned int    user;
    unsigned int    group;
    struct sockaddr addr;

    struct timespec ctime;
    struct timespec mtime;
    struct timespec atime;

    struct bproc_node_attr_set_t attr;
};

static struct bproc_knode_t  *  nodes = 0;
static struct bproc_knode_t **  node_map = 0;
static int                      node_ct;
static int                      id_ct;
static struct bproc_node_attr_set_t master_attr =
    {LIST_HEAD_INIT(master_attr.list), 0};
static struct sockaddr          master_addr;
static int xattr_max = BPROC_XATTR_MAX;

/* This should probably be some kind of rw lock */
static spinlock_t             nodeset_lock = SPIN_LOCK_UNLOCKED;

static struct timespec nodeset_ctime;
static struct timespec nodeset_mtime;
static struct timespec nodeset_atime;

static void bpfs_status_notify(int event);


/* This function cleans up a node entry when a node goes down.  All
 * owner, permissions and any extended attributes get reset */
static
void attrset_free(struct bproc_node_attr_set_t *attrset) {
    struct bproc_node_attr_t *attr;
    while (!list_empty(&attrset->list)) {
	attr = list_entry(attrset->list.next,
			  struct bproc_node_attr_t, list);
	list_del(&attr->list);
	kfree(attr);
	attrset->count--;
    }
}

static
void clear_node(struct bproc_knode_t *n) {
    /* The node status should already be "down" */
    n->mode = 0;
    n->user = 0;
    n->group = 0;
    memset(&n->addr, 0, sizeof(n->addr));

    attrset_free(&n->attr);
}

int nodeset_init(int node_ct_new, int id_ct_new, int *id_list) {
    int i, err, node_ct_old;
    struct timespec now;
    struct bproc_knode_t *nodes_new=0, **node_map_new=0;
    struct bproc_knode_t *nodes_old, **node_map_old;

    printk(KERN_INFO "bproc: Initializing node set. node_ct=%d id_ct=%d\n",
	   node_ct_new, id_ct_new);

    err = -ENOMEM;
    if (node_ct_new == 0 || id_ct_new == 0) {
	node_ct_new = id_ct_new = 0; /* set 'em both to zero */
	nodes_new = 0;
	node_map_new = 0;
    } else {
	nodes_new = vmalloc(sizeof(*nodes_new) * node_ct_new);
	if (!nodes_new) goto bail_out;

	node_map_new = vmalloc(sizeof(*node_map_new) * id_ct_new);
	if (!node_map_new) goto bail_out;
    }

    /* Initialize the contents of the new node set */
    now = CURRENT_TIME;
    memset(nodes_new, 0, sizeof(*nodes_new) * node_ct_new);

    for (i=0; i < id_ct_new; i++)
	node_map_new[i] = 0;

    for (i=0; i < node_ct_new; i++) {
	int id;
	if (get_user(id, &id_list[i])) {
	    err = -EFAULT;
	    goto bail_out;
	}

	if (id < 0 || id > id_ct_new) {
	    err = -EINVAL;
	    goto bail_out;
	}

	nodes_new[i].node = id;
	node_map_new[id] = &nodes_new[i];
    }

    /* Atomically swap to new structures */
    spin_lock(&nodeset_lock);
    nodeset_ctime = nodeset_mtime = nodeset_atime = now;

    /* XXX FIX ME: We MUST transfer node states from the old nodeset.
     * For now we're just initializing to "down" */


    /* Initialize the new node set.  By default everything is down
     * (and has no attributes) */
    for (i=0; i < node_ct_new; i++) {
	strcpy(nodes_new[i].status, "down");
	nodes_new[i].ctime = nodes_new[i].mtime = nodes_new[i].atime = now;
	nodes_new[i].attr.count = 0;
	INIT_LIST_HEAD(&nodes_new[i].attr.list);
    }

    /* Copy from the old node set to the new one */
    for (i=0; i < node_ct; i++) {
	struct bproc_knode_t *n, *nnew;

	n    = &nodes[i];
	nnew = (n->node < id_ct_new) ? node_map_new[n->node] : 0;
	if (nnew) {
	    strcpy(nnew->status, n->status);
	    nnew->mode  = n->mode;
	    nnew->user  = n->user;
	    nnew->group = n->group;
	    memcpy(&nnew->addr, &n->addr, sizeof(n->addr));
	    nnew->ctime = n->ctime;
	    nnew->mtime = n->mtime;
	    nnew->atime = n->atime;

	    /* Transfer xattrs */
	    nnew->attr.count = n->attr.count;
	    list_add_tail(&nnew->attr.list, &n->attr.list);
	    list_del(&n->attr.list);
	    INIT_LIST_HEAD(&n->attr.list); /* empty list so we don't
					      try to free anything */
	}
    }

    nodes_old    = nodes;	/* set aside "old" for freeing */
    node_map_old = node_map;
    node_ct_old  = node_ct;

    node_ct      = node_ct_new;	/* and replace with new */
    id_ct        = id_ct_new;
    nodes        = nodes_new;
    node_map     = node_map_new;

    spin_unlock(&nodeset_lock);

    /* Free old data structures if necessary */
    if (nodes_old) {
	for (i=0; i < node_ct_old; i++)	/* free remaining xattrs */
	    attrset_free(&nodes_old[i].attr);
	vfree(nodes_old);
    }
    if (node_map_old) vfree(node_map_old);

    bpfs_status_notify(1);
    return 0;

 bail_out:
    if (nodes_new)    vfree(nodes_new);
    if (node_map_new) vfree(node_map_new);
    return err;
}

/* This only sets node state.  This is because all ownership
 * information is maintained in the bpfs VFS. */
int nodeset_set_state(int id, char *state) {
    struct bproc_knode_t *n;

    spin_lock(&nodeset_lock);
    if (id < 0 || id >= id_ct) {
	spin_unlock(&nodeset_lock);
	printk(KERN_ERR "nodeset_set_state: invalid id: %d\n", id);
	return -EINVAL;
    }

    n = node_map[id];
    if (!n) {
	spin_unlock(&nodeset_lock);
	printk(KERN_ERR "nodeset_set_state: no map entry for id %d \n", id);
	return -EINVAL;
    }

    if (strcmp(n->status, "down") == 0 && strcmp(state, "down") != 0) {
	/* Node coming up, set bring-up permissions */
	n->mode  = 0100;
	n->user  = 0;
	n->group = 0;
    }

    strcpy(n->status, state);

    /* Special case - when nodes go down, they lose their owners,
     * permissions, etc. */
    if (strcmp(n->status, "down") == 0)
	clear_node(n);
    spin_unlock(&nodeset_lock);

    bpfs_status_notify(1);
    return 0;
}

int nodeset_set_addr(int id, struct sockaddr *addr) {
    struct bproc_knode_t *n;

    if (id == -1) {
	memcpy(&master_addr, addr, sizeof(master_addr));
    } else {
	spin_lock(&nodeset_lock);
	if (id < 0 || id >= id_ct) {
	    spin_unlock(&nodeset_lock);
	    printk(KERN_ERR "nodeset_set_state: invalid id: %d\n", id);
	    return -EINVAL;
	}

	n = node_map[id];
	if (!n) {
	    spin_unlock(&nodeset_lock);
	    printk(KERN_ERR "nodeset_set_state: no map entry for id %d \n",id);
	    return -EINVAL;
	}

	memcpy(&n->addr, addr, sizeof(n->addr));
	spin_unlock(&nodeset_lock);
    }

    bpfs_status_notify(1);
    return 0;
}

/* This is used by the master daemon to check if a move is legal */
int nodeset_move_perm(struct file *filp, struct nodeset_perm_t *mp) {
    int retval;
    struct inode *inode;

    /* Saved permission information for the permission check */
    uid_t saved_uid;
    gid_t saved_gid;
    struct group_info *saved_gi, *new_gi;
    kernel_cap_t saved_cap;

    /* The moving to front end case is handled in the master daemon. */

    /* This would probably be simpler to do directly but we want a
     * single well-understood path for doing permission checking. */
    if (mp->node < 0 || mp->node >= id_ct)
	return -BE_INVALIDNODE;

    inode = bpfs_get_inode(filp->f_dentry->d_inode->i_sb,
			   mp->node + BPFS_MASTER_NODE0_INO);
    if (!inode)
	return -BE_INVALIDNODE;

    /* Set File system IDs to reflect this request */
    saved_uid = current->fsuid;
    saved_gid = current->fsgid;
    saved_cap = current->cap_effective;

    new_gi = groups_alloc(mp->ngroups);
    if (!new_gi) {
	printk(KERN_ERR "bproc: bpfs: out of memory allocating groups. (%d)\n",
	       mp->ngroups);
	return -ENOMEM;
    }    
    copy_to_groups(new_gi, mp->groups, mp->ngroups);

    /* Swap group info */
    saved_gi = current->group_info;
    get_group_info(saved_gi);
    if (set_current_groups(new_gi)) {
	printk(KERN_ERR "bproc: bpfs: failed to set groups!\n");
	put_group_info(saved_gi);
	put_group_info(new_gi);
	return -EPERM;
    }
    put_group_info(new_gi);

    current->fsuid   = mp->euid;
    current->fsgid   = mp->egid;
    current->cap_effective = mp->cap_effective;

    /* Do the permission check */
    retval = permission(inode, MAY_EXEC, 0);
    iput(inode);

    /* Restore permissions */
    current->fsuid   = saved_uid;
    current->fsgid   = saved_gid;
    current->cap_effective = saved_cap;
    if (set_current_groups(saved_gi)) {
	printk(KERN_ERR "bproc: bpfs: failed to restore groups!\n");
	put_group_info(saved_gi);
	return -EPERM;
    }
    put_group_info(saved_gi);
    return retval;
}

int nodeset_nodeup(int node) {
    struct bproc_knode_t *n;

    spin_lock(&nodeset_lock);
    if (node < 0 || node >= id_ct) {
	spin_unlock(&nodeset_lock);
	return -BE_INVALIDNODE;
    }

    n = node_map[node];
    if (!n) {
	spin_unlock(&nodeset_lock);
	return -BE_INVALIDNODE;
    }

    if (strcmp(n->status, "down") == 0) {
	spin_unlock(&nodeset_lock);
	return -BE_NODEDOWN;
    }
    spin_unlock(&nodeset_lock);
    return 0;
}

void nodeset_cleanup(void) {
    nodeset_init(0,0,0);
    attrset_free(&master_attr);
}


/*-----------------------------------------------------------------------*/

static struct super_operations  bprocfs_ops;
static struct inode_operations  bpfs_dir_iops;
static struct inode_operations  bpfs_status_iops;
static struct inode_operations  bpfs_node_iops;
static struct inode_operations  bpfs_node_slave_iops;
static struct inode_operations  bpfs_self_iops;
static struct dentry_operations bpfs_node_dentry_operations_m; /* master */
static struct dentry_operations bpfs_node_dentry_operations_s; /* slave */
static struct file_operations   bpfs_dir_fops;
static struct file_operations   bpfs_status_fops;

static inline
struct bproc_knode_t *dentry2node(struct dentry *dentry) {
    int id = dentry->d_inode->i_ino - BPFS_MASTER_NODE0_INO;
    if (id < 0 || id >= id_ct)
	return 0;
    return node_map[id];
}

static inline
struct bproc_knode_t *inode2node(struct inode *inode) {
    int id = inode->i_ino - BPFS_MASTER_NODE0_INO;
    if (id < 0 || id >= id_ct)
	return 0;
    return node_map[id];
}

/*--------------------------------------------------------------------
 * Inode operations
 *------------------------------------------------------------------*/
static
void bpfs_refresh_inode(struct inode *inode) {
    int node_num;
    struct bproc_knode_t *node;

    switch (inode->i_ino) {
    case BPFS_MASTER_STATUS_INO:
	inode->i_size = sizeof(struct bproc_node_info_t) * node_ct;
	break;
    default:
	/* Check to see if this inode corresponds to a valid node number */
	node_num = inode->i_ino - BPFS_MASTER_NODE0_INO;

	/* On the front end, our inode entries have a bit more
	 * meaning.  We also check that they're present in the node
	 * set. */
	spin_lock(&nodeset_lock);
	if (node_num < 0 || node_num > id_ct) {
	    spin_unlock(&nodeset_lock);
	    break;
	}

	node = node_map[node_num];
	if (!node) {
	    spin_unlock(&nodeset_lock);
	    break;
	}

	inode->i_mode  = S_IFREG | node->mode;
	inode->i_uid   = node->user;
	inode->i_gid   = node->group;
	inode->i_atime = node->atime;
	inode->i_mtime = node->mtime;
	inode->i_ctime = node->ctime;
	spin_unlock(&nodeset_lock);
	break;
    }
}


static
void bpfs_read_inode(struct inode *inode) {
    /* Some default crud */
    inode->i_atime = nodeset_atime;
    inode->i_mtime = nodeset_mtime;
    inode->i_ctime = nodeset_ctime;
    inode->i_uid   = inode->i_gid = 0;
    inode->i_size  = 0;
    inode->i_fop   = 0;

    switch(inode->i_ino) {
    case BPFS_ROOT_INO:
	inode->i_mode = S_IFDIR | 0555;
	inode->i_op   = &bpfs_dir_iops;
	inode->i_fop  = &bpfs_dir_fops;
	break;
    case BPFS_MASTER_INO:
	inode->i_mode = S_IFREG | 0600;
	inode->i_fop  = &bproc_master_fops;
	break;
    case BPFS_SLAVE_INO:
	inode->i_mode = S_IFREG | 0600;
	inode->i_fop  = &bproc_slave_fops;
	break;
    case BPFS_IOD_INO:
	inode->i_mode = S_IFREG | 0600;
	inode->i_fop  = &bproc_iod_fops;
	break;
    case BPFS_MEMFILE_INO:
	inode->i_mode = S_IFREG | 0666;
	inode->i_fop  = &bproc_memfile_fops;
	break;
    case BPFS_SELF_INO:
	inode->i_mode = S_IFLNK | 0777;
	inode->i_op   = &bpfs_self_iops;
	break;

    /*--- Slave node specific stuff --- */
    case BPFS_SLAVE_NODE_MASTER_INO:
	inode->i_mode = S_IFREG | 0111;
	inode->i_op   = &bpfs_node_slave_iops;
	break;
    case BPFS_SLAVE_NODE_SELF_INO:
	inode->i_mode = S_IFREG | 0111;
	inode->i_op   = &bpfs_node_slave_iops;
	break;


    /*--- Master node specific stuff --- */
    case BPFS_MASTER_STATUS_INO:
	inode->i_mode = S_IFREG | 0444;
	inode->i_op   = &bpfs_status_iops;
	inode->i_fop  = &bpfs_status_fops;
	bpfs_refresh_inode(inode);
	break;
    case BPFS_MASTER_NODE_MASTER_INO:
	inode->i_mode = S_IFREG | 0111;
	inode->i_op   = &bpfs_node_iops;
	break;
    default:
	inode->i_op   = &bpfs_node_iops;
	bpfs_refresh_inode(inode);
	break;
    }
}

static
struct inode *bpfs_get_inode(struct super_block *sb, int ino) {
    struct inode *inode;

    inode = iget(sb, ino);
    if (inode)
	bpfs_refresh_inode(inode);
    return inode;
}


/* All the validation to make sure that this inode should exist is
 * done with the dentry revalidate stuff.  This function just
 * refreshes the contents of the inode for the stat call.  There is a
 * chance, however, that things will have changed between the dentry
 * validation and the stat call.  In that case we have two options:
 * ignore it and return the possibly very old data or return some kind
 * of error.  We're currently opting to just return the old data. */
static
int bpfs_inode_getattr(struct vfsmount *mnt, struct dentry *dentry,
		      struct kstat *stat) {
    bpfs_refresh_inode(dentry->d_inode);
    generic_fillattr(dentry->d_inode, stat);
    return 0;
}


static
int bpfs_node_setattr(struct dentry *dentry, struct iattr *ia) {
    int error;
    struct bproc_knode_t *n;

    /* Basic built-in permission check */
    error = inode_change_ok(dentry->d_inode, ia);
    if (error) return error;

    error = -EPERM;
    if (dentry->d_inode->i_ino < BPFS_MASTER_NODE0_INO)
	return error;

    spin_lock(&nodeset_lock);
    n = inode2node(dentry->d_inode);
    if (!n) goto done;

    /* Additional validity checks */

    /* can't modify nodes that are down */
    if (strcmp(n->status, "down") == 0) goto done;

    /* Only the execute bits are valid */
    if ((ia->ia_valid & ATTR_MODE) &&
	(ia->ia_mode & S_IALLUGO & ~0111)) goto done;

    /* Things are ok - make these changes to the inode and nodeset */
    if (ia->ia_valid & ATTR_MODE)
	n->mode = ia->ia_mode & S_IALLUGO;

    if (ia->ia_valid & ATTR_UID)
	n->user = ia->ia_uid;

    if (ia->ia_valid & ATTR_GID)
	n->group = ia->ia_gid;

    /* Finally, everything is ok so update modification times */
    n->mtime = n->atime = CURRENT_TIME;
    nodeset_mtime = nodeset_atime = CURRENT_TIME;

    error = 0;
 done:
    spin_unlock(&nodeset_lock);

    /* Flush changes out to the inode structure */
    if (!error) {
	bpfs_status_notify(1);
	error = inode_setattr(dentry->d_inode, ia);
    }
    return error;
}

static
int readdir_master(struct file *filp, void *dirent, filldir_t filldir) {
    int i, len, ino;
    char tmp[30];

    switch((long)filp->f_pos) {
    case 4:
	if (filldir(dirent, "status", 6, filp->f_pos,
		    BPFS_MASTER_STATUS_INO, DT_REG)<0)
	    return 0;
	filp->f_pos++;
    default:
	i = filp->f_pos - 5;
	spin_lock(&nodeset_lock);
	for (;i < node_ct; i++) {
	    if (nodes[i].node == -1) {
		printk("Invalid node in nodeset at index %d\n", i);
		continue;
	    }

	    ino = nodes[i].node + BPFS_MASTER_NODE0_INO;
	    len = sprintf(tmp, "%d", nodes[i].node);
	    spin_unlock(&nodeset_lock);
	    if (filldir(dirent, tmp, len, filp->f_pos, ino, DT_REG)<0)
		return 0;
	    filp->f_pos++;
	    spin_lock(&nodeset_lock);
	}
	spin_unlock(&nodeset_lock);
    }
    return 1;
}

static
int readdir_masq(struct file *filp, void *dirent, filldir_t filldir) {
    char tmp[30];
    struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);
    sprintf(tmp, "%d", m->node_number);

    switch((long)filp->f_pos) {
    case 4:
	if (filldir(dirent, tmp, strlen(tmp), filp->f_pos,
		    m->node_number + BPFS_MASTER_NODE0_INO, DT_REG) < 0)
	    return 0;
	filp->f_pos++;
	/* fall through */
    }
    return 1;
}

static
int bpfs_readdir(struct file * filp, void * dirent, filldir_t filldir) {
    /* We have only directory in this file system for now so we do
     * this in a real straight forward fashion. */

    switch ((long)filp->f_pos) {
	/* These first 4 are the directory entries that exist whether
	 * or not we're a masqueraded process. */
    case 0:
	if (filldir(dirent, ".", 1, filp->f_pos,
		    filp->f_dentry->d_inode->i_ino, DT_DIR) < 0)
	    return 0;
	filp->f_pos++;
	/* fall through */
    case 1:
	if (filldir(dirent, "..", 2, filp->f_pos,
		    filp->f_dentry->d_parent->d_inode->i_ino, DT_DIR) < 0)
	    return 0;
	filp->f_pos++;
	/* fall through */
    case 2:
	if (filldir(dirent, "self", 4, filp->f_pos,
		    BPFS_SELF_INO, DT_LNK) < 0)
	    return 0;
	filp->f_pos++;
	/* fall through */
    case 3:
	if (filldir(dirent, "-1", 2, filp->f_pos,
		    BPFS_MASTER_NODE_MASTER_INO, DT_REG) < 0)
	    return 0;
	filp->f_pos++;
	/* fall through */
    default:
	if (BPROC_ISMASQ(current))
	    return readdir_masq(filp, dirent, filldir);
	else
	    return readdir_master(filp, dirent, filldir);
    }
    return 1;
}

static
struct dentry *bpfs_node_lookup(struct inode * dir, struct dentry *dentry,
				struct nameidata *ni) {
    struct inode *inode;
    struct bproc_knode_t *n;
    int node_num;
    char *check;

    /* Special case: "self" */
    if (dentry->d_name.len == 4 &&
	strncmp(dentry->d_name.name, "self", 4) == 0) {
	inode = bpfs_get_inode(dir->i_sb, BPFS_SELF_INO);
	if (!inode)
	    return ERR_PTR(-ENOENT);
	/* no d_op on this one since revalidate is always ok. */
	d_add(dentry, inode);
	return NULL;
    }

    if (BPROC_ISMASQ(current)) {
	struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);

	/* Special case: "-1" */
	if (dentry->d_name.len == 2 &&
	    strncmp(dentry->d_name.name, "-1", 2) == 0) {
	    inode = bpfs_get_inode(dir->i_sb, BPFS_SLAVE_NODE_MASTER_INO);
	    if (!inode)
		return ERR_PTR(-ENOENT);
	    dentry->d_op = &bpfs_node_dentry_operations_s;
	    d_add(dentry, inode);
	    return NULL;
	}

	node_num = simple_strtol(dentry->d_name.name, &check, 10);
	if (*check || node_num != m->node_number)
	    return ERR_PTR(-ENOENT);

	inode = bpfs_get_inode(dir->i_sb, BPFS_SLAVE_NODE_SELF_INO);
	if (!inode)
	    return ERR_PTR(-ENOENT);
	dentry->d_op = &bpfs_node_dentry_operations_s;
	d_add(dentry, inode);
	return NULL;
    } else {
	/* Special case: "status" */
	if (!BPROC_ISMASQ(current) && dentry->d_name.len == 6 &&
	    strncmp(dentry->d_name.name, "status", 6) == 0) {
	    inode = bpfs_get_inode(dir->i_sb, BPFS_MASTER_STATUS_INO);
	    if (!inode)
		return ERR_PTR(-ENOENT);
	    dentry->d_op = &bpfs_node_dentry_operations_m;
	    d_add(dentry, inode);
	    return NULL;
	}

	/* Special case: "-1" */
	if (dentry->d_name.len == 2 &&
	    strncmp(dentry->d_name.name, "-1", 2) == 0) {
	    inode = bpfs_get_inode(dir->i_sb, BPFS_MASTER_NODE_MASTER_INO);
	    if (!inode)
		return ERR_PTR(-ENOENT);
	    dentry->d_op = &bpfs_node_dentry_operations_m;
	    d_add(dentry, inode);
	    return NULL;
	}

	/* Normal case - a node number */
	node_num = simple_strtol(dentry->d_name.name, &check, 10);
	if (*check || node_num < 0 || node_num >= id_ct)
	    return ERR_PTR(-ENOENT);

	n = node_map[node_num];
	if (!n) return ERR_PTR(-ENOENT);

	inode = bpfs_get_inode(dir->i_sb, node_num + BPFS_MASTER_NODE0_INO);
	if (!inode)
	    return ERR_PTR(-ENOENT);

	dentry->d_op = &bpfs_node_dentry_operations_m;
	d_add(dentry, inode);
	return NULL;		/* weird but correct... */
    }
}

static
int bpfs_self_readlink(struct dentry *dentry, char *buffer, int buflen) {
    char tmp[30];
    if (BPROC_ISMASQ(current)) {
	struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);
	sprintf(tmp, "%d", m->node_number);
    } else {
	strcpy(tmp, "-1");
    }
    return vfs_readlink(dentry, buffer, buflen, tmp);
}

static
int bpfs_self_follow_link(struct dentry *dentry, struct nameidata *nd) {
    char tmp[30];
    if (BPROC_ISMASQ(current)) {
	struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);
	sprintf(tmp, "%d", m->node_number);
    } else {
	strcpy(tmp, "-1");
    }
    return vfs_follow_link(nd,tmp);
}


/*-------------------------------------------------------------------------
 *   Extended attribute handling code
 *-----------------------------------------------------------------------*/
static
int get_node_and_attr(struct dentry *dentry, struct bproc_knode_t **node,
		      struct bproc_node_attr_set_t **attr) {
    struct bproc_knode_t *n;
    struct bproc_node_attr_set_t *a;
    if (dentry->d_inode->i_ino == BPFS_MASTER_NODE_MASTER_INO) {
	n = 0;
	a = &master_attr;
    } else {
	n = dentry2node(dentry);
	if (!n) return -ENOATTR;
	a = &n->attr;
    }

    *node = n;
    *attr = a;
    return 0;
}

static
struct bproc_node_attr_t *find_xattr(const char *name,
				     struct bproc_node_attr_set_t *attrset) {
    struct list_head *l;
    struct bproc_node_attr_t *a;
    for (l = attrset->list.next; l != &attrset->list; l = l->next) {
	a = list_entry(l, struct bproc_node_attr_t, list);
	if (strcmp(a->key, name) == 0)
	    return a;
    }
    return 0;
}

/*--------------------------------------------------------------------
 * Slave side (masq) extended attribute handling code.
 */
static
ssize_t bpfs_node_slave_getxattr(struct dentry *dentry, const char *name,
				void *value, size_t size) {
    void *val;
    int len;
    struct bproc_masq_master_t *m = BPROC_MASQ_MASTER(current);

    /* Only the "ADDR" attribute exists on the slave side */
    if (strcmp(name, BPROC_ADDR_XATTR) != 0)
	return -ENOATTR;

    if (dentry->d_inode->i_ino == BPFS_SLAVE_NODE_MASTER_INO) {
	val = &m->master_addr;
	len = sizeof(m->master_addr);
    } else {
	val = &m->my_addr;
	len = sizeof(m->my_addr);
    }

    if (size == 0)
	return len;

    if (len > size)
	return -ERANGE;

    memcpy(value, val, len);
    return len;
}

static
int bpfs_node_slave_setxattr(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags) {
    return -EPERM;
}

static
ssize_t bpfs_node_slave_listxattr(struct dentry *dentry, char *list,
				 size_t size) {
    int len;

    /* Just one attribute on the slave side - address */
    len = strlen(BPROC_ADDR_XATTR)+1;
    if (size == 0)
	return len;
    if (len > size)
	return -ERANGE;
    memcpy(list, BPROC_ADDR_XATTR, len);
    return len;
}


static
int bpfs_node_slave_removexattr(struct dentry *dentry, const char *name) {
    return -EPERM;
}

/*--------------------------------------------------------------------
 * Master node extended attribute handling code.
 */
static
ssize_t bpfs_node_getxattr(struct dentry *dentry, const char *name,
			   void *value, size_t size) {
    int len = 0;
    void *val = 0;
    struct bproc_knode_t *n;
    struct bproc_node_attr_t *attr;
    struct bproc_node_attr_set_t *attrset;

    spin_lock(&nodeset_lock);
    if (get_node_and_attr(dentry, &n, &attrset)) {
	spin_unlock(&nodeset_lock);
	return -ENOATTR;
    }

    /* Somwhat magical attributes.  These exist only for the slave
     * nodes to prevent the master node from trying to grab these. */
    if (!val && n && strcmp(name, BPROC_STATE_XATTR) == 0) {
	val = n->status;
	len = strlen(n->status)+1; /* include trailing null. */
    }

    /* The address attribute */
    if (!val && strcmp(name, BPROC_ADDR_XATTR) == 0) {
	if (n) {	      /* Normal node on the front end case. */
	    if (strcmp(n->status, "down") != 0) {
		val = &n->addr;
		len = sizeof(n->addr);
	    }
	} else {
	    val = &master_addr;
	    len = sizeof(master_addr);
	}
    }

    /* Look through the rest of the attributes */
    if (!val) {
	attr = find_xattr(name, attrset);
	if (attr) {
	    len = attr->len;
	    val = attr->value;
	}
    }

    if (!val) {
	spin_unlock(&nodeset_lock);
	return -ENOATTR;
    }
    if (size == 0) {
	spin_unlock(&nodeset_lock);
	return len;
    }
    if (len > size) {
	spin_unlock(&nodeset_lock);
	return -ERANGE;
    }

    memcpy(value, val, len);
    spin_unlock(&nodeset_lock);
    return len;
}


/* This little function checks to see if a node state supplied by the
 * user is a valid node state. */
static
int check_node_string(const char *str, int len) {
    int i;
    /* Node states must be alphanumeric and may optionally include the
     * trailing null */
    for (i=0; i < len; i++)
	if (!isalnum(str[i]) || (i != len-1 && str[i] == 0))
	    return -EINVAL;
    return 0;
}

static
int special_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags) {
    int err = 0;
    int send_down = -1;
    struct bproc_knode_t *n;
    struct bproc_node_attr_set_t *attrset;

    spin_lock(&nodeset_lock);
    if (get_node_and_attr(dentry, &n, &attrset)) {
	err = -ENOATTR;
	goto out;
    }

    if (strcmp(name, BPROC_STATE_XATTR) == 0) {
	if (!n) {		/* no node state on the master */
	    err = -ENOATTR;
	    goto out;
	}
	if (strcmp(n->status, "down") == 0) {
	    err = -EINVAL;
	    goto out;
	}
	if (flags & XATTR_CREATE) {
	    err = -EEXIST;
	    goto out;
	}
	if (size > BPROC_STATE_LEN) {
	    err = -ENOSPC;
	    goto out;
	}
	if (check_node_string(value, size) != 0) {
	    err = -EINVAL;
	    goto out;
	}

	memcpy(n->status, value, size);
	n->status[size] = 0;	/* make sure it's null terminated */

	/* Special case: setting the node's state to "down"
	 * disconnects the node from the front end */
	if (strcmp(n->status, "down") == 0) {
	    send_down = n->node; /* Send a down event to this node */
	    clear_node(n);
	}

	n->mtime = CURRENT_TIME;
    } else if (strcmp(name, BPROC_ADDR_XATTR) == 0) {
	/* Users are not allowed to set the node address on the slave
	 * nodes or the front end */
	err = -EPERM;
    }
 out:
    spin_unlock(&nodeset_lock);
    if (send_down != -1) {
	struct bproc_krequest_t *req;
	struct bproc_null_msg_t *msg;
	req = bproc_new_req(BPROC_NODE_DOWN, sizeof(*msg), GFP_KERNEL);
	if (req) {
	    msg = bproc_msg(req);
	    bpr_from_node(msg, -1);
	    bpr_to_node(msg, send_down);
	    bproc_send_req(&bproc_ghost_reqs, req);
	    bproc_put_req(req);
	} else {
	    printk("bpfs: out of memory sending down event!\n");
	}
    }
    if (err == 0)
	bpfs_status_notify(1);
    return err;
}


static
int bpfs_node_setxattr(struct dentry *dentry, const char *name,
		       const void *value, size_t size, int flags) {
    int namelen;
    struct bproc_knode_t *n;
    struct bproc_node_attr_t *attr, *newattr;
    struct bproc_node_attr_set_t *attrset;

    /* We need an extra permission check here - only root is allowed
     * modify attributes on our nodes. */
    if (!capable(CAP_SYS_ADMIN))
	return -EPERM;

    /* Our special attributes are handled differently so branch off
     * here. */
    if (strcmp(name, BPROC_STATE_XATTR) == 0 ||
	strcmp(name, BPROC_ADDR_XATTR) == 0) {
	return special_setxattr(dentry, name, value, size, flags);
    }

    if (strncmp(name, BPROC_XATTR_PREFIX, strlen(BPROC_XATTR_PREFIX)) != 0) {
	/* We only allow messing with attributes that start with "bproc." */
	return -EINVAL;
    }

    /* Limit the size of these things */
    namelen = strlen(name);
    if (namelen > BPROC_XATTR_MAX_NAME_SIZE ||
	size    > BPROC_XATTR_MAX_VALUE_SIZE)
	return -ENOSPC;

    /* We malloc and setup this thing up front.  That way we don't
     * have dork around with releasing locks and rechecking previous
     * checks before actually sticking the value in. */
    newattr = kmalloc(sizeof(*newattr) + namelen + size + 1, GFP_KERNEL);
    if (!newattr) return -ENOMEM;
    newattr->len   = size;
    newattr->key   = (char *)(newattr+1);
    newattr->value = newattr->key + namelen + 1;
    strcpy(newattr->key, name);
    memcpy(newattr->value, value, size);

    spin_lock(&nodeset_lock);
    if (get_node_and_attr(dentry, &n, &attrset)) {
	spin_unlock(&nodeset_lock);
	kfree(newattr);
	return -ENOATTR;
    }

    /* We can't do anything to a node that is down */
    if (n && strcmp(n->status, "down") == 0) {
	spin_unlock(&nodeset_lock);
	kfree(newattr);
	return -ENOATTR;
    }

    attr = find_xattr(name, attrset);
    if (attr) {
	/* Attribute already exists - doing replace */
	if (flags & XATTR_CREATE) {
	    spin_unlock(&nodeset_lock);
	    kfree(newattr);
	    return -EEXIST;
	}
	list_del(&attr->list);
	kfree(attr);
    } else {
	/* Attribute doesn't exist - creating new */
	if (flags & XATTR_REPLACE) {
	    spin_unlock(&nodeset_lock);
	    kfree(newattr);
	    return -ENOATTR;
	}
	if (attrset->count >= xattr_max) {
	    spin_unlock(&nodeset_lock);
	    kfree(newattr);
	    return -ENOSPC;
	}
	attrset->count++;
    }
    list_add_tail(&newattr->list, &attrset->list);
    spin_unlock(&nodeset_lock);

    bpfs_status_notify(1);
    return 0;
}

static
ssize_t bpfs_node_listxattr(struct dentry *dentry, char *list, size_t size) {
    int len = 0, retval;
    struct bproc_knode_t *n;
    struct bproc_node_attr_set_t *attrset;
    struct bproc_node_attr_t *attr;
    struct list_head *l;

    spin_lock(&nodeset_lock);
    if (get_node_and_attr(dentry, &n, &attrset)) {
	spin_unlock(&nodeset_lock);
	return -ENOATTR;
    }

    if (n) 			/* state only for slave nodes */
	len += strlen(BPROC_STATE_XATTR)+1;

    if (!n || strcmp(n->status, "down") != 0)
	len += strlen(BPROC_ADDR_XATTR)+1;

    for (l = attrset->list.next; l != &attrset->list; l = l->next) {
	attr = list_entry(l, struct bproc_node_attr_t, list);
	    len += strlen(attr->key)+1;
    }

    if (size == 0) {
	spin_unlock(&nodeset_lock);
	return len;
    }

    if (len > size) {
	spin_unlock(&nodeset_lock);
	return -ERANGE;
    }
    retval = len;

    /* Now we actually copy the information into the buffer.  Note
     * that the buffer is a kernel space buffer so we don't have to
     * worry about copy_to_user and releasing the spin locks while
     * doing this. */
    /* Two special cases */
    if (n) {			/* state only for slave nodes */
	len = strlen(BPROC_STATE_XATTR)+1;
	memcpy(list, BPROC_STATE_XATTR, len);
	list += len;
    }

    if (!n || strcmp(n->status, "down") != 0) {
	len = strlen(BPROC_ADDR_XATTR)+1;
	memcpy(list, BPROC_ADDR_XATTR, len);
	list += len;
    }

    for (l = attrset->list.next; l != &attrset->list; l = l->next) {
	attr = list_entry(l, struct bproc_node_attr_t, list);
	len = strlen(attr->key)+1;
	memcpy(list, attr->key, len);
	list += len;
    }
    spin_unlock(&nodeset_lock);
    return retval;
}

static
int bpfs_node_removexattr(struct dentry *dentry, const char *name) {
    struct bproc_knode_t *n;
    struct bproc_node_attr_set_t *attrset;
    struct bproc_node_attr_t *attr;

    /* We need an extra permission check here - only root is allowed
     * modify attributes on our nodes. */
    if (!capable(CAP_SYS_ADMIN))
	return -EPERM;

    /* Our special attributes are handled differently so branch off
     * here. */
    if (strcmp(name, BPROC_STATE_XATTR) == 0 ||
	strcmp(name, BPROC_ADDR_XATTR) == 0) {
	return -EPERM;		/* not allowed to remove these */
    }

    spin_lock(&nodeset_lock);
    if (get_node_and_attr(dentry, &n, &attrset)) {
	spin_unlock(&nodeset_lock);
	return -ENOATTR;
    }

    attr = find_xattr(name, attrset);
    if (!attr) {
	spin_unlock(&nodeset_lock);
	return -ENOATTR;
    }

    list_del(&attr->list);
    attrset->count--;
    spin_unlock(&nodeset_lock);
    kfree(attr);
    return 0;
}

/*--------------------------------------------------------------------
 * Dentry operations
 *
 * Dentry revalidation: There are two versions of the dentry
 * revalidation functions.  One for the master's context and one for
 * the slave's (masq) context.  Basically, if a dentry was created in
 * the master's context, it will use the _m version of the
 * revalidation function.  Then if anything masqueraded tries to
 * revalidate, it will fail.  The same is true in reverse for the _s
 * version of the function.
 *------------------------------------------------------------------*/
static
int bpfs_file_dentry_revalidate_m(struct dentry *dentry,
				  struct nameidata *nd) {
    struct bproc_knode_t *n;
    struct inode *ino;

    ino = dentry->d_inode;
    if (!ino) return 0;		/* negative dentry (fail) */

    if (BPROC_ISMASQ(current))
	return 0;

    if (ino->i_ino >= BPFS_MASTER_NODE0_INO) {
	n = dentry2node(dentry);
	if (!n) return 0;		/* node gone (fail) */
    }
    bpfs_refresh_inode(dentry->d_inode);
    return 1;			/* revalidate ok */
}

static
int bpfs_file_dentry_revalidate_s(struct dentry *dentry, struct nameidata *nd){
    int node_num;
    char *check;
    struct inode *ino;
    struct bproc_masq_master_t *m;

    ino = dentry->d_inode;
    if (!ino)
	return 0;		/* negative dentry (fail) */

    if (!BPROC_ISMASQ(current))
	return 0;
    m = BPROC_MASQ_MASTER(current);
    node_num = simple_strtol(dentry->d_name.name, &check, 10);
    if (*check || node_num != m->node_number)
	return 0;		/* fail */
    bpfs_refresh_inode(dentry->d_inode);
    return 1;			/* revalidate ok */
}

/*--------------------------------------------------------------------
 * Superblock operations
 *------------------------------------------------------------------*/
static
int bpfs_statfs(struct super_block *sb, struct kstatfs *buf) {
    buf->f_type = BPROCFS_MAGIC;
    buf->f_bsize = PAGE_SIZE/sizeof(long);
    buf->f_bfree = 0;
    buf->f_bavail = 0;
    buf->f_ffree = 0;
    buf->f_namelen = NAME_MAX;
    return 0;
}

static
int bprocfs_fill_super(struct super_block *sb,
		       void *data, int silent) {
    struct inode *root_inode;
    struct qstr   name = { .name = "bproc:",
			   .len  = 6,
			   .hash = 0 };

    /* Some random crud */
    sb->s_blocksize      = 1024;
    sb->s_blocksize_bits = 10;
    sb->s_magic          = BPROCFS_MAGIC;
    sb->s_op             = &bprocfs_ops;

    root_inode = bpfs_get_inode(sb, BPFS_ROOT_INO);
    if (!root_inode)
	return -ENOMEM;

    /* This is some cruft to make the /proc/pid/fd entry for the
     * daemons look different.  We set the name of the root dentry to
     * "bproc:" much like the socketfs or pipefs.  This will get
     * ignored for other opens in a mounted bpfs file system since
     * those will be mounted on top of something else. */
    sb->s_root = d_alloc(NULL, &name);
    if (!sb->s_root) {
	iput(root_inode);
	return -ENOMEM;
    }

    sb->s_root->d_sb = sb;
    sb->s_root->d_parent = sb->s_root;
    d_instantiate(sb->s_root, root_inode);
    return 0;
}

static
struct super_block *bprocfs_get_sb(struct file_system_type *fs_type,
				   int flags, const char *dev_name,void *data){
    return get_sb_single(fs_type, flags, data, bprocfs_fill_super);
}

/*--------------------------------------------------------------------
 * VFS structures
 *------------------------------------------------------------------*/
static DECLARE_WAIT_QUEUE_HEAD(notifier_wait);
static spinlock_t notifier_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(notifier_list);
struct notifier_private_t {
    struct list_head list;
    int mask;
    int event;
};

static
void bpfs_status_notify(int event) {
    struct list_head *l;
    struct notifier_private_t *n;
    spin_lock(&notifier_lock);
    for (l=notifier_list.next; l != &notifier_list; l = l->next) {
        n = list_entry(l, struct notifier_private_t, list);
        n->event |= event;
    }
    spin_unlock(&notifier_lock);
    wake_up(&notifier_wait);
}

static
int bpfs_status_file_open(struct inode *ino, struct file *filp) {
    struct notifier_private_t *n;

    n = kmalloc(sizeof(*n), GFP_KERNEL);
    if (!n) return -ENOMEM;
    n->mask  = ~0;		/* This should be tunable at some point */
    n->event = 0;
    spin_lock(&notifier_lock);
    list_add(&n->list, &notifier_list);
    spin_unlock(&notifier_lock);
    filp->private_data = n;
    return 0;
}

static
int bpfs_status_file_release(struct inode *ino, struct file *filp) {
    struct notifier_private_t *n = filp->private_data;
    spin_lock(&notifier_lock);
    list_del(&n->list);
    spin_unlock(&notifier_lock);
    kfree(n);
    return 0;
}

static
unsigned int bpfs_status_file_poll(struct file * filp, poll_table * wait) {
    unsigned int mask = 0;
    struct notifier_private_t *notifier = filp->private_data;
    poll_wait(filp, &notifier_wait, wait);
    if (notifier->event & notifier->mask) mask |= POLLIN | POLLRDNORM;
    return mask;
}

static
ssize_t bpfs_status_file_read(struct file *filp, char *buff,
			      size_t size, loff_t *l) {
    struct bproc_node_info_t tmp;
    struct bproc_knode_t *n;
    int idx, offset, len;
    ssize_t bytes = 0;
    struct notifier_private_t *status = filp->private_data;

    /* Clear events if we're re-reading the status file */
    if (filp->f_pos == 0)
	status->event = 0;

    /* UGLY HACK: type cast the file pointer here because x86 doesn't
     * include __divdi3 or __moddi3 which gcc expects to do math on 64
     * bit ints. */
    idx = ((long)filp->f_pos) / sizeof(tmp);

    spin_lock(&nodeset_lock);
    while (idx < node_ct && size > 0) {
	n = &nodes[idx];
	/* Copy node information into the structure that the user is
	 * expecting to see. */
	tmp.node = n->node;
	memcpy(tmp.status, n->status, sizeof(n->status));
	tmp.mode = n->mode;
	tmp.user = n->user;
	tmp.group = n->group;
	memcpy(&tmp.addr, &n->addr, sizeof(n->addr));
	spin_unlock(&nodeset_lock);

	/* Figure out if we're doing a partial write, etc... */
	offset = ((long)filp->f_pos) % sizeof(tmp);
	len = sizeof(tmp) - offset;
	if (len > size) len = size;

	if (copy_to_user(buff, ((void *)&tmp) + offset, len))
	    return -EFAULT;

	buff  += len;
	size  -= len;
	bytes += len;
	idx++;
	spin_lock(&nodeset_lock);
    }
    spin_unlock(&nodeset_lock);
    return bytes;
}

/*--------------------------------------------------------------------
 * VFS structures
 *------------------------------------------------------------------*/
static
struct super_operations bprocfs_ops = {
    read_inode:  bpfs_read_inode,
    statfs:      bpfs_statfs,
};

static
struct file_operations bpfs_dir_fops = {
    read:        generic_read_dir,
    readdir:     bpfs_readdir,
};

static
struct inode_operations bpfs_dir_iops = {
    getattr:     bpfs_inode_getattr,
    lookup:	 bpfs_node_lookup,
};

static
struct inode_operations bpfs_node_iops = {
    getattr:     bpfs_inode_getattr,
    setattr:     bpfs_node_setattr,

    getxattr:    bpfs_node_getxattr,
    setxattr:    bpfs_node_setxattr,
    listxattr:   bpfs_node_listxattr,
    removexattr: bpfs_node_removexattr
};

static
struct inode_operations bpfs_status_iops = {
    getattr:     bpfs_inode_getattr,
    setattr:     bpfs_node_setattr,
};

static
struct inode_operations bpfs_node_slave_iops = {
    getattr:     bpfs_inode_getattr,
    setattr:     bpfs_node_setattr,

    getxattr:    bpfs_node_slave_getxattr,
    setxattr:    bpfs_node_slave_setxattr,
    listxattr:   bpfs_node_slave_listxattr,
    removexattr: bpfs_node_slave_removexattr
};

static
struct inode_operations bpfs_self_iops = {
    getattr:     bpfs_inode_getattr,
    follow_link: bpfs_self_follow_link,
    readlink:    bpfs_self_readlink,
};

static
struct file_operations bpfs_status_fops = {
    open:        bpfs_status_file_open,
    release:     bpfs_status_file_release,
    read:        bpfs_status_file_read,
    poll:        bpfs_status_file_poll,
};

static
struct dentry_operations bpfs_node_dentry_operations_m = {
    d_revalidate: bpfs_file_dentry_revalidate_m,
};

static
struct dentry_operations bpfs_node_dentry_operations_s = {
    d_revalidate: bpfs_file_dentry_revalidate_s,
};

/*-------------------------------------------------------------------------
 * bpfs special file stuff
 *-----------------------------------------------------------------------*/

/* This is a weird "lookup" like thing that gets the dentry for the
 * inode in our kernel-based bogo-fs world. */
static
struct dentry *get_dentry(struct vfsmount *mount, 
			  struct inode *inode, char *name_) {
    struct dentry *parent, *dentry;
    struct qstr name = { .name = name_,
			 .len  = strlen(name_),
			 .hash = 0};	/* screw the hash... */

    parent = mount->mnt_root;

    down(&inode->i_sem);
    dentry = d_lookup(parent, &name);
    if (dentry) {
	/* Dentry already exists - put the inode back and return the dentry */
	up(&inode->i_sem);
	iput(inode);
    } else {
	/* No dentry yet.  Make a new one with this inode */
	dentry = d_alloc(parent, &name);
	if (dentry)
	    d_add(dentry, inode);
    }
    up(&inode->i_sem);
    return dentry;
}

/* This function spits out file pointers for the BProc magic file
 * types.  Each new open magic file type gets its own kernel mount.
 * This fixes a reference counting problem on the module with
 * get_sb_single().  The problem is that the user space mount should
 * count as a reference and any kernel uses should not be a reference.
 * By having a mount for every open file allows the kernel to
 * automagically dispose of mounts when the file gets closed.  Thanks
 * to get_sb_single, this also happens to be reasonably cheap. */
struct file *bpfs_get_file(enum bpfs_inode ino, char *name) {
    struct file   *file;
    struct inode  *inode;
    struct dentry *dentry;
    struct vfsmount *mount;

    mount = kern_mount(&bprocfs_type);
    if (IS_ERR(mount))
	return (struct file *) mount;

    /* Start by getting the inode we want */
    inode = bpfs_get_inode(mount->mnt_sb, ino);
    if (!inode) {
	mntput(mount);
	return ERR_PTR(-ENOMEM);
    }

    /* Get the dentry for that inode */
    dentry = get_dentry(mount, inode, name);
    if (!dentry) {
	iput(inode);
	mntput(mount);
	return ERR_PTR(-ENOMEM);
    }

    /* dentry_open does dput + mntput on failure */
    file = dentry_open(dentry, mount, O_RDWR);
    return file;
}

/* It would probably me more appropriate to use FS_SINGLE as a flag
 * argument here.  However, there's a problem with that - it does not
 * increment the module use count every time it is mounted.  Since we
 * are doing a kern_mount the reference count will always be one so we
 * have two options with FS_SINGLE:
 *
 * - MOD_DEC_USE_COUNT after kern_mount and normal mounts after that
 *   will not be counted.
 * - Leave the use count alone and the reference count bproc will
 *   always be 1 and we'll never be able to unload the module.
 *
 * Therefore, even though it's potentially wasteful, we will not be
 * using FS_SINGLE here....
 */

/*DECLARE_FSTYPE(bprocfs_type, "bpfs", bprocfs_read_super, 0);*/


struct file_system_type bprocfs_type = {
    .name    = "bpfs",
    .get_sb  = bprocfs_get_sb,
    .kill_sb = kill_anon_super,
    .owner   = THIS_MODULE
};


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
