/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif
#define nelem(x) (sizeof(x)/sizeof(x[0]))
#include "a.h"

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	DIR *dp;
	struct dirent *de;
	int res = 0;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		res = filler(h, de->d_name, de->d_type);
		if (res != 0)
			break;
	}

	closedir(dp);
	return res;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utime(const char *path, struct utimbuf *buf)
{
	int res;

	res = utime(path, buf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, int flags)
{
	int res;

	res = open(path, flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset)
{
	int fd;
	int res;

	return -1;
}

#if 0
friggin example code fails. great. 
static int xmp_statfs(struct fuse_statfs *fst)
{
    struct statfs st;
    int rv = statfs("/",&st);
    if(!rv) {
    	fst->block_size  = st.f_bsize;
    	fst->blocks      = st.f_blocks;
    	fst->blocks_free = st.f_bavail;
    	fst->files       = st.f_files;
    	fst->files_free  = st.f_ffree;
    	fst->namelen     = st.f_namelen;
    }
    return rv;
}
#endif

static int xmp_release(const char *path, int flags)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) flags;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    return 0;
}

void
f2timeout(double f, __u64 *s, __u32 *ns)
{
	*s = f;
	*ns = (f - (int)f)*1e9;
}


/*
 * Statfs.  Send back information about file system.
 * Not really worth implementing, except that if we
 * reply with ENOSYS, programs like df print messages like
 *   df: `/tmp/z': Function not implemented
 * and that gets annoying.  Returning all zeros excludes
 * us from df without appearing to cause any problems.
 */
void
fusestatfs(FuseMsg *m)
{
	struct fuse_statfs_out out;
	
	memset(&out, 0, sizeof out);
	replyfuse(m, &out, sizeof out);
}

void
fuseopendir(FuseMsg *m)
{
	struct fuse_open_in *in;
	struct fuse_open_out out;

	in = m->tx;
	if (m->hdr->nodeid == 1) {
		out.fh = 1;
	} else {
		replyfuseerrno(m, ENOENT);
		return;
	}
	replyfuse(m, &out, sizeof out);
}

void
fillattr(__u64  inode, struct fuse_attr *attr)
{
	memset(attr, 0, sizeof attr);

	if (inode == 1) {
		attr->ino = 1;
		attr->size = 1;
		attr->blocks = (1)/8192;
		attr->atime = 0;
		attr->mtime = 0;
		attr->ctime = 0;
		attr->atimensec = 0;
		attr->mtimensec = 0;
		attr->ctimensec = 0;
		attr->mode = S_IFDIR|0555;
		attr->nlink = 1;	/* works for directories! - see FUSE FAQ */
		attr->uid = 0;
		attr->gid = 0;
		attr->rdev = 0;
	}
	if (inode == 2) {
		attr->ino = 2;
		attr->size = 1;
		attr->blocks = (1)/8192;
		attr->atime = 0;
		attr->mtime = 0;
		attr->ctime = 0;
		attr->atimensec = 0;
		attr->mtimensec = 0;
		attr->ctimensec = 0;
		attr->mode = S_IFDIR|0555;
		attr->nlink = 1;	/* works for directories! - see FUSE FAQ */
		attr->uid = 0;
		attr->gid = 0;
		attr->rdev = 0;
	}
	if (inode == 3) {
		attr->ino = 3;
		attr->size = 1;
		attr->blocks = (1)/8192;
		attr->atime = 0;
		attr->mtime = 0;
		attr->ctime = 0;
		attr->atimensec = 0;
		attr->mtimensec = 0;
		attr->ctimensec = 0;
		attr->mode = S_IFREG|0444;
		attr->nlink = 1;	/* works for directories! - see FUSE FAQ */
		attr->uid = 0;
		attr->gid = 0;
		attr->rdev = 0;
	}
	if (inode & 0x100000) {
		attr->ino = inode;
		attr->size = 1;
		attr->blocks = (1)/8192;
		attr->atime = 0;
		attr->mtime = 0;
		attr->ctime = 0;
		attr->atimensec = 0;
		attr->mtimensec = 0;
		attr->ctimensec = 0;
		attr->mode = S_IFREG|0444;
		attr->nlink = 1;	/* works for directories! - see FUSE FAQ */
		attr->uid = 0;
		attr->gid = 0;
		attr->rdev = 0;
	}
}

int
nodenum(char *name)
{
	int i;
	for(i = 0; i < strlen(name); i++)
		if (! isdigit(name[i]))
			return -1;

	i = strtoul(name, 0, 10);

	i = bprocnode(i);
	return i;
}
/*
 * Lookup.  Walk to the name given as the argument.
 * The response is a fuse_entry_out giving full stat info.
 */
void
fuselookup(FuseMsg *m)
{
	char *name;
	struct fuse_entry_out out;
	struct fuse_attr *attr;
	int node;

	name = m->tx;
	if(strchr(name, '/')){
		replyfuseerrno(m, ENOENT);
		return;
	}
	/* bpfs directory is 1. 
	 * bpfs status file is 2. 
	 * bproc nodes have id with bit 30 set.
	 */
	if (strcmp(name, ".") == 0) {
		out.nodeid = 1;
		out.generation = 1;
		attr = &out.attr;
		fillattr(1, attr);
	} else if (strcmp(name, "..") == 0) {
		out.nodeid = 1;
		out.generation = 1;
		attr = &out.attr;
		fillattr(2, attr);
	} else if (strcmp(name, "status") == 0) {
		out.nodeid = 3;
		out.generation = 1;
		attr = &out.attr;
		fillattr(3, attr);
	} else if ((node = nodenum(name)) > -1) {
		out.nodeid = node | 0x100000;
		out.generation = 1;
		attr = &out.attr;
		fillattr(out.nodeid, attr);
	} else {
		replyfuseerrstr(m);
		return;
	}

	f2timeout(1.0, &out.attr_valid, &out.attr_valid_nsec);
	f2timeout(1.0, &out.entry_valid, &out.entry_valid_nsec);
	replyfuse(m, &out, sizeof out);
}
/*
 * Setattr.
 * FUSE treats the many Unix attribute setting routines
 * more or less like 9P does, with a single message.
 */
void
fusesetattr(FuseMsg *m)
{
	struct fuse_setattr_in *in;
	struct fuse_attr_out out;
	int node = m->hdr->nodeid;
	int ok = FATTR_UID | FATTR_GID;

	/* we can only change node attributes */

	if (! (node & 0x100000)){
		replyfuseerrno(m, ESTALE);
		return;
	}

	node &= ~0x100000;
	if (bprocnode(node) < 0) {
		replyfuseerrno(m, ESTALE);
		return;
	}
#if 0
	if(in->valid&FATTR_SIZE)
		d.length = in->size;
	if(in->valid&FATTR_ATIME)
		d.atime = in->atime;
	if(in->valid&FATTR_MTIME)
		d.mtime = in->mtime;
	if(in->valid&FATTR_MODE)
		d.mode = in->mode;
#endif

	if (in->valid & (~ ok)) {
		replyfuseerrno(m, EPERM);
		return;
	}

	if (in->valid&FATTR_UID)
		bprocuid(node, in->uid);

	if (in->valid&FATTR_GID){
		bprocgid(node, in->gid);
	}

stat:
	memset(&out, 0, sizeof out);
	fillattr(m->hdr->nodeid, &out.attr);
	replyfuse(m, &out, sizeof out);
}
/*
 * Getattr.
 * Replies with a fuse_attr_out structure giving the
 * attr for the requested nodeid in out.attr.
 * Out.attr_valid and out.attr_valid_nsec give 
 * the amount of time that the attributes can
 * be cached.
 *
 * Empirically, though, if I run ls -ld on the root
 * twice back to back, I still get two getattrs,
 * even with a one second attribute timeout!
 */
void
fusegetattr(FuseMsg *m)
{
	struct fuse_attr_out out;
printf("fusegetattr\n");
	out.attr_valid = 5;
	out.attr_valid_nsec = 0;
	fillattr(m->hdr->nodeid, &out.attr);
printf("reply!\n");
	replyfuse(m, &out, sizeof out);
}
/*
 * Fuse assumes that it can always read two directory entries.
 * If it gets just one, it will double it in the dirread results.
 * Thus if a directory contains just "a", you see "a" twice.
 * Adding . as the first directory entry works around this.
 */

static int
canpack(char *name, int ino, unsigned long long off, unsigned char **pp, unsigned char *ep)
{
	unsigned char *p;
	struct fuse_dirent *de;
	int pad, size;
	
	p = *pp;
	size = sizeof(struct fuse_dirent) - 1 + strlen(name);
	pad = 0;
	if(size%8)
		pad = 8 - size%8;
	if(size+pad > ep - p)
		return 0;
	de = (struct fuse_dirent*)p;
	de->ino = ino;
	de->off = off;
	de->namelen = strlen(name);
	memmove(de->name, name, de->namelen);
	if(pad > 0)
		memset(de->name+de->namelen, 0, pad);
	*pp = p+size+pad;
	return 1;
}


/* 
 * Readdir.
 * Read from file handle in->fh at offset in->offset for size in->size.
 * We truncate size to maxwrite just to keep the buffer reasonable.
 * We assume 9P directory read semantics: a read at offset 0 rewinds
 * and a read at any other offset starts where we left off.
 * If it became necessary, we could implement a crude seek
 * or cache the entire list of directory entries.
 * Directory entries read from 9P but not yet handed to FUSE
 * are stored in m->d,nd,d0.
 */

void
fusereaddir(FuseMsg *m)
{
	struct fuse_read_in *in;
	unsigned char *buf, *p, *ep;
	int n;
	int bprocnode(int node);
	unsigned long long i;;
	unsigned long long offset;
	char bname[256];
	
	in = m->tx;
	if(in->fh != 1){
		replyfuseerrno(m, ESTALE);
		return;
	}	
	n = in->size;
	if(n > fusemaxwrite)
		n = fusemaxwrite;
	buf = calloc(1, n);
	p = buf;
	ep = buf + n;
	offset = in->offset;
	if(offset == 0){
		if (! canpack(".", 1, ++offset, &p, ep)) {
			replyfuseerrno(m, ESTALE);
			return;
		}
	}
	if (offset == 1) {
		if (! canpack("..", 1, ++offset, &p, ep)) {
			replyfuseerrno(m, ESTALE);
			return;
		}
		goto out;
	}
	if (offset == 2) {
		if (!canpack("status", 3, ++offset, &p, ep)) {
			replyfuseerrno(m, ESTALE);
			return;
		}
		goto out;
	}
	if (offset > 2) {
	/* if we put other nodes in here we need to change the 2 below */
		while (1) {
		int node = offset-3;
		int bpnode;
		bpnode = bprocnode(node);
		if (bpnode < 0)
			break;
		snprintf(bname, sizeof(bname), "%d",bpnode);
		if (!canpack(bname, (int)0x100000|bpnode, ++offset, &p, ep))
			break;
	}
	}
out:			
	replyfuse(m, buf, p - buf);
	free(buf);
}
/*
 * Release.
 *
 * in->flags is the open mode used in Open or Opendir.
 */
void
fuserelease(FuseMsg *m)
{
	//struct fuse_release_in *in;
	replyfuse(m, NULL, 0);
}

void
fusereleasedir(FuseMsg *m)
{
	fuserelease(m);
}


void (*fusehandlers[100])(FuseMsg*);

struct {
	int op;
	void (*fn)(FuseMsg*);
} fuselist[] = {
	{ FUSE_STATFS,		fusestatfs },
	{ FUSE_OPENDIR,		fuseopendir },
	{ FUSE_LOOKUP,		fuselookup },
	{ FUSE_GETATTR,		fusegetattr },
	{ FUSE_READDIR,		fusereaddir },
	{ FUSE_RELEASEDIR,	fusereleasedir },
	{ FUSE_RELEASE,		fuserelease },
	{ FUSE_SETATTR,		fusesetattr },
#if 0
	{ FUSE_FORGET,		fuseforget },
	/*
	 * FUSE_SYMLINK, FUSE_MKNOD are unimplemented.
	 */
	{ FUSE_READLINK,	fusereadlink },
	{ FUSE_MKDIR,		fusemkdir },
	{ FUSE_UNLINK,		fuseunlink },
	{ FUSE_RMDIR,		fusermdir },
	{ FUSE_RENAME,		fuserename },
	/*
	 * FUSE_LINK is unimplemented.
	 */
	{ FUSE_OPEN,		fuseopen },
	{ FUSE_READ,		fuseread },
	{ FUSE_WRITE,		fusewrite },
	{ FUSE_FSYNC,		fusefsync },
	/*
	 * FUSE_SETXATTR, FUSE_GETXATTR, FUSE_LISTXATTR, and
	 * FUSE_REMOVEXATTR are unimplemented. 
	 * FUSE will stop sending these requests after getting
	 * an -ENOSYS reply (see dispatch below).
	 */
	{ FUSE_FLUSH,		fuseflush },
	/*
	 * FUSE_INIT is handled in initfuse and should not be seen again.
	 */
	{ FUSE_FSYNCDIR,	fusefsyncdir },
	{ FUSE_ACCESS,		fuseaccess },
	{ FUSE_CREATE,		fusecreate },
#endif
};

void
fusedispatch(void *v)
{
	int i;
	FuseMsg *m;
	static int first = 1;
	m = v;
fprintf(stderr, "fusedispatch: op %d\n", m->hdr->opcode);
	if (first) {
		first = 0;
		atexit(unmountatexit);	

		for(i=0; i<nelem(fuselist); i++){
			if(fuselist[i].op >= nelem(fusehandlers))
				sysfatal("make fusehandlers bigger op=%d", fuselist[i].op);
			fusehandlers[fuselist[i].op] = fuselist[i].fn;
		}
	}

	if((unsigned int)m->hdr->opcode >= nelem(fusehandlers) 
		|| !fusehandlers[m->hdr->opcode]){
		fprintf(stderr, "UNIMPLEMENTED %d\n", m->hdr->opcode);
		replyfuseerrno(m, ENOSYS);
		return;
	}
	fusehandlers[m->hdr->opcode](m);
}

