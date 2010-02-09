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
	int openmode, flags, err;

	in = m->tx;
	flags = in->flags;
	openmode = flags&3;
	if(flags){
		fprintf(stderr, "unexpected open flags 0%uo", (unsigned int)in->flags);
		replyfuseerrno(m, EACCES);
		return;
	}
	replyfuse(m, &out, sizeof out);
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
		attr->ino = 1;
		attr->size = 1;
		attr->blocks = (1)/8192;
		attr->atime = 0;
		attr->mtime = 0;
		attr->ctime = 0;
		attr->atimensec = 0;
		attr->mtimensec = 0;
		attr->ctimensec = 0;
		attr->mode = S_IFDIR|0755;
		attr->nlink = 1;	/* works for directories! - see FUSE FAQ */
		attr->uid = 0;
		attr->gid = 0;
		attr->rdev = 0;
	} else {
		replyfuseerrstr(m);
		return;
	}

	f2timeout(1.0, &out.attr_valid, &out.attr_valid_nsec);
	f2timeout(1.0, &out.entry_valid, &out.entry_valid_nsec);
	replyfuse(m, &out, sizeof out);
}

void (*fusehandlers[100])(FuseMsg*);

struct {
	int op;
	void (*fn)(FuseMsg*);
} fuselist[] = {
	{ FUSE_STATFS,		fusestatfs },
	{ FUSE_OPENDIR,		fuseopendir },
	{ FUSE_LOOKUP,		fuselookup },
#if 0
	{ FUSE_FORGET,		fuseforget },
	{ FUSE_GETATTR,		fusegetattr },
	{ FUSE_SETATTR,		fusesetattr },
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
	{ FUSE_RELEASE,		fuserelease },
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
	{ FUSE_READDIR,		fusereaddir },
	{ FUSE_RELEASEDIR,	fusereleasedir },
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

