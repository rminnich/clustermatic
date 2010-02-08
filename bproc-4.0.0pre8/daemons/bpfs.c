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

void (*fusehandlers[100])(FuseMsg*);

struct {
	int op;
	void (*fn)(FuseMsg*);
} fuselist[] = {
#if 0
	{ FUSE_LOOKUP,		fuselookup },
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
	{ FUSE_STATFS,		fusestatfs },
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
	{ FUSE_OPENDIR,		fuseopendir },
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

	if (first) {
		first = 0;
		atexit(unmountatexit);	

		for(i=0; i<nelem(fuselist); i++){
				if(fuselist[i].op >= nelem(fusehandlers))
			sysfatal("make fusehandlers bigger op=%d", fuselist[i].op);
			fusehandlers[fuselist[i].op] = fuselist[i].fn;
		}
	}

	m = v;
	if((unsigned int)m->hdr->opcode >= nelem(fusehandlers) 
	|| !fusehandlers[m->hdr->opcode]){
		replyfuseerrno(m, ENOSYS);
		return;
	}
	fusehandlers[m->hdr->opcode](m);
}

