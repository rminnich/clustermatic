#include "a.h"

int fusefd;
int fuseeof;
int fusebufsize;
int fusemaxwrite;
FuseMsg *fusemsglist;
int debug = 1;

int mountfuse(char *mtpt);
void unmountfuse(char *mtpt);

void sysfatal(char *msg)
{
	perror(msg);
	exit(1);
}

FuseMsg *allocfusemsg(void)
{
	FuseMsg *m;
	void *vbuf;

	m = malloc(sizeof(*m) + fusebufsize);
	vbuf = m + 1;
	m->buf = vbuf;
	m->nbuf = 0;
	m->hdr = vbuf;
	m->tx = m->hdr + 1;
	return m;
}

void freefusemsg(FuseMsg * m)
{
	free(m);
}

FuseMsg *readfusemsg(void)
{
	FuseMsg *m;
	int n, nn;

	m = allocfusemsg();
	errno = 0;
	/*
	 * The FUSE kernel device apparently guarantees
	 * that this read will return exactly one message.
	 * You get an error return if you ask for just the
	 * length (first 4 bytes).
	 * FUSE returns an ENODEV error, not EOF,
	 * when the connection is unmounted.
	 */
	if ((n = read(fusefd, m->buf, fusebufsize)) < 0) {
		if (errno != ENODEV)
			sysfatal("readfusemsg");
	}
	if (n <= 0) {
		fuseeof = 1;
		freefusemsg(m);
		return NULL;
	}
	m->nbuf = n;

	/*
	 * FreeBSD FUSE sends a short length in the header
	 * for FUSE_INIT even though the actual read length
	 * is correct.
	 */
	if (n == sizeof(*m->hdr) + sizeof(struct fuse_init_in)
	    && m->hdr->opcode == FUSE_INIT && m->hdr->len < n)
		m->hdr->len = n;

	if (m->hdr->len != n) {
		fprintf(stderr, "readfusemsg: got %d wanted %ld",
			(int)n, m->hdr->len);
		exit(1);
	}
	m->hdr->len -= sizeof(*m->hdr);

	/*
	 * Paranoia.
	 * Make sure lengths are long enough.
	 * Make sure string arguments are NUL terminated.
	 * (I don't trust the kernel module.)
	 */
	switch (m->hdr->opcode) {
	default:
		/*
		 * Could sysfatal here, but can also let message go
		 * and assume higher-level code will return an
		 * "I don't know what you mean" error and recover.
		 */
		break;
	case FUSE_LOOKUP:
	case FUSE_UNLINK:
	case FUSE_RMDIR:
	case FUSE_REMOVEXATTR:
		/* just a string */
		if (((char *)m->tx)[m->hdr->len - 1] != 0)
		      bad:
			sysfatal("readfusemsg: bad message");
		break;
	case FUSE_FORGET:
		if (m->hdr->len < sizeof(struct fuse_forget_in))
			goto bad;
		break;
	case FUSE_GETATTR:
		break;
	case FUSE_SETATTR:
		if (m->hdr->len < sizeof(struct fuse_setattr_in))
			goto bad;
		break;
	case FUSE_READLINK:
		break;
	case FUSE_SYMLINK:
		/* two strings */
		if (((char *)m->tx)[m->hdr->len - 1] != 0
		    || memchr(m->tx, 0, m->hdr->len - 1) == 0)
			goto bad;
		break;
	case FUSE_MKNOD:
		if (m->hdr->len <= sizeof(struct fuse_mknod_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0)
			goto bad;
		break;
	case FUSE_MKDIR:
		if (m->hdr->len <= sizeof(struct fuse_mkdir_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0)
			goto bad;
		break;
	case FUSE_RENAME:
		/* a struct and two strings */
		if (m->hdr->len <= sizeof(struct fuse_rename_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0
		    || memchr((unsigned char *)m->tx +
			      sizeof(struct fuse_rename_in), 0,
			      m->hdr->len - sizeof(struct fuse_rename_in) -
			      1) == 0)
			goto bad;
		break;
	case FUSE_LINK:
		if (m->hdr->len <= sizeof(struct fuse_link_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0)
			goto bad;
		break;
	case FUSE_OPEN:
	case FUSE_OPENDIR:
		if (m->hdr->len < sizeof(struct fuse_open_in))
			goto bad;
		break;
	case FUSE_READ:
	case FUSE_READDIR:
		if (m->hdr->len < sizeof(struct fuse_read_in))
			goto bad;
		break;
	case FUSE_WRITE:
		/* no strings, but check that write length is sane */
		if (m->hdr->len <
		    sizeof(struct fuse_write_in) +
		    ((struct fuse_write_in *)m->tx)->size)
			goto bad;
		break;
	case FUSE_STATFS:
		break;
	case FUSE_RELEASE:
	case FUSE_RELEASEDIR:
		if (m->hdr->len < sizeof(struct fuse_release_in))
			goto bad;
		break;
	case FUSE_FSYNC:
	case FUSE_FSYNCDIR:
		if (m->hdr->len < sizeof(struct fuse_fsync_in))
			goto bad;
		break;
	case FUSE_SETXATTR:
		/* struct, one string, and one binary blob */
		if (m->hdr->len <= sizeof(struct fuse_setxattr_in))
			goto bad;
		nn = ((struct fuse_setxattr_in *)m->tx)->size;
		if (m->hdr->len < sizeof(struct fuse_setxattr_in) + nn + 1)
			goto bad;
		if (((char *)m->tx)[m->hdr->len - nn - 1] != 0)
			goto bad;
		break;
	case FUSE_GETXATTR:
		/* struct and one string */
		if (m->hdr->len <= sizeof(struct fuse_getxattr_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0)
			goto bad;
		break;
	case FUSE_LISTXATTR:
		if (m->hdr->len < sizeof(struct fuse_getxattr_in))
			goto bad;
		break;
	case FUSE_FLUSH:
		if (m->hdr->len < sizeof(struct fuse_flush_in))
			goto bad;
		break;
	case FUSE_INIT:
		if (m->hdr->len < sizeof(struct fuse_init_in))
			goto bad;
		break;
	case FUSE_ACCESS:
		if (m->hdr->len < sizeof(struct fuse_access_in))
			goto bad;
		break;
	case FUSE_CREATE:
		if (m->hdr->len <= sizeof(struct fuse_open_in)
		    || ((char *)m->tx)[m->hdr->len - 1] != 0)
			goto bad;
		break;
	}
	if (debug) {
		fprintf(stderr, "FUSE -> ");
		fusedumpreq(stderr, m->hdr, m->tx);
	}
	return m;
}

/*
 * Reply to FUSE request m using additonal 
 * argument buffer arg of size narg bytes.
 * Perhaps should free the FuseMsg here?
 */
void replyfuse(FuseMsg * m, void *arg, int narg)
{
	struct iovec vec[2];
	struct fuse_out_header hdr;
	int nvec;

	hdr.len = sizeof hdr + narg;
	hdr.error = 0;
	hdr.unique = m->hdr->unique;
	if (debug) {
		fprintf(stderr, "FUSE <- ");
		fusedumpresp(stderr, m->hdr, &hdr, arg);
	}

	vec[0].iov_base = &hdr;
	vec[0].iov_len = sizeof hdr;
	nvec = 1;
	if (arg && narg) {
		vec[1].iov_base = arg;
		vec[1].iov_len = narg;
		nvec++;
	}
	writev(fusefd, vec, nvec);
	freefusemsg(m);
}

/*
 * Reply to FUSE request m with errno e.
 */
void replyfuseerrno(FuseMsg * m, int e)
{
	struct fuse_out_header hdr;

	hdr.len = sizeof hdr;
	hdr.error = -e;		/* FUSE sends negative errnos. */
	hdr.unique = m->hdr->unique;
	if (debug) {
		fprintf(stderr, "FUSE <- ");
		fusedumpresp(stderr, m->hdr, &hdr, 0);
	}
	write(fusefd, &hdr, sizeof hdr);
	freefusemsg(m);
}

void replyfuseerrstr(FuseMsg * m)
{
	replyfuseerrno(m, errno);
}

char *fusemtpt;
void unmountatexit(void)
{
	if (fusemtpt)
		unmountfuse(fusemtpt);
}

void initfuse(char *mtpt)
{
	FuseMsg *m;
	struct fuse_init_in *tx;
	struct fuse_init_out rx;

	fusemtpt = mtpt;

	/*
	 * The 4096 is for the message headers.
	 * It's a lot, but it's what the FUSE libraries ask for.
	 */
	fusemaxwrite = getpagesize();
	fusebufsize = 4096 + fusemaxwrite;

	if ((fusefd = mountfuse(mtpt)) < 0)
		sysfatal("mountfuse");

	if ((m = readfusemsg()) == NULL)
		sysfatal("readfusemsg");
	if (m->hdr->opcode != FUSE_INIT) {
		fprintf(stderr, "fuse: expected FUSE_INIT (26) got %d",
			(int)m->hdr->opcode);
		sysfatal("Fuse init");
	}
	tx = m->tx;

	/*
	 * Complain if the kernel is too new.
	 * We could forge ahead, but at least the one time I tried,
	 * the kernel rejected the newer version by making the 
	 * writev fail in replyfuse, which is a much more confusing
	 * error message.  In the future, might be nice to try to 
	 * support older versions that differ only slightly.
	 */
	if (tx->major < FUSE_KERNEL_VERSION
	    || (tx->major == FUSE_KERNEL_VERSION
		&& tx->minor < FUSE_KERNEL_MINOR_VERSION)) {
		fprintf(stderr,
			"fuse: too kernel version %ld.%ld older than program version %d.%d",
			tx->major, tx->minor, FUSE_KERNEL_VERSION,
			FUSE_KERNEL_MINOR_VERSION);
		sysfatal("KERNEL VERSION");
	}

	memset(&rx, 0, sizeof rx);
	rx.major = FUSE_KERNEL_VERSION;
	rx.minor = FUSE_KERNEL_MINOR_VERSION;
	rx.max_write = fusemaxwrite;
	replyfuse(m, &rx, sizeof rx);
}

/*
 * Print FUSE messages.  Assuming it is installed as %G,
 * use %G with hdr, arg arguments to format a request,
 * and %#G with reqhdr, hdr, arg arguments to format a response.
 * The reqhdr is necessary in the %#G form because the
 * response does not contain an opcode tag.
 */
int fusedumpreq(FILE * f, struct fuse_in_header *hdr, void *a)
{				/* "%G", hdr, arg */
	fprintf(f, "len %ld unique 0x%llux uid %ld gid %ld pid %ld ",
		hdr->len, hdr->unique, hdr->uid, hdr->gid, hdr->pid);

	switch (hdr->opcode) {
	default:{
			fprintf(f, "??? opcode %ld", hdr->opcode);
			break;
		}
	case FUSE_LOOKUP:{
			fprintf(f, "Lookup nodeid 0x%llux name %p",
				hdr->nodeid, a);
			break;
		}
	case FUSE_FORGET:{
			struct fuse_forget_in *tx = a;
			/* nlookup (a ref count) is a vlong! */
			fprintf(f, "Forget nodeid 0x%llux nlookup %lld",
				hdr->nodeid, tx->nlookup);
			break;
		}
	case FUSE_GETATTR:{
			fprintf(f, "Getattr nodeid 0x%llux", hdr->nodeid);
			break;
		}
	case FUSE_SETATTR:{
			struct fuse_setattr_in *tx = a;
			fprintf(f, "Setattr nodeid 0x%llux", hdr->nodeid);
			if (tx->valid & FATTR_FH)
				fprintf(f, " fh 0x%llux", tx->fh);
			if (tx->valid & FATTR_SIZE)
				fprintf(f, " size %lld", tx->size);
			if (tx->valid & FATTR_ATIME)
				fprintf(f, " atime %.20g",
					tx->atime + tx->atimensec * 1e-9);
			if (tx->valid & FATTR_MTIME)
				fprintf(f, " mtime %.20g",
					tx->mtime + tx->mtimensec * 1e-9);
			if (tx->valid & FATTR_MODE)
				fprintf(f, " mode 0%luo", tx->mode);
			if (tx->valid & FATTR_UID)
				fprintf(f, " uid %ld", tx->uid);
			if (tx->valid & FATTR_GID)
				fprintf(f, " gid %ld", tx->gid);
			break;
		}
	case FUSE_READLINK:{
			fprintf(f, "Readlink nodeid 0x%llux", hdr->nodeid);
			break;
		}
	case FUSE_SYMLINK:{
			char *old, *new;

			old = a;
			new = a + strlen(a) + 1;
			fprintf(f, "Symlink nodeid 0x%llux old %p new %p",
				hdr->nodeid, old, new);
			break;
		}
	case FUSE_MKNOD:{
			struct fuse_mknod_in *tx = a;
			fprintf(f,
				"Mknod nodeid 0x%llux mode 0%luo rdev 0x%lux name %p",
				hdr->nodeid, tx->mode, tx->rdev, tx + 1);
			break;
		}
	case FUSE_MKDIR:{
			struct fuse_mkdir_in *tx = a;
			fprintf(f, "Mkdir nodeid 0x%llux mode 0%luo name %p",
				hdr->nodeid, tx->mode, tx + 1);
			break;
		}
	case FUSE_UNLINK:{
			fprintf(f, "Unlink nodeid 0x%llux name %p",
				hdr->nodeid, a);
			break;
		}
	case FUSE_RMDIR:{
			fprintf(f, "Rmdir nodeid 0x%llux name %p",
				hdr->nodeid, a);
			break;
		}
	case FUSE_RENAME:{
			struct fuse_rename_in *tx = a;
			char *old = (char *)(tx + 1);
			char *new = old + strlen(old) + 1;
			fprintf(f,
				"Rename nodeid 0x%llux old %p newdir 0x%llux new %p",
				hdr->nodeid, old, tx->newdir, new);
			break;
		}
	case FUSE_LINK:{
			struct fuse_link_in *tx = a;
			fprintf(f,
				"Link oldnodeid 0x%llux nodeid 0x%llux name %p",
				tx->oldnodeid, hdr->nodeid, tx + 1);
			break;
		}
	case FUSE_OPEN:{
			struct fuse_open_in *tx = a;
			/* Should one or both of flags and mode be octal? */
			fprintf(f,
				"Open nodeid 0x%llux flags 0x%lux mode 0x%lux",
				hdr->nodeid, tx->flags, tx->mode);
			break;
		}
	case FUSE_READ:{
			struct fuse_read_in *tx = a;
			fprintf(f,
				"Read nodeid 0x%llux fh 0x%llux offset %lld size %lud",
				hdr->nodeid, tx->fh, tx->offset, tx->size);
			break;
		}
	case FUSE_WRITE:{
			struct fuse_write_in *tx = a;
			fprintf(f,
				"Write nodeid 0x%llux fh 0x%llux offset %lld size %lud flags 0x%lux",
				hdr->nodeid, tx->fh, tx->offset, tx->size,
				tx->write_flags);
			break;
		}
	case FUSE_STATFS:{
			fprintf(f, "Statfs");
			break;
		}
	case FUSE_RELEASE:{
			struct fuse_release_in *tx = a;
			fprintf(f,
				"Release nodeid 0x%llux fh 0x%llux flags 0x%lux",
				hdr->nodeid, tx->fh, tx->flags);
			break;
		}
	case FUSE_FSYNC:{
			struct fuse_fsync_in *tx = a;
			fprintf(f,
				"Fsync nodeid 0x%llux fh 0x%llux flags 0x%lux",
				hdr->nodeid, tx->fh, tx->fsync_flags);
			break;
		}
	case FUSE_SETXATTR:{
			struct fuse_setxattr_in *tx = a;
			char *name = (char *)(tx + 1);
			char *value = name + strlen(name) + 1;
			fprintf(f,
				"Setxattr nodeid 0x%llux size %ld flags 0x%lux name %p value %p",
				hdr->nodeid, tx->size, tx->flags, name, value);
			break;
		}
	case FUSE_GETXATTR:{
			struct fuse_getxattr_in *tx = a;
			fprintf(f, "Getxattr nodeid 0x%llux size %ld name %p",
				hdr->nodeid, tx->size, tx + 1);
			break;
		}
	case FUSE_LISTXATTR:{
			struct fuse_getxattr_in *tx = a;
			fprintf(f, "Listxattr nodeid 0x%llux size %ld",
				hdr->nodeid, tx->size);
			break;
		}
	case FUSE_REMOVEXATTR:{
			fprintf(f, "Removexattr nodeid 0x%llux name %p",
				hdr->nodeid, a);
			break;
		}
	case FUSE_FLUSH:{
			struct fuse_flush_in *tx = a;
			fprintf(f,
				"Flush nodeid 0x%llux fh 0x%llux flags 0x%lux",
				hdr->nodeid, tx->fh, tx->flush_flags);
			break;
		}
	case FUSE_INIT:{
			struct fuse_init_in *tx = a;
			fprintf(f, "Init major %ld minor %ld",
				tx->major, tx->minor);
			break;
		}
	case FUSE_OPENDIR:{
			struct fuse_open_in *tx = a;
			fprintf(f,
				"Opendir nodeid 0x%llux flags 0x%lux mode 0x%lux",
				hdr->nodeid, tx->flags, tx->mode);
			break;
		}
	case FUSE_READDIR:{
			struct fuse_read_in *tx = a;
			fprintf(f,
				"Readdir nodeid 0x%llux fh 0x%llux offset %lld size %lud",
				hdr->nodeid, tx->fh, tx->offset, tx->size);
			break;
		}
	case FUSE_RELEASEDIR:{
			struct fuse_release_in *tx = a;
			fprintf(f,
				"Releasedir nodeid 0x%llux fh 0x%llux flags 0x%lux",
				hdr->nodeid, tx->fh, tx->flags);
			break;
		}
	case FUSE_FSYNCDIR:{
			struct fuse_fsync_in *tx = a;
			fprintf(f,
				"Fsyncdir nodeid 0x%llux fh 0x%llux flags 0x%lux",
				hdr->nodeid, tx->fh, tx->fsync_flags);
			break;
		}
	case FUSE_ACCESS:{
			struct fuse_access_in *tx = a;
			fprintf(f, "Access nodeid 0x%llux mask 0x%lux",
				hdr->nodeid, tx->mask);
			break;
		}
	case FUSE_CREATE:{
			struct fuse_open_in *tx = a;
			fprintf(f,
				"Create nodeid 0x%llx flags 0x%lux mode 0x%lux name %p",
				hdr->nodeid, tx->flags, tx->mode, tx + 1);
			break;
		}
	}
}

int
fusedumpresp(FILE * f, struct fuse_in_header *hdr, struct fuse_out_header *ohdr,
	     void *a)
{
	/* "%#G", reqhdr, hdr, arg - use reqhdr only for type */
	int len = ohdr->len - sizeof *ohdr;
	fprintf(f, "unique 0x%llux ", ohdr->unique);
	if (ohdr->error) {
		fprintf(f, "error %ld %s", ohdr->error, strerror(-ohdr->error));
	} else
		switch (hdr->opcode) {
		default:{
				fprintf(f, "??? opcode %ld", hdr->opcode);
				break;
			}
		case FUSE_LOOKUP:{
				/*
				 * For a negative entry, can send back ENOENT
				 * or rx->ino == 0.  
				 * In protocol version 7.4 and before, can only use
				 * the ENOENT method.
				 * Presumably the benefit of sending rx->ino == 0
				 * is that you can specify the length of time to cache
				 * the negative result.
				 */
				struct fuse_entry_out *rx;
				fprintf(f, "(Lookup) ");
			      fmt_entry_out:
				rx = a;
				fprintf(f,
					"nodeid 0x%llux gen 0x%llux entry_valid %.20g attr_valid %.20g ",
					rx->nodeid, rx->generation,
					rx->entry_valid +
					rx->entry_valid_nsec * 1e-9,
					rx->attr_valid +
					rx->attr_valid_nsec * 1e-9);
				fprintf(f,
					" ino 0x%llux size %lld blocks %lld atime %.20g mtime %.20g ctime %.20g mode 0%luo nlink %ld uid %ld gid %ld rdev 0x%lux",
					rx->attr.ino, rx->attr.size,
					rx->attr.blocks,
					rx->attr.atime +
					rx->attr.atimensec * 1e-9,
					rx->attr.mtime +
					rx->attr.mtimensec * 1e-9,
					rx->attr.ctime +
					rx->attr.ctimensec * 1e-9,
					rx->attr.mode, rx->attr.nlink,
					rx->attr.uid, rx->attr.gid,
					rx->attr.rdev);
				break;
			}
		case FUSE_FORGET:{
				/* Can't happen! No reply. */
				fprintf(f, "(Forget) can't happen");
				break;
			}
		case FUSE_GETATTR:{
				struct fuse_attr_out *rx;
				fprintf(f, "(Getattr) ");
			      fmt_attr_out:
				rx = a;
				fprintf(f, "attr_valid %.20g",
					rx->attr_valid +
					rx->attr_valid_nsec * 1e-9);
				fprintf(f,
					" ino 0x%llux size %lld blocks %lld atime %.20g mtime %.20g ctime %.20g mode 0%luo nlink %ld uid %ld gid %ld rdev 0x%lux",
					rx->attr.ino, rx->attr.size,
					rx->attr.blocks,
					rx->attr.atime +
					rx->attr.atimensec * 1e-9,
					rx->attr.mtime +
					rx->attr.mtimensec * 1e-9,
					rx->attr.ctime +
					rx->attr.ctimensec * 1e-9,
					rx->attr.mode, rx->attr.nlink,
					rx->attr.uid, rx->attr.gid,
					rx->attr.rdev);
				break;
			}
		case FUSE_SETATTR:{
				fprintf(f, "(Setattr) ");
				goto fmt_attr_out;
				break;
			}
		case FUSE_READLINK:{
				fprintf(f, "(Readlink) ");	//%#.*q",
				//      utfnlen(a, len), a);
				break;
			}
		case FUSE_SYMLINK:{
				fprintf(f, "(Symlink) ");
				goto fmt_entry_out;
				break;
			}
		case FUSE_MKNOD:{
				fprintf(f, "(Mknod) ");
				goto fmt_entry_out;
				break;
			}
		case FUSE_MKDIR:{
				fprintf(f, "(Mkdir) ");
				goto fmt_entry_out;
				break;
			}
		case FUSE_UNLINK:{
				fprintf(f, "(Unlink)");
				break;
			}
		case FUSE_RMDIR:{
				fprintf(f, "(Rmdir)");
				break;
			}
		case FUSE_RENAME:{
				fprintf(f, "(Rename)");
				break;
			}
		case FUSE_LINK:{
				fprintf(f, "(Link) ");
				goto fmt_entry_out;
				break;
			}
		case FUSE_OPEN:{
				struct fuse_open_out *rx;
				fprintf(f, "(Open) ");
			      fmt_open_out:
				rx = a;
				fprintf(f, "fh 0x%llux flags 0x%lux", rx->fh,
					rx->open_flags);
				break;
			}
		case FUSE_READ:{
				fprintf(f, "(Read) size %d", len);
				break;
			}
		case FUSE_WRITE:{
				struct fuse_write_out *rx = a;
				fprintf(f, "(Write) size %ld", rx->size);
				break;
			}
		case FUSE_STATFS:{
				/*
				 * Before protocol version 7.4, only first 48 bytes are used.
				 */
				struct fuse_statfs_out *rx = a;
				fprintf(f,
					"(Statfs) blocks %lld bfree %lld bavail %lld files %lld ffree %lld bsize %lud namelen %lud frsize %lud",
					rx->st.blocks, rx->st.bfree,
					rx->st.bavail, rx->st.files,
					rx->st.ffree, rx->st.bsize,
					rx->st.namelen, rx->st.frsize);
				break;
			}
		case FUSE_RELEASE:{
				fprintf(f, "(Release)");
				break;
			}
		case FUSE_FSYNC:{
				fprintf(f, "(Fsync)");
				break;
			}
		case FUSE_SETXATTR:{
				fprintf(f, "(Serxattr)");
				break;
			}
		case FUSE_GETXATTR:{
				fprintf(f, "(Getxattr) size %d", len);
				break;
			}
		case FUSE_LISTXATTR:{
				fprintf(f, "(Lisrxattr) size %d", len);
				break;
			}
		case FUSE_REMOVEXATTR:{
				fprintf(f, "(Removexattr)");
				break;
			}
		case FUSE_FLUSH:{
				fprintf(f, "(Flush)");
				break;
			}
		case FUSE_INIT:{
				struct fuse_init_out *rx = a;
				fprintf(f,
					"(Init) major %ld minor %ld max_write %ld",
					rx->major, rx->minor, rx->max_write);
				break;
			}
		case FUSE_OPENDIR:{
				fprintf(f, "(Opendir) ");
				goto fmt_open_out;
				break;
			}
		case FUSE_READDIR:{
				fprintf(f, "(Readdir) size %d", len);
				break;
			}
		case FUSE_RELEASEDIR:{
				fprintf(f, "(Releasedir)");
				break;
			}
		case FUSE_FSYNCDIR:{
				fprintf(f, "(Fsyncdir)");
				break;
			}
		case FUSE_ACCESS:{
				fprintf(f, "(Access)");
				break;
			}
		case FUSE_CREATE:{
				struct fuse_create_out *rx = a;
				fprintf(f, "(Create) ");
				fprintf(f,
					"nodeid 0x%llux gen 0x%lluxentry_valid %.20g attr_valid %.20g ",
					rx->e.nodeid, rx->e.generation,
					rx->e.entry_valid +
					rx->e.entry_valid_nsec * 1e-9,
					rx->e.attr_valid +
					rx->e.attr_valid_nsec * 1e-9);
				fprintf(f,
					" ino 0x%llux size %lld blocks %lld atime %.20g mtime %.20g ctime %.20g mode 0%luo nlink %ld uid %ld gid %ld rdev 0x%lux",
					rx->e.attr.ino, rx->e.attr.size,
					rx->e.attr.blocks,
					rx->e.attr.atime +
					rx->e.attr.atimensec * 1e-9,
					rx->e.attr.mtime +
					rx->e.attr.mtimensec * 1e-9,
					rx->e.attr.ctime +
					rx->e.attr.ctimensec * 1e-9,
					rx->e.attr.mode, rx->e.attr.nlink,
					rx->e.attr.uid, rx->e.attr.gid,
					rx->e.attr.rdev);
				fprintf(f, " fh 0x%lluxflags 0x%lux", rx->o.fh,
					rx->o.open_flags);
				break;
			}
		}
	return 0;
}

#if defined(__APPLE__)
#include <sys/param.h>
#include <sys/mount.h>
#endif

/*
 * Mounts a fuse file system on mtpt and returns
 * a file descriptor for the corresponding fuse 
 * message conversation.
 */
int mountfuse(char *mtpt)
{
#if defined(__linux__)
	int p[2], pid, fd;
	char buf[20];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) < 0)
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		close(p[1]);
		snprintf(buf, sizeof buf, "_FUSE_COMMFD=%d", p[0]);
		putenv(buf);
		execlp("fusermount", "fusermount", "--", mtpt, NULL);
		perror("exec fusermount");
		exit(1);
	}
	close(p[0]);
	fd = recvfd(p[1]);
	close(p[1]);
	return fd;
#elif defined(__FreeBSD__) && !defined(__APPLE__)
	int pid, fd;
	char buf[20];

	if ((fd = open("/dev/fuse", ORDWR)) < 0)
		return -1;
	snprint(buf, sizeof buf, "%d", fd);

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		execlp("mount_fusefs", "mount_fusefs", buf, mtpt, NULL);
		fprintf(stderr, "exec mount_fusefs: %r\n");
		_exit(1);
	}
	return fd;
#elif defined(__APPLE__)
	int i, pid, fd, r;
	char buf[20];
	struct vfsconf vfs;
	char *f;

	if (getvfsbyname("fusefs", &vfs) < 0) {
		if (access(f = "/System/Library/Extensions/fusefs.kext"
			   "/Contents/Resources/load_fusefs", 0) < 0 &&
		    access(f = "/Library/Extensions/fusefs.kext"
			   "/Contents/Resources/load_fusefs", 0) < 0 &&
		    access(f = "/Library/Filesystems"
			   "/fusefs.fs/Support/load_fusefs", 0) < 0 &&
		    access(f = "/System/Library/Filesystems"
			   "/fusefs.fs/Support/load_fusefs", 0) < 0) {
			werrstr("cannot find load_fusefs");
			return -1;
		}
		if ((r = system(f)) < 0) {
			werrstr("%s: %r", f);
			return -1;
		}
		if (r != 0) {
			werrstr("load_fusefs failed: exit %d", r);
			return -1;
		}
		if (getvfsbyname("fusefs", &vfs) < 0) {
			werrstr("getvfsbyname fusefs: %r");
			return -1;
		}
	}

	/* Look for available FUSE device. */
	for (i = 0;; i++) {
		snprint(buf, sizeof buf, "/dev/fuse%d", i);
		if (access(buf, 0) < 0) {
			werrstr("no available fuse devices");
			return -1;
		}
		if ((fd = open(buf, ORDWR)) >= 0)
			break;
	}

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		snprint(buf, sizeof buf, "%d", fd);
		putenv("MOUNT_FUSEFS_CALL_BY_LIB", "");
		/*
		 * Different versions of MacFUSE put the
		 * mount_fusefs binary in different places.
		 * Try all.
		 */
		/* Leopard location */
		putenv("MOUNT_FUSEFS_DAEMON_PATH",
		       "/Library/Filesystems/fusefs.fs/Support/mount_fusefs");
		execl("/Library/Filesystems/fusefs.fs/Support/mount_fusefs",
		      "mount_fusefs", buf, mtpt, NULL);

		/* possible Tiger locations */
		execl("/System/Library/Filesystems/fusefs.fs/mount_fusefs",
		      "mount_fusefs", buf, mtpt, NULL);
		execl
		    ("/System/Library/Filesystems/fusefs.fs/Support/mount_fusefs",
		     "mount_fusefs", buf, mtpt, NULL);
		fprintf(stderr, "exec mount_fusefs: %r\n");
		_exit(1);
	}
	return fd;

#else
	werrstr("cannot mount fuse on this system");
	return -1;
#endif
}

void waitfuse(void)
{
	waitpid();
}

void unmountfuse(char *mtpt)
{
	int pid;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
#if defined(__linux__)
		execlp("fusermount", "fusermount", "-u", "-z", "--", mtpt,
		       NULL);
		perror("exec fusermount -u");
#else
		execlp("umount", "umount", mtpt, NULL);
		perror("exec umount");
#endif
		_exit(1);
	}
	waitpid();
}
