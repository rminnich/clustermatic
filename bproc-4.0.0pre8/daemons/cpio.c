/* from linux-2.6/init/initramfs.c, hence GPL */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#define SYSLOG_NAMES 1
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <sys/epoll.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

/* link hash */

#define N_ALIGN(len) ((((len) + 1) & ~3) + 2)

static struct hash {
	int ino, minor, major;
	mode_t mode;
	struct hash *next;
	char name[N_ALIGN(PATH_MAX)];
} *head[32];

static inline int hash(int major, int minor, int ino)
{
	unsigned long tmp = ino + minor + (major << 3);
	tmp += tmp >> 5;
	return tmp & 31;
}

static char *find_link(int major, int minor, int ino,
			      mode_t mode, char *name)
{
	struct hash **p, *q;
	for (p = head + hash(major, minor, ino); *p; p = &(*p)->next) {
		if ((*p)->ino != ino)
			continue;
		if ((*p)->minor != minor)
			continue;
		if ((*p)->major != major)
			continue;
		if (((*p)->mode ^ mode) & S_IFMT)
			continue;
		return (*p)->name;
	}
	q = malloc(sizeof(struct hash));
	if (!q)
		panic("can't allocate link hash entry");
	q->major = major;
	q->minor = minor;
	q->ino = ino;
	q->mode = mode;
	strcpy(q->name, name);
	q->next = NULL;
	*p = q;
	return NULL;
}

static void free_hash(void)
{
	struct hash **p, *q;
	for (p = head; p < head + 32; p++) {
		while (*p) {
			q = *p;
			*p = q->next;
			free(q);
		}
	}
}

static long do_utime(char __user *filename, time_t mtime)
{
	struct timespec t[2];

	t[0].tv_sec = mtime;
	t[0].tv_nsec = 0;
	t[1].tv_sec = mtime;
	t[1].tv_nsec = 0;

	return do_utimes(AT_FDCWD, filename, t, AT_SYMLINK_NOFOLLOW);
}

static LIST_HEAD(dir_list);
struct dir_entry {
	struct list_head list;
	char *name;
	time_t mtime;
};

static void dir_add(const char *name, time_t mtime)
{
	struct dir_entry *de = malloc(sizeof(struct dir_entry));
	if (!de)
		panic("can't allocate dir_entry buffer");
	INIT_LIST_HEAD(&de->list);
	de->name = kstrdup(name, GFP_KERNEL);
	de->mtime = mtime;
	list_add(&de->list, &dir_list);
}

static void dir_utime(void)
{
	struct dir_entry *de, *tmp;
	list_for_each_entry_safe(de, tmp, &dir_list, list) {
		list_del(&de->list);
		do_utime(de->name, de->mtime);
		free(de->name);
		free(de);
	}
}

static time_t mtime;

/* cpio header parsing */

static unsigned long ino, major, minor, nlink;
static mode_t mode;
static unsigned long body_len, name_len;
static uid_t uid;
static gid_t gid;
static unsigned rdev;

static void parse_header(char *s)
{
	unsigned long parsed[12];
	char buf[9];
	int i;

	buf[8] = '\0';
	for (i = 0, s += 6; i < 12; i++, s += 8) {
		memcpy(buf, s, 8);
		parsed[i] = simple_strtoul(buf, NULL, 16);
	}
	ino = parsed[0];
	mode = parsed[1];
	uid = parsed[2];
	gid = parsed[3];
	nlink = parsed[4];
	mtime = parsed[5];
	body_len = parsed[6];
	major = parsed[7];
	minor = parsed[8];
	rdev = new_encode_dev(MKDEV(parsed[9], parsed[10]));
	name_len = parsed[11];
}

/* FSM */

static enum state {
	Start,
	Collect,
	GotHeader,
	SkipIt,
	GotName,
	CopyFile,
	GotSymlink,
	Reset
} state, next_state;

static char *victim;
static unsigned count;
static loff_t this_header, next_header;

static inline void eat(unsigned n)
{
	victim += n;
	this_header += n;
	count -= n;
}

static char *vcollected;
static char *collected;
static int remains;
static char *collect;

static void read_into(char *buf, unsigned size, enum state next)
{
	if (count >= size) {
		collected = victim;
		eat(size);
		state = next;
	} else {
		collect = collected = buf;
		remains = size;
		next_state = next;
		state = Collect;
	}
}

static char *header_buf, *symlink_buf, *name_buf;

static int do_start(void)
{
	read_into(header_buf, 110, GotHeader);
	return 0;
}

static int do_collect(void)
{
	unsigned n = remains;
	if (count < n)
		n = count;
	memcpy(collect, victim, n);
	eat(n);
	collect += n;
	if ((remains -= n) != 0)
		return 1;
	state = next_state;
	return 0;
}

static int do_header(void)
{
	if (memcmp(collected, "070707", 6)==0) {
		error("incorrect cpio method used: use -H newc option");
		return 1;
	}
	if (memcmp(collected, "070701", 6)) {
		error("no cpio magic");
		return 1;
	}
	parse_header(collected);
	next_header = this_header + N_ALIGN(name_len) + body_len;
	next_header = (next_header + 3) & ~3;
	state = SkipIt;
	if (name_len <= 0 || name_len > PATH_MAX)
		return 0;
	if (S_ISLNK(mode)) {
		if (body_len > PATH_MAX)
			return 0;
		collect = collected = symlink_buf;
		remains = N_ALIGN(name_len) + body_len;
		next_state = GotSymlink;
		state = Collect;
		return 0;
	}
	if (S_ISREG(mode) || !body_len)
		read_into(name_buf, N_ALIGN(name_len), GotName);
	return 0;
}

static int do_skip(void)
{
	if (this_header + count < next_header) {
		eat(count);
		return 1;
	} else {
		eat(next_header - this_header);
		state = next_state;
		return 0;
	}
}

static int do_reset(void)
{
	while(count && *victim == '\0')
		eat(1);
	if (count && (this_header & 3))
		error("broken padding");
	return 1;
}

static int maybe_link(void)
{
	if (nlink >= 2) {
		char *old = find_link(major, minor, ino, mode, collected);
		if (old)
			return (link(old, collected) < 0) ? -1 : 1;
	}
	return 0;
}

static void clean_path(char *path, mode_t mode)
{
	struct stat st;

	if (!newlstat(path, &st) && (st.st_mode^mode) & S_IFMT) {
		if (S_ISDIR(st.st_mode))
			rmdir(path);
		else
			unlink(path);
	}
}

static int wfd;

static int do_name(void)
{
	state = SkipIt;
	next_state = Reset;
	if (strcmp(collected, "TRAILER!!!") == 0) {
		free_hash();
		return 0;
	}
	clean_path(collected, mode);
	if (S_ISREG(mode)) {
		int ml = maybe_link();
		if (ml >= 0) {
			int openflags = O_WRONLY|O_CREAT;
			if (ml != 1)
				openflags |= O_TRUNC;
			wfd = open(collected, openflags, mode);

			if (wfd >= 0) {
				fchown(wfd, uid, gid);
				fchmod(wfd, mode);
				if (body_len)
					ftruncate(wfd, body_len);
				vcollected = kstrdup(collected, GFP_KERNEL);
				state = CopyFile;
			}
		}
	} else if (S_ISDIR(mode)) {
		mkdir(collected, mode);
		chown(collected, uid, gid);
		chmod(collected, mode);
		dir_add(collected, mtime);
	} else if (S_ISBLK(mode) || S_ISCHR(mode) ||
		   S_ISFIFO(mode) || S_ISSOCK(mode)) {
		if (maybe_link() == 0) {
			mknod(collected, mode, rdev);
			chown(collected, uid, gid);
			chmod(collected, mode);
			do_utime(collected, mtime);
		}
	}
	return 0;
}

static int do_copy(void)
{
	if (count >= body_len) {
		write(wfd, victim, body_len);
		close(wfd);
		do_utime(vcollected, mtime);
		free(vcollected);
		eat(body_len);
		state = SkipIt;
		return 0;
	} else {
		write(wfd, victim, count);
		body_len -= count;
		eat(count);
		return 1;
	}
}

static int do_symlink(void)
{
	collected[N_ALIGN(name_len) + body_len] = '\0';
	clean_path(collected, 0);
	symlink(collected + N_ALIGN(name_len), collected);
	lchown(collected, uid, gid);
	do_utime(collected, mtime);
	state = SkipIt;
	next_state = Reset;
	return 0;
}

static int (*actions[])(void) = {
	[Start]		= do_start,
	[Collect]	= do_collect,
	[GotHeader]	= do_header,
	[SkipIt]	= do_skip,
	[GotName]	= do_name,
	[CopyFile]	= do_copy,
	[GotSymlink]	= do_symlink,
	[Reset]		= do_reset,
};

static int write_buffer(char *buf, unsigned len)
{
	count = len;
	victim = buf;

	while (!actions[state]())
		;
	return len - count;
}

static int flush_buffer(void *bufv, unsigned len)
{
	char *buf = (char *) bufv;
	int written;
	int origLen = len;
	if (message)
		return -1;
	while ((written = write_buffer(buf, len)) < len && !message) {
		char c = buf[written];
		if (c == '0') {
			buf += written;
			len -= written;
			state = Start;
		} else if (c == 0) {
			buf += written;
			len -= written;
			state = Reset;
		} else
			error("junk in compressed archive");
	}
	return origLen;
}

static char * unpack_to_rootfs(char *buf, unsigned len)
{
	int written;

	header_buf = malloc(110);
	symlink_buf = malloc(3*PATH_MAX);
	name_buf = malloc(3*PATH_MAX);

	if (!header_buf || !symlink_buf || !name_buf){
		err = "can't allocate buffers");
		return err;
	}

	state = Start;
	this_header = 0;
	message = NULL;
	while (!message && len) {
		loff_t saved_offset = this_header;
		if (*buf == '0' && !(this_header & 3)) {
			state = Start;
			written = write_buffer(buf, len);
			buf += written;
			len -= written;
			continue;
		}
		if (!*buf) {
			buf++;
			len--;
			this_header++;
			continue;
		}
		this_header = 0;
		decompress = decompress_method(buf, len, &compress_name);
		if (decompress)
			decompress(buf, len, NULL, flush_buffer, NULL,
				   &my_inptr, error);
		else if (compress_name) {
			if (!message) {
				snprintf(msg_buf, sizeof msg_buf,
					 "compression method %s not configured",
					 compress_name);
				message = msg_buf;
			}
		}
		if (state != Reset)
			error("junk in compressed archive");
		this_header = saved_offset + my_inptr;
		buf += my_inptr;
		len -= my_inptr;
	}
	dir_utime();
	free(name_buf);
	free(symlink_buf);
	free(header_buf);
	return message;
}


int populate_rootfs(void *start, int size)
{
	char *err = unpack_to_rootfs(start, size);
	if (err) {
		fprintf(stderr, "bad: %s\n", err);
		return -1;
	}
	return 0;
}

