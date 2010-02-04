/*------------------------------------------------------------ -*- C -*-
 * nodeup / miscfiles: generic file transfer module
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.  LA-CC Number 01-67.
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference to
 * http://www.gnu.org/licenses/gpl.html.
 *
 * This software is provided by the author(s) "as is" and any express
 * or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose
 * are disclaimed.  In no event shall the author(s) be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability,
 * whether in contract, strict liability, or tort (including
 * negligence or otherwise) arising in any way out of the use of this
 * software, even if advised of the possibility of such damage.
 *
 * $Id: miscfiles.c,v 1.10 2004/03/12 20:20:25 mkdist Exp $
 *--------------------------------------------------------------------*/

/* XXX To-do list:
 *  1 - recursively store directories
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <glob.h>
#include <sys/mman.h>

#include "node_up.h"

MODULE_DESC("Generic file transfer module.");
MODULE_INFO("Usage: miscfiles [-i] [-f] files ...\n"
	    "    miscfiles is a generic file transfer module for LANL beoboot node_up.\n"
	    "    It takes a list of files to copy to the remote nodes.  Those files will\n"
	    "    be loaded into memory on the front end and re-created on the remote\n"
	    "    node.  Any required leading path elements will also be copied.\n"
	    "\n"
	    "    - Absolute path names should be supplied.\n"
	    "    - Paths leading up to specified files will be saved and recreated along\n"
	    "      with the files themselves.\n"
	    "    - Symlink structures will be followed and re-created.\n"
	    "    - A fileA>fileB syntax may be used to rename files during copy.\n"
	    "    - Shell style globbing will be done on the provided filenames.\n"
	    "\n"
	    "    Options:\n"
	    "      -i  Ignore missing files - do not fail if a file is missing.\n"
	    "      -f  Do not follow symlinks.  If the specified path is a symbolic \n"
	    "          only the link is copied - possibly creating a dangling symlink.\n"
	    "          The default behavior is to copy the link and the file that it\n"
	    "          points to.  Note that symlinks which appear in the path leading\n"
	    "          will always be followed.\n");

struct file_t {
	struct file_t *prev, *next;	/* circular list */
	int call;		/* which call to write this one out on */

	char *name;		/* vital info */
	int user;
	int group;
	int mode;
	int dev;

	long size;
	void *data;		/* file contents */
};

static struct file_t file_head = { &file_head, &file_head };

static int ignore_missing;
static int follow_symlink;

/* We can get called more than once if the plugin appears in the
 * configuration file more than once.  The module doesn't actually get
 * loaded more than once though.  That means that all the files we
 * load end up on the same list of files.  The call field in the file
 * structure lets us figure out which files got loaded on which call.
 * That way they'll get written out at the right point on the slave
 * node.  This is useful because we might want to copy a device node
 * or two manually, switch networks and mount filesystems before
 * finishing the file copies.
 */
static int premove_call_count = 0;
static int postmove_call_count = 0;

static
int load_one_file(const char *name, const char *destname)
{
	int fd;
	struct stat buf;
	struct file_t *f;
	int len;

	/* First check to see if we already have this file on our list.
	 * (Ignore it if we do. */
	for (f = file_head.next; f != &file_head; f = f->next) {
		if (strcmp(f->name, destname) == 0)
			return 0;
	}

	/* Check leading directories */
	if (lstat(name, &buf) == -1) {
		log_print(LOG_ERROR, "stat(\"%s\"): %s\n", name,
			  strerror(errno));
		return -1;
	}

	if (!(f = malloc(sizeof(*f)))) {
		log_print(LOG_ERROR, "Out of memory.\n");
		exit(1);
	}

	/* Save info about this file */
	f->name = strdup(destname);
	f->call = premove_call_count;
	f->size = buf.st_size;
	f->mode = buf.st_mode;
	f->dev = buf.st_rdev;
	f->user = buf.st_uid;
	f->group = buf.st_gid;

	/* Append to big ol' linked list */
	f->next = &file_head;
	f->prev = file_head.prev;
	f->next->prev = f;
	f->prev->next = f;

	/* Store information for this file type */
	if (S_ISREG(f->mode)) {
		fd = open(name, O_RDONLY);
		if (fd == -1) {
			log_print(LOG_ERROR, "%s: %s", name, strerror(errno));
			return -1;
		}
		f->data = mmap(0, f->size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (f->data == MAP_FAILED) {
			log_print(LOG_ERROR, "%s: mmap: %s\n", name,
				  strerror(errno));
			return -1;
		}
		close(fd);
		log_print(LOG_INFO, "loaded %s (size=%ld;id=%d,%d;mode=%o)\n",
			  name, f->size, f->user, f->group, f->mode);
		return 0;
	}
	if (S_ISLNK(f->mode)) {
		f->data = malloc(256);
		if ((len = readlink(name, f->data, 255)) == -1) {
			log_print(LOG_ERROR, "readlink(\"%s\"): %s\n",
				  name, strerror(errno));
			return -1;
		}
		((char *)f->data)[len] = 0;	/* null terminate the string */
		return 0;
	}
	return 0;		/* ignore this error for now */
}

#if 0
static
void squeezeslash(char *path)
{
	int i = 0, j = 0;
	while (path[i]) {
		if (i > 0 && path[i] == '/' && path[i - 1] == '/') {
			/* Don't copy repeated slashes */
			i++;
		} else {
			path[j++] = path[i++];
		}
	}
	path[j] = path[i];
}
#endif

static
void sanitize_filename(char *path)
{
	int i, j;
	/* Clean up file names (remove double slash, /./, etc.) */
	i = j = 0;
	while (path[i]) {
		path[j++] = path[i];
		if (path[i] == '/') {
			while (path[i] == '/')
				i++;
			while (path[i] == '.' && path[i + 1] == '/') {
				i += 2;
				while (path[i] == '/')
					i++;
			}
		} else
			i++;
	}
	path[j] = 0;
}

static
int follow_link(char *path, char *link)
{
	char *p_end, *l_slash;
	/* path = absolute name of symlink
	 * link = contents of symlink
	 * path will be modified to reflect following the link
	 */

	/* easy case */
	if (link[0] == '/') {
		strcpy(path, link);
		sanitize_filename(path);	/* paranoia ? */
		return 0;
	}

	/* Find end of path (w/o file bit) */
	p_end = path + strlen(path);
	while (p_end > path && *p_end != '/')
		p_end--;
	p_end[0] = 0;		/* lop off the last piece */
	while (*link) {
		l_slash = strchr(link, '/');
		if (!l_slash)
			l_slash = strchr(link, 0);
		if (l_slash - link == 2 && strncmp("..", link, 2) == 0) {
			/* backup */
			while (p_end > path && *p_end != '/')
				p_end--;
			*p_end = 0;
		} else if (l_slash - link == 1 && strncmp(".", link, 1) == 0) {
			/* ignore this chunk */
		} else {
			/* Copy a segment over from the symlink */
			/* Check that we're not about to overflow anything */
			if ((p_end + 1 + (l_slash - link)) >= (path + PATH_MAX))
				return -1;
			p_end[0] = '/';
			memcpy(p_end + 1, link, l_slash - link);
			p_end[1 + (l_slash - link)] = 0;

			p_end += 1 + (l_slash - link);
		}
		link = *l_slash ? l_slash + 1 : l_slash;
	}
	sanitize_filename(path);	/* paranoia ? */
	return 0;
}

static int load_file(const char *name_);
static
int load_file_follow_symlink(const char *name)
{
	int r;
	char link[PATH_MAX + 1], *path;
	r = readlink(name, link, PATH_MAX);
	if (r > 0) {
		link[r] = 0;	/* needs to be null terminated */
		path = alloca(strlen(name) + strlen(link) + 1);
		strcpy(path, name);
		if (follow_link(path, link))
			return -1;
		log_print(LOG_DEBUG, "followed link to: %s\n", path);
		load_file(path);
	}
	return 0;
}

static
int load_file(const char *name_)
{
	char *name, *slash, *destname;

	/* Get a writable copy of the name */
	name = alloca(strlen(name_) + 1);
	strcpy(name, name_);
	sanitize_filename(name);

	destname = strchr(name, '>');
	if (destname) {
		*destname = 0;
		destname++;
	} else {
		destname = name;
	}

	/* Store the path up to the destination name...  This kinda needs
	 * to exist on the front end as well at this point */
	slash = strchr(destname + 1, '/');	/* skip leading slash */
	while (slash) {
		*slash = 0;
		if (load_one_file(destname, destname))
			return -1;
		/* If that one was a symlink, we need to start over again with
		 * the path resulting from following the symlink.  Also, note
		 * that we always follow symlinks embedded in paths. */
		if (load_file_follow_symlink(destname))
			return -1;
		*slash = '/';
		slash = strchr(slash + 1, '/');
	}
	if (load_one_file(name, destname))
		return -1;
	if (follow_symlink && load_file_follow_symlink(destname))
		return -1;
	return 0;
}

/* Returns true if attributes (owner, mode, size, etc.  match) */
static
int check_attribute_match(struct file_t *f)
{
	int errnosave;
	struct stat statbuf;

	errnosave = errno;

	if (lstat(f->name, &statbuf)) {
		log_print(LOG_ERROR, "lstat(\"%s\"): %s\n", f->name,
			  strerror(errno));
		errno = errnosave;	/* restore errno... */
		return 0;
	}
	errno = errnosave;	/* restore errno */

	if (statbuf.st_mode != f->mode) {
		log_print(LOG_ERROR, "%s exists but the file type/mode"
			  " doesn't match.  (expected=0%o; got=0%o)\n",
			  f->name, f->mode, statbuf.st_mode);
		return 0;
	}

	if (!S_ISLNK(f->mode) &&
	    (statbuf.st_uid != f->user || statbuf.st_gid != f->group)) {
		log_print(LOG_ERROR,
			  "%s exists but the uid/gid doesn't match.  "
			  "(expected=%d/%d; got=%d/%d)\n", f->name, f->user,
			  f->group, statbuf.st_uid, statbuf.st_gid);
		return 0;
	}

	if (S_ISREG(f->mode) && f->size != statbuf.st_size) {
		/* XXX We need to check the file contents */
		log_print(LOG_ERROR, "%s exists but the size is incorrect.  "
			  "(expected=%ld; got=%ld)\n", f->name,
			  f->size, statbuf.st_size);
		return 0;
	}

	/* XXX Need to check symlink contents */

	if ((S_ISBLK(f->mode) || S_ISCHR(f->mode)) && f->dev != statbuf.st_rdev) {
		log_print(LOG_ERROR, "%s exists but the major/minor device"
			  " numbers don't match.  (expected=0x%x; got=0x%x)\n",
			  f->name, f->dev, statbuf.st_rdev);
		return 0;
	}
	return 1;
}

static
int store_file(struct file_t *f)
{
	int fd, w;

	log_print(LOG_INFO, "creating %s (size=%ld;uid=%d;gid=%d;mode=%o)\n",
		  f->name, f->size, f->user, f->group, f->mode);

	if (S_ISREG(f->mode)) {
		fd = open(f->name, O_WRONLY | O_CREAT | O_TRUNC,
			  f->mode & 0777);
		if (fd == -1) {
			if (errno == EEXIST && check_attribute_match(f))
				return 0;
			log_print(LOG_ERROR, "%s: %s\n", f->name,
				  strerror(errno));
			return -1;
		}
		w = write(fd, f->data, f->size);
		close(fd);
		if (w != f->size) {
			log_print(LOG_ERROR,
				  "Short write: expected %ld; got %d\n",
				  f->size, w);
			return -1;
		}
	}
	if (S_ISDIR(f->mode)) {
		if (mkdir(f->name, f->mode) != 0) {
			if (errno == EEXIST && check_attribute_match(f))
				return 0;
			log_print(LOG_ERROR, "mkdir(\"%s\"): %s\n",
				  f->name, strerror(errno));

			return -1;
		}
	}
	if (S_ISBLK(f->mode) || S_ISCHR(f->mode)) {
		if (mknod(f->name, f->mode, f->dev)) {
			if (errno == EEXIST && check_attribute_match(f))
				return 0;
			log_print(LOG_ERROR, "mknod(\"%s\", 0%o, 0x%x): %s\n",
				  f->name, f->mode, f->dev, strerror(errno));
			return -1;
		}
	}
	if (S_ISLNK(f->mode)) {
		if (symlink(f->data, f->name) == -1) {
			if (errno == EEXIST && check_attribute_match(f))
				return 0;
			log_print(LOG_ERROR, "symlink(\"%s\", \"%s\"): %s\n",
				  f->data, f->name, strerror(errno));
			return -1;
		}
		return 0;	/* don't do mode business for links ? */
	}

	/* Set the owner, group and mode (don't bother for symlinks) */
	if (!S_ISLNK(f->mode)) {
		if (chown(f->name, f->user, f->group) != 0) {
			log_print(LOG_ERROR, "chown(\"%s\", %d, %d): %s\n",
				  f->name, f->user, f->group, strerror(errno));
			return -1;
		}
		if (chmod(f->name, f->mode) != 0) {
			log_print(LOG_ERROR, "chmod(\"%s\", 0%o): %s\n",
				  f->name, f->mode, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int miscfiles_premove(int argc, char *argv[])
{
	int i, j, c;
	glob_t gl;

	ignore_missing = 0;
	follow_symlink = 1;

	premove_call_count++;

	while ((c = getopt(argc, argv, "if")) != -1) {
		switch (c) {
		case 'i':
			ignore_missing = 1;
			break;
		case 'f':
			follow_symlink = 0;
			break;
		default:
			log_print(LOG_ERROR, "Unrecognized flag: %c\n",
				  (char)optopt);
			return -1;
		}
	}

	for (i = optind; i < argc; i++) {
		glob(argv[i], GLOB_NOCHECK, 0, &gl);
		for (j = 0; j < gl.gl_pathc; j++) {
			if (load_file(gl.gl_pathv[j]))
				return -1;
		}
		globfree(&gl);
	}
	return 0;
}

int miscfiles_postmove(int argc, char *argv[])
{
	struct file_t *f;

	postmove_call_count++;
	for (f = file_head.next; f != &file_head; f = f->next) {
		if (f->call == postmove_call_count)
			if (store_file(f))
				return -1;
	}
	return 0;
}

/* The premove and post move functions are defined with unique names
 * so that they can be called to move files from other modules.  These
 * aliases provide the names that the node_up program is looking
 * for. */
int nodeup_premove(int argc, char *argv[])
    __attribute__ ((alias("miscfiles_premove")));
int nodeup_postmove(int argc, char *argv[])
    __attribute__ ((alias("miscfiles_postmove")));

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
