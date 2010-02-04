/*------------------------------------------------------------ -*- C -*-
 * setupfs: nodeup module to mount file systems using a file system table
 * Erik Hendriks <hendriks@lanl.gov>
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
 * $Id: setupfs.c,v 1.14 2004/08/09 18:46:09 mkdist Exp $
 *--------------------------------------------------------------------*/
/*
 * To-do List:
 *   - Flesh out mount point point compare
 *   - Support remount?
 *   - Mount swap space
 *   - Worry some more about defaults like nosuid for nfs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <getopt.h>

#include "node_up.h"

MODULE_DESC("File system mounting module.");
MODULE_INFO("Usage: setupfs [-i] [-f] files ...\n"
	    "    setupfs is file system mounting module.  It reads " CONFIGDIR
	    "/fstab\n"
	    "    on the front end and mounts the file systems on the slave node.\n"
	    "\n" "  Options:\n" "  Retry Options: \n"
	    "    These options apply to retryable operations such as NFS mounts.  Retry\n"
	    "    will start with an initial delay between tries and back off with each\n"
	    "    failed attempt.\n"
	    "    --timeout  secs    Timeout for retryable operations (e.g. NFS mount)\n"
	    "    --delay    secs    Initial interval between retries.\n"
	    "    --maxdelay secs    Maximum interval between retries.\n"
	    "    --backoff  factor  Backoff factor.  The interval between tries will get\n"
	    "                       multiplied by factor after each failed attempt.\n"
	    "\n" "  Requirements:\n"
	    "    This module requires the kmod module in order to load file system\n"
	    "    modules.\n");

#define MAX_FSTAB 50

#define PROC_TMP "/.setupfs.proc.tmp"

struct fstab_entry_t {
	char *device;
	int mode, dev, user, group;	/* Device info for  */
	char *mount_point;
	char *fstype;		/* ext2, nfs, etc. */
	int flags;
	char *options;
};

static struct fstab_entry_t fstab[MAX_FSTAB];

static char *root = "/";

struct retry_arg_t {
	int initial_delay;
	int max_delay;
	float backoff;
	int max_time;
	float rand;
};

static struct retry_arg_t retry_args = {
      initial_delay:1000000,	/* usec */
      max_delay:100000000,	/* usec */
      backoff:1.2,		/* sec */
      max_time:600,		/* sec */
      rand:0.1
};

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

static
int do_mkdir(const char *path, int mode)
{
	struct stat statbuf;
	/*log_print(LOG_DEBUG, "mkdir %s\n", path); */

	if (mkdir(path, mode) == 0)
		return 0;

	if (lstat(path, &statbuf) != 0) {
		log_print(LOG_ERROR, "Couldn't mkdir or stat %s: %s\n", path,
			  strerror(errno));
		return -1;
	}

	if (!S_ISDIR(statbuf.st_mode)) {
		log_print(LOG_ERROR, "%s exists but is not a directory.\n",
			  path);
		return -1;
	}

	return 0;
}

static
int mkpath(const char *path, int mode)
{
	char *realpath;
	char *slash;

	/* Need a writable copy of the path... */
	realpath = alloca(strlen(path) + 1);
	strcpy(realpath, path);

	slash = strchr(realpath + 1, '/');	/* skip leading slash */
	while (slash) {
		*slash = 0;
		if (do_mkdir(realpath, mode))
			return -1;
		*slash = '/';
		slash = strchr(slash + 1, '/');
	}
	if (do_mkdir(realpath, mode))
		return -1;
	return 0;
}

void kmod_modprobe(const char *modname) __attribute__ ((weak));
void kmod_modprobe(const char *modname)
{
	log_print(LOG_WARNING, "kmod plugin not loaded before setupfs plugin - "
		  "can't automagically load modules.\n");
}

static
int check_fstype_proc(struct fstab_entry_t *fs)
{
	FILE *f;
	char line[100], *p;

	if (strcmp(fs->fstype, "swap") == 0)
		return 0;

	f = fopen(PROC_TMP "/filesystems", "r");
	if (!f) {
		log_print(LOG_WARNING,
			  "Failed to open " PROC_TMP "/filesystems (%s) -"
			  " unable to auto-load file system modules.\n",
			  strerror(errno));
		return -1;
	}
	while (fgets(line, 100, f)) {
		if ((p = strchr(line, '\n')))
			*p = 0;	/* remove newline */
		if (!(p = strchr(line, '\t')))
			continue;	/* skip to fs name */
		p++;
		if (strcmp(p, fs->fstype) == 0) {
			/* file system already supported. */
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static
int check_fstype(struct fstab_entry_t *fs)
{
	if (check_fstype_proc(fs) == -1) {
		/* If we get here, we need to probe the file system type */
		kmod_modprobe(fs->fstype);
		/* XXX THIS IS BUSTED RIGHT NOW - KMOD DOESN'T RETURN STATUS */

		/* We need to check if we really managed to load the right
		 * module */
		if (check_fstype_proc(fs) == -1)
			return -1;
	}

	return 0;
}

static
int check_mount_match(struct fstab_entry_t *fs, char *altdev)
{
	FILE *f;
	char dev[101], mnt[101], fstype[101], opts[101];
	if (!(f = fopen(PROC_TMP "/mounts", "r"))) {
		/* Can't check for matches without PROC_TMP/mounts */
		return 0;
	}

	while (fscanf(f, "%100s %100s %100s %100s %*s %*s\n",
		      dev, mnt, fstype, opts) == 4) {
		if ((strcmp(dev, fs->device) == 0 ||
		     (altdev && strcmp(dev, altdev) == 0)) &&
		    strcmp(mnt, fs->mount_point) == 0 &&
		    strcmp(fstype, fs->fstype) == 0) {
			/* XXX we're ignoring the mount options for now... */
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/* XXX WARNING: This code could break if you set the initial delay too
 * low or RARP_RAND too high... */
static
int update_delay(struct retry_arg_t *args, int delay)
{
	float factor;
	delay = delay * args->backoff;

	/* Constrain delay to be within our bounds */
	if (delay > args->max_delay)
		delay = args->max_delay;
	if (delay < args->initial_delay)
		delay = args->initial_delay;

	/* Add some randomness to the delay */
	factor =
	    1.0 - args->rand + (rand() / ((float)RAND_MAX)) * args->rand * 2;
	delay = delay * factor;

	if (delay < 0)
		delay = 1;	/* safety net... */
	return delay;
}

static
int do_nfs_mount(struct fstab_entry_t *fs, char *path, char *realpath,
		 char **mount_opts)
{
	int elapsed;
	struct timeval start, last_send;
	struct timeval now;
	int delay;
	int ver = 4;
	extern int nfsmount(const char *spec, const char *node, int *flags,
			    char **extra_opts, char **mount_opts,
			    int *nfs_mount_vers, int running_bg);
	struct retry_arg_t *args = &retry_args;

	gettimeofday(&start, 0);
	now = start;
	srand(now.tv_usec);

	last_send = now;
	if (nfsmount(path, realpath, &fs->flags,
		     &fs->options, mount_opts, &ver, 0) == 0) {
		return 0;
	}

	delay = update_delay(args, 0);

	while (now.tv_sec - start.tv_sec < args->max_time) {
		elapsed = (now.tv_sec - last_send.tv_sec) * 1000000 +
		    now.tv_usec - last_send.tv_usec;
		if (elapsed >= delay) {
			delay = update_delay(args, delay);

			log_print(LOG_INFO, "Retrying NFS mount.\n");
			if (nfsmount(path, realpath, &fs->flags,
				     &fs->options, mount_opts, &ver, 0) == 0) {
				return 0;
			}

			elapsed = 0;
		} else
			usleep(delay - elapsed);
		gettimeofday(&now, 0);
	}

	/* Flailure to receive a response */
	log_print(LOG_ERROR, "NFS mount failed.\n");
	return -1;
}

static
int do_mount(struct fstab_entry_t *fs)
{
	char *realpath;

	log_print(LOG_INFO, "Doing mount: dev=%s  mntpt=%s  type=%s  opts=%s\n",
		  fs->device, fs->mount_point, fs->fstype, fs->options);

	/* Figure out the real path for the mount point */
	realpath = alloca(strlen(root) + strlen(fs->mount_point) + 3);
	sprintf(realpath, "/%s/%s", root, fs->mount_point);
	squeezeslash(realpath);

	/* Make sure that the mount point exists */
	if (mkpath(realpath, 0755)) {
		log_print(LOG_ERROR, "Failed to create mount point: %s\n",
			  realpath);
		return 1;
	}

	if (check_fstype(fs) == -1) {
		log_print(LOG_ERROR,
			  "File system type \"%s\" is not supported by"
			  " the kernel and modprobe failed to fix that.\n",
			  fs->fstype);
		return 1;
	}

	/* Special cases for certain file system types */
	if (strcmp(fs->fstype, "nfs") == 0) {
		char *mount_opts;
		char *path;

		/* Do special mapping on the hostname */
		path = fs->device;
		if (strncmp("MASTER", fs->device, 6) == 0) {
			char *p;
			path = alloca(strlen(fs->device) + 20);
			p = strchr(fs->device, ':');
			sprintf(path, "%s:%s",
				inet_ntoa(nodeup_master.sin_addr), p + 1);
		}

		if (do_nfs_mount(fs, path, realpath, &mount_opts))
			return -1;

		if (mount(path, realpath, fs->fstype, fs->flags, mount_opts) ==
		    -1) {
			if (errno == EBUSY && check_mount_match(fs, path)) {
				log_print(LOG_INFO,
					  "  Already mounted - skipping.\n");
				return 0;
			}
			log_print(LOG_ERROR, "mount failed: %s\n",
				  strerror(errno));
			return -1;
		}
		return 0;
	}

	/* Do a simple mount call for this filesystem */

	if (strcmp(fs->device, "none") != 0 && fs->mode) {
		char *p;
		/* Create path elements leading up to where the device node
		 * will live */
		p = strrchr(fs->device, '/');
		if (p) {
			*p = 0;
			if (mkpath(fs->device, 0755)) {
				*p = '/';
				return -1;
			}
			*p = '/';
		}

		if (mknod(fs->device, fs->mode, fs->dev)) {
			/*if (errno == EEXIST && check_attribute_match(f)) return 0; */
			log_print(LOG_ERROR, "mknod(\"%s\", 0%o, 0x%x): %s\n",
				  fs->device, fs->mode, fs->dev,
				  strerror(errno));
			return -1;
		}
		if (chown(fs->device, fs->user, fs->group) != 0) {
			log_print(LOG_ERROR, "chown(\"%s\", %d, %d): %s\n",
				  fs->device, fs->user, fs->group,
				  strerror(errno));
			return -1;
		}
		if (chmod(fs->device, fs->mode) != 0) {
			log_print(LOG_ERROR, "chmod(\"%s\", 0%o): %s\n",
				  fs->device, fs->mode, strerror(errno));
			return -1;
		}
	}

	/* More special case filesystem types */
	if (strcmp(fs->fstype, "swap") == 0) {
		/* XXX check for swap signature or something ? */
		if (swapon(fs->device, 0)) {
			if (errno == EEXIST)
				return 0;	/* already on - ok */
			log_print(LOG_ERROR, "swapon(\"%s\", 0): %s\n",
				  fs->device, strerror(errno));
			return -1;
		}
		return 0;
	}

	if (mount(fs->device, realpath, fs->fstype, fs->flags, fs->options) ==
	    -1) {
		if (errno == EBUSY && check_mount_match(fs, 0)) {
			log_print(LOG_INFO, "  Already mounted - skipping.\n");
			return 0;
		}
		log_print(LOG_ERROR, "mount failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static
int do_mtab(void)
{
	char path[PATH_MAX + 1];

	/* Instead of creating a real mtab, just use /proc/mounts.  This
	 * presumes that the user mounted procfs on /proc but that's a
	 * pretty reasonable assumption. */
	sprintf(path, "/%s/etc", root);
	squeezeslash(path);
	if (mkdir(path, 0755) && errno != EEXIST) {
		log_print(LOG_ERROR, "mkdir(\"%s\", 0755): %s\n",
			  path, strerror(errno));
		return -1;
	}

	sprintf(path, "/%s/etc/mtab", root);
	squeezeslash(path);
	if (symlink("../proc/mounts", path)) {
		log_print(LOG_ERROR, "symlink(\"%s\", \"%s\"): %s\n",
			  "../proc/mounts", path, strerror(errno));
		return -1;
	}

	return 0;
}

struct mount_opts {
	char *str;
	int mnt_flag;
	int invert;		/* turn off instead of on */
};

static struct mount_opts mount_opts[] = {
	{"ro", MS_RDONLY, 0},
	{"rw", MS_RDONLY, 1},
	{"suid", MS_NOSUID, 1},
	{"dev", MS_NODEV, 1},
	{"exec", MS_NOEXEC, 1},
	{"sync", MS_SYNCHRONOUS, 0},
	{"atime", MS_NOATIME, 1},
	{"diratime", MS_NODIRATIME, 1},
	/* This list is not complete... */
	{0}
};

/* parse_options: translate and remove the options that correspond to
 * bit-flags.  Preserve other options. */
static
int parse_options(struct fstab_entry_t *ent)
{
	int i, invert;
	char *tmp, *tok, *p;
	tmp = alloca(strlen(ent->options) + 1);
	tmp[0] = 0;
	ent->flags = 0;

	tok = strtok_r(ent->options, ",", &p);
	while (tok) {
		/* Try for a straight match with mount options */
		invert = (strncmp(tok, "no", 2) == 0) ? 1 : 0;
		/*log_print(LOG_DEBUG, "considering: \"%s\" %d\n", tok, invert); */
		for (i = 0; mount_opts[i].str; i++) {
			if (strcmp(invert ? tok + 2 : tok, mount_opts[i].str) ==
			    0) {
				if (invert ^ mount_opts[i].invert)
					ent->flags &= ~mount_opts[i].mnt_flag;
				else
					ent->flags |= mount_opts[i].mnt_flag;
				break;
			}
		}
		if (!mount_opts[i].str) {
			/* If it didn't match anything add it to the extra options
			 * string... */
			if (tmp[0])
				strcat(tmp, ",");
			strcat(tmp, tok);
		}
		tok = strtok_r(0, ",", &p);
	}
	strcpy(ent->options, tmp);
	log_print(LOG_DEBUG, "mount flags for %s are %x / %s\n",
		  ent->mount_point, ent->flags, ent->options);
	return 0;
}

static
int load_fstab(const char *filename)
{
	FILE *f;
	char line[1000], *p, *tokp;
	int idx = 0;
	struct stat statbuf;

	char *device, *mount_point, *fstype, *options;

	f = fopen(filename, "r");
	if (!f) {
		log_print(LOG_ERROR, "Failed to open %s: %s\n", filename,
			  strerror(errno));
		return -1;
	}

	while (fgets(line, 1000, f)) {
		if ((p = strchr(line, '#')))
			*p = 0;	/* remove comments */

		/* Device name */
		device = strtok_r(line, " \t\r\n", &tokp);
		if (!device)
			continue;	/* empty/short line */
		mount_point = strtok_r(0, " \t\r\n", &tokp);
		if (!mount_point)
			continue;	/* empty/short line */
		fstype = strtok_r(0, " \t\r\n", &tokp);
		if (!fstype)
			continue;	/* empty/short line */
		options = strtok_r(0, " \t\r\n", &tokp);
		if (!options)
			continue;	/* empty/short line */

		if (strcmp(options, "defaults") == 0)
			options = "";

		fstab[idx].device = strdup(device);
		fstab[idx].mount_point = strdup(mount_point);
		fstab[idx].fstype = strdup(fstype);
		fstab[idx].options = strdup(options);

		/* Is there anything mountable (w/o loopback) that isn't a
		 * block device? */
		if (strcmp(device, "none") != 0 &&
		    stat(device, &statbuf) == 0 && S_ISBLK(statbuf.st_mode)) {
			fstab[idx].mode = statbuf.st_mode;
			fstab[idx].dev = statbuf.st_rdev;
			fstab[idx].user = statbuf.st_uid;
			fstab[idx].group = statbuf.st_gid;
		} else {
			fstab[idx].mode = 0;
		}

		/* Paw through the options string looking for special things */
		parse_options(&fstab[idx]);

		idx++;
	}
	fstab[idx].fstype = 0;

	log_print(LOG_INFO, "Successfully loaded fstab from %s\n", filename);
	return 0;
}

int nodeup_premove(int argc, char *argv[])
{
	int c;
	char *check;
	static struct option long_opts[] = {
		{"timeout", 1, 0, 't'},	/* max_time */
		{"delay", 1, 0, 'i'},	/* initial_delay */
		{"maxdelay", 1, 0, 'm'},	/* max_delay */
		{"backoff", 1, 0, 'b'},	/* backoff */
		{0, 0, 0, 0}
	};
	while ((c = getopt_long(argc, argv, "r:", long_opts, 0)) != -1) {
		switch (c) {
		case 'r':
			root = optarg;
			break;
		case 't':
			retry_args.max_time = strtod(optarg, &check);
			if (*check || retry_args.max_time < 0) {
				log_print(LOG_ERROR, "Invalid timeout: %s\n",
					  optarg);
				return -1;
			}
			break;
		case 'i':
			retry_args.initial_delay =
			    strtod(optarg, &check) * 1000000;
			if (*check || retry_args.initial_delay < 0) {
				log_print(LOG_ERROR, "Invalid delay: %s\n",
					  optarg);
				return -1;
			}
			break;
		case 'm':
			retry_args.max_delay = strtod(optarg, &check) * 1000000;
			if (*check || retry_args.max_delay < 0) {
				log_print(LOG_ERROR, "Invalid max delay: %s\n",
					  optarg);
				return -1;
			}
			break;
		case 'b':

			break;
		default:
			log_print(LOG_ERROR, "Invalid option.\n");
			return -1;
		}
	}

	/* XXX we need to the fsta by node-number thing here */
	if (load_fstab(CONFIGDIR "/fstab")) {
		log_print(LOG_ERROR, "Failed to load node fstab.\n");
		return -1;
	}

	return 0;
}

int nodeup_postmove(int argc, char *argv[])
{
	int i;

	/* We did the argument processing before we moved so we don't have
	 * to do it here.  Now we start the actual file system setup. */

	if (nodeup_mnt_proc(PROC_TMP))
		return -1;

	/* Make sure that the "root" directory exists */
	if (mkpath(root, 0755) == -1) {
		log_print(LOG_ERROR,
			  "Failed to create the root directory (%s).\n", root);
		return -1;
	}

	/* Start working through our fstab. */
	for (i = 0; fstab[i].fstype; i++) {
		if (do_mount(&fstab[i]))
			return -1;
	}

	/* Create a symlink for mtab */
	do_mtab();

	/* We should support an option to pivot root here... */
	if (strcmp(root, "/") != 0) {
		if (chroot(root) != 0) {
			log_print(LOG_ERROR, "chroot(\"%s\"): %s\n", root,
				  strerror(errno));
			return -1;
		}
		/* Make sure we're sitting in our new root */
		if (chdir("/")) {
			log_print(LOG_ERROR, "chdir(\"/\"): %s\n",
				  strerror(errno));
			return -1;
		}
	}
	return 0;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
