#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <archive.h>		/* libarchive */
#include <archive_entry.h>  /* libarchive */
#include <syslog.h>
#include "cpio.h"

int cpio(void *buf, size_t len, const char *prepend_string) {
	struct archive *arch_read;
	struct archive *arch_write;
	struct archive_entry *entry;
	int r;
	int count = 0;
	int flags = ARCHIVE_EXTRACT_TIME;
	char *tmp;
	

	arch_read = archive_read_new();
	archive_read_support_format_cpio(arch_read);

	arch_write = archive_write_disk_new();
	archive_write_disk_set_options(arch_write, flags);

	r = archive_read_open_memory(arch_read, buf, len);
	if (r != ARCHIVE_OK) {
		syslog(LOG_NOTICE, "archive is NOT ok");
		return -1;
	}

	while (archive_read_next_header(arch_read, &entry) == ARCHIVE_OK) {
		syslog(LOG_NOTICE, "Entry %d name %s", count, archive_entry_pathname(entry));
		count++;
		if (prepend_string) {
			tmp = calloc(1, strlen(archive_entry_pathname(entry)) + strlen(prepend_string) + 1);
			strcat(tmp, prepend_string);
			strcat(tmp, archive_entry_pathname(entry));
			archive_entry_set_pathname(entry, tmp);
			free(tmp);
			tmp = NULL;
		}
		syslog(LOG_NOTICE, "Write filename %s\n", archive_entry_pathname(entry));
		r = archive_write_header(arch_write, entry);
		if (r != ARCHIVE_OK) {
			syslog(LOG_NOTICE, "Write filename %s, archive_write_header failed", archive_entry_pathname(entry));
			write(2, archive_error_string(arch_read), strlen(archive_error_string(arch_read)));
		}
		else {
			const void *buff;
			size_t size;
			off_t offset;

			for (;;) {
				r = archive_read_data_block(arch_read, &buff, &size, &offset);
				if (r == ARCHIVE_EOF) {
					break;
				}
				if (r != ARCHIVE_OK) {
					syslog(LOG_NOTICE, "%s", archive_error_string(arch_read));
					return -1;
				}

				r = archive_write_data_block(arch_write, buff, size, offset);
				if (r != ARCHIVE_OK) {
					syslog(LOG_NOTICE, "%s", archive_error_string(arch_write));
					return -1;
				}
			}
		}
	}
	syslog(LOG_NOTICE, "Total %d entries processed", count);
	r = archive_read_finish(arch_read);
	if (r != ARCHIVE_OK) {
		return -1;
	}
	r = archive_write_finish(arch_write);
	if (r != ARCHIVE_OK) {
		return -1;
	}

	return count;
}
struct cpio {
	/* Options */
	const char *filename;
	const char *format; /* -H format */
	int       bytes_per_block; /* -b block_size */
	int       extract_flags; /* Flags for extract operation */
	int fd;

	/* Miscellaneous state information */
	struct archive *archive;
	struct archive_entry_linkresolver *linkresolver;

	/* Work data. */
	char         *buff;
	size_t        buff_size;
};



static int entry_to_archive(struct cpio *cpio, struct archive_entry *entry) {
	const char *destpath = archive_entry_pathname(entry);
	const char *srcpath = archive_entry_sourcepath(entry);
	int fd = -1;
	ssize_t bytes_read;
	int r;

	/*
	 * Make sure we can open the file (if necessary) before
	 * trying to write the header.
	 */
	if (archive_entry_filetype(entry) == AE_IFREG) {
		if (archive_entry_size(entry) > 0) {
			fd = open(srcpath, O_RDONLY);
			if (fd < 0) {
				warn("%s: could not open file", srcpath);
				goto cleanup;
			}
		}
	} else {
		archive_entry_set_size(entry, 0);
	}

	r = archive_write_header(cpio->archive, entry);

	if (r != ARCHIVE_OK) {
		archive_errno(cpio->archive);
		warnx("%s: %s", destpath, archive_error_string(cpio->archive));
	}
	if (r == ARCHIVE_FATAL)
		exit(1);

	if (r >= ARCHIVE_WARN && fd >= 0) {
		bytes_read = read(fd, cpio->buff, cpio->buff_size);
		while (bytes_read > 0) {
			r = archive_write_data(cpio->archive, cpio->buff, bytes_read);
			if (r < 0)
				errx(1, "%s", archive_error_string(cpio->archive));
			if (r < bytes_read) {
				warnx("Truncated write; file may have grown while being archived.");
			}
			bytes_read = read(fd, cpio->buff, cpio->buff_size);
		}
	}

cleanup:
	if (fd >= 0)
		close(fd);
	return (0);
}


/*
 * This is used by both out mode (to copy objects from disk into
 * an archive) and pass mode (to copy objects from disk to
 * an archive_write_disk "archive").
 */
static int file_to_archive(struct cpio *cpio, const char *srcpath) {
	struct stat st;
	const char *destpath;
	struct archive_entry *entry, *spare;
	int lnklen;
	int r;

	/* Create an archive_entry describing the source file. */
	entry = archive_entry_new();
	if (entry == NULL)
		errx(1, "Couldn't allocate entry");
	archive_entry_copy_sourcepath(entry, srcpath);

	/* Get stat information. */
	r = stat(srcpath, &st);
	if (r != 0) {
		warn("Couldn't stat \"%s\"", srcpath);
		archive_entry_free(entry);
		return (0);
	}

	archive_entry_copy_stat(entry, &st);

	/* If its a symlink, pull the target. */
	if (S_ISLNK(st.st_mode)) {
		lnklen = readlink(srcpath, cpio->buff, cpio->buff_size);
		if (lnklen < 0) {
			warn("%s: Couldn't read symbolic link", srcpath);
			archive_entry_free(entry);
			return (0);
		}
		cpio->buff[lnklen] = 0;
		archive_entry_set_symlink(entry, cpio->buff);
	}

	destpath = srcpath;
	if (destpath == NULL)
		return (0);
	archive_entry_copy_pathname(entry, destpath);

	/*
	 * If we're trying to preserve hardlinks, match them here.
	 */
	spare = NULL;
	if (cpio->linkresolver != NULL && !S_ISDIR(st.st_mode)) {
		archive_entry_linkify(cpio->linkresolver, &entry, &spare);
	}

	if (entry != NULL) {
		r = entry_to_archive(cpio, entry);
		archive_entry_free(entry);
	}
	if (spare != NULL) {
		if (r == 0)
			r = entry_to_archive(cpio, spare);
		archive_entry_free(spare);
	}
	return (r);
}

int cpio_create(char **filenames, int elements) {
	struct cpio *cpio;
	struct archive_entry *entry, *spare;
	int r, i;
	static char buff[16384];
	int output_buf_size = 33554432;
	char *output_buf = calloc(1, output_buf_size);
	size_t output_buf_used = 0;

	cpio = calloc(1, sizeof(struct cpio));

	cpio->buff = buff;
	cpio->buff_size = sizeof(buff);
	cpio->format = "newc";
	cpio->extract_flags = ARCHIVE_EXTRACT_NO_AUTODIR;
	cpio->extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER;
	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
	cpio->extract_flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
	cpio->extract_flags |= ARCHIVE_EXTRACT_PERM;
	cpio->extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
	cpio->extract_flags |= ARCHIVE_EXTRACT_ACL;
	cpio->bytes_per_block = 512;
	cpio->filename = NULL;

	cpio->archive = archive_write_new();
	if (cpio->archive == NULL)
		errx(1, "Failed to allocate archive object");

	r = archive_write_set_format_by_name(cpio->archive, cpio->format);
	if (r != ARCHIVE_OK)
		errx(1, "%s", archive_error_string(cpio->archive));
	archive_write_set_bytes_per_block(cpio->archive, cpio->bytes_per_block);
	cpio->linkresolver = archive_entry_linkresolver_new();
	archive_entry_linkresolver_set_strategy(cpio->linkresolver, archive_format(cpio->archive));

	r = archive_write_open_memory(cpio->archive, output_buf, output_buf_size, &output_buf_used);
	if (r != ARCHIVE_OK) {
		errx(1, "%s", archive_error_string(cpio->archive));
	}

	for (i = 0; i < elements; i++) {
		file_to_archive(cpio, filenames[i]);
	}

	/*
	 * The hardlink detection may have queued up a couple of entries
	 * that can now be flushed.
	 */
	entry = NULL;
	archive_entry_linkify(cpio->linkresolver, &entry, &spare);
	while (entry != NULL) {
		entry_to_archive(cpio, entry);
		archive_entry_free(entry);
		entry = NULL;
		archive_entry_linkify(cpio->linkresolver, &entry, &spare);
	}

	r = archive_write_close(cpio->archive);
	if (r != ARCHIVE_OK)
		errx(1, "%s", archive_error_string(cpio->archive));

	archive_write_finish(cpio->archive);
	write(1, output_buf, output_buf_used);

	return 0;
}
