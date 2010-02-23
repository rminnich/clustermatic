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
