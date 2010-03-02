#ifndef CPIO_H_
#define CPIO_H_

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

int cpio(void *buf, size_t len, const char *append_string);

/* Creates a cpio archive in memory and sets the buf pointer and the resulting buf size
 * Input:
 *   char ***filenames:  Should be an array of filenames
 *   int total_files:    Total number of files in the array
 *   void **cpio_buf:    Ptr to where the cpio buffer will be stored
 *   int *cpio_buf_size: Ptr to the size of the cpio buffer
 * Output:
 *   char ***filenames:  Any additional sym resolved links will be added to the end of the list
 *   int total_files:    *total_files will have the total # of files, including new addtions
 *   void **cpio_buf:    *cpio_buf will point to the cpio buffer in memory
 *   int *cpio_buf_size: *cpio_buf_size will stove  the size of the cpio buffer
 * Returns:
 *  -1 on error, 0 on success */
int cpio_create(char ***filenames_, int *total_files_, void **cpio_buf, int *cpio_buf_size);

#endif /*CPIO_H_*/
