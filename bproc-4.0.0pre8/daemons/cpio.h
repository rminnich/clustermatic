#ifndef CPIO_H_
#define CPIO_H_

int cpio(void *buf, size_t len, const char *append_string);
int cpio_create(char **filenames, int elements);

#endif /*CPIO_H_*/
