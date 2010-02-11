#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/statfs.h>
#include <dirent.h>
#include <fuse.h>
#include "bproc.h"


#if defined(__APPLE__)
#define __FreeBSD__ 10
#endif

#include "fuse_kernel.h"

/* Somehow the FUSE guys forgot to define this one! */
struct fuse_create_out {
	struct fuse_entry_out e;
	struct fuse_open_out o;
};

typedef struct FuseMsg FuseMsg;
struct FuseMsg
{
	FuseMsg *next;
	unsigned char *buf;
	int nbuf;
	struct fuse_in_header *hdr;	/* = buf */
	void *tx;	/* = hdr+1 */
};

extern int debug;

extern int fusefd;
extern int fuseeof;
extern int fusebufsize;
extern int fusemaxwrite;
extern FuseMsg *fusemsglist;
extern char *fusemtpt;

void		freefusemsg(FuseMsg *m);
int
fusedumpreq(FILE *f, struct fuse_in_header *hdr, void *a);
int
fusedumpresp(FILE *f, struct fuse_in_header *reqhdr, struct fuse_out_header *ohdr, void *a);
int		initfuse(char *mtpt);
void	waitfuse(void);
FuseMsg*	readfusemsg(void);
void		replyfuse(FuseMsg *m, void *arg, int narg);
void		replyfuseerrno(FuseMsg *m, int e);
void		replyfuseerrstr(FuseMsg*);

void unmountatexit(void);
