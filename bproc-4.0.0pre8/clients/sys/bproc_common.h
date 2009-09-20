/*-------------------------------------------------------------------------
 *  bproc_common.h: Beowulf distributed PID space (bproc) definitions
 *     This file contains definitions shared by user space and kernel space.
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: bproc_common.h,v 1.6 2004/10/09 01:07:49 mkdist Exp $
 *-----------------------------------------------------------------------*/
#ifndef _BPROC_COMMON
#define _BPROC_COMMON
/*--- BProc version tag stuff --------------------------------------*/
#define BPROC_MAGIC {'B','P','r'}
enum {
    BPROC_ARCH_X86 = 1,
    BPROC_ARCH_ALPHA = 2,
    BPROC_ARCH_PPC = 3,
    BPROC_ARCH_X86_64 = 4,
    BPROC_ARCH_PPC64 = 5
};
#if defined(__i386__)
#define BPROC_ARCH BPROC_ARCH_X86
#elif defined(__alpha__)
#define BPROC_ARCH BPROC_ARCH_ALPHA
#elif defined(powerpc)
#define BPROC_ARCH BPROC_ARCH_PPC
#elif defined(__x86_64__)
#define BPROC_ARCH BPROC_ARCH_X86_64
#elif defined(__powerpc64__)
#define BPROC_ARCH BPROC_ARCH_PPC64
#else
#error "BProc does not support this architecture."
#endif

struct bproc_version_t {
    char     bproc_magic[3];
    uint8_t  arch;
    uint32_t magic;
    char     version_string[24];
};

/*--- Structs passed in and out of the kernel ----------------------*/


/* All BProc attributes start with this */
#define BPROC_XATTR_PREFIX   "bproc."
#define BPROC_STATE_XATTR    "bproc.state"
#define BPROC_ADDR_XATTR     "bproc.addr"
#define BPROC_XATTR_MAX_NAME_SIZE  63
#define BPROC_XATTR_MAX_VALUE_SIZE 64
#define BPROC_XATTR_MAX      32	/* max # of extended attributes */





#define BPROC_STATE_LEN 15
struct bproc_node_info_t {
    int      node;
    char     status[BPROC_STATE_LEN+1];
    unsigned int mode;
    unsigned int user;
    unsigned int group;
    struct sockaddr addr;
};

/* I/O connection types */
#define BPROC_IO_MAX_LEN      16 /* max # of I/O redirections to setup */
#define BPROC_IO_FILE      0x000
#define BPROC_IO_SOCKET    0x001
#define BPROC_IO_MEMFILE   0x002 /* used internally by bproc */

/* I/O setup flags */
#define BPROC_IO_SEND_INFO 0x001
#define BPROC_IO_DELAY     0x002

struct bproc_io_t {
    int fd;
    short type;
    short flags;
    union {
	struct sockaddr addr;
	struct {
	    int   flags;
	    int   mode;
	    long  offset;
	    char  name[256];
	} file;
	struct {
	    void *base;
	    long  size;
        } mem; 
    } d;
};

struct bproc_proc_info_t {
    int pid;
    int node;
};


/*--- BProc specific errno values ----------------------------------*/

#define BE_BASE           300
#define BE_INVALIDNODE    (BE_BASE+0)
#define BE_NODEDOWN       (BE_BASE+1)
#define BE_SAMENODE       (BE_BASE+2) /* formerly ELOOP */
#define BE_SLAVEDIED      (BE_BASE+3)
#define BE_INVALIDPROC    (BE_BASE+4)

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
