/*------------------------------------------------------------ -*- C -*-
 *  2 Kernel Monte a.k.a. Linux loading Linux on x86
 *  libmonte.c:  User level kernel loader/interpreter library
 *
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *  Copyright (C) 2000 Scyld Computing Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  $Id: libmonte.c,v 1.18 2004/08/16 20:38:21 mkdist Exp $
 *--------------------------------------------------------------------*/
#define _GNU_SOURCE		/* needed for mremap() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <syscall.h>

#define MAXREGIONS 10
#include "monte.h"

struct monte_boot_t {
    struct monte_param_t   param;
    struct monte_region_t  regions[MAXREGIONS];
    struct kernel_setup_t *setup;
};

/*static struct monte_param_t  params = {0, 0, 0, 0};
  static struct monte_region_t regionlist[MAXREGIONS+1];*/

static long PAGE_SIZE;
static long PAGE_MASK;

/*--- Memory management -------------------------------------------------*/
/* We need to get together the chunks for monte in a nice and page
 * aligned way.  Hence the wackiness down here with mmap. */
static
struct monte_region_t *region_new(struct monte_boot_t *boot, void *destaddr) {
    int i, fd;
    void *addr;

    /* See if we already have a region for this address.  XXX We
     * should really learn to merge regions in region_size */
    for (i=0; i < boot->param.nregions; i++)
	if (boot->regions[i].destaddr == destaddr)
	    return &boot->regions[i];

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1) {
	perror("/dev/zero");
	exit(1);
    }

    addr = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
	perror("mmap(/dev/zero)");
	exit(1);
    }
    close(fd);

    /* Add this thing to the region list */
    boot->regions[boot->param.nregions].addr     = addr;
    boot->regions[boot->param.nregions].destaddr = destaddr;
    boot->regions[boot->param.nregions].size     = PAGE_SIZE;
    boot->param.nregions++;
    return &boot->regions[boot->param.nregions-1];
}

static
void *region_size(struct monte_region_t *r, long size) {
    size = (size + PAGE_SIZE-1) & PAGE_MASK;
    if (r->size < size) {
	r->addr = mremap(r->addr, r->size, size, MREMAP_MAYMOVE);
	if (r->addr == MAP_FAILED) {
	    perror("mremap");
	    exit(1);
	}
	r->size = size;
    }
    return r->addr;
}

/*--------------------------------------------------------------------
 *  Definitions specific to loading Linux
 *------------------------------------------------------------------*/
#if defined(__i386__)
/* Linux loading memory map:
 * 0x00090000  Setup sectors            <- Loaded directly from vmlinuz
 *      (48K)
 * 0x0009C000  Kernel command line
 *
 * 0x00100000  Kernel Data              <- Loaded directly from vmlinuz
 *
 * 0x?????000  Initial ram disk data.
 */
#define MAX_SETUP_SECTS             96
#define MONTE_SETUP_BEGIN   0x00090000
#define MONTE_CMDLINE_BEGIN 0x0009C000
#define MONTE_KERNEL_BEGIN  0x00100000
#define BS_SIG_VAL              0xaa55
#define SETUP_SIG_VAL           "HdrS"
#define CMDLINE_MAGIC           0xA33F
#define DFL_SETUP_SECTS              4

struct kernel_setup_t {
    char __pad1[2];
    unsigned short ext_mem_k;	/*   2: */
    char __pad1_1[28];
    unsigned short cmd_magic;	/*  32: Command line magic 0xA33F */
    unsigned short cmd_offset;	/*  34: Command line offset from 0x90000 */
    char __pad2[124];
    struct {
	unsigned short length;
	unsigned char table[0];
    } sys_desc;			/* 160: */
    char __pad2_1[318];
    unsigned long  alt_mem_k;   /* 480: */
    char __pad2_2[13];
    unsigned char  setup_sects; /* 497: setup size in sectors (512) */
    unsigned short root_flags;	/* 498: 1 = ro ; 0 = rw */
    unsigned short kernel_para;	/* 500: kernel size in paragraphs (16) */
    unsigned short swap_dev;	/* 502: */
    unsigned short ram_size;	/* 504: */
    unsigned short vid_mode;	/* 506: */
    unsigned short root_dev;	/* 508: */
    unsigned short boot_flag;	/* 510: signature*/
    unsigned short jump;        /* 512: jump to startup code */
    char signature[4];          /* 514: "HdrS" */
    unsigned short version;     /* 518: header version */
    unsigned short x,y,z;       /* 520: LOADLIN hacks */
    unsigned short ver_offset;  /* 526: kernel version string */
    unsigned char loader;       /* 528: loader type */
    unsigned char flags;        /* 529: loader flags */
    unsigned short a;           /* 530: more LOADLIN hacks */
    unsigned long start;        /* 532: kernel start, filled in by loader */
    unsigned long ramdisk;      /* 536: RAM disk start address */
    unsigned long ramdisk_size; /* 540: RAM disk size */
    unsigned short b,c;         /* 544: bzImage hacks */
    unsigned short heap_end_ptr;/* 548: end of free area after setup code */
    char __pad3[2];
    unsigned long  cmd_line_ptr;/* 552: pointer to cmd line (32bit, linear) */
    unsigned long  ramdisk_max;	/* 556: ?? highest address for an initrd */
};
/*static struct kernel_setup_t *setup_header;*/

static
int save_old_setup(struct monte_boot_t *boot) {
    int rootdev;

    rootdev = boot->setup->root_dev;

    memset(boot->setup, 2, PAGE_SIZE);
    if (syscall(__NR_reboot,MONTE_MAGIC_1,MONTE_MAGIC_2,1,boot->setup) != 0) {
	fprintf(stderr, "Failed to grab real mode configuration data.\n");
	return -1;
    }
    boot->setup->root_dev = rootdev;

#if 0
    /* Dump out the contents of the setup block */
    printf("ext_mem_k       = 0x%x\n", (int) boot->setup->ext_mem_k);
    printf("cmd_magic       = 0x%x\n", (int) boot->setup->cmd_magic);
    printf("cmd_offset      = 0x%x\n", (int) boot->setup->cmd_offset);

    printf("sys_desc.length = 0x%x\n", (int) boot->setup->sys_desc.length);
    printf("alt_mem_k       = 0x%x\n", (int) boot->setup->alt_mem_k);
    printf("setup_sects     = 0x%x\n", (int) boot->setup->setup_sects);
    printf("root_flags      = 0x%x\n", (int) boot->setup->root_flags);
    printf("kernel_para     = 0x%x\n", (int) boot->setup->kernel_para);
    printf("swap_dev        = 0x%x\n", (int) boot->setup->swap_dev);
    printf("ram_size        = 0x%x\n", (int) boot->setup->ram_size);
    printf("vid_mode        = 0x%x\n", (int) boot->setup->vid_mode);
    printf("root_dev        = 0x%x\n", (int) boot->setup->root_dev);
    printf("boot_flag       = 0x%x\n", (int) boot->setup->boot_flag);
    printf("jump            = 0x%x\n", (int) boot->setup->jump);
    printf("signature       = \"%.4s\"\n",   boot->setup->signature);
    printf("version         = 0x%x\n", (int) boot->setup->version);

    printf("ramdisk         = 0x%x\n", (int) boot->setup->ramdisk);
    printf("ramdisk_size    = 0x%x\n", (int) boot->setup->ramdisk_size);
    printf("ramdisk_max     = 0x%x\n", (int) boot->setup->ramdisk_max);
#endif
    return 0;
}

int monte_load_linux_kernel(struct monte_boot_t *boot,
			    const void *buffer, long size){
    void *setup_data, *kernel_data;
    struct monte_region_t *region;
    struct kernel_setup_t *stmp;

    stmp = (struct kernel_setup_t *)buffer;
    /* Sanity check */
    /* Check for the kernel setup signature */
    if (stmp->boot_flag != BS_SIG_VAL) {
	fprintf(stderr, "monte: Boot signature not found.\n");
	return -1;
    }
    /* Sanity check number of sectors */
    if (stmp->setup_sects > MAX_SETUP_SECTS) {
	fprintf(stderr, "monte: number of setup sectors too large: %d"
		" (max %d)\n",(int) stmp->setup_sects, MAX_SETUP_SECTS);
	return -1;
    }
    /* Check for that setup signature. */
    if (strncmp(stmp->signature, SETUP_SIG_VAL,
		strlen(SETUP_SIG_VAL)) != 0) {
	fprintf(stderr, "monte: Kernel image setup signature not found.\n");
	return -1;
    }
    
    /* Setup the region for the setup code */
    region = region_new(boot, (void *)MONTE_SETUP_BEGIN);
    setup_data = region_size(region, (stmp->setup_sects+1)*512);
    boot->setup = setup_data;

    memcpy(setup_data, buffer, (stmp->setup_sects+1)*512);
    printf("monte: kernel setup   : %8d bytes at %p\n",
	   ((int) stmp->setup_sects)*512, (void*)MONTE_SETUP_BEGIN);

    buffer += (stmp->setup_sects+1)*512; /* update buffer pointers */
    size   -= (stmp->setup_sects+1)*512;

    /* The number of kernel "paragraphs" is getting overflowed by
     * todays kernels.  Ignore it and just load the rest of the data
     * we have. */
    region = region_new(boot, (void*)boot->setup->start);
    kernel_data = region_size(region, size);
    memcpy(kernel_data, buffer, size);
    printf("monte: kernel code    : %8d bytes at %p\n",
	   (int) size, (void *) boot->setup->start);

    if (boot->param.flags & MONTE_PROTECTED) {
	if (save_old_setup(boot)) return -1;
	boot->param.entrypoint = boot->setup->start;
    } else
	boot->param.entrypoint = 0x90200000; /* Real mode 9020:0000 */

    /* XXXXX FIX ME XXXXXX THIS IS A HACK!!! XXXXXX */
    if (boot->param.entrypoint == 0) {
	printf("monte: Forcing entry point to 0x100000\n");
	boot->param.entrypoint = 0x100000;
    }
    /* XXXXX FIX ME XXXXXX THIS IS A HACK!!! XXXXXX */

    boot->setup->loader       = 0x50;	/* Set the loader type. */
    boot->setup->ramdisk      = 0;
    boot->setup->ramdisk_size = 0;
    boot->setup->cmd_magic    = 0;
    boot->setup->cmd_offset   = 0;

    return 0;
}
#endif
/*--------------------------------------------------------------------
 * Alpha kernel loader
 */
#if defined(__alpha__)

/*
 * Definitions of __pa and __va have to agree with include/asm-alpha/page.h
 * in Linux sources.
 *
 * USE_48_BIT_KSEG will be not defined for "generic" kernels
 */

#ifdef USE_48_BIT_KSEG
#define PAGE_OFFSET		0xffff800000000000
#else
#define PAGE_OFFSET		0xfffffc0000000000
#endif

#define __pa(x)			((unsigned long) (x) - PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long) (x) + PAGE_OFFSET))

#include <elf.h>		/* Alpha kernels are just ELF images */
#include <zlib.h>
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
static char gz_magic[2] = {0x1f, 0x8b};

static
int skip_gzip_header(const unsigned char * src, int size) {
    int idx;
    if (size < 10 || memcmp(src, gz_magic, 2))
	return -1;
    if (src[2] != Z_DEFLATED) {
	fprintf(stderr, "unsupported compression method (%d).\n", (int)src[3]);
	return -1;
    }
    idx = 10;			/* skip past header, mtime and xos */
    if (src[3] & EXTRA_FIELD)
	idx += src[idx] + (src[idx+1]<<8) + 2;
    if (src[3] & ORIG_NAME) {
	while (src[idx]) idx++;	idx++; /* skip over string */
    }
    if (src[3] & COMMENT) {
	while (src[idx]) idx++;	idx++; /* skip over string */
    }
    if (src[3] & HEAD_CRC) 
	idx += 2;
    return idx;
}

#define CHUNK 65536
int gunzip(const void *src, int size, void **uncomp, long *uncomp_size) {
    int r;
    long  bsize;
    void *tmp;
    long data_start;
    z_stream zs;

    memset(&zs, 0, sizeof(zs));
    *uncomp = 0;
    bsize = 0;

    data_start = skip_gzip_header(src, size);
    if (data_start == -1) return -1;
    zs.next_in  = (void *)(src  + data_start);
    zs.avail_in = size - data_start;

    printf("monte: uncompressing..."); fflush(0);
    /* wackiness required for gzip */
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK)
	return -1;
    
    do {
	if (zs.avail_out == 0) {
	    tmp = realloc(*uncomp, bsize+CHUNK);
	    if (!tmp) {
		if (*uncomp) free(*uncomp);
		inflateEnd(&zs);
	    }
	    *uncomp = tmp;
	    zs.next_out  = (*uncomp)+bsize;
	    zs.avail_out = CHUNK;
	    bsize += CHUNK;
	}
	if (zs.avail_in == 0) {
	    /* Barf */
	    fprintf(stderr, "Out of data unzipping.\n");
	    if (*uncomp) free(*uncomp);
	    inflateEnd(&zs);
	    return -1;
	}
	r = inflate(&zs, Z_NO_FLUSH);
    } while (r == Z_OK);
    if (r != Z_STREAM_END) {
	/* Barf */
	fprintf(stderr, "Decompression error.\n");
	if (*uncomp) free(*uncomp);
	inflateEnd(&zs);
	return -1;
    }
    printf("done\n");
    inflateEnd(&zs);
    *uncomp_size = zs.total_out;
    return 0;
}

static
int load_elf_image(struct monte_boot_t *boot, const void *buffer, long size) {
    int i;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct monte_region_t *region;
    void *kernimage;

    /* Super simple ELF loader that makes gobs of assumptions that
     * won't be valid anywhere except Linux ELF kernel images */
    ehdr = (Elf64_Ehdr *) buffer;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
	fprintf(stderr, "not an ELF file.\n");
	return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
	fprintf(stderr, "ELF object is not an ELF64 object.\n");
	return -1;
    }

    phdr = (Elf64_Phdr *)(buffer + ehdr->e_phoff);
    for (i=0; i < ehdr->e_phnum; i++) {
	/* Load a program section */
	/* Setup a region for this thing */
	region    = region_new(boot, (void*)__pa(phdr[i].p_vaddr));
	kernimage = region_size(region, phdr[i].p_memsz+(1024*PAGE_SIZE));

	/* Load data and zero the rest (BSS) */
	printf("monte: kernel code    : %8ld bytes at %p\n",
	       phdr[i].p_filesz, (void*) __pa(phdr[i].p_vaddr));
	memcpy(kernimage, buffer + phdr[i].p_offset, phdr[i].p_filesz);
	memset(kernimage + phdr[i].p_filesz, 0,
	       phdr[i].p_memsz - phdr[i].p_filesz);	
    }

    boot->param.entrypoint = ehdr->e_entry;
    printf("monte: entry point    : %p\n", (void*)boot->param.entrypoint);
    return 0;
}


int monte_load_linux_kernel(struct monte_boot_t *boot,
			    const void *buffer, long size) {
    int err = -1;
    void *buffer2;
    long size2;
    
    if (gunzip(buffer, size, &buffer2, &size2) != 0) {
	/* decompression failed - try to load directly */
	buffer2 = (void*)buffer;
	size2   = size;
    }

    /* try it as a simple ELF image */
    err = load_elf_image(boot, buffer2, size2);

    if (buffer2 != buffer) free(buffer2); /* free it if necessary */
    return err;
}

#endif

int monte_load_linux_initrd(struct monte_boot_t *boot,
			    const void *buffer, long size) {
    long initrd_addr;
    void *ramdisk_data;
    struct monte_region_t *region;
    /*--- XXX Disgusting hack ---------------------------------------------
     * We can't tell how big memory is very easily from user space.
     * /proc/meminfo is close but a pain to read.  In stead we just
     * stat /proc/kcore.  This seems easiest and comes closest to the
     * correct answer.  What a mess.
     *-------------------------------------------------------------------*/
    struct stat buf;
    if (stat("/proc/kcore", &buf) == -1) {
	buf.st_size = 32*1024*1024; /* a random guess if /proc isn't mounted.*/
    }

    initrd_addr = ((buf.st_size/4)*3) & PAGE_MASK;
    
    /* Next problem: We don't know how big this ram disk image is a
     * head of time so just start loading a page at a time :P */
    region = region_new(boot, (void *) initrd_addr);
    ramdisk_data = region_size(region, size);
    memcpy(ramdisk_data, buffer, size);
    printf("monte: initial ramdisk: %8ld bytes at %p\n",
	   size, (void *)initrd_addr);

    /* Put the right bits in RAM so the kernel will find the initrd */
#if defined(__i386__)
    boot->setup->ramdisk      = initrd_addr;
    boot->setup->ramdisk_size = size;
#elif defined(__alpha__)
    region = region_new(boot, (void *) __pa(boot->param.entrypoint - 0x6000));
    ramdisk_data = region_size(region, PAGE_SIZE);
    ramdisk_data += 0x100;
    ((long*)ramdisk_data)[0] = __va(initrd_addr);
    ((long*)ramdisk_data)[1] = size;
#else
#error No initrd argument placement code for this architecture.
#endif
    return 0;
}

#if defined(__i386__)
int monte_load_linux_command_line(struct monte_boot_t *boot, char *cmdline) {
    struct monte_region_t *region;
    char *cmd_line;

    /* Setup the kernel command line */
    region = region_new(boot, (void *) MONTE_CMDLINE_BEGIN);
    cmd_line = region_size(region, PAGE_SIZE);
    boot->setup->cmd_line_ptr = MONTE_CMDLINE_BEGIN;
    boot->setup->cmd_magic    = CMDLINE_MAGIC;
    boot->setup->cmd_offset   = MONTE_CMDLINE_BEGIN - MONTE_SETUP_BEGIN;
    strcpy(cmd_line, cmdline);
    printf("monte: command line   : \"%s\"\n", cmdline);
    return 0;
}
#endif
#if defined(__alpha__)
int monte_load_linux_command_line(struct monte_boot_t *boot, char *cmdline) {
    struct monte_region_t *region;
    char *cmd_line;

    /* Setup the kernel command line */

    /* On alpha, the command line sits in the zero page at address
     * ?0a000 which is in the region before the kernel entry
     * point...   Also, one page should be enough for it.*/
    region = region_new(boot, (void *) __pa(boot->param.entrypoint - 0x6000));
    cmd_line = region_size(region, PAGE_SIZE);
    strcpy(cmd_line, cmdline);
    printf("monte: command line   : \"%s\"\n", cmdline);
    return 0;
}
#endif

struct monte_boot_t *monte_new(int flags) {
    struct monte_boot_t *boot;
    if (!(boot = malloc(sizeof(*boot)))) {
	errno = ENOMEM;
	return 0;
    }
    memset(boot, 0, sizeof(*boot));
    boot->param.flags = flags;
    boot->param.regions = boot->regions;
    return boot;
}

int monte_boot(struct monte_boot_t *boot) {
    int i, npages=0;
    
    for (i=0; i < boot->param.nregions; i++) {
	printf("monte: region: %6ld pages at %p\n",
	       boot->regions[i].size / PAGE_SIZE, boot->regions[i].destaddr);
	npages += boot->regions[i].size / PAGE_SIZE;
	if (mlock(boot->regions[i].addr, boot->regions[i].size)) {
	    perror("mlock");
	    return -1;
	}
    }
    printf("monte:         %6d pages to be relocated.\n", npages);
#if defined(__i386__)
    if (boot->param.flags & MONTE_PROTECTED)
	printf("monte: entry point (protected mode): %p\n",
	       (void *)boot->param.entrypoint);
    else
	printf("monte: entry point (real mode): %04lx:%04lx\n",
	       (boot->param.entrypoint >>16) & 0xffff,
	       boot->param.entrypoint & 0xffff);
#else
    printf("monte: entry point: %p\n",
	   (void *)boot->param.entrypoint);
#endif
    fflush(stdout);
    sync(); sync(); sync();
    return syscall(__NR_reboot, MONTE_MAGIC_1, MONTE_MAGIC_2, 0, &boot->param);
}


static void pginit(void) __attribute__((constructor));
static void pginit(void) {
    PAGE_SIZE = getpagesize();
    PAGE_MASK = ~(PAGE_SIZE-1);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
