#ifndef _BOOT_H
#define _BOOT_H

#include <stdint.h>
#include <sys/bproc.h>

/* Defaults */
#define BPROC_PORT   2223	/* THIS SHOULD COME FROM SOMEWHERE ELSE! */
#define FILE_PORT    4711
#define BOOT_FILE    "/var/clustermatic/boot.img"

/*--- Boot image definitions ---------------------------------------*/
struct beoboot_header {
	char magic[4];
	uint8_t arch;
	uint8_t flags;
	uint16_t cmdline_size;	/* length of command line (including null) */
	/* The alpha chunk is a backward compatibility hack.  The original
	 * assumption was that integer sizes didn't matter because we
	 * would never mix architectures.  x86_64 + i386 broke that
	 * assumption.  It's fixed for that combination and the future.
	 * However, alpha needs a little hack now... */
#ifdef __alpha__
	unsigned long kernel_size;
	unsigned long initrd_size;
#else
	uint32_t kernel_size;
	uint32_t initrd_size;
#endif
};

#define BEOBOOT_MAGIC     "BeoB"
#define BEOBOOT_ARCH_I386  1
#define BEOBOOT_ARCH_ALPHA 2
#define BEOBOOT_ARCH_PPC   3
#define BEOBOOT_ARCH_PPC64 4
#if defined(__i386__) || defined(__x86_64__)
#define BEOBOOT_ARCH BEOBOOT_ARCH_I386
#elif defined(__alpha__)
#define BEOBOOT_ARCH BEOBOOT_ARCH_ALPHA
#elif defined(powerpc)
#define BEOBOOT_ARCH BEOBOOT_ARCH_PPC
#elif defined(__powerpc64__)
#define BEOBOOT_ARCH BEOBOOT_ARCH_PPC64
#else
#error Unsupported architecture.
#endif
#define BEOBOOT_INITRD_PRESENT 1
/*------------------------------------------------------------------*/

/*--------------------------------------------------------------------
 * RARP Definitions
 *------------------------------------------------------------------*/
#define BOOTFILE_MAXLEN 100
struct arpdata_eth_ip {
	unsigned char src_eth[6];
	unsigned char src_ip[4];
	unsigned char tgt_eth[6];
	unsigned char tgt_ip[4];
	unsigned char netmask[4];
	struct bproc_version_t version;
	uint16_t bproc_port;
	uint16_t file_port;	/* File resend port */
	char boot_file[BOOTFILE_MAXLEN + 1];
};

#include <net/if.h>
struct rarp_data_t {
	char interface[IFNAMSIZ];
	struct in_addr server_ip;
	struct in_addr my_ip;
	struct in_addr netmask;
	int bproc_port;
	int file_port;
	char boot_file[BOOTFILE_MAXLEN + 1];
};

/* RARP parameters */
#define RARP_INITIAL_DELAY  1000000	/* (usec) 1s   between rarp requests */
#define RARP_MAX_DELAY    100000000	/* (usec) 100s max delay between requests */
#define RARP_BACKOFF            1.2	/* Factor for exponential backoff */
#define RARP_MAX_TIME           600	/* (sec) total maximum time for RARP */
#define RARP_RAND               0.1	/* fraction of delay to randomly +/- */

int rarp(struct rarp_data_t *data);
/*------------------------------------------------------------------*/

/* Boot image download parameters */
#define CONNECT_DELAY        1	/* Retry delay for boot server connects. */
#define CONNECT_MAX_TRIES 1200	/* Number of tries before we reboot. */

#define FATAL_REBOOT_DELAY  30	/* Delay before machine reset on fatal error. */

/*--- misc functions ---*/
void fatal(char *fmt, ...) __attribute__ ((noreturn));

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
