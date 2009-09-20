/*------------------------------------------------------------ -*- C -*-
 *  2 Kernel Monte a.k.a. Linux loading Linux on x86
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
 *  $Id: monte.h,v 1.4 2001/10/03 21:45:02 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _MONTE_H
#define _MONTE_H

/*--- Definitions for syscall interface (not for the faint of heart) ------
 *
 * Call monte from user space like this:
 * syscall(__NR_reboot, MONTE_MAGIC_1, MONTE_MAGIC_2, 0, (struct monte_param_t) param);
 * param is a pointer to a struct monte_param_t
 *-----------------------------------------------------------------------*/
/* Magic values for reboot interface */
#define MONTE_MAGIC_1 0x326b6d6f
#define MONTE_MAGIC_2 0x6e746522

#define MONTE_PROTECTED   0x00000001 /* jump to entry point in protected mode (default = real mode) */
#define MONTE_PCI_DISABLE 0x00000002 /* disable PCI bus masters before restarting */
#define MONTE_NOT_REALLY  0x80000000 /* do everything except actually restarting */
struct monte_region_t {
    void *addr;			/* Address in my memory space (must be page aligned) */
    void *destaddr;		/* Address to put this stuff. (must be page aligned) */
    long size;			/* The size of this region. */
};

struct monte_param_t {
    int flags;
    int nregions;
    unsigned long entrypoint;	/* Address to jump to */
    struct monte_region_t *regions;
};

/*--- User Interface ----------------------------------------------------*/
/* Functions for use by normal humans... */
struct monte_boot_t;
struct monte_boot_t *monte_new(int flags);
int monte_boot(struct monte_boot_t *boot);
int monte_load_linux_kernel(struct monte_boot_t *, const void *, long);
int monte_load_linux_initrd(struct monte_boot_t *, const void *, long);
int monte_load_linux_command_line  (struct monte_boot_t *boot, char *cmdline);

#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
