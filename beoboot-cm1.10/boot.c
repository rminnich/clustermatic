/*------------------------------------------------------------ -*- C -*-
 *  boot.c:
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * This is a derivative work of Scyld Beoboot
 *  Erik Arjan Hendriks <hendriks@lanl.gov>
 *  Daniel Ridge <newt@scyld.com>
 *  Copyright (C) 2000 Scyld Computing Corporation
 *
 *  Portions are:
 *  Copyright(C) 2004 University of California.  LA-CC Number 01-67.
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
 *  $Id: boot.c,v 1.61 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/

#define _GNU_SOURCE		/* strndup */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <syscall.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include "cmconf.h"

#include "boot.h"
#include "module.h"
#include "beoboot_boothooks.h"

#ifdef PHASE1
#include "monte/monte.h"
#include "send.h"		/* For send/recv definitions */
#endif

#define CONFIG_FILE "config.boot"

static int phase = 0;
static struct rarp_data_t rarp_data;

/*--------------------------------------------------------------------
 *
 *------------------------------------------------------------------*/
static char *current_hook = 0;
void fatal(char *fmt, ...)
{
	va_list valist;
	va_start(valist, fmt);
	vfprintf(stderr, fmt, valist);
	fprintf(stderr, "\nA fatal error has occurred.\n");

#ifndef DEBUG
	fprintf(stderr, "Resetting machine in %d seconds.\n",
		FATAL_REBOOT_DELAY);
	sleep(FATAL_REBOOT_DELAY);
	reboot(RB_AUTOBOOT);
	fprintf(stderr, "Failed to reboot.  Wow, that sucks.\n");
	while (1)
		pause();
#else
	exit(1);
#endif
}

void console_log_v(char *fmt, va_list valist)
{
	if (current_hook)
		fprintf(stderr, "boot: %s: ", current_hook);
	else
		fputs("boot: ", stderr);
	vfprintf(stderr, fmt, valist);
	fflush(0);
}

void console_log(char *fmt, ...)
{
	va_list valist;
	va_start(valist, fmt);
	console_log_v(fmt, valist);
	va_end(valist);
}

static
void *check_malloc(size_t bytes)
{
	void *m;
	m = malloc(bytes);
	if (!m)
		fatal("Out of memory allocating %d bytes", bytes);
	return m;
}

static
char *str_merge(char **strs)
{
	int i, len;
	char *str;

	len = 0;
	for (i = 0; strs[i]; i++)
		len += strlen(strs[i]) + 1;

	str = check_malloc(len);
	for (i = 0; strs[i]; i++) {
		strcat(str, strs[i]);
		if (strs[i + 1])
			strcat(str, " ");
	}
	return str;
}

/*--------------------------------------------------------------------
 * Hook stuff for plugins
 *------------------------------------------------------------------*/
/* Hook explanations:
 *
 * first           - first thing - before boot does anything
 * phase1_pre_rarp - After driver load, before RARPing in phase1
 * phase2_pre_rarp - After driver load, before RARPing in phase2
 * phsae2_last     - last thing before becoming init
 */
struct boot_hook_t *boot_hook_first = 0;
struct boot_hook_t *boot_hook_phase1_pre_rarp = 0;
struct boot_hook_t *boot_hook_phase2_pre_rarp = 0;
struct boot_hook_t *boot_hook_phase1_pre_rarp_every = 0;
struct boot_hook_t *boot_hook_phase2_pre_rarp_every = 0;
struct boot_hook_t *boot_hook_phase1_post_rarp = 0;
struct boot_hook_t *boot_hook_phase2_post_rarp = 0;
struct boot_hook_t *boot_hook_phase2_last = 0;

struct boot_conf_t *boot_conf = 0;

#define run_hooks(hn) run_hooks_( boot_hook_ ## hn )
void run_hooks_(struct boot_hook_t *hooks)
{
	struct boot_hook_t *h;
	for (h = hooks; h; h = h->next) {
		current_hook = h->name;
		h->func();
		current_hook = 0;
	}
}

/*--------------------------------------------------------------------
 *  Module configuration handling code
 *------------------------------------------------------------------*/
/*
 *  module_scan - get alias information for modules
 */
static
int module_scan(void)
{
	DIR *dir;
	struct dirent *de;
	int len;
	struct module_t *mod;
	int count;
	const char *alias;

	console_log("Scanning modules...\n");

	dir = opendir(module_path);
	if (!dir) {
		console_log("module_path (%s): %s\n", module_path,
			    strerror(errno));
		return -1;
	}

	while ((de = readdir(dir))) {
		len = strlen(de->d_name);
		if (len > 3 && strcmp(de->d_name + len - 3, ".ko") == 0) {
			de->d_name[len - 3] = 0;	/* chop off .ko */

			mod = module_get(0, de->d_name);

			count = 0;
			alias = module_modinfo_first(mod->map, mod->size);
			while (alias) {
				if (strncmp(alias, "alias=", 6) == 0)
					count++;
				alias =
				    module_modinfo_next(mod->map, mod->size,
							alias);
			}
			mod->aliases =
			    malloc(sizeof(*mod->aliases) * (count + 1));

			count = 0;
			alias = module_modinfo_first(mod->map, mod->size);
			while (alias) {
				if (strncmp(alias, "alias=", 6) == 0) {
					mod->aliases[count++] = strdup(alias);
				}
				alias =
				    module_modinfo_next(mod->map, mod->size,
							alias);
			}
			mod->aliases[count] = 0;
		}
	}
	closedir(dir);
	return 0;
}

/* Shut up gcc warning about this not being used */
static void module_remove_all(void) __attribute__ ((unused));
static
void module_remove_all(void)
{
	struct module_t *mod;
	install_seq--;
	while (install_seq > 0) {
		for (mod = modlist; mod; mod = mod->next)
			if (mod->installed == install_seq) {
				console_log("Removing module \"%s\"\n",
					    mod->name);
				if (delete_module(mod->loaded_name, 0) != 0) {
					console_log
					    ("   delete module failed: %s\n",
					     strerror(errno));
				}
				break;
			}
		install_seq--;
	}
}

static
int mod_config_callback(struct cmconf *conf, char **args)
{
	struct module_t *mod;
	if (strcmp(args[0], "modarg") == 0) {
		mod = module_get(0, args[1]);
		/* Ignore this if this modules doesn't seem to be present on
		 * our boot image. */
		if (mod) {
			if (strlen(mod->args) > 0) {
				console_log
				    ("WARNING: duplicate module arguments for %s "
				     "(using last set)\n", args[1]);
			}
			free(mod->args);
			mod->args = str_merge(args + 2);
		}
	}
	return 0;
}

/*--------------------------------------------------------------------
 * Device scanning code
 *------------------------------------------------------------------*/
struct scan_key_t {
	const char *name;	/* for pretty printing... */
	const char *alias_tag;	/* tag to look for in the alias */
	const char *alias_pattern;	/* pattern for data after tag */
	const char *file;	/* file to find the value in */
	const char *file_pattern;	/* scanf() pattern to get from the file */

	/* Scratch values used by the scanner */
	int valid;		/* value found ? */
	long value;		/* scratch space for values... */
};

struct scan_class_t {
	const char *name;	/* this is the class name */
	const char *dir;	/* each dev is a file entry in here... */
	struct scan_key_t *keys;	/* list of keys that we use to match */
};

#define SYSFS_PATH "/sys"
#define PCI_PATH   SYSFS_PATH "/bus/pci/devices"
#define USB_PATH   SYSFS_PATH "/bus/usb/devices"

static
struct scan_key_t pci_scan_keys[] = {
	{"vendor", "v", "%08lx", PCI_PATH "/%s/vendor", "0x%lx"},
	{"device", "d", "%08lx", PCI_PATH "/%s/device", "0x%lx"},
	{"subvendor", "sv", "%08lx", PCI_PATH "/%s/subsystem_vendor", "0x%lx"},
	{"subdevice", "sd", "%08lx", PCI_PATH "/%s/subsystem_device", "0x%lx"},
	{"baseclass", "bc", "%02lx", PCI_PATH "/%s/class", "0x%02lx"},
	{"subclass", "sc", "%02lx", PCI_PATH "/%s/class", "0x%*02lx%02lx"},
	{"interface", "i", "%02lx", PCI_PATH "/%s/class",
	 "0x%*02lx%*02lx%02lx"},
	{0, 0, 0, 0, 0, 0, 0}
};

static
struct scan_key_t usb_scan_keys[] = {
	{"vendor", "v", "%04lx", USB_PATH "/%s/idVendor", "%04lx"},
	{"prod", "p", "%04lx", USB_PATH "/%s/idProduct", "%04lx"},
	{"devclass", "dc", "%02lx", USB_PATH "/%s/bDeviceClass", "%02lx"},
	{"devsubclass", "dsc", "%02lx", USB_PATH "/%s/bDeviceSubClass",
	 "%02lx"},
	{"devproto", "dp", "%02lx", USB_PATH "/%s/bDeviceProtocol", "%02lx"},
	{"ifclass", "ic", "%02lx", USB_PATH "/%s/bInterfaceClass", "%02lx"},
	{"ifsubclass", "isc", "%02lx", USB_PATH "/%s/bInterfaceSubClass",
	 "%02lx"},
	{"ifproto", "ip", "%02lx", USB_PATH "/%s/bInterfaceProtocol", "%02lx"},
	{0, 0, 0}
};

static
struct scan_class_t scan_classes[] = {
	{"pci", PCI_PATH, pci_scan_keys},
	{"usb", USB_PATH, usb_scan_keys},
	{0, 0, 0}
};

static
int generic_read_sysfs(const char *path_pattern, const char *key,
		       const char *id_pattern, ...)
{
	int r;
	char *path;
	FILE *f;
	va_list scanf_args;

	/* Assemble the path name */
	path = alloca(strlen(path_pattern) + strlen(key) + 1);
	sprintf(path, path_pattern, key);

	f = fopen(path, "r");
	if (!f)
		return 0;

	va_start(scanf_args, id_pattern);
	r = vfscanf(f, id_pattern, scanf_args);
	va_end(scanf_args);
	fclose(f);

	return r;
}

static
int compare_alias(struct scan_class_t *sc, const char *alias)
{
	const char *p;
	struct scan_key_t *sk;
	int valid;
	long value;

	if (strncmp(alias, "alias=", 6) != 0)	/* not an alias line... */
		return -1;

	p = strchr(alias, ':');
	if (!p)
		return -1;

	if (strncmp(alias + 6, sc->name, (p - alias) - 6) != 0)	/* check class name */
		return -1;

	alias = p + 1;
	for (sk = sc->keys; sk->name; sk++) {
		/* Horrible, horrible, horrible presumption: no tag that we're
		 * looking for is a substring of another tag.  This is true so
		 * far. */
		p = strstr(alias, sk->alias_tag);
		if (p) {
			valid = (sscanf(p + strlen(sk->alias_tag),
					sk->alias_pattern, &value) > 0);
		} else {
			valid = 0;
		}

		/* What to do here:
		 *                         alias
		 *                    Valid  Missing
		 *                  +-------+-------+
		 *  sk        Valid | Match |  OK   |
		 * from             +-------+-------+
		 * device   Missing |  BAD  |  OK   |
		 *                  +-------+-------+
		 */
		/* Compare */
		if (valid) {
			if (!sk->valid || (value != sk->value))
				return -1;
		}
	}
	return 0;		/* MATCH! */
}

static
int device_probe(struct scan_class_t *class)
{
	DIR *dir;
	struct dirent *de;
	struct scan_key_t *sk;
	int i;
	struct module_t *mod;

	dir = opendir(class->dir);
	if (!dir) {
		if (errno != ENOENT) {
			console_log("%s: %s\n", class->dir, strerror(errno));
			return -1;
		}
		return 0;
	}

	for (de = readdir(dir); de; de = readdir(dir)) {
		if (de->d_name[0] == '.')
			continue;

		/* Get all the key values for the device */
		for (sk = class->keys; sk->alias_pattern; sk++) {
			sk->valid = generic_read_sysfs(sk->file, de->d_name,
						       sk->file_pattern,
						       &sk->value);
		}

		for (mod = modlist; mod; mod = mod->next) {
			if (mod->aliases) {
				for (i = 0; mod->aliases[i]; i++) {
					if (compare_alias
					    (class, mod->aliases[i]) == 0
					    && !mod->installed) {
						modprobe(mod, 0);

						/* Do this so that we don't end up retrying
						 * the same module over and over again. */
						if (!mod->installed)
							mod->installed = -1;
					}
				}
			}
		}
	}
	closedir(dir);
	return 0;
}

static
int device_dump(struct scan_class_t *class)
{
	DIR *dir;
	struct dirent *de;
	struct scan_key_t *sk;

	dir = opendir(class->dir);
	if (!dir) {
		if (errno != ENOENT) {
			fprintf(stderr, "%s: %s\n", class->dir,
				strerror(errno));
			return -1;
		}
		return 0;
	}

	for (de = readdir(dir); de; de = readdir(dir)) {
		if (de->d_name[0] == '.')
			continue;

		/* Get all the key values for the device */
		for (sk = class->keys; sk->alias_pattern; sk++) {
			sk->valid = generic_read_sysfs(sk->file, de->d_name,
						       sk->file_pattern,
						       &sk->value);
		}

		fprintf(stderr, "%s (%s):", class->name, de->d_name);
		for (sk = class->keys; sk->alias_pattern; sk++) {
			fprintf(stderr, "%s", sk->alias_tag);
			if (sk->valid)
				fprintf(stderr, "%08lX", sk->value);
			else
				fprintf(stderr, "*");
		}
		fprintf(stderr, "\n");
	}
	closedir(dir);
	return 0;

}

/*--------------------------------------------------------------------
 * Configuration handling code
 *
 * Note: We always want to limp along if possible.  In order to make
 * sure the configuration loader loads as much configuration as
 * possible, none of these callbacks should ever return an error.
 *------------------------------------------------------------------*/
static
int modprobe_callback(struct cmconf *conf, char **args)
{
	if (strcmp(args[0], "insmod") == 0 || strcmp(args[0], "modprobe") == 0) {
		struct module_t *mod;
		char *modargs;
		mod = module_get(0, args[1]);
		modargs = args[2] ? str_merge(args + 2) : mod->args;
		if (modprobe(mod, modargs))
			console_log("configuration: modprobe failure for: %s\n",
				    args[1]);
	}
	return 0;
}

static struct cmconf_option configoptions[];	/* This one has them all.. */
static
int phase_callback(struct cmconf *conf, char **args)
{
	int num;
	if (!args[1])
		return 0;
	num = args[1][0] - '0';	/* sleaze... */
	if (phase == num)
		return cmconf_process_args(conf, args + 2, configoptions);
	return 0;
}

/*------------------------------------------------------------------*/

/* This is the catch-all that allows plugins to add configuration
 * options config.boot */
static
int config_other(struct cmconf *conf, char **args)
{
	struct boot_conf_t *bc;
	for (bc = boot_conf; bc; bc = bc->next) {
		if (strcmp(bc->tag, args[0]) == 0 &&
		    (bc->phase == 0 || bc->phase == phase)) {
			cmconf_process_args(conf, args + 1, bc->conflist);
			/* Always return success... We don't want failures in
			 * plugins to screw everything up... */
			return 0;
		}
	}
	return 0;
}

static
struct cmconf_option configoptions[] = {
	{"modarg", 2, -1, 0, mod_config_callback},
	{"insmod", 1, -1, 1, modprobe_callback},
	{"modprobe", 1, -1, 1, modprobe_callback},
	{"phase", 1, -1, 0, phase_callback},
	{"*", 0, -1, 0, config_other},
	{0,}
};

static
void mount_sysfs(void)
{
	mkdir("/sys", 0755);
	if (mount("none", "/sys", "sysfs", MS_MGC_VAL, 0) == -1) {
		if (errno == EBUSY) {
			console_log("/sys already mounted?\n");
			return;
		}
		perror("mount");
	}
}

static
int configure_interface(struct rarp_data_t *data)
{
	int sockfd;
	struct ifreq ifr;
	struct sockaddr_in addr, bcast;
	struct rtentry route;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!sockfd) {
		console_log("sockte AF_INET, SOCK_DGRAM: %s\n",
			    strerror(errno));
		return -1;
	}

	/* Set interface address */
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, &data->my_ip, sizeof(data->my_ip));
	strcpy(ifr.ifr_name, data->interface);
	memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) == -1) {
		console_log("SIOCSIFADDR %s: %s\n", data->interface,
			    strerror(errno));
		close(sockfd);
		return -1;
	}

	/* Set interface netmask to whatever out response said */
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, &data->netmask, sizeof(data->netmask));
	strcpy(ifr.ifr_name, data->interface);
	memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
	if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) == -1) {
		console_log("SIOCSIFNETMASK %s: %s\n", data->interface,
			    strerror(errno));
		close(sockfd);
		return -1;
	}

	/* Set broadcast addr */
	bcast.sin_family = AF_INET;
	bcast.sin_addr.s_addr = data->my_ip.s_addr | ~data->netmask.s_addr;
	strcpy(ifr.ifr_name, data->interface);
	memcpy(&ifr.ifr_broadaddr, &bcast, sizeof(bcast));
	if (ioctl(sockfd, SIOCSIFBRDADDR, &ifr) == -1) {
		console_log("SIOCSIFBRDADDR %s: %s\n", data->interface,
			    strerror(errno));
		close(sockfd);
		return -1;
	}

	/* Enable this interface (if necessary) */
	strcpy(ifr.ifr_name, data->interface);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
		console_log("SIOCGIFFLAGS %s: %s\n", data->interface,
			    strerror(errno));
		close(sockfd);
		return -1;
	}
	if ((ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
			console_log("SIOCSIFFLAGS %s: %s\n", data->interface,
				    strerror(errno));
			close(sockfd);
			return -1;
		}
	}

	/* Add the default route...  This gets sketchy if we ever
	 * want to handle multiple responses.... */
	memset(&route, 0, sizeof(route));
	/* dst, mask, gw are all zeros for this route... easy :) */
	route.rt_dst.sa_family = AF_INET;
	route.rt_gateway.sa_family = AF_INET;
	memcpy(&(((struct sockaddr_in *)&route.rt_gateway)->sin_addr),
	       &data->server_ip, sizeof(data->server_ip));
	route.rt_genmask.sa_family = AF_INET;
	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_dev = data->interface;
	if (ioctl(sockfd, SIOCADDRT, &route) == -1) {
		console_log("SIOCADDRT %s: %s\n", data->interface,
			    strerror(errno));
		return -1;
	}
	close(sockfd);
	return 0;
}

/*-------------------------------------------------------------------------
 * PHASE1
 *-----------------------------------------------------------------------*/
#ifdef PHASE1
static
void download_boot_image(void)
{
	int len;
	char *command_line;
	struct beoboot_header *header;
	struct monte_boot_t *boot;
	void *bootimg;
	long bootimglen;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr = rarp_data.server_ip;
	addr.sin_port = htons(rarp_data.file_port);
	if (recv_file(&addr, rarp_data.boot_file, &bootimg, &bootimglen))
		fatal("Boot image download failure.");

	/* Check it out */
	header = (struct beoboot_header *)bootimg;
	if (memcmp(&header->magic, BEOBOOT_MAGIC, sizeof(header->magic)))
		fatal("Invalid boot image (Bad magic number)");
	if (header->arch != BEOBOOT_ARCH)
		fatal
		    ("boot image has wrong architecture.  expected %d; got %d\n",
		     (int)BEOBOOT_ARCH, (int)header->arch);

	bootimg += sizeof(*header);
	bootimglen -= sizeof(*header);

	/* Grab the command line */
	command_line = bootimg;
	bootimg += ntohs(header->cmdline_size);
	bootimglen -= ntohs(header->cmdline_size);

	boot = monte_new(MONTE_PROTECTED);
	len = monte_load_linux_kernel(boot, bootimg, header->kernel_size);
	if (len == -1)
		fatal("Failed to load kernel image");
	bootimg += header->kernel_size;
	bootimglen -= header->kernel_size;

	if (header->flags & BEOBOOT_INITRD_PRESENT) {
		len =
		    monte_load_linux_initrd(boot, bootimg, header->initrd_size);
		if (len == -1)
			fatal("Failed to load initial ramdisk");
	}

	if (monte_load_linux_command_line(boot, command_line))
		fatal("Failed to set command line");

	module_remove_all();
	if (monte_boot(boot))	/* contains a delay */
		perror("monte_boot");
	fatal("Monte reboot failed.\n");
}

static void do_phase1(void) __attribute__ ((noreturn));
static
void do_phase1(void)
{
	int i, result;
	struct module_t *mod;

	console_log("Reading config file from: %s\n", CONFIG_FILE);
	if (cmconf_process_file(CONFIG_FILE, configoptions))
		console_log("Error reading config file.\n");

	mod = module_get(0, "kmonte");
	if (!mod)
		fatal("Failed to find kernel module \"kmonte\"\n");
	modprobe(mod, mod->args);
	mod->installed = -1;	/* XXX hack to keep it from getting
				   cleaned up later */
	mount_sysfs();

	/* Load modules and RARP */
	module_scan();
	for (i = 0; scan_classes[i].name; i++)
		device_probe(&scan_classes[i]);

	run_hooks(phase1_pre_rarp);
	run_hooks(phase1_pre_rarp_every);
	result = rarp(&rarp_data);
	while (result == 0) {
		/* recheck for new devices */
		for (i = 0; scan_classes[i].name; i++)
			device_probe(&scan_classes[i]);

		run_hooks(phase1_pre_rarp_every);
		result = rarp(&rarp_data);
	}

	if (result < 0) {
		for (i = 0; scan_classes[i].name; i++)
			device_dump(&scan_classes[i]);
		fatal("RARP failed.");
	}
	if (configure_interface(&rarp_data)) {
		fatal("Failed to configure network interface.\n");
	}

	run_hooks(phase1_post_rarp);

	download_boot_image();
	fatal("Boot image download failed.");
}
#endif

/*-------------------------------------------------------------------------
 * PHASE2
 *-----------------------------------------------------------------------*/
#ifdef PHASE2
extern int slave_main(int argc, char *argv[]);
static
int start_bproc(void)
{
	int pid;
	char serverip[30];
	char serverport[10];
	char *argv[] = { "bpslave", "-devi", serverip, serverport, 0 };
	int argc;

	if (slave_main == 0)
		fatal("The BProc slave daemon is not linked "
		      "with this boot program.\n");

	strcpy(serverip, inet_ntoa(rarp_data.server_ip));
	sprintf(serverport, "%d", rarp_data.bproc_port);

	fprintf(stderr, "boot: starting bpslave:");
	for (argc = 0; argv[argc]; argc++)
		fprintf(stderr, " %s", argv[argc]);
	fprintf(stderr, "\n");

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		optind = 0;	/* re-init getopt */
		exit(slave_main(argc, argv));
	}
	return pid;
}

static
int rm_rf(const char *path)
{
	DIR *d;
	struct dirent *de;
	char *tmp;
	struct stat st;

	if (lstat(path, &st) != 0) {
		fprintf(stderr, "stat(\"%s\"): %s\n", path, strerror(errno));
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		tmp = alloca(NAME_MAX + strlen(path) + 1);
		if (!(d = opendir(path))) {
			fprintf(stderr, "%s: %s\n", path, strerror(errno));
			return -1;
		}

		for (de = readdir(d); de; de = readdir(d)) {
			if (strcmp(de->d_name, ".") == 0
			    || strcmp(de->d_name, "..") == 0)
				continue;

			sprintf(tmp, "%s/%s", path, de->d_name);
			if (rm_rf(tmp)) {
				closedir(d);
				return -1;
			}
		}
		closedir(d);
		/* Special case - we can't rmdir / */
		if (strcmp(path, "/") != 0 && rmdir(path)) {
			fprintf(stderr, "rmdir(\"%s\"): %s\n", path,
				strerror(errno));
			return -1;
		}
	} else {
		if (unlink(path)) {
			fprintf(stderr, "unlink(\"%s\"): %s\n", path,
				strerror(errno));
			return -1;
		}
	}
	return 0;
}

static void do_phase2(void) __attribute__ ((noreturn));
static
void do_phase2(void)
{
	int i, result;
	int pid, bproc_pid;
	struct module_t *mod;
	struct bproc_version_t vers;

	console_log("Reading config file from: %s\n", CONFIG_FILE);
	if (cmconf_process_file(CONFIG_FILE, configoptions))
		console_log("Error reading config file.\n");

	/* Load the modules we require */
	mod = module_get(0, "bproc");
	if (!mod)
		fatal("Failed to load the bproc module.\n");
	modprobe(mod, mod->args);

	/* Load optional modules */
	mod = module_get(0, "supermon_proc");
	if (mod)
		modprobe(mod, mod->args);

	if (bproc_version(&vers) != 0)
		fatal("Failed to get BProc version.\n");
	console_log("BProc version %s-%u-%d\n",
		    vers.version_string, vers.magic, vers.arch);

	mount_sysfs();

	/* Load modules and RARP */
	module_scan();
	for (i = 0; scan_classes[i].name; i++)
		device_probe(&scan_classes[i]);

	run_hooks(phase2_pre_rarp);
	run_hooks(phase2_pre_rarp_every);
	result = rarp(&rarp_data);
	while (result == 0) {
		/* recheck for new devices */
		for (i = 0; scan_classes[i].name; i++)
			device_probe(&scan_classes[i]);

		run_hooks(phase2_pre_rarp_every);
		result = rarp(&rarp_data);
	}

	if (result < 0) {
		for (i = 0; scan_classes[i].name; i++)
			device_dump(&scan_classes[i]);
		fatal("RARP failed.");
	}
	if (configure_interface(&rarp_data)) {
		fatal("Failed to configure network interface.\n");
	}

	console_log("Server IP address: %s\n", inet_ntoa(rarp_data.server_ip));
	console_log("My IP address    : %s\n", inet_ntoa(rarp_data.my_ip));

	/* XXX Clean up our root file system before starting bproc.  We
	 * should be able to completely empty our root fs before starting
	 * the slave daemon. */
	if (umount("/sys")) {
		console_log("Unable to unmount /sys: %s\n", strerror(errno));
	}
	rm_rf("/");

	run_hooks(phase2_last);

	bproc_pid = start_bproc();

	/* IMPORTANT! This program is init! That means that it has to
	 * block on wait(0) pretty much all the time and pick up
	 * orphaned processes.  Otherwise you'll slowly accumulate
	 * zombies on the slave nodes. */
	do {
		pid = wait(0);
	} while (pid != bproc_pid && pid != -1);
	fatal("bproc slave daemon finished.");
}
#endif

/*------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	setlinebuf(stdout);	/* probably shouldn't be necessary */
	setlinebuf(stderr);
	umask(0);

	/* Ungarble serial output ?   I have no idea if this will help */
	{
		int flag;
		flag = fcntl(1, F_GETFL);
		flag |= O_SYNC;
		if (fcntl(1, F_SETFL, flag))
			console_log("setting osync 1: %s\n", strerror(errno));
		flag = fcntl(2, F_GETFL);
		flag |= O_SYNC;
		if (fcntl(2, F_SETFL, flag))
			console_log("setting osync 2: %s\n", strerror(errno));
	}

	module_path = "/modules";	/* where modules live on our boot images */
#ifdef DEBUG
    /*--- Testing mode ---------------------------------------------*/
	{
		int c, i;
		console_log("Entering testing mode.\n");
		while ((c = getopt(argc, argv, "C:r:M:m:pRc")) != -1) {
			switch (c) {
			case 'C':
				console_log("Reading config file from: %s\n",
					    optarg);
				if (cmconf_process_file(optarg, configoptions)) {
					console_log
					    ("Error reading config file.\n");
					exit(1);
				}
				break;
			case 'r':
				if (chroot(optarg) != 0) {
					console_log("chroot: %s\n",
						    strerror(errno));
					exit(1);
				}
				chdir("/");
				mount_sysfs();
				break;
			case 'M':
				module_path = optarg;
				break;
			case 'm':{
					struct module *mod;
					mod = module_get_boot(optarg);
					modprobe(mod, 0);
				} break;
			case 'p':	/* Perform the device scan step */
				module_scan();
				device_probe(&scan_classes[0]);	/* PCI */
				device_probe(&scan_classes[1]);	/* USB */

				while (1) {
					sleep(5);
					console_log("beginning next scan.\n");
					device_probe(&scan_classes[0]);	/* PCI */
					device_probe(&scan_classes[1]);	/* USB */
				}

				break;
			case 'R':{	/* Perform the RARP step. */
					int result;

					/* Load modules and RARP */
					module_scan();
					for (i = 0; scan_classes[i].name; i++)
						device_probe(&scan_classes[i]);

					run_hooks(phase2_pre_rarp);
					run_hooks(phase2_pre_rarp_every);
					result = rarp(&rarp_data);
					while (result == 0) {
						/* recheck for new devices */
						for (i = 0;
						     scan_classes[i].name; i++)
							device_probe
							    (&scan_classes[i]);

						run_hooks
						    (phase2_pre_rarp_every);
						result = rarp(&rarp_data);
					}

					if (result < 0) {
						for (i = 0;
						     scan_classes[i].name; i++)
							device_dump
							    (&scan_classes[i]);
						fatal("RARP failed.");
					}
				}
				break;
			case 'c':
				if (configure_interface(&rarp_data)) {
					fatal
					    ("Failed to configure interface\n");
				}
				break;
#if 0
			case 'R':
				module_remove_all();
				break;
#endif
			default:
				exit(1);
			}
		}
		exit(0);
	}
    /*--------------------------------------------------------------*/
#endif

#ifdef PHASE1
	phase = 1;
#endif
#ifdef PHASE2
	phase = 2;
#endif
	run_hooks(first);

	console_log("LANL beoboot version %s\n", PACKAGE_VERSION);
	console_log("Built %s %s\n", __DATE__, __TIME__);
	console_log("System boot phase %d in progress.\n", phase);

	/* This is a work around for the fact that the cpio archives end
	 * up with random user ids and permissions in them... */
	chown("/", 0, 0);
	chmod("/", 0755);

#ifdef PHASE1
	do_phase1();
#endif
#ifdef PHASE2
	do_phase2();
#endif
	/* NOT REACHED */
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
