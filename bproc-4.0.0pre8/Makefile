#
# Copyright (c) 2000 Erik Arjan Hendriks <erik@hendriks.cx>
#
# $Id: Makefile,v 1.39 2004/10/01 17:48:21 mkdist Exp $
.PHONY: all vmadump kernel daemons clients doc modules clean install-clients \
	install-sys install-modules modules_install install-doc install
prefix=
export prefix

include Makefile.conf

CC=gcc

#LINUX:=$(shell echo $(LINUX) | sed -e 's|^\([^/]\)|../\1|')

ifeq ($(BUILD_STUB),)
	INSTALL_TARGETS:=install-clients install-sys install-doc \
	install-vheaders
	BUILD_TARGETS=daemons clients doc
ifneq ($(LINUX),)
	BUILD_TARGETS+=kernel
	INSTALL_TARGETS+=install-modules
endif
else
	INSTALL_TARGETS=install-clients
	BUILD_TARGETS=clients
endif

all: $(BUILD_TARGETS)

#vmadump:
#	$(MAKE) -C vmadump vmadump.ko
kernel:
	$(MAKE) -C kernel
daemons:
	$(MAKE) -C daemons
clients:
	$(MAKE) -C clients
doc:
	$(MAKE) -C doc

# Build modules ONLY (this builds both)
modules:
	$(MAKE) -C kernel

clean:
	$(MAKE) -C vmadump  clean
	$(MAKE) -C kernel   clean
	$(MAKE) -C daemons  clean
	$(MAKE) -C clients  clean

install-clients:
	$(MAKE) -C clients  install

install-sys:
	$(MAKE) -C daemons  install

modules_install: install-modules
install-modules:
	$(MAKE) -C kernel LINUX=$(LINUX) INSTALL_MOD_PATH=$(prefix) install

install-doc:
	$(MAKE) -C doc install

install-vheaders:
	$(MAKE) -C vmadump install-headers

install: $(INSTALL_TARGETS)

##
##  Quick install for testing
##

mods: vmadump_ kernel_
	/sbin/insmod -m > vmadump.map     vmadump/vmadump.ko
	/sbin/insmod -m > bproc.map       kernel/bproc.ko

rmods:
	-/sbin/rmmod bproc
	-/sbin/rmmod vmadump

#cough:
#	$(MAKE) -s -C $(LINUX) -f Makefile -f $(PWD)/coughitup cflags
