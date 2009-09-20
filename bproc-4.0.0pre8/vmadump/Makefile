# -------------------------------------------------------------------------
#   Copyright (C) 1999 by Erik Hendriks <erik@hendriks.cx>
# 
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
# 
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
#  $Id: Makefile,v 1.33 2004/08/10 13:54:39 mkdist Exp $
# -------------------------------------------------------------------------
# LINUX=     which linux kernel tree to build against
ifneq ($(BUILD_VMADUMP_KO),)
#---------------------------------------------------------------------
# Linux 2.6.x build goop...
#   The linux 2.6.x build system sucks in this make file.  We use the
#   variable MODULE_BUILD=y to inidicate that the make file should
#   contain only this little scrap.
# The linux kernel goop should define $(ARCH) for us...
obj-m:=vmadump.o
vmadump-objs:=vmadump_common.o vmadump_$(ARCH).o
else #---------------------------------------------------------------------
VERSION:=4.0.0pre8

LINUX:=/lib/modules/$(shell uname -r)/build
CC:=gcc

prefix=
includedir:=/usr/include

DEFS:=
LIBS:=

CFLAGS:=-Wall -DPACKAGE_VERSION='"$(VERSION)"' -g
DIR:=$(shell pwd)
KCFLAGS:=-DPACKAGE_VERSION=$(VERSION)

ifneq ($(NRVMADUMP),)
DEFS+=-D__NR_vmadump=$(NRVMADUMP)
KDEFS+=-D__NR_vmadump=$(NRVMADUMP)
else
LIBS+=-lbproc
endif

ARCH:=$(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)

MODULES:=vmadump.ko
BIN:=vmadtest vmadstress vmadcheck vmadlib
all: $(MODULES) $(BIN)
clean:
	rm -f  $(BIN)
	rm -rf $(MODULES) .tmp_versions *.o *.mod.c .*.cmd

install: install-headers
# Module installation
	@$(MAKE) --no-print-directory -C $(LINUX) \
	    KBUILD_EXTMOD=$(DIR) EXTRA_CFLAGS="$(KCFLAGS)" BUILD_VMADUMP_KO=y \
	    modules_install

install-headers:
# Install the headers
	mkdir -p $(prefix)$(includedir)/sys && \
	    install -m 644 vmadump.h $(prefix)$(includedir)/sys

# testhook.o: testhook.c vmadump.h
# 	$(KCC) $(KCFLAGS) $(KDEFS) -c $<

#---------------------------------------------------------------------
#  Kernel module build with 2.6.x build goop
.PHONY: vmadump.ko
vmadump.ko:
	@$(MAKE) --no-print-directory -C $(LINUX) \
	    KBUILD_EXTMOD=$(DIR) EXTRA_CFLAGS="$(KCFLAGS)" BUILD_VMADUMP_KO=y
#---------------------------------------------------------------------
# Utility programs
vmadtest: vmadtest.c vmadump.h
	$(CC) $(CFLAGS) $(DEFS) -o $@ $< $(LIBS)

vmadstress: vmadstress.c vmadump.h
	$(CC) $(CFLAGS) $(DEFS) -o $@ $< $(LIBS)
vmadcheck: vmadcheck.c vmadump.h
	$(CC) $(CFLAGS) $(DEFS) -I$(LINUX)/include -o $@ $<
vmadlib: vmadlib.c vmadump.h
	$(CC) $(CFLAGS) $(DEFS) -o $@ $<

deps: vmadump_common.c
	$(KCC) $(KCPPFLAGS) $(KCFLAGS) $(KDEFS) -M $<

endif # ifneq ($(BUILD_VMADUMP_KO),)
