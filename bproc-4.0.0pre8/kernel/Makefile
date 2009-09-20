#--------------------------------------------------------------------------
# Makefile for kernel bits
# $Id: Makefile,v 1.67 2004/10/01 19:44:48 mkdist Exp $
#--------------------------------------------------------------------------
ifneq ($(BUILD_BPROC_KO),)
ifeq ($(CONFIG_BPROC),y)
CONFIG_BPROC_MOD:=m
else
CONFIG_BPROC_MOD:=n
endif

obj-$(CONFIG_BPROC_MOD) :=bproc.o
bproc-objs:=ghost.o masq.o move.o msg.o hooks.o interface.o \
	    master.o slave.o iod.o bpfs.o ksyscall.o sysdep_$(ARCH).o

# Include vmadump here so that we get the deps right and everything?
#
obj-$(CONFIG_BPROC_MOD) += vmadump.o
vmadump-objs:=../vmadump/vmadump_common.o ../vmadump/vmadump_$(ARCH).o

else #---------------------------------------------------------------------

include ../Makefile.conf

DIR:=$(shell pwd)
KCFLAGS:=-I$(DIR)/../vmadump -I$(DIR)/../clients \
         -DPACKAGE_VERSION=$(VERSION) -DPACKAGE_MAGIC=$(MAGIC) \
	 -DENABLE_DEBUG -DLINUX_TCP_IS_BROKEN

all: bproc.ko
clean:
	rm -rf *.ko .tmp_versions *.o *.mod.c .*.cmd

.PHONY: bproc.ko
bproc.ko:
	@$(MAKE) --no-print-directory -C $(LINUX) \
	    KBUILD_EXTMOD=$(DIR) EXTRA_CFLAGS="$(KCFLAGS)" BUILD_BPROC_KO=y

install:
	@$(MAKE) --no-print-directory -C $(LINUX) \
	    KBUILD_EXTMOD=$(DIR) EXTRA_CFLAGS="$(KCFLAGS)" BUILD_BPROC_KO=y \
	    modules_install
# Mount point for bproc file system
	mkdir -p $(prefix)/bpfs
endif

