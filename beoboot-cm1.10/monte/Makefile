# 2 Kernel Monte
# $Id: Makefile,v 1.15 2004/08/09 18:46:08 mkdist Exp $
ifeq ($(BUILD_KMONTE_KO),y)	#-------------------------------------
obj-m := kmonte.o
else	#-------------------------------------------------------------
VERSION:=cm1.10

LINUX:=/lib/modules/$(shell uname -r)/build

prefix:=
CC:=gcc
CFLAGS:=-Wall -g -DPACKAGE_VERSION='"$(VERSION)"'
AS86:=as86
LD86:=ld86
CPP:=gcc -E


all: monte kmonte.ko libmonte.a
clean:
	rm -f *.a *.o monte
	rm -f monte.txt monte*.html
	rm -rf *.ko *.mod.c .*.cmd .tmp_versions

# Linux 2.6.x build wackiness
KCFLAGS:=$(EXTRAKDEFS) -DPACKAGE_VERSION=$(VERSION)
.PHONY: kmonte.ko
kmonte.ko:
	@$(MAKE) --no-print-directory -C $(LINUX) KBUILD_EXTMOD=`pwd` \
	    EXTRA_CFLAGS="$(KCFLAGS)" BUILD_KMONTE_KO=y

modules_install:
	@$(MAKE) --no-print-directory -C $(LINUX) KBUILD_EXTMOD=`pwd` \
	    EXTRA_CFLAGS="$(KCFLAGS)" BUILD_KMONTE_KO=y modules_install
install_module: modules_install

#--- User space stuff
monte: monte.c monte.h libmonte.a
	$(CC) $(CFLAGS) -o $@ $< -L. -lmonte -lz

libmonte.o: libmonte.c monte.h
	$(CC) $(CFLAGS) -c -o $@ $<
libmonte.a: libmonte.o
	ar rcs libmonte.a libmonte.o


install: modules_install
	install -m 644 monte.8  $(prefix)/usr/man/man8
	install -m 755 monte    $(prefix)/sbin

# This is only needed to do 'make install'
kver: kver.c
	$(CC) $(CFLAGS) -o $@ $<

# Stuff for building small ASM test images.
#.SUFFIXES: .o86 .s .S .com .bin .img
.S.s:
	$(CPP) $< -o $@
.s.o86:
	if ! $(AS86) -2 -j -w $< -o $@ ; then rm -f $@ ; exit 1 ; fi
.o86.img:
	$(LD86) -d -s -o $@ $<
#
#.bin.img:
#	(cat bsect $< ; dd if=/dev/zero bs=512 count=4 2>/dev/null) > $@
#test1.img: test1.S
test.img: test.S
#test3.img: test3.S
endif
