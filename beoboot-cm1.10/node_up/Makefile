# Clustermatic node setup
# Erik Hendriks <hendriks@lanl.gov>
#
# $Id: Makefile,v 1.39 2004/11/03 19:19:01 mkdist Exp $
.SUFFIXES: .so .lo .x

VERSION:=cm1.10

prefix:=
libdir:=/usr/lib
mandir:=/usr/share/man
includedir:=/usr/include
sbindir:=/usr/sbin
bindir:=/usr/bin
sysconfdir:=/etc
moduledir:=/lib/modules
localstatedir:=/var/log

CONFIGDIR:=$(sysconfdir)/clustermatic
LOGDIR:=$(localstatedir)/clustermatic

CC=gcc
RPCGEN=rpcgen
DEFS:=-DPACKAGE_VERSION='"$(VERSION)"' \
      -DCONFIGDIR='"$(CONFIGDIR)"' -DLOGDIR='"$(LOGDIR)"'

CFLAGS:=-Wall -I. -I.. -g #-s

#---------------------------------------------------------------------
# auto-configuration stuff
ARCH:=$(shell uname -m | sed -e s/i.86/i386/)
ifeq ($(ARCH),i386)
    CC+=-m32
    LD+=-melf_i386
endif
ifeq ($(ARCH),alpha)
endif
ifeq ($(ARCH),x86_64)
    libdir:=/usr/lib64
    CC+=-m64
    LD+=-melf_x86_64
endif
ifeq ($(ARCH),ppc)
    CC+=-m32
    LD+=-melf32ppc
endif
ifeq ($(ARCH),ppc64)
    libdir:=/usr/lib64
    CC+=-m64
    LD+=-melf64ppc
endif
#---------------------------------------------------------------------
.c.o:
	$(CC) $(CFLAGS) $(DEFS) -c -o $@ $<
#.c.lo:
.c.lo:
	$(CC) -fPIC $(CFLAGS) $(DEFS) -c -o $@ $< 

#%.lo: ../%.c
#	$(CC) -fPIC $(CFLAGS) $(DEFS) -c -o $@ $< 

.lo.so:
	$(CC) $(CFLAGS) $(DEFS) -shared -o $@ $<

PLUGINS:=vmadlib.so miscfiles.so nodeinfo.so \
	ifconfig.so switchnet.so setupfs.so rarp.so kmod.so sysctl.so \
	symdm.so ifdup.so exec.so
ifneq ($(GM_HOME),)
    PLUGINS+=gm.so
endif


all: node_up $(PLUGINS)

vmadlib.so:   vmadlib.c node_up.h
miscfiles.so: miscfiles.c node_up.h
nodeinfo.so:  nodeinfo.c node_up.h
#pciprobe.so:  pciprobe.c node_up.h
ifconfig.so:  ifconfig.c node_up.h
switchnet.so: switchnet.c node_up.h
rarp.so:      rarp.c node_up.h
sysctl.so:    sysctl.c node_up.h
symdm.so:     symdm.c node_up.h
ifdup.so:     ifdup.c node_up.h

#--- The module loader is built out of a few different pieces.
kmod.lo: kmod.c node_up.h ../module.h
module.lo: ../module.c ../module.h
	$(CC) -fPIC $(CFLAGS) \
	    -include node_up.h \
	    -D'modinfo_print(x ...)=log_print(LOG_INFO, x)' \
	    -D'moderr_print(x ...)=log_print(LOG_ERROR, x)' \
	    $(DEFS) -c -o $@ $< 
kmod.so: kmod.lo module.lo
	$(CC) -fPIC $(CFLAGS) $(DEFS) -shared -o $@ kmod.lo module.lo

# setupfs is built out of a bunch of pieces....
nfsmount.h: nfsmount.x
	rm -f $@ && $(RPCGEN) -o $@ -h $<
nfsmount_xdr.c: nfsmount.x nfsmount.h
	rm -f $@ && $(RPCGEN) -o $@ -c $<
nfsmount.lo: nfsmount.c sundries.h mount_constants.h nfs_mount4.h nls.h nfsmount.h
sundries.lo: sundries.c sundries.h
setupfs.lo: setupfs.c node_up.h
setupfs.so: setupfs.lo nfsmount.lo nfsmount_xdr.lo sundries.lo
	$(CC) $(CFLAGS) $(DEFS) -shared -o $@ $^

# These two need to be linked against the nodeinfo library.
nodeinfo.so: nodeinfo.lo
	$(CC) $(CFLAGS) $(DEFS) -shared -o $@ $<

# gm is special because it links against the GM libraries.
gm.lo: gm.c node_up.h
	$(CC) -fPIC $(CFLAGS) -I$(GM_HOME)/include $(DEFS) -c -o $@ $< 
gm.so: gm.lo
	$(CC) $(CFLAGS) $(DEFS) -shared -o $@ $< -L$(GM_HOME)/lib -lgm

iolib.o: iolib.c node_up.h iolib.h
node_up.o: node_up.c node_up.h ../cmconf.h
node_up: node_up.o ../cmconf.o
	$(CC) -o $@ $^ -rdynamic -lbproc -ldl

install: all
	mkdir -p $(prefix)$(libdir)/beoboot/bin
	mkdir -p $(prefix)$(libdir)/beoboot/lib
	mkdir -p $(prefix)$(CONFIGDIR)

#	--- Conditional installation of configuration files
	if [ ! -f $(prefix)$(CONFIGDIR)/node_up.conf ] ; then \
	    install -m 644 node_up.conf $(prefix)$(CONFIGDIR)/node_up.conf; \
	fi
	if [ ! -f $(prefix)$(CONFIGDIR)/node_up ] ; then \
	    install -m 755 node_up.stub $(prefix)$(CONFIGDIR)/node_up; \
	fi
	if [ ! -f $(prefix)$(CONFIGDIR)/nsswitch.conf ] ; then \
	    install -m 644 nsswitch.conf $(prefix)$(CONFIGDIR)/nsswitch.conf; \
	fi
	if [ ! -f $(prefix)$(CONFIGDIR)/fstab ] ; then \
	    install -m 644 fstab $(prefix)$(CONFIGDIR)/fstab; \
	fi

#	--- Installation of binaries.
	install -m 755 node_up $(prefix)$(libdir)/beoboot/bin
	for plugin in $(PLUGINS) ; do \
	    install -m 755 $$plugin $(prefix)$(libdir)/beoboot/lib || exit 1 ;\
	done

clean:
	rm -f *.o *.lo *.so node_up
	rm -f nfsmount.h nfsmount_xdr.c
