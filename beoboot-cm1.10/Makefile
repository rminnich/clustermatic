# Clustermatic Boot utilities
# Erik Hendriks <hendriks@lanl.gov>
#
# $Id: Makefile,v 1.69 2004/11/03 23:18:01 mkdist Exp $
VERSION:=cm1.10
export VERSION

#---------------------------------------------------------------------
# Autoconf-like prefixes 
prefix=

# Installation configuration.
prefix:=
libdir:=/usr/lib
mandir:=/usr/share/man
includedir:=/usr/include
sbindir:=/usr/sbin
bindir:=/usr/bin
sysconfdir:=/etc
moduledir:=/lib/modules
localstatedir:=/var/log

CC=gcc
LD=ld
CFLAGS=-O2 -Wall -Wstrict-prototypes -g \
       -DPACKAGE_VERSION='"$(VERSION)"' -DCONFIGDIR='"$(CONFIGDIR)"' \
       -DLOGDIR='"$(LOGDIR)"' -DLIBDIR='"$(LIBDIR)"'

LDFLAGS=-L. -lbproc

SBIN_PROGS:=beoserv
BIN_PROGS:=beoboot
BEOB_PROGS:=mkbootimg kver nodeadd modhelper
BEOB_OBJS:=init2.o
MOD_LIST:=
PROGS:=$(SBIN_PROGS) $(BIN_PROGS) $(BEOB_PROGS)

#---------------------------------------------------------------------
# auto-configuration stuff
LINUX:=/lib/modules/$(shell uname -r)/build
ARCH:=$(shell uname -m | sed -e s/i.86/i386/)
ifeq ($(ARCH),i386)
    HAVE_MONTE:=y
    CC+=-m32
    LD+=-melf_i386
endif
ifeq ($(ARCH),alpha)
    HAVE_MONTE:=y
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

ifeq ($(HAVE_MONTE),y)
    CFLAGS+=-DHAVE_MONTE
    BEOB_OBJS+=init1.o
    ifneq ($(LINUX),)
        MOD_LIST+=monte/kmonte.ko
    endif
endif
#---------------------------------------------------------------------
CONFIGDIR:=$(sysconfdir)/clustermatic
LOGDIR:=$(localstatedir)/clustermatic
LIBDIR:=$(libdir)/beoboot


all: $(PROGS) $(BEOB_OBJS) $(MOD_LIST) node_up_
.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

# We link with most of our libraries now so that we don't need this
# junk around when we're building boot images.
boottest: $(INIT_OBJS)
	$(CC) -o $@ $^ -lz -lcmconf -lbproc

beoserv.o: beoserv.c
boot.o: boot.c cmconf.h boot.h module.h beoboot_boothooks.h
chkswap.o: chkswap.c
cmconf.o: cmconf.c list.h cmconf.h
kver.o: kver.c
mkbootimg.o: mkbootimg.c boot.h
modhelper.o: modhelper.c
module.o: module.c module.h
nodeadd.o: nodeadd.c cmconf.h boot.h
nodeup.o: nodeup.c cmconf.h
rarp.o: rarp.c cmconf.h boot.h beoboot_boothooks.h
rarpserv.o: rarpserv.c cmconf.h boot.h
recv.o: recv.c cmconf.h beoboot_boothooks.h send.h
send.o: send.c cmconf.h send.h list.h

#---------------------------------------------------------------------
#
# Beoserv - RARP + boot image server
#
beoserv: beoserv.o rarpserv.o send.o nodeup.o cmconf.o
	$(CC) $(CFLAGS) -o $@ $^ -lbproc


#---------------------------------------------------------------------
#
# Boot up program.  2 versions, 1 for each phase.
#
boot1.o: boot.c boot.h monte/monte.h beoboot_boothooks.h module.h
	$(CC) $(CFLAGS) -DPHASE1 -c -o $@ $<
init1.o: boot1.o rarp.o recv.o module.o cmconf.o monte/libmonte.a
	$(LD) -r -o $@ boot1.o rarp.o recv.o module.o cmconf.o -Lmonte -lmonte

boot2.o: boot.c boot.h beoboot_boothooks.h module.h
	$(CC) $(CFLAGS) -DPHASE2 -c -o $@ $<
init2.o: boot2.o rarp.o module.o cmconf.o
	$(LD) -r -o $@ $^

monte/libmonte.a:
	$(MAKE) -C monte libmonte.a

# The debugging version....
boot_debug.o: boot.c boot.h monte/monte.h beoboot_boothooks.h module.h
	$(CC) $(CFLAGS) -DDEBUG -c -o $@ $<
boot: boot_debug.o recv.o rarp.o module.o cmconf.o monte/libmonte.a
	$(CC) -o $@ boot_debug.o recv.o rarp.o cmconf.o -Lmonte -lmonte -lbproc

#---------------------------------------------------------------------

node_up_:
	$(MAKE) -C node_up

node_up_install_:
	$(MAKE) -C node_up install

#-- Misc Helper Programs
mkbootimg: mkbootimg.o
	$(CC) $(CFLAGS) -o $@ $^

nodeadd: nodeadd.o cmconf.o
	$(CC) $(CFLAGS) -o $@ $^

# the bfd version number is too distribution specific.  statically link it.
kver: kver.c
	$(CC) $(CFLAGS) -o $@ $< -Wl,-Bstatic -lbfd -liberty -Wl,-Bdynamic

modhelper: modhelper.o
	$(CC) $(CFLAGS) -o $@ $<

# A few debug targets
rarpserv: rarpserv.o cmconf.o
	$(CC) $(CFLAGS) -o $@ $^ -lbproc
send: send.o cmconf.o
	$(CC) $(CFLAGS) -o $@ $^ -lbproc
recv: recv.o cmconf.o
	$(CC) $(CFLAGS) -o $@ $^

#PCITABLE=/usr/share/kudzu/pcitable

.PHONY: monte/kmonte.ko
monte/kmonte.ko:
	$(MAKE) -C monte LINUX=$(LINUX) EXTRAKDEFS="$(EXTRAKDEFS)" kmonte.ko

install_common: $(PROGS) $(BEOB_OBJS) node_up_install_
#     /etc
	mkdir -p $(prefix)$(CONFIGDIR)
	if [ ! -f $(prefix)$(CONFIGDIR)/config ] ; then \
	    install -m 644 config $(prefix)$(CONFIGDIR)/config; \
	fi
	if [ ! -f $(prefix)$(CONFIGDIR)/config.boot ] ; then \
	    install -m 644 config.boot $(prefix)$(CONFIGDIR)/config.boot; \
	fi

#     rc.d scripts
	mkdir -p $(prefix)$(sysconfdir)/init.d
	install -m 755 rc.clustermatic \
	    $(prefix)$(sysconfdir)/init.d/clustermatic

#     User binaries and helper programs
	mkdir -p $(prefix)$(bindir)
	for binary in $(BIN_PROGS); do \
	    install -m 755 $$binary $(prefix)$(bindir); \
	done
	mkdir -p $(prefix)$(sbindir)
	for binary in $(SBIN_PROGS);do \
	    install -m 755 $$binary $(prefix)$(sbindir) ; \
	done
	mkdir -p $(prefix)$(libdir)/beoboot/bin
	for binary in $(BEOB_PROGS);do \
	    install -m 755 $$binary $(prefix)$(libdir)/beoboot/bin ; \
	done
	mkdir -p $(prefix)$(libdir)/beoboot/lib
	for obj in $(BEOB_OBJS); do \
	    install -m 644 $$obj $(prefix)$(libdir)/beoboot/lib ; \
	done
	mkdir -p $(prefix)$(libdir)/beoboot/plugins

#     Install the include file for building plugins
	mkdir -p $(prefix)/usr/include
	install -m 644 beoboot_boothooks.h $(prefix)/usr/include

# Architecture specific parts of the install.
#      The Boot loader we use on x86
	if [ $(ARCH) = i386 ] ; then \
	  mkdir -p $(prefix)$(libdir)/beoboot/boot && \
	  install -m 644 syslinux/syslinux.bs $(prefix)$(libdir)/beoboot/boot &&\
	  install -m 644 syslinux/ldlinux.sys $(prefix)$(libdir)/beoboot/boot;\
	fi

#     Subdirs...
	$(MAKE) -C node_up install

ifneq ($(MOD_LIST),)
install_modules:
	$(MAKE) -C monte install_module
else
install_modules:
endif

install: install_common install_modules install_docs

install_docs:
#     Manual pages
	cd doc && \
	    for sec in 5 8 ; do \
	        mkdir -p $(prefix)$(mandir)/man$$sec || exit 1; \
	        for pg in *.$$sec ; do \
	            install -m 644 $$pg $(prefix)$(mandir)/man$$sec/$$pg && \
	                gzip -f9 $(prefix)$(mandir)/man$$sec/$$pg || \
	                exit 1; \
	        done ; \
	    done

clean:
	$(MAKE) -C monte   clean
	$(MAKE) -C node_up clean
	rm -f *.o $(SBIN_PROGS) $(BEOB_PROGS)

distclean: clean
