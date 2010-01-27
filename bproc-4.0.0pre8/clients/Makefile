#
# Erik Hendriks <erik@hendriks.cx>
#
# $Id: Makefile,v 1.60 2004/10/09 01:07:48 mkdist Exp $

include ../Makefile.conf
LIBS+=-L. -lbproc

LIB_MAJ=4
LIB_MIN=0
LIB_PATCH=0

BINS=bpsh
SOLINK=libbproc.so
SONAME=$(SOLINK).$(LIB_MAJ)
SO_LIB=$(SONAME).$(LIB_MIN).$(LIB_PATCH)
A_LIB=libbproc.a

LIBOBJS:=bproc.o
# This crud is so that we can work on systems whose C libraries.  The
# build rules are basically the same except that we need use the
# headers from our linux source tree to the syscall number in this
# case.
ifneq ($(HAVE_XATTR),y)
    LIBOBJS+=xattr.o
    CFLAGS+=-I$(LINUX)
endif


all: $(BINS) $(A_LIB) $(SO_LIB) $(SONAME) $(SOLINK) compat
clean: compat_clean
	rm -f *.o $(BINS) $(SO_LIB) $(A_LIB) $(SONAME) $(SOLINK)

install: $(A_LIB) $(SO_LIB) $(BINS) compat_install
# Headers
	install -m 644 sys/bproc.h        $(prefix)$(includedir)/sys
	install -m 644 sys/bproc_common.h $(prefix)$(includedir)/sys
# Libraries
	install -m 644 $(A_LIB)           $(prefix)$(libdir)
	install -m 755 $(SO_LIB)          $(prefix)$(libdir)
	ln -sf $(SONAME) $(prefix)$(libdir)/$(SOLINK)
#	-/sbin/ldconfig
# Programs
	install -s -m 755 bpsh            $(prefix)$(bindir)
	install -s -m 755 bpcp            $(prefix)$(bindir)
	install -s -m 755 bpstat          $(prefix)$(bindir)
	install -s -m 755 bpctl           $(prefix)$(sbindir)
	install -s -m 755 bplib           $(prefix)$(sbindir)

##
##  Library stuff
##
%.o: %.c
	$(CC) -fPIC $(CFLAGS) $(DEFS) -c -o $@ $<

bproc.o: bproc.c ../include/bproc.h sys/bproc.h sys/bproc_common.h
xattr.o: xattr.c xattr.h

$(A_LIB): $(LIBOBJS)
	ar cru $(A_LIB) $^
	ranlib $(A_LIB)

$(SO_LIB) $(SONAME) $(SOLINK): $(LIBOBJS)
	$(CC) -shared -Wl,-soname -Wl,$(SONAME) -o $(SO_LIB) $^
# For linking:
	ln -sf $(SO_LIB) $(SONAME)
	ln -sf $(SONAME) $(SOLINK)

#--------------------------------------------------------------------------
#  32-bit compatiblity libraries
#
ifeq ($(COMPAT32),y)
SO_LIB32=libbproc_32.so.$(LIB_MAJ).$(LIB_MIN).$(LIB_PATCH)
A_LIB32=libbproc_32.a

compat: $(A_LIB32) $(SO_LIB32)
compat_clean:
	rm -f $(A_LIB32) $(SO_LIB32)
##
##  Compat....  (build 32-bit compat library on 64-bit)
##
%_32.o: %.c
	$(COMPAT32_CC) -fPIC $(COMPAT32_CFLAGS) $(DEFS) -c -o $@ $<

bproc.32.o: bproc.c ../include/bproc.h sys/bproc.h sys/bproc_common.h
xattr.32.o: xattr.c xattr.h

$(A_LIB32): $(LIBOBJS:%.o=%_32.o)
	ar cru $(A_LIB32) $^
	ranlib $(A_LIB32)

$(SO_LIB32): $(LIBOBJS:%.o=%_32.o)
	$(COMPAT32_CC) -shared -Wl,-soname -Wl,$(SONAME) -o $(SO_LIB32) $^

compat_install: $(A_LIB32) $(SO_LIB32)
# Libraries (renaming the 32 bit stuff as we go...)
	install -m 755 -d $(prefix)$(lib32dir)
	install -m 644 $(A_LIB32)   $(prefix)$(lib32dir)/$(A_LIB)
	install -m 755 $(SO_LIB32)  $(prefix)$(lib32dir)/$(SO_LIB)
	ln -sf $(SONAME)            $(prefix)$(lib32dir)/$(SOLINK)
else
compat:
compat_clean:
compat_install:
endif
#--------------------------------------------------------------------------



##
##  Client programs
##
bsh.o:    bsh.c    sys/bproc.h sys/bproc_common.h
bpsh.o:   bpsh.c   sys/bproc.h sys/bproc_common.h
bpcp.o:   bpcp.c   sys/bproc.h sys/bproc_common.h
bpctl.o:  bpctl.c  sys/bproc.h sys/bproc_common.h
bplib.o:  bplib.c  sys/bproc.h sys/bproc_common.h

bpstat.o: bpstat.c sys/bproc.h  sys/bproc_common.h

bsh: bsh.o $(SOLINK)
	$(CC) bsh.o -o bsh $(LIBS)
bpsh: bpsh.o  $(SOLINK)
	$(CC) bpsh.o -o bpsh $(LIBS)
bpcp: bpcp.o $(SOLINK)
	$(CC) bpcp.o -o bpcp $(LIBS)
bpstat: bpstat.o $(SOLINK)
	$(CC) -o $@ bpstat.o $(LIBS)
bpctl: bpctl.o $(SOLINK)
	$(CC) bpctl.o -o bpctl $(LIBS)
bplib: bplib.o
	$(CC) bplib.o -o bplib $(LIBS)



.PHONY: all clean compat compat_clean compat_install
