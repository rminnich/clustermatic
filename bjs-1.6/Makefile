#
# Erik Hendriks <hendriks@lanl.gov>
#
# $Id: Makefile,v 1.28 2004/11/03 17:49:02 mkdist Exp $
.SUFFIXES: .so
.PHONY: all clean doc install
# Silly auto-magic versioning
VERSION:=1.6

BINPROGS:=bjssub bjsstat bjsctl
SBINPROGS:=bjs
MODULES:=simple.so shared.so filler.so

prefix:=
libdir:=/usr/lib
mandir:=/usr/share/man
includedir:=/usr/include
sbindir:=/usr/sbin
bindir:=/usr/bin
sysconfdir:=/etc
localstatedir:=/var

CONFIGDIR:=$(sysconfdir)/clustermatic
SPOOLDIR:=$(localstatedir)/spool/bjs

CFLAGS:=-Wall -g -I. -O0 -DPACKAGE_VERSION='"$(VERSION)"' \
	-DCONFIGDIR='"$(CONFIGDIR)"'

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
.c.so:
	gcc -fPIC -shared $(CFLAGS) -o $@ $<

all: $(BINPROGS) $(SBINPROGS) $(MODULES)
clean:
	rm -f $(BINPROGS) $(SBINPROGS) $(MODULES) *.o

doc:
	doxygen bjs.doxy

install: all
	mkdir -p  $(prefix)$(sysconfdir)/init.d
	mkdir -p  $(prefix)$(CONFIGDIR)
	mkdir -p  $(prefix)$(bindir)
	mkdir -p  $(prefix)$(sbindir)
	mkdir -p  $(prefix)$(libdir)/bjs
	mkdir -p  $(prefix)$(SPOOLDIR)
	chmod 700 $(prefix)$(SPOOLDIR)
	for n in $(MODULES); do \
	    install -s -m 755 $$n $(prefix)$(libdir)/bjs/$$n || exit 1; \
	done
	for n in $(SBINPROGS); do \
	    install -s -m 755 $$n $(prefix)$(sbindir)/$$n || exit 1; \
	done
	for n in $(BINPROGS); do \
	    install -s -m 755 $$n $(prefix)$(bindir)/$$n || exit 1; \
	done
	install -m 755 rc.bjs $(prefix)$(sysconfdir)/init.d/bjs
	if [ ! -f $(prefix)$(CONFIGDIR)/bjs.conf ] ; then \
	    install -m 644 bjs.conf $(prefix)$(CONFIGDIR)/bjs.conf; \
	fi

bjs: bjs.o sexp.o cmconf.o
	gcc $(CFLAGS) -rdynamic -o $@ $^ -lbproc -ldl

bjs.o: bjs.c bjs.h

bjssub: bjssub.o client.o sexp.o
	gcc -o $@ $^

bjsstat: bjsstat.o client.o sexp.o
	gcc -o $@ $^

bjsctl: bjsctl.o client.o sexp.o
	gcc -o $@ $^

bjs.o: bjs.c cmconf.h sexp.h bjs.h bjs_list.h
bjsctl.o: bjsctl.c bjs.h sexp.h bjs_list.h
bjsstat.o: bjsstat.c bjs.h sexp.h bjs_list.h
bjssub.o: bjssub.c sexp.h bjs.h bjs_list.h
client.o: client.c sexp.h bjs.h bjs_list.h
cmconf.o: cmconf.c bjs_list.h cmconf.h
sexp.o: sexp.c sexp.h

# Policy modules
simple.so: simple.c bjs.h sexp.h bjs_list.h
shared.so: shared.c bjs.h sexp.h bjs_list.h
filler.so: filler.c bjs.h sexp.h bjs_list.h

manual.ind: manual.tex
	latex manual
	makeindex manual

manual.dvi: manual.ind manual.tex
	latex manual
	latex manual
