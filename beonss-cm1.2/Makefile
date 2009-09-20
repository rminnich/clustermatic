# beonss -- glibc nss functions for beowulf
# $Id: Makefile,v 1.6 2004/11/04 17:04:13 mkdist Exp $

ETCDIR = /etc
LIBDIR = /lib

BEONSS_LIB = libnss_bproc.so.2

CFLAGS=-Wall -O2

all: $(BEONSS_LIB)
clean:
	rm -f *.o $(BEONSS_LIB)

CC=gcc
LD=ld

$(BEONSS_LIB): nss_bproc.c
	$(CC) -fPIC -shared -o $@ -Wl,-soname,$@ $< -Wl,-Bstatic -lbproc -Wl,-Bdynamic

test: $(BEONSS_LIB) test.o
	ln -s $(BEONSS_LIB) libnss_bproc.so
	gcc -o $@ test.o -L. -lnss_bproc
	rm -f libnss_bproc.so

install: $(BEONSS_LIB)
	cp -ap $(BEONSS_LIB) $(LIBDIR)
	if [ -f $(ETCDIR)/nsswitch.conf ] ; then cat $(ETCDIR)/nsswitch.conf | awk '{ if((/^hosts:/) && !(/bproc/)) { print("#" $$0); printf("hosts:\t"); for(x=2;x<=NF;x++) { if($$x == "dns") printf(" bproc dns"); else printf(" " $$x); } print(""); } else print($$0);}' > /tmp/nsswitch.conf.bproc && mv -f $(ETCDIR)/nsswitch.conf $(ETCDIR)/nsswitch.conf.bak && mv -f /tmp/nsswitch.conf.bproc $(ETCDIR)/nsswitch.conf ; fi
