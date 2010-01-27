#
#
# $Id: Makefile,v 1.48 2004/11/03 21:08:43 mkdist Exp $

include ../Makefile.conf

.c.o:
	$(CC) $(CFLAGS) $(DEFS) -c -o $@ $<

ALL:=bpmaster bpslave libbpslave.a bptrace
all: $(ALL)
clean:
	rm -f $(ALL) *.o

bptrace.o: bptrace.c list.h debug.h bproc.h \
  ../clients/sys/bproc_common.h messages.h
cmconf.o: cmconf.c list.h cmconf.h
db.o: db.c bproc.h ../clients/sys/bproc_common.h \
  ../clients/sys/bproc.h
master.o: master.c bproc.h ../clients/sys/bproc_common.h \
  ../clients/sys/bproc.h list.h cmconf.h messages.h debug.h
slave.o: slave.c list.h bproc.h ../clients/sys/bproc_common.h \
  ../clients/sys/bproc.h messages.h debug.h


bptrace: bptrace.o
	$(CC) -o $@ $^ 

bpmaster: master.o cmconf.o
	$(CC) $^ -o bpmaster
bpslave: slave.o 
	$(CC) $^ -o bpslave

libbpslave.a: slave.o
	objcopy --redefine-sym main=slave_main \
		--redefine-sym .main=.slave_main \
		slave.o lslave.o
	ar rcs $@ lslave.o 
	rm -f lslave.o

install: $(ALL)
	install -s -m 755 bpmaster  $(prefix)$(sbindir)/bpmaster
	install -s -m 755 bpslave   $(prefix)$(sbindir)/bpslave
	install -m 755 libbpslave.a $(prefix)$(libdir)/libbpslave.a
	if [ ! -f $(prefix)$(CONFIGDIR)/config ] ; then \
	    mkdir -p $(prefix)$(CONFIGDIR) ; \
	    install -m 644 node_config $(prefix)$(CONFIGDIR)/config  ; \
	fi
	install -m 755 -d $(prefix)$(LOGDIR)
