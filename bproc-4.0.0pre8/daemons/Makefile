#
#
# $Id: Makefile,v 1.48 2004/11/03 21:08:43 mkdist Exp $

include ../Makefile.conf

.c.o:
	$(CC) $(CFLAGS) $(DEFS) -c -o $@ $<

ALL:=bpmaster bpslave libbpslave.a bptrace
all: $(ALL)
clean:
	rm -f $(ALL) *.o *~

bptrace.o: bptrace.c list.h debug.h ../include/bproc.h \
 messages.h
cmconf.o: cmconf.c list.h cmconf.h
db.o: db.c ../include/bproc.h 
master.o: master.c ../include/bproc.h  \
	list.h cmconf.h messages.h debug.h
slave.o: slave.c list.h ../include/bproc.h  \
  messages.h debug.h


bptrace: bptrace.o
	$(CC) -o $@ $^ 

bpmaster: master.o cmconf.o cpio.o 
	$(CC)  -static $^ -o bpmaster -larchive -lacl
bpslave: slave.o  cpio.o
	$(CC) $^ -o bpslave -larchive

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
