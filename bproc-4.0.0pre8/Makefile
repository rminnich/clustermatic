#
# Copyright (c) 2000 Erik Arjan Hendriks <erik@hendriks.cx>
#
# $Id: Makefile,v 1.39 2004/10/01 17:48:21 mkdist Exp $
.PHONY: all daemons clients doc modules clean install-clients \
	install-sys  install-doc install
prefix=
export prefix

include Makefile.conf

CC=gcc

ifeq ($(BUILD_STUB),)
	INSTALL_TARGETS:=install-clients install-sys install-doc
	BUILD_TARGETS=daemons clients doc
else
	INSTALL_TARGETS=install-clients
	BUILD_TARGETS=clients
endif

all: $(BUILD_TARGETS)

daemons:
	$(MAKE) -C daemons
clients:
	$(MAKE) -C clients
doc:
	$(MAKE) -C doc

clean:
	$(MAKE) -C daemons  clean
	$(MAKE) -C clients  clean

install-clients:
	$(MAKE) -C clients  install

install-sys:
	$(MAKE) -C daemons  install

install-doc:
	$(MAKE) -C doc install

install: $(INSTALL_TARGETS)
