# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2017-2019 Roy Marples <roy@marples.name>

SUBDIRS=	crypt eloop-bench

all: 
	for x in ${SUBDIRS}; do ${MAKE} -C $xx $@ || exit $$?; done

install:

proginstall:

clean:
	for x in ${SUBDIRS}; do ${MAKE} -C $$x $@ || exit $$?; done

distclean: clean
	rm -f *.diff *.patch *.orig *.rej
	for x in ${SUBDIRS}; do ${MAKE} -C $$x $@ || exit $$?; done

test:
	for x in ${SUBDIRS}; do ${MAKE} -C $$x $@ || exit $$?; done

tests: test
