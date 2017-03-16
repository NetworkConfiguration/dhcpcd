SUBDIRS=	src hooks

VERSION!=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' src/defs.h

FOSSILID?=	current

DISTPREFIX?=	${PROG}-${VERSION}
DISTFILEGZ?=	${DISTPREFIX}.tar.gz
DISTFILE?=	${DISTPREFIX}.tar.xz
DISTINFO=	${DISTFILE}.distinfo
DISTINFOSIGN=	${DISTINFO}.asc
CKSUM?=		cksum -a SHA256
PGP?=		netpgp

HOST_SH?=	/bin/sh

CLEANFILES+=	*.tar.xz

.PHONY:		hooks import import-bsd test

.SUFFIXES:	.in

all: config.h
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

depend: config.h
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

test:
	cd $@; ${MAKE} $@; ./$@

hooks:
	cd $@; ${MAKE}

eginstall:
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

install:
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

clean:
	for x in ${SUBDIRS} test; do cd $$x; ${MAKE} $@; cd ..; done

distclean: clean
	rm -f config.h config.mk config.log \
		${DISTFILE} ${DISTFILEGZ} ${DISTINFO} ${DISTINFOSIGN}

dist:
	fossil tarball --name ${DISTPREFIX} ${FOSSILID} ${DISTFILEGZ}
	gunzip -c ${DISTFILEGZ} | xz >${DISTFILE}
	rm ${DISTFILEGZ}

distinfo: dist
	rm -f ${DISTINFO} ${DISTINFOSIGN}
	${CKSUM} ${DISTFILE} >${DISTINFO}
	#printf "SIZE (${DISTFILE}) = %s\n" $$(wc -c <${DISTFILE}) >>${DISTINFO}
	${PGP} --clearsign --output=${DISTINFOSIGN} ${DISTINFO}
	chmod 644 ${DISTINFOSIGN}
	ls -l ${DISTFILE} ${DISTINFO} ${DISTINFOSIGN}

snapshot:
	rm -rf /tmp/${DISTPREFIX}
	${INSTALL} -d /tmp/${DISTPREFIX}
	cp -RPp * /tmp/${DISTPREFIX}
	${MAKE} -C /tmp/${DISTPREFIX} distclean
	tar cf - -C /tmp ${DISTPREFIX} | xz >${DISTFILE}
	ls -l ${DISTFILE}

import: ${SRCS} hooks
	rm -rf /tmp/${DISTPREFIX}
	${INSTALL} -d /tmp/${DISTPREFIX}
	cp genembedc genembedh /tmp/${DISTPREFIX}
	cp $$(echo ${SRCS} | sed -e 's/\(dhcpcd-embedded.[ch]\)/\1.in/') \
		/tmp/${DISTPREFIX}
	cp dhcpcd.conf dhcpcd-definitions.conf *.in /tmp/${DISTPREFIX}
	cp dhcpcd-definitions-small.conf *.in /tmp/${DISTPREFIX}
	cp $$(${CC} ${CPPFLAGS} -DDEPGEN -MM \
		$$(echo ${SRCS} | sed -e 's/dhcpcd-embedded.c//') | \
		sed -e 's/^.*\.c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
		tr ' ' '\n' | \
		sed -e '/^dhcpcd-embedded.h$$/d' | \
		sed -e '/^compat\//d' | \
		sed -e '/^crypt\//d' | \
		sort -u) /tmp/${DISTPREFIX}; \
	if test -n "${CRYPT_SRCS}"; then \
		${INSTALL} -d /tmp/${DISTPREFIX}/crypt; \
		cp ${CRYPT_SRCS} /tmp/${DISTPREFIX}/crypt; \
		cp $$(${CC} ${CPPFLAGS} -DDEPGEN -MM ${CRYPT_SRCS} | \
			sed -e 's/^.*c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
			tr ' ' '\n' | sed -e '/\/\.\.\//d'  | \
			sort -u) /tmp/${DISTPREFIX}/crypt; \
	fi;
	if test -n "${COMPAT_SRCS}"; then \
		${INSTALL} -d /tmp/${DISTPREFIX}/compat; \
		cp ${COMPAT_SRCS} /tmp/${DISTPREFIX}/compat; \
		cp $$(${CC} ${CPPFLAGS} -DDEPGEN -MM ${COMPAT_SRCS} | \
			sed -e 's/^.*c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
			tr ' ' '\n' | \
			sort -u) /tmp/${DISTPREFIX}/compat; \
	fi;
	cd dhcpcd-hooks; ${MAKE} DISTPREFIX=${DISTPREFIX} $@

include Makefile.inc
