# dhcpcd Makefile

PROG=		dhcpcd
SRCS=		common.c control.c dhcpcd.c duid.c eloop.c
SRCS+=		if.c if-options.c script.c
SRCS+=		dhcp-common.c

CFLAGS?=	-O2
MKDIRS=

TOP?=		.
include ${TOP}/iconfig.mk

CSTD?=		c99
CFLAGS+=	-std=${CSTD}

SRCS+=		${DHCPCD_SRCS}

SRCS+=		auth.c
CPPFLAGS+=	-I./crypt
CRYPT_SRCS=	crypt/hmac_md5.c ${MD5_SRC} ${SHA256_SRC}

OBJS+=		${SRCS:.c=.o} ${COMPAT_SRCS:.c=.o} ${CRYPT_SRCS:.c=.o}

SCRIPT=		${LIBEXECDIR}/dhcpcd-run-hooks
HOOKDIR=	${LIBEXECDIR}/dhcpcd-hooks

MAN5=		dhcpcd.conf.5
MAN8=		dhcpcd.8 dhcpcd-run-hooks.8
CLEANFILES=	dhcpcd.conf.5 dhcpcd.8 dhcpcd-run-hooks.8

SCRIPTS=	dhcpcd-run-hooks
SCRIPTSDIR=	${LIBEXECDIR}
CLEANFILES+=	dhcpcd-run-hooks

FILES=		dhcpcd.conf
FILESDIR=	${SYSCONFDIR}

SUBDIRS=	dhcpcd-hooks ${MKDIRS}

SED_RUNDIR=		-e 's:@RUNDIR@:${RUNDIR}:g'
SED_DBDIR=		-e 's:@DBDIR@:${DBDIR}:g'
SED_LIBDIR=		-e 's:@LIBDIR@:${LIBDIR}:g'
SED_HOOKDIR=		-e 's:@HOOKDIR@:${HOOKDIR}:g'
SED_SERVICEEXISTS=	-e 's:@SERVICEEXISTS@:${SERVICEEXISTS}:g'
SED_SERVICECMD=		-e 's:@SERVICECMD@:${SERVICECMD}:g'
SED_SERVICESTATUS=	-e 's:@SERVICESTATUS@:${SERVICESTATUS}:g'
SED_SCRIPT=		-e 's:@SCRIPT@:${SCRIPT}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

DEPEND!=	test -e .depend && echo ".depend" || echo ""
VERSION!=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' defs.h

FOSSILID?=	current

DISTPREFIX?=	${PROG}-${VERSION}
DISTFILEGZ?=	${DISTPREFIX}.tar.gz
DISTFILE?=	${DISTPREFIX}.tar.bz2

HOST_SH?=	/bin/sh

CLEANFILES+=	*.tar.bz2

.PHONY:		import import-bsd dev test

.SUFFIXES:	.in

.in:
	${SED} ${SED_RUNDIR} ${SED_DBDIR} ${SED_LIBDIR} ${SED_HOOKDIR} \
		${SED_SYS} ${SED_SCRIPT} \
		${SED_SERVICEEXISTS} ${SED_SERVICECMD} ${SED_SERVICESTATUS} \
		$< > $@

all: config.h ${PROG} ${SCRIPTS} ${MAN5} ${MAN8}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

dev:
	cd dev && ${MAKE}

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

CLEANFILES+=	dhcpcd-embedded.h dhcpcd-embedded.c

dhcpcd-embedded.h: genembedh dhcpcd-definitions.conf dhcpcd-embedded.h.in
	${HOST_SH} ${.ALLSRC} $^ > $@

dhcpcd-embedded.c: genembedc dhcpcd-definitions.conf
	${HOST_SH} ${.ALLSRC} $^ > $@

if-options.c: dhcpcd-embedded.h

.depend: ${SRCS} ${COMPAT_SRCS} ${CRYPT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${COMPAT_SRCS} ${CRYPT_SRCS} > .depend

depend: .depend

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

test:
	cd $@; ${MAKE} $@; ./$@

_embeddedinstall: dhcpcd-definitions.conf
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${CONFMODE} dhcpcd-definitions.conf ${DESTDIR}${SCRIPTSDIR}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${SBINDIR}
	${INSTALL} -d ${DESTDIR}${DBDIR}

_scriptsinstall: ${SCRIPTS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${BINMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}

proginstall: _proginstall _scriptsinstall ${EMBEDDEDINSTALL}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

_maninstall: ${MAN5} ${MAN8}
	${INSTALL} -d ${DESTDIR}${MANDIR}/man5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}/man5
	${INSTALL} -d ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}/man8

_confinstall:
	${INSTALL} -d ${DESTDIR}${SYSCONFDIR}
	test -e ${DESTDIR}${SYSCONFDIR}/dhcpcd.conf || \
		${INSTALL} -m ${CONFMODE} dhcpcd.conf ${DESTDIR}${SYSCONFDIR}

install: proginstall _maninstall _confinstall

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}
	for x in ${SUBDIRS} test; do cd $$x; ${MAKE} $@; cd ..; done

distclean: clean
	rm -f .depend config.h config.mk config.log

dist:
	fossil tarball --name ${DISTPREFIX} ${FOSSILID} ${DISTFILEGZ}
	gunzip -c ${DISTFILEGZ} |  bzip2 >${DISTFILE}
	rm ${DISTFILEGZ}

import: ${SRCS}
	rm -rf /tmp/${DISTPREFIX}
	${INSTALL} -d /tmp/${DISTPREFIX}
	cp ${SRCS} dhcpcd.conf dhcpcd-definitions.conf *.in /tmp/${DISTPREFIX}
	cp $$(${CC} ${CPPFLAGS} -DDEPGEN -MM ${SRCS} | \
		sed -e 's/^.*\.c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
		tr ' ' '\n' | \
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
