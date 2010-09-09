# dhcpcd Makefile

PROG=		dhcpcd
SRCS=		arp.c bind.c common.c control.c dhcp.c dhcpcd.c duid.c eloop.c
SRCS+=		if-options.c if-pref.c ipv4ll.c net.c signals.c
SRCS+=		configure.c

CFLAGS?=	-O2
CSTD?=		c99
CFLAGS+=	-std=${CSTD}
include config.mk

OBJS+=		${SRCS:.c=.o} ${COMPAT_SRCS:.c=.o}

SCRIPT=		${LIBEXECDIR}/dhcpcd-run-hooks
HOOKDIR=	${LIBEXECDIR}/dhcpcd-hooks

MAN5=		dhcpcd.conf.5
MAN8=		dhcpcd.8 dhcpcd-run-hooks.8
CLEANFILES=	dhcpcd.conf.5 dhcpcd.8 dhcpcd-run-hooks.8

SCRIPTS=	dhcpcd-run-hooks
SCRIPTSDIR=	${LIBEXECDIR}
CLEANFILES+=	dhcpcd-run-hooks
CLEANFILES+=	.depend

FILES=		dhcpcd.conf
FILESDIR=	${SYSCONFDIR}

SUBDIRS=	dhcpcd-hooks

SED_DBDIR=		-e 's:@DBDIR@:${DBDIR}:g'
SED_HOOKDIR=		-e 's:@HOOKDIR@:${HOOKDIR}:g'
SED_SERVICEEXISTS=	-e 's:@SERVICEEXISTS@:${SERVICEEXISTS}:g'
SED_SERVICECMD=		-e 's:@SERVICECMD@:${SERVICECMD}:g'
SED_SERVICESTATUS=	-e 's:@SERVICESTATUS@:${SERVICESTATUS}:g'
SED_SCRIPT=		-e 's:@SCRIPT@:${SCRIPT}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

_DEPEND_SH=	test -e .depend && echo ".depend" || echo ""
_DEPEND!=	${_DEPEND_SH}
DEPEND=		${_DEPEND}$(shell ${_DEPEND_SH})

_VERSION_SH=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' defs.h
_VERSION!=	${_VERSION_SH}
VERSION=	${_VERSION}$(shell ${_VERSION_SH})

GITREF?=	HEAD
DISTPREFIX?=	${PROG}-${VERSION}
DISTFILE?=	${DISTPREFIX}.tar.bz2

CLEANFILES+=	*.tar.bz2

.PHONY:		import import-bsd

.SUFFIXES:	.in

.in:
	${SED} ${SED_DBDIR} ${SED_HOOKDIR} ${SED_SCRIPT} ${SED_SYS} \
		${SED_SERVICEEXISTS} ${SED_SERVICECMD} ${SED_SERVICESTATUS} \
		$< > $@

all: config.h ${PROG} ${SCRIPTS} ${MAN5} ${MAN8}

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

.depend: ${SRCS} ${COMPAT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${COMPAT_SRCS} > .depend

depend: .depend

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${SBINDIR}
	${INSTALL} -d ${DESTDIR}${DBDIR}

_scriptsinstall: ${SCRIPTS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${BINMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}

_maninstall: ${MAN5} ${MAN8}
	${INSTALL} -d ${DESTDIR}${MANDIR}/man5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}/man5
	${INSTALL} -d ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}/man8

_confinstall:
	${INSTALL} -d ${DESTDIR}${SYSCONFDIR}
	test -e ${DESTDIR}${SYSCONFDIR}/dhcpcd.conf || \
		${INSTALL} -m ${CONFMODE} dhcpcd.conf ${DESTDIR}${SYSCONFDIR}

install: _proginstall _scriptsinstall _maninstall _confinstall
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

distclean: clean
	rm -f .depend config.h config.mk

dist:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | bzip2 > ${DISTFILE}

import:
	rm -rf /tmp/${DISTPREFIX}
	${INSTALL} -d /tmp/${DISTPREFIX}
	cp ${SRCS} dhcpcd.conf *.in /tmp/${DISTPREFIX}
	cp $$(${CC} ${CPPFLAGS} -MM ${SRCS} | \
		sed -e 's/^.*\.c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
		tr ' ' '\n' | \
		sed -e '/^compat\//d' | \
		sort -u) /tmp/${DISTPREFIX}
	if test -n "${COMPAT_SRCS}"; then \
		${INSTALL} -d /tmp/${DISTPREFIX}/compat; \
		cp ${COMPAT_SRCS} /tmp/${DISTPREFIX}/compat; \
		cp $$(${CC} ${CPPFLAGS} -MM ${COMPAT_SRCS} | \
			sed -e 's/^.*c //g' -e 's/.*\.c$$//g' -e 's/\\//g' | \
			tr ' ' '\n' | \
			sort -u) /tmp/${DISTPREFIX}/compat; \
	fi;
	cd dhcpcd-hooks; ${MAKE} DISTPREFIX=${DISTPREFIX} $@

include Makefile.inc
