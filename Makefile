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
CPPFLAGS+=	-I./crypt

SRCS+=		${DHCPCD_SRCS}
DHCPCD_DEFS?=	dhcpcd-definitions.conf

OBJS+=		${SRCS:.c=.o} ${CRYPT_SRCS:.c=.o} ${COMPAT_SRCS:.c=.o}

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
SED_DATADIR=		-e 's:@DATADIR@:${DATADIR}:g'
SED_HOOKDIR=		-e 's:@HOOKDIR@:${HOOKDIR}:g'
SED_SERVICEEXISTS=	-e 's:@SERVICEEXISTS@:${SERVICEEXISTS}:g'
SED_SERVICECMD=		-e 's:@SERVICECMD@:${SERVICECMD}:g'
SED_SERVICESTATUS=	-e 's:@SERVICESTATUS@:${SERVICESTATUS}:g'
SED_STATUSARG=		-e 's:@STATUSARG@:${STATUSARG}:g'
SED_SCRIPT=		-e 's:@SCRIPT@:${SCRIPT}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

DEPEND!=	test -e .depend && echo ".depend" || echo ""
VERSION!=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' defs.h

DIST!=		if test -f .fslckout; then echo "dist-fossil"; \
		elif test -d .git; then echo "dist-git"; \
		else echo "dist-inst"; fi
FOSSILID?=	current
GITREF?=	HEAD

DISTSUFFIX=
DISTPREFIX?=	dhcpcd-${VERSION}${DISTSUFFIX}
DISTFILEGZ?=	${DISTPREFIX}.tar.gz
DISTFILE?=	${DISTPREFIX}.tar.xz
DISTINFO=	${DISTFILE}.distinfo
DISTINFOSIGN=	${DISTINFO}.asc

CKSUM?=		cksum -a SHA256
PGP?=		netpgp

HOST_SH?=	/bin/sh

CLEANFILES+=	*.tar.xz

.PHONY:		import import-bsd dev test

.SUFFIXES:	.in

.in: Makefile config.mk
	${SED} ${SED_RUNDIR} ${SED_DBDIR} ${SED_LIBDIR} ${SED_HOOKDIR} \
		${SED_SYS} ${SED_SCRIPT} ${SED_DATADIR} \
		${SED_SERVICEEXISTS} ${SED_SERVICECMD} ${SED_SERVICESTATUS} \
		${SED_STATUSARG} \
		$< > $@

all: config.h ${PROG} ${SCRIPTS} ${MAN5} ${MAN8}
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

dev:
	cd dev && ${MAKE}

.c.o: Makefile config.mk
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

CLEANFILES+=	dhcpcd-embedded.h dhcpcd-embedded.c

dhcpcd-embedded.h: genembedh ${DHCPCD_DEFS} dhcpcd-embedded.h.in
	${HOST_SH} ${.ALLSRC} $^ > $@

dhcpcd-embedded.c: genembedc ${DHCPCD_DEFS} dhcpcd-embedded.c.in
	${HOST_SH} ${.ALLSRC} $^ > $@

if-options.c: dhcpcd-embedded.h

.depend: ${SRCS} ${COMPAT_SRCS} ${CRYPT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${COMPAT_SRCS} ${CRYPT_SRCS} > .depend

depend: .depend

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

test:
	cd $@; ${MAKE} $@; ./$@

_embeddedinstall: ${DHCPCD_DEFS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${CONFMODE} ${DHCPCD_DEFS} ${DESTDIR}${SCRIPTSDIR}

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
hooks:
	cd dhcpcd-hooks; ${MAKE}; cd ..; done

eginstall:
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

install: proginstall _maninstall _confinstall eginstall

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}
	for x in ${SUBDIRS} test; do cd $$x; ${MAKE} $@; cd ..; done

distclean: clean
	rm -f .depend config.h config.mk config.log \
		${DISTFILE} ${DISTFILEGZ} ${DISTINFO} ${DISTINFOSIGN}

dist-fossil:
	fossil tarball --name ${DISTPREFIX} ${FOSSILID} ${DISTFILEGZ}
	gunzip -c ${DISTFILEGZ} | xz >${DISTFILE}
	rm ${DISTFILEGZ}

dist-git:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | xz >${DISTFILE}

dist-inst:
	mkdir /tmp/${DISTPREFIX}
	cp -RPp * /tmp/${DISTPREFIX}
	(cd /tmp/${DISTPREFIX}; make clean)
	tar -cvjpf ${DISTFILE} -C /tmp ${DISTPREFIX}
	rm -rf /tmp/${DISTPREFIX}

dist: ${DIST}

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
