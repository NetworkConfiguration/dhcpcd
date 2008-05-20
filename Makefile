# Makefile based on BSD make.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		dhcpcd
SRCS=		common.c dhcp.c dhcpcd.c logger.c net.c signals.c
SRCS+=		configure.c client.c
SRCS+=		${SRC_IF} ${SRC_SOCKET}

SCRIPTDIR=	${PREFIX}/libexec
SCRIPT=		${SCRIPTDIR}/dhcpcd.sh
HOOKDIR=	${SCRIPTDIR}/dhcpcd.hook.d

BINDIR=		${PREFIX}/sbin
SYSCONFDIR?=	${PREFIX}/etc

MAN=		dhcpcd.conf.5 dhcpcd.8 dhcpcd.sh.8
CLEANFILES=	dhcpcd.conf.5 dhcpcd.8 dhcpcd.sh.8

SCRIPTS=	dhcpcd.sh
SCRIPTSDIR=	${SCRIPTDIR}
CLEANFILES+=	dhcpcd.sh

FILES=		dhcpcd.conf
FILESDIR=	${SYSCONFDIR}

CPPFLAGS+=	-DDBDIR=\"${DBDIR}\"
CPPFLAGS+=	-DSCRIPT=\"${SCRIPT}\"
CPPFLAGS+=	-DSYSCONFDIR=\"${SYSCONFDIR}\"
LDADD+=		${LIBRT}

SUBDIRS=	hook.d

.SUFFIXES:	.in .sh.in

SED_DBDIR=	-e 's:@DBDIR@:${DBDIR}:g'
SED_HOOKDIR=	-e 's:@HOOKDIR@:${HOOKDIR}:g'
SED_SCRIPT=	-e 's:@SCRIPT@:${SCRIPT}:g'
SED_SYS=	-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

.in:
	${SED} ${SED_DBDIR} ${SED_HOOKDIR} ${SED_SCRIPT} ${SED_SYS} $< > $@

.sh.in.sh:
	${SED} ${SED_HOOKDIR} ${SED_SCRIPT} ${SED_SYS} $< > $@

MK=		mk
include ${MK}/prog.mk
