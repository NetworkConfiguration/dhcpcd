# Makefile based on BSD make.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		dhcpcd
SRCS=		common.c dhcp.c dhcpcd.c logger.c net.c signals.c
SRCS+=		configure.c client.c
SRCS+=		${SRC_IF} ${SRC_SOCKET}

BINDIR=		${PREFIX}/sbin
SYSCONFDIR?=	${PREFIX}/etc/dhcpcd

MAN=		dhcpcd.conf.5 dhcpcd.8 dhcpcd.sh.8
CLEANFILES=	dhcpcd.conf.5 dhcpcd.8 dhcpcd.sh.8

SCRIPTS=	dhcpcd.sh
SCRIPTSDIR=	${SYSCONFDIR}
CLEANFILES+=	dhcpcd.sh

FILES=		dhcpcd.conf
FILESDIR=	${SYSCONFDIR}

.SUFFIXES:	.in .sh.in

MK=		mk
include ${MK}/prog.mk

CFLAGS+=	-DSYSCONFDIR=\"${SYSCONFDIR}\"
CFLAGS+=	-DDBDIR=\"${DBDIR}\"
LDADD+=		${LIBRT}

.in:
	${SED} 's:@SYSCONFDIR@:${SYSCONFDIR}:g; s:@DBDIR@:${DBDIR}:g' $< > $@

.sh.in.sh:
	${SED} 's:@SYSCONFDIR@:${SYSCONFDIR}:g' $< > $@
