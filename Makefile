# Makefile based on BSD's pmake.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		dhcpcd
SRCS=		common.c dhcp.c dhcpcd.c logger.c net.c signal.c
SRCS+=		configure.c client.c
SRCS+=		${SRC_IF} ${SRC_SOCKET}
SCRIPT=		dhcpcd.sh
CONF=		dhcpcd.conf
MAN5=		dhcpcd.conf.5
MAN8=		dhcpcd.8 dhcpcd.sh.8

VERSION=	4.0.0-alpha3
CLEANFILES=	dhcpcd.sh dhcpcd.8 dhcpcd.sh.8

BINDIR=		${PREFIX}/sbin
SYSCONFDIR?=	${PREFIX}/etc/${PROG}

.SUFFIXES:	.in .sh.in

MK=		mk
include ${MK}/prog.mk

CFLAGS+=	-DVERSION=\"${VERSION}\"
CFLAGS+=	-DSYSCONFDIR=\"${SYSCONFDIR}\"
CFLAGS+=	-DDBDIR=\"${DBDIR}\"
LDADD+=		${LIBRT}

.in:
	${SED} 's:@SYSCONFDIR@:${SYSCONFDIR}:g; s:@DBDIR@:${DBDIR}:g' $< > $@

.sh.in.sh:
	${SED} 's:@SYSCONFDIR@:${SYSCONFDIR}:g' $< > $@

