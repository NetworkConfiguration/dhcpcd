# Makefile based on BSD's pmake.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		dhcpcd
SRCS=		common.c dhcp.c dhcpcd.c logger.c net.c signal.c
SRCS+=		configure.c client.c
SRCS+=		${SRC_IF} ${SRC_SOCKET}
MAN=		dhcpcd.8

VERSION=	3.3.0-alpha1
CLEANFILES=	dhcpcd.8

BINDIR=		${PREFIX}/sbin

.SUFFIXES:	.in

MK=		mk
include ${MK}/prog.mk

CFLAGS+=	-DVERSION=\"${VERSION}\"

# Work out how to restart services 
_RC_SH=		if test -n "${HAVE_INIT}"; then \
		test "${HAVE_INIT}" = "no" || echo "-DENABLE_${HAVE_INIT}"; \
		elif test -x /sbin/runscript; then echo "-DENABLE_OPENRC"; \
		elif test -x /sbin/service; then echo "-DENABLE_SERVICE"; \
		elif test -x /etc/rc.d/rc.S -a -x /etc/rc.d/rc.M; then echo "-DENABLE_SLACKRC"; \
		elif test -d /etc/rc.d; then echo "-DENABLE_BSDRC"; \
		elif test -d /etc/init.d; then echo "-DENABLE_SYSV"; \
		fi
_RC!=		${_RC_SH}
CFLAGS+=	${_RC}$(shell ${_RC_SH})

CFLAGS+=	-DINFODIR=\"${INFODIR}\"
LDADD+=		${LIBRESOLV} ${LIBRT}

.in:
	${SED} 's:@PREFIX@:${PREFIX}:g; s:@INFODIR@:${INFODIR}:g' $< > $@
