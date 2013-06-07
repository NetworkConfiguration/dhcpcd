TOP?=	../
include ${TOP}/Makefile.inc
include ${TOP}/config.mk

SCRIPTSDIR=	${LIBEXECDIR}/dhcpcd-hooks
SCRIPTS=	01-test 02-dump
SCRIPTS+=	10-mtu 10-wpa_supplicant 15-timezone 20-resolv.conf
SCRIPTS+=	29-lookup-hostname 30-hostname
SCRIPTS+=	${HOOKSCRIPTS}

all:

install:
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}

import:
	${INSTALL} -d /tmp/${DISTPREFIX}/dhcpcd-hooks
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} /tmp/${DISTPREFIX}/dhcpcd-hooks

