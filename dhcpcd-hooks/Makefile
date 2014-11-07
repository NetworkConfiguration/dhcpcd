TOP?=	../
include ${TOP}/Makefile.inc
include ${TOP}/iconfig.mk

SCRIPTSDIR=	${LIBEXECDIR}/dhcpcd-hooks
SCRIPTS=	01-test 02-dump
SCRIPTS+=	10-mtu 10-wpa_supplicant 15-timezone 20-resolv.conf
SCRIPTS+=	29-lookup-hostname 30-hostname
SCRIPTS+=	${HOOKSCRIPTS}

50-ypbind: 50-ypbind.in
	${SED} \
		-e 's:@YPDOMAIN_DIR@:${YPDOMAIN_DIR}:g' \
		-e 's:@YPDOMAIN_SUFFIX@:${YPDOMAIN_SUFFIX}:g' \
		50-ypbind.in > $@

all: ${HOOKSCRIPTS}

clean:
	rm -f 50-ypbind

proginstall: ${HOOKSCRIPTS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}

install: proginstall

import: ${HOOKSCRIPTS}
	${INSTALL} -d /tmp/${DISTPREFIX}/dhcpcd-hooks
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} /tmp/${DISTPREFIX}/dhcpcd-hooks
