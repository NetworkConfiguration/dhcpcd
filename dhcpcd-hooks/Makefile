TOP?=	../
include ${TOP}/Makefile.inc
include ${TOP}/iconfig.mk

SCRIPTSDIR=	${LIBEXECDIR}/dhcpcd-hooks
SCRIPTS=	01-test 02-dump
SCRIPTS+=	20-resolv.conf
SCRIPTS+=	30-hostname
SCRIPTS+=	${HOOKSCRIPTS}

# Some hooks should not be installed by default
FILESDIR=	${DATADIR}/dhcpcd/hooks
FILES=		10-wpa_supplicant
FILES+=		15-timezone
FILES+=		29-lookup-hostname
FILES+=		${EGHOOKSCRIPTS}

50-ypbind: 50-ypbind.in
	${SED} \
		-e 's:@YPDOMAIN_DIR@:${YPDOMAIN_DIR}:g' \
		-e 's:@YPDOMAIN_SUFFIX@:${YPDOMAIN_SUFFIX}:g' \
		50-ypbind.in > $@

all: ${HOOKSCRIPTS} ${EGHOOKSCRIPTS}

clean:
	rm -f 50-ypbind

proginstall: ${HOOKSCRIPTS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}
	# We need to remove the old MTU change script if we at all can.
	rm -f ${DESTDIR}${SCRIPTSDIR}/10-mtu

eginstall: ${EGHOOKSCRIPTS}
	${INSTALL} -d ${DESTDIR}${FILESDIR}
	${INSTALL} -m ${NONBINMODE} ${FILES} ${DESTDIR}${FILESDIR}

install: proginstall eginstall

import: ${HOOKSCRIPTS}
	${INSTALL} -d /tmp/${DISTPREFIX}/dhcpcd-hooks
	${INSTALL} -m ${NONBINMODE} ${SCRIPTS} /tmp/${DISTPREFIX}/dhcpcd-hooks
	${INSTALL} -m ${NONBINMODE} ${FILES} /tmp/${DISTPREFIX}/dhcpcd-hooks
