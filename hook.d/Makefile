SCRIPTDIR?=	${PREFIX}/libexec
HOOKDIR?=	${SCRIPTDIR}/dhcpcd.hook.d
SYSTEMSCRIPTS=	01-test.sh 10-resolv.conf.sh 15-hostname.sh
SCRIPTS=	${SYSTEMSCRIPTS} ${HOOKSCRIPTS}
SCRIPTSDIR=	${HOOKDIR}

MK=		../mk
include ${MK}/scripts.mk
install: _scriptsinstall
