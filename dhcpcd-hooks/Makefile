SCRIPTDIR?=	${PREFIX}/libexec
HOOKDIR?=	${SCRIPTDIR}/dhcpcd-hooks
SYSTEMSCRIPTS=	01-test 10-resolv.conf 15-hostname
SCRIPTS=	${SYSTEMSCRIPTS} ${HOOKSCRIPTS}
SCRIPTSDIR=	${HOOKDIR}

MK=		../mk
include ${MK}/os.mk
include ${MK}/sys.mk
include ${MK}/scripts.mk
install: _scriptsinstall
