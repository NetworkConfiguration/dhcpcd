SYSCONFDIR?=	/etc/dhcpcd

SYSTEMSCRIPTS=	01-test.sh 10-resolv.conf.sh 15-hostname.sh
SCRIPTS=	${SYSTEMSCRIPTS} ${HOOKSCRIPTS}
SCRIPTSDIR=	${SYSCONFDIR}/hook.d

MK=		../mk
include ${MK}/scripts.mk
install: _scriptsinstall
