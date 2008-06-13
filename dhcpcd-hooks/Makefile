LIBEXECDIR=	${PREFIX}/libexec
HOOKDIR=	${LIBEXECDIR}/dhcpcd-hooks
SYSTEMSCRIPTS=	01-test 05-mtu 10-resolv.conf 15-hostname
FILES=		${SYSTEMSCRIPTS} ${HOOKSCRIPTS}
FILESDIR=	${HOOKDIR}

MK=		../mk
include ${MK}/os.mk
include ${MK}/sys.mk
include ${MK}/files.mk
install: _filesinstall
