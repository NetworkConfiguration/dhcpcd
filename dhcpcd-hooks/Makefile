LIBEXECDIR?=	${PREFIX}/libexec
HOOKDIR=	${LIBEXECDIR}/dhcpcd-hooks
SYSTEMSCRIPTS=	01-test 10-mtu 20-resolv.conf 30-hostname
FILES=		${SYSTEMSCRIPTS} ${HOOKSCRIPTS}
FILESDIR=	${HOOKDIR}

all:

MK=		../mk
include ${MK}/os.mk
include ${MK}/sys.mk
include ${MK}/files.mk
install: _filesinstall
