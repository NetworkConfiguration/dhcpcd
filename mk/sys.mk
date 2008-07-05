# Simple defaults

BINDIR?=	${PREFIX}/usr/bin
BINMODE?=	0755
NONBINMODE?=	0644

SYSCONFDIR?=	${PREFIX}/etc

INSTALL?=	install
SED?=		sed

_LIBNAME_SH=		case `readlink /lib` in "") echo "lib";; *) basename `readlink /lib`;; esac
_LIBNAME!=		${_LIBNAME_SH}
LIBNAME?=		${_LIBNAME}$(shell ${_LIBNAME_SH})
