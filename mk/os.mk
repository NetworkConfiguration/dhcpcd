# Setup OS specific variables
# Copyright 2008 Roy Marples <roy@marples.name>

_UNAME_S_SH=	case `uname -s` in *BSD|DragonFly) echo "BSD";; *) uname -s;; esac
_UNAME_S!=	${_UNAME_SH}
UNAME_S=	${_UNAME_S}$(shell ${_UNAME_S_SH})
include ${MK}/os-${UNAME_S}.mk
