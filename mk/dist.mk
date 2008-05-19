# rules to make a distribution tarball from a git repo
# Copyright 2008 Roy Marples <roy@marples.name>

GITREF?=	HEAD
DISTPREFIX?=	${PROG}-${VERSION}
DISTFILE?=	${DISTPREFIX}.tar.bz2

CLEANFILES+=	${DISTFILE}

_VERSION_SH=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' config.h
_VERSION!=	${_VERSION_SH}
VERSION=	${_VERSION}$(shell ${_VERSION_SH})

dist:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | bzip2 > ${DISTFILE}
