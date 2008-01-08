# rules to make a distribution tarball
# Copyright 2008 Roy Marples

GITREF?=	HEAD
DISTFILE?=	${PROG}-${VERSION}.tar.bz2

CLEANFILES+=	${DISTFILE}

dist:
	git archive ${GITREF} | bzip2 >${DISTFILE}
