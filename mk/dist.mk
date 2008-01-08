# rules to make a distribution tarball from a git repo
# Copyright 2008 Roy Marples <roy@marples.name>

GITREF?=	HEAD
DISTFILE?=	${PROG}-${VERSION}.tar.bz2

CLEANFILES+=	${DISTFILE}

dist:
	git archive ${GITREF} | bzip2 > ${DISTFILE}
