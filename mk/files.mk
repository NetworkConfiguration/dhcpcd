# Quick and dirty files
# Copyright 2008 Roy Marples <roy@marples.name>

FILESDIR?=	${BINDIR}
FILESMODE?=	${NONBINMODE}

_filesinstall:
	${INSTALL} -d ${DESTDIR}${FILESIR}
	${INSTALL} -m ${FILESMODE} ${FILES} ${DESTDIR}${FILESDIR}
