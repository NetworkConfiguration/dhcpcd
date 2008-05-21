# Quick and dirty scripts
# Copyright 2008 Roy Marples <roy@marples.name>

SCRIPTSDIR?=	${BINDIR}
SCRIPTSMODE?=	${BINMODE}

_scriptsinstall: ${SCRIPTS}
	${INSTALL} -d ${DESTDIR}${SCRIPTSDIR}
	${INSTALL} -m ${SCRIPTSMODE} ${SCRIPTS} ${DESTDIR}${SCRIPTSDIR}
