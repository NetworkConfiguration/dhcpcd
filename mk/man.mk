# rules to install manpages
# Copyright 2008 Roy Marples <roy@marples.name>

MANPREFIX?=	/usr/share
MANDIR?=	${MANPREFIX}/man/man
MANMODE?=	0444

man: ${MAN5} ${MAN8}

maninstall: man
	${INSTALL} -d ${DESTDIR}${MANDIR}5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}5
	${INSTALL} -d ${DESTDIR}${MANDIR}8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}8
