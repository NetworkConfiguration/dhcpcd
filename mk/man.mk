# rules to install manpages
# Copyright 2008 Roy Marples <roy@marples.name>

MANPREFIX?=	/usr/share
MANDIR?=	${MANPREFIX}/man/man
MANMODE?=	0444
MINSTALL?=	${INSTALL} -m ${MANMODE}

man: ${MAN}

# We cheat as all our pages go into section 8
maninstall: man
	${INSTALL} -d ${DESTDIR}${MANDIR}8
	for man in ${MAN}; do ${MINSTALL} $$man ${DESTDIR}${MANDIR}8; done
