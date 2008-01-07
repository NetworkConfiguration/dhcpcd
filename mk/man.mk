# rules to install manpages
# Copyright 2008 Roy Marples

MANPREFIX?=	/usr/share
MANMODE?=	0444
MINSTALL?=	${INSTALL} -m ${MANMODE}

# We cheat as all our pages go into section 8
maninstall: ${MAN}
	${INSTALL} -d ${DESTDIR}${MANPREFIX}/man/man8
	for man in ${MAN}; do ${MINSTALL} $$man ${DESTDIR}${MANPREFIX}/man/man8; done
