# rules to install manpages
# Copyright 2008 Roy Marples <roy@marples.name>

_MANPREFIX_SH=	if [ -n "${PREFIX}" ]; then echo "${PREFIX}"; else echo "/usr/share"; fi
_MANPREFIX!=	${_MANPREFIX_SH}
MANPREFIX?=	${_MANPREFIX}$(shell ${_MANPREFIX_SH})

MANDIR?=	${MANPREFIX}/man/man
MANMODE?=	0444

_MAN5_SH=	for man in ${MAN}; do case $$man in *.5) echo $$man;; esac; done
_MAN5!=		${_MAN5_SH}
MAN5=		${_MAN5}$(shell ${_MAN5_SH})

_MAN8_SH=	for man in ${MAN}; do case $$man in *.8) echo $$man;; esac; done
_MAN8!=		${_MAN8_SH}
MAN8=		${_MAN8}$(shell ${_MAN8_SH})

_man: ${MAN}

_maninstall: _man
	${INSTALL} -d ${DESTDIR}${MANDIR}5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}5
	${INSTALL} -d ${DESTDIR}${MANDIR}8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}8
