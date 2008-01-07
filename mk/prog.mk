# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples

BINDIR?=	/sbin
OBJS+=		${SRCS:.c=.o}

INSTALL?=	install

all: ${PROG} ${MAN}

${PROG}: ${SCRIPTS} ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} ${PROGLDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} ${PROG} ${DESTDIR}${BINDIR}

_progclean:
	rm -f ${OBJS} ${PROG} ${CLEANFILES}

include ${MK}/depend.mk
include ${MK}/man.mk

install: _proginstall maninstall

clean: _progclean _dependclean
