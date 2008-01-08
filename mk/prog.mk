# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

BINDIR?=	/sbin
OBJS+=		${SRCS:.c=.o}

INSTALL?=	install

all: ${PROG} ${MAN}

${PROG}: ${SCRIPTS} ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} ${PROG} ${DESTDIR}${BINDIR}

include ${MK}/depend.mk
include ${MK}/man.mk
include ${MK}/dist.mk

install: _proginstall maninstall

clean:
	rm -f ${OBJS} ${PROG} ${CLEANFILES}
