# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

BINDIR?=	${PREFIX}/usr/bin
BINMODE?=	0755
OBJS+=		${SRCS:.c=.o}

INSTALL?=	install

all: ${PROG} ${MAN}

${PROG}: ${SCRIPTS} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${BINDIR}

include ${MK}/depend.mk
include ${MK}/man.mk
include ${MK}/dist.mk

install: _proginstall maninstall

clean:
	rm -f ${OBJS} ${PROG} ${CLEANFILES}

LINTFLAGS?=	-hx
LINTFLAGS+=	-X 159,247,352

lint: ${SRCS:.c=.c}
	${LINT} ${LINTFLAGS} ${CFLAGS:M-[DIU]*} $^ ${.ALLSRC}
