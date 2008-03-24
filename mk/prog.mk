# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

include ${MK}/cc.mk
include ${MK}/os.mk

BINDIR?=	${PREFIX}/usr/bin
BINMODE?=	0755
OBJS+=		${SRCS:.c=.o}

INSTALL?=	install

all: ${PROG} ${MAN}

${PROG}: ${SCRIPTS} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

# We could save about 500 bytes by building it like this
# instead of the more traditional method above
#${PROG}: ${SRCS}
#	echo "" > _${PROG}.c
#	for src in ${SRCS}; do echo "#include \"$$src\"" >> _${PROG}.c; done
#	${CC} ${CFLAGS} -DSYSLOG_NAMES -c _${PROG}.c -o _${PROG}.o
#	${CC} ${LDFLAGS} -o $@ _${PROG}.o ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${BINDIR}

include ${MK}/depend.mk
include ${MK}/man.mk
include ${MK}/dist.mk

install: _proginstall maninstall

clean:
	rm -f ${OBJS} ${PROG} _${PROG}.c _${PROG}.o ${CLEANFILES}

LINTFLAGS?=	-hx
LINTFLAGS+=	-X 159,247,352

lint: ${SRCS:.c=.c}
	${LINT} ${LINTFLAGS} ${CFLAGS:M-[DIU]*} $^ ${.ALLSRC}
