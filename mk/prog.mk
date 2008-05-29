# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

include ${MK}/cc.mk

OBJS+=		${SRCS:.c=.o}

all: ${PROG} ${SCRIPTS} _man

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

# We could save about 600 bytes by building it like this
# instead of the more traditional method above
small: ${SRCS}
	echo "" > _${PROG}.c
	for src in ${SRCS}; do echo "#include \"$$src\"" >> _${PROG}.c; done
	${CC} ${CPPFLAGS} -c _${PROG}.c -o _${PROG}.o
	${CC} ${LDFLAGS} -o ${PROG} _${PROG}.o ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${BINDIR}
	${INSTALL} -d ${DESTDIR}${DBDIR}

include ${MK}/depend.mk
include ${MK}/files.mk
include ${MK}/scripts.mk
include ${MK}/man.mk
include ${MK}/dist.mk

install: _proginstall _scriptsinstall _filesinstall _maninstall
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

clean:
	rm -f ${OBJS} ${PROG} _${PROG}.c _${PROG}.o ${PROG}.core ${CLEANFILES}

LINTFLAGS?=	-hx
LINTFLAGS+=	-X 159,247,352

lint: ${SRCS:.c=.c}
	${LINT} ${LINTFLAGS} ${CFLAGS:M-[DIU]*} $^ ${.ALLSRC}
