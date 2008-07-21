# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

include ${MK}/cc.mk

OBJS+=		${SRCS:.c=.o}

# If building for /, ensure we use the libc in / if different from
# the default one in /usr/lib
LINK_RPATH?=		-Wl,-rpath
_RPATH_SH=		if test "${PREFIX}" = "" -o "${PREIX}" = "/"; then \
				echo "${LINK_RPATH}=${PREFIX}/${LIBNAME}"; \
			else \
				echo ""; \
			fi
_RPATH!=		${_RPATH_SH}
LDFLAGS+=		${_RPATH}$(shell ${_RPATH_SH})

# If building for /, ensure we use the linker in /libexec if different from
# the default one in /usr/libexec
_DYNLINK_SH=		if test "${PREFIX}" = "" -o "${PREFIX}" = "/" && test -e /libexec/ld.elf_so; then \
				echo "-Wl,-dynamic-linker=/libexec/ld.elf_so"; \
			else \
				echo ""; \
			fi
_DYNLINK!=		${_DYNLINK_SH}
LDFLAGS+=		${_DYNLINK}$(shell ${_DYNLINK_SH})

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
	${CC} ${CFLAGS} ${CPPFLAGS} -c _${PROG}.c -o _${PROG}.o
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
