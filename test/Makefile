TOP?=	..
include ${TOP}/iconfig.mk

PROG=		test
SRCS=		test.c
SRCS+=		test_hmac_md5.c ../crypt/hmac_md5.c

CFLAGS?=	-O2
CSTD?=		c99
CFLAGS+=	-std=${CSTD}

CPPFLAGS+=	-I../crypt

T_COMPAT_SRCS=	${COMPAT_SRCS:compat/%=../compat/%}
T_MD5_SRC=	${MD5_SRC:crypt/%=../crypt/%}
OBJS+=		${SRCS:.c=.o} ${T_COMPAT_SRCS:.c=.o} ${T_MD5_SRC:.c=.o}

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

all: ${PROG}

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

distclean: clean
	rm -f .depend

.depend: ${SRCS} ${T_COMPAT_SRCS} ${T_CRYPT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${T_COMPAT_SRCS} ${T_CRYPT_SRCS} > .depend

depend: .depend

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}
