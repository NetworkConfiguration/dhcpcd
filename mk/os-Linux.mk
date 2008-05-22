# Setup OS specific variables
# Copyright 2008 Roy Marples <roy@marples.name>

SRC_PF=		lpf.c
SRC_IF=		if-linux.c

CPPFLAGS+=	-D_BSD_SOURCE -D_XOPEN_SOURCE=600
LIBRT=		-lrt

# Work out if our fork() works or not.
# If cross-compiling, you'll need to set HAVE_FORK to yes or no depending
# on your target arch.
_HAVE_FORK_SH= if test "${HAVE_FORK}" = "yes"; then \
		echo ""; \
	elif test -n "${HAVE_FORK}"; then \
		echo "-DTHERE_IS_NO_FORK"; \
	else \
		printf '\#include <stdlib.h>\n\#include <unistd.h>\nint main (void) { pid_t pid = fork(); if (pid == -1) exit (-1); exit (0); }\n' > .fork.c; \
		${CC} .fork.c -o .fork >/dev/null 2>&1; \
		if ./.fork; then \
			echo ""; \
		else \
			echo "-DTHERE_IS_NO_FORK"; \
		fi; \
		rm -f .fork.c .fork; \
	fi;
_HAVE_FORK!=	${_HAVE_FORK_SH}
CPPFLAGS+=	${_HAVE_FORK}$(shell ${_HAVE_FORK_SH})
