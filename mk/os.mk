# Setup OS specific variables
# Copyright 2008 Roy Marples <roy@marples.name>

# Work out if we need -lresolv or not
_LIBRESOLV_SH= printf '\#include <netinet/in.h>\n\#include <resolv.h>\nint main (void) { return (res_init ()); }\n' > .res_init.c; \
	if ${CC} .res_init.c -o .res_init >/dev/null 2>&1; then \
		echo ""; \
	elif ${CC} .res_init.c -lresolv -o .res_init >/dev/null 2>&1; then \
		echo "-lresolv"; \
	else \
		echo "Cannot work out how to get res_init to link" >&2; \
		rm -f .res_init.c .res_init; \
		exit 1; \
	fi; \
	rm -f .res_init.c .res_init
_LIBRESOLV!= ${_LIBRESOLV_SH}
LIBRESOLV= ${_LIBRESOLV}$(shell ${_LIBRESOLV_SH})

# Work out if we need -lrt or not
_LIBRT_SH= printf '\#include <time.h>\n\#include <unistd.h>\n\nint main (void) { struct timespec ts;\n\#if defined(_POSIX_MONOTONIC_CLOCK) && defined(CLOCK_MONOTONIC)\nreturn (clock_gettime (CLOCK_MONOTONIC, &ts));\n\#else\nreturn -1;\n\#endif\n}\n' > .clock_gettime.c; \
	if ${CC} .clock_gettime.c -o .clock_gettime >/dev/null 2>&1; then \
		echo ""; \
	elif ${CC} .clock_gettime.c -lrt -o .clock_gettime >/dev/null 2>&1; then \
		echo "-lrt"; \
	else \
		echo ""; \
	fi; \
	rm -f .clock_gettime.c .clock_gettime
_LIBRT!= ${_LIBRT_SH}
LIBRT= ${_LIBRT}$(shell ${_LIBRT_SH})

# Work out if our fork() works or not
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
_HAVE_FORK!= ${_HAVE_FORK_SH}
FORK= ${_HAVE_FORK}$(shell ${_HAVE_FORK_SH})

# info dir defaults to /var/lib/dhcpcd on Linux and /var/db elsewhere
_INFODIR_SH= if test -n "${INFODIR}"; then \
			  echo "${INFODIR}"; \
			  else \
			  case `uname -s` in \
			  Linux) echo "/var/lib/dhcpcd";; \
			  *) echo "/var/db";; \
			  esac \
			  fi
_INFODIR!= ${_INFODIR_SH}
INFOD?= ${_INFODIR}$(shell ${_INFODIR_SH})

# Work out how to restart services 
_RC_SH= if test -n "${HAVE_INIT}"; then \
		 test "${HAVE_INIT}" = "no" || echo "-DENABLE_${HAVE_INIT}"; \
		 elif test -x /sbin/runscript; then echo "-DENABLE_OPENRC"; \
		 elif test -x /sbin/service; then echo "-DENABLE_SERVICE"; \
		 elif test -x /etc/rc.d/rc.S -a -x /etc/rc.d/rc.M; then echo "-DENABLE_SLACKRC"; \
		 elif test -d /etc/rc.d; then echo "-DENABLE_BSDRC"; \
		 elif test -d /etc/init.d; then echo "-DENABLE_SYSV"; \
		 fi
_RC!= ${_RC_SH}
RC= ${_RC}$(shell ${_RC_SH})
