# Should work for both GNU make and BSD make
# NOTE: I really don't like autotools, but we do need to work a few things out
# such as the need to link to libresolv and/or librt so please forgive the
# embedded code :)

NAME = dhcpcd
VERSION = 3.1.8
PKG = $(NAME)-$(VERSION)

CFLAGS ?= -O2 -pipe

INSTALL ?= install
DESTDIR =
MANPREFIX ?= /usr/share
SBINDIR = $(DESTDIR)$(PREFIX)/sbin
MANDIR = $(DESTDIR)$(MANPREFIX)/man
INFODIR = /var/lib/dhcpcd

SBIN_TARGETS = dhcpcd
MAN_TARGETS = dhcpcd.8
TARGET = $(SBIN_TARGETS) $(MAN_TARGETS)

# Work out if we need -lresolv or not
_LIBRESOLV_SH = printf '\#include <netinet/in.h>\n\#include <resolv.h>\nint main (void) { return (res_init ()); }\n' > .res_init.c; \
	if $(CC) .res_init.c -o .res_init >/dev/null 2>&1; then \
		echo ""; \
	elif $(CC) .res_init.c -lresolv -o .res_init >/dev/null 2>&1; then \
		echo "-lresolv"; \
	else \
		echo "Cannot work out how to get res_init to link" >&2; \
		rm -f .res_init.c .res_init; \
		exit 1; \
	fi; \
	rm -f .res_init.c .res_init
_LIBRESOLV != $(_LIBRESOLV_SH)
LIBRESOLV = $(_LIBRESOLV)$(shell $(_LIBRESOLV_SH))

# Work out if we need -lrt or not
_LIBRT_SH = printf '\#include <time.h>\n\#include <unistd.h>\n\nint main (void) { struct timespec ts;\n\#if defined(_POSIX_MONOTONIC_CLOCK) && defined(CLOCK_MONOTONIC)\nreturn (clock_gettime (CLOCK_MONOTONIC, &ts));\n\#else\nreturn -1;\n\#endif\n}\n' > .clock_gettime.c; \
	if $(CC) .clock_gettime.c -o .clock_gettime >/dev/null 2>&1; then \
		echo ""; \
	elif $(CC) .clock_gettime.c -lrt -o .clock_gettime >/dev/null 2>&1; then \
		echo "-lrt"; \
	else \
		echo ""; \
	fi; \
	rm -f .clock_gettime.c .clock_gettime
_LIBRT != $(_LIBRT_SH)
LIBRT = $(_LIBRT)$(shell $(_LIBRT_SH))

# Work out if our fork() works or not
_HAVE_FORK_SH = if [ "$(HAVE_FORK)" = "yes" ]; then \
		echo ""; \
	elif [ -n "$(HAVE_FORK)" ]; then \
		echo "-DTHERE_IS_NO_FORK"; \
	else \
		printf '\#include <stdlib.h>\n\#include <unistd.h>\nint main (void) { pid_t pid = fork(); if (pid == -1) exit (-1); exit (0); }\n' > .fork.c; \
		$(CC) .fork.c -o .fork >/dev/null 2>&1; \
		if ./.fork; then \
			echo ""; \
		else \
			echo "-DTHERE_IS_NO_FORK"; \
		fi; \
		rm -f .fork.c .fork; \
	fi;
_HAVE_FORK != $(_HAVE_FORK_SH)
FORK = $(_HAVE_FORK)$(shell $(_HAVE_FORK_SH))

# Work out how to restart services 
_RC_SH = if [ -n "$(HAVE_INIT)" ]; then \
		 [ "$(HAVE_INIT)" = "no" ] || echo "-DENABLE_$(HAVE_INIT)"; \
		 elif [ -x /sbin/runscript ]; then echo "-DENABLE_OPENRC"; \
		 elif [ -x /sbin/service ]; then echo "-DENABLE_SERVICE"; \
		 elif [ -x /etc/rc.d/rc.S -a -x /etc/rc.d/rc.M ]; then echo "-DENABLE_SLACKRC"; \
		 elif [ -d /etc/rc.d ]; then echo "-DENABLE_BSDRC"; \
		 elif [ -d /etc/init.d ]; then echo "-DENABLE_SYSV"; \
		 fi
_RC != $(_RC_SH)
RC = $(_RC)$(shell $(_RC_SH))

# pmake check for extra cflags 
WEXTRA != for x in -Wdeclaration-after-statement -Wsequence-point -Wextra; do \
	if $(CC) -Wdeclaration-after-statement -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
	then echo -n "$$x "; fi \
	done

# gmake function for similar, but called below
check_gcc=$(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
		  then echo "$(1)"; else echo "$(2)"; fi)

# Loads of nice flags to ensure our code is good
# IMPORTANT: We should be using c99 instead of gnu99 but for some reason
# generic linux headers as of 2.6.19 don't allow this in asm/types.h
CFLAGS += -pedantic -std=gnu99 \
		  -Wall -Wunused -Wimplicit -Wshadow -Wformat=2 \
		  -Wmissing-declarations -Wno-missing-prototypes -Wwrite-strings \
		  -Wbad-function-cast -Wnested-externs -Wcomment -Winline \
		  -Wchar-subscripts -Wcast-align -Wno-format-nonliteral \
		  $(call check_gcc, -Wdeclaration-after-statement) \
		  $(call check_gcc, -Wsequence-point) \
		  $(call check_gcc, -Wextra) $(WEXTRA)

# -Werrror is a good flag to use for development, but some platforms may
#  have buggy headers from time to time, so you may need to comment this out
#CFLAGS += -Werror

all: $(TARGET)

dhcpcd_H = version.h
dhcpcd_OBJS = arp.o client.o common.o configure.o dhcp.o dhcpcd.o duid.o \
			  info.o interface.o ipv4ll.o logger.o signal.o socket.o

$(dhcpcd_OBJS): 
	$(CC) $(FORK) $(RC) -DINFODIR=\"$(INFODIR)\" $(CFLAGS) -c $*.c

dhcpcd: $(dhcpcd_H) .depend $(dhcpcd_OBJS)
	$(CC) $(LDFLAGS) $(dhcpcd_OBJS) $(LIBRESOLV) $(LIBRT) -o dhcpcd

version.h:
	echo '#define VERSION "$(VERSION)"' > version.h

dhcpcd.8: dhcpcd.8.in
	sed 's:%%INFODIR%%:$(INFODIR):g' dhcpcd.8.in > dhcpcd.8

man: $(MAN_TARGETS) 

.PHONY: clean install dist

# We always need to have a .depend file as not all make implentations can work
# with each others way of optionally including a file
clean:
	echo > .depend
	touch -r Makefile .depend
	rm -f $(TARGET) $(dhcpcd_H) *.o *~ *.core *.bz2

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(SBINDIR)
	$(INSTALL) -m 0755 $(SBIN_TARGETS) $(SBINDIR)
	$(INSTALL) -m 0755 -d $(MANDIR)/man8
	$(INSTALL) -m 0644 $(MAN_TARGETS) $(MANDIR)/man8

dist:
	$(INSTALL) -d /tmp/$(PKG)
	cp -RPp . /tmp/$(PKG)
	(cd /tmp/$(PKG); $(MAKE) clean)
	rm -rf /tmp/$(PKG)/*.bz2 /tmp/$(PKG)/.git /tmp/$(PKG)/test
	tar cvjpf $(PKG).tar.bz2 -C /tmp $(PKG) 
	rm -rf /tmp/$(PKG) 
	ls -l $(PKG).tar.bz2

# Sucky, but I cannot find a way of optional including the .depend file
# that works for all make implementations :/
include .depend
_DEPS != ls *.c *.h
.depend: $(dhcpcd_H) $(_DEPS)$(wildcard *.c *.h)
	$(CC) $(CPPFLAGS) -MM *.c > .depend
