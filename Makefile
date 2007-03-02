# Should work for both GNU make and BSD make

VERSION = 3.0.16

CFLAGS ?= -O2 -pipe

# Loads of nice flags to ensure our code is good
# IMPORTANT: We should be using c99 instead of gnu99 but for some reason
# generic linux headers as of 2.6.19 don't allow this in asm/types.h
CFLAGS += -pedantic -std=gnu99 \
    -Wall -Wunused -Wimplicit -Wshadow -Wformat=2 \
    -Wmissing-declarations -Wno-missing-prototypes -Wwrite-strings \
    -Wbad-function-cast -Wnested-externs -Wcomment -Winline \
    -Wchar-subscripts -Wcast-align -Wno-format-nonliteral

# Early GCC versions don't support these flags, so you may need to comment
# this line out
CFLAGS += -Wsequence-point -Wextra -Wdeclaration-after-statement

# -Werrror is a good flag to use for development, but some platforms may
#  have buggy headers from time to time, so you may need to comment this out
#CFLAGS += -Werror

# We define _BSD_SOURCE as GNU supports BSD too - which is nice :)
CDEFS = -D_BSD_SOURCE

INSTALL ?= install
DESTDIR =
SBINDIR = $(DESTDIR)/sbin
MANDIR = $(DESTDIR)/usr/share/man

SBIN_TARGETS = dhcpcd
MAN8_TARGETS = dhcpcd.8
TARGET = $(SBIN_TARGETS)

dhcpcd_H = version.h
dhcpcd_OBJS = arp.o client.o common.o configure.o dhcp.o dhcpcd.o \
		interface.o logger.o signals.o socket.o

# By default we don't need to link to anything
# Except on Darwin where we need -lresolv, so they need to uncomment this
#dhcpcd_LIBS = -lresolv

dhcpcd: $(dhcpcd_H) $(dhcpcd_OBJS)
	$(CC) $(LDFLAGS) $(dhcpcd_OBJS) $(dhcpcd_LIBS) -o dhcpcd

version.h:
	echo '#define VERSION "$(VERSION)"' > version.h

$(dhcpcd_OBJS): 
	$(CC) $(CDEFS) $(CFLAGS) -c $*.c

all: $(TARGET)

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(SBINDIR)
	$(INSTALL) -m 0755 $(SBIN_TARGETS) $(SBINDIR)
	$(INSTALL) -m 0755 -d $(MANDIR)/man8
	$(INSTALL) -m 0755 $(MAN8_TARGETS) $(MANDIR)/man8

clean:
	rm -f $(TARGET) $(dhcpcd_H) *.o *~ *.core *.bz2

dist:
	$(INSTALL) -m 0755 -d /tmp/dhcpcd-$(VERSION)
	cp -RPp . /tmp/dhcpcd-$(VERSION)
	$(MAKE) -C /tmp/dhcpcd-$(VERSION) clean
	rm -rf /tmp/dhcpcd-$(VERSION)/*.bz2 /tmp/dhcpcd-$(VERSION)/.svn
	tar cvjpf dhcpcd-$(VERSION).tar.bz2 -C /tmp dhcpcd-$(VERSION)
	rm -rf /tmp/dhcpcd-$(VERSION)
