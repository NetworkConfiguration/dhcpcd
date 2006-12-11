# Should work for both GNU make and BSD make

VERSION = 3.0.6

INSTALL ?= install
CFLAGS ?= -Wall -O2 -pedantic -std=gnu99

DESTDIR =
SBINDIR = $(DESTDIR)/sbin
MANDIR = $(DESTDIR)/usr/share/man

SBIN_TARGETS = dhcpcd
MAN8_TARGETS = dhcpcd.8
TARGET = $(SBIN_TARGETS)

dhcpcd_H = version.h
dhcpcd_OBJS = arp.o client.o common.o configure.o dhcp.o dhcpcd.o \
		interface.o logger.o signals.o socket.o

dhcpcd: $(dhcpcd_H) $(dhcpcd_OBJS)
	$(CC) $(LDFLAGS) $(dhcpcd_OBJS) -o dhcpcd

version.h:
	echo '#define VERSION "$(VERSION)"' > version.h

$(dhcpcd_OBJS): 
	$(CC) $(CFLAGS) -c $*.c

all: $(TARGET)

install: $(TARGET)
	$(INSTALL) -m 0755 -d $(SBINDIR)
	$(INSTALL) -m 0755 $(SBIN_TARGETS) $(SBINDIR)
	$(INSTALL) -m 0755 -d $(MANDIR)/man8
	$(INSTALL) -m 0755 $(MAN8_TARGETS) $(MANDIR)/man8

clean:
	rm -f $(TARGET) $(dhcpcd_H) *.o *~

dist:
	$(INSTALL) -m 0755 -d /tmp/dhcpcd-$(VERSION)
	cp -RPp . /tmp/dhcpcd-$(VERSION)
	$(MAKE) -C /tmp/dhcpcd-$(VERSION) clean
	rm -rf /tmp/dhcpcd-$(VERSION)/*.bz2 /tmp/dhcpcd-$(VERSION)/.svn
	tar cvjpf dhcpcd-$(VERSION).tar.bz2 -C /tmp dhcpcd-$(VERSION)
	rm -rf /tmp/dhcpcd-$(VERSION)
