/*
 * dhcpcd - DHCP client daemon -
 * Copyright 2006-2007 Roy Marples <uberlord@gentoo.org>
 * 
 * dhcpcd is an RFC2131 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

/* Netlink suff */
#ifdef __linux__
#include <asm/types.h> /* Needed for 2.4 kernels */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
/* Only glibc-2.3 ships with ifaddrs.h */
#if defined (__GLIBC__) && defined (__GLIBC_PREREQ)
#  if  __GLIBC_PREREQ (2,3)
#    define HAVE_IFADDRS_H
#    include <ifaddrs.h>
#  endif
#endif
#else
#include <net/if_arp.h> /*dietlibc requires this - normally from
						  netinet/ether.h */
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#define HAVE_IFADDRS_H
#  include <ifaddrs.h>
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"
#include "pathnames.h"

void free_address (address_t *addresses)
{
	address_t *p = addresses;
	address_t *n = NULL;

	if (! addresses)
		return;

	while (p) {
		n = p->next;
		free (p);
		p = n;
	}
}

void free_route (route_t *routes)
{
	route_t *p = routes;
	route_t *n = NULL;

	if (! routes)
		return;

	while (p) {
		n = p->next;
		free (p);
		p = n;
	}
}

int inet_ntocidr (struct in_addr address)
{
	int cidr = 0;
	uint32_t mask = htonl (address.s_addr);

	while (mask) {
		cidr++;
		mask <<= 1;
	}

	return (cidr);
}

char *hwaddr_ntoa (const unsigned char *hwaddr, int hwlen)
{
	static char buffer[128];
	char *p = buffer;
	int i;

	for (i = 0; i < hwlen && i < 125; i++) {
		if (i > 0)
			*p ++= ':';
		p += snprintf (p, 3, "%.2x", hwaddr[i]);
	}
	*p ++= '\0';

	return (buffer);
}

interface_t *read_interface (const char *ifname, int metric)
{

	int s;
	struct ifreq ifr;
	interface_t *iface;
	unsigned char hwaddr[16];
	int hwlen = 0;
	sa_family_t family = 0;
	unsigned short mtu;

#ifndef __linux__
	struct ifaddrs *ifap;
	struct ifaddrs *p;
#endif

	if (! ifname)
		return NULL;

	memset (hwaddr, sizeof (hwaddr), 0);

#ifndef __linux__
	if (getifaddrs (&ifap) != 0)
		return NULL;

	for (p = ifap; p; p = p->ifa_next) {
		union {
			struct sockaddr *sa;
			struct sockaddr_dl *sdl;
		} us;

		if (strcmp (p->ifa_name, ifname) != 0)
			continue;

		us.sa = p->ifa_addr;

		if (p->ifa_addr->sa_family != AF_LINK
			|| (us.sdl->sdl_type != IFT_ETHER))
			/*
			   && us.sdl->sdl_type != IFT_ISO88025))
			   */
		{
			logger (LOG_ERR, "interface is not Ethernet");
			freeifaddrs (ifap);
			return NULL;
		}

		memcpy (hwaddr, us.sdl->sdl_data + us.sdl->sdl_nlen, ETHER_ADDR_LEN);
		family = ARPHRD_ETHER;
		hwlen = ETHER_ADDR_LEN;
		break;
	}
	freeifaddrs (ifap);

	if (! p) {
		logger (LOG_ERR, "could not find interface %s", ifname);
		return NULL;
	}
#endif

	memset (&ifr, 0, sizeof (struct ifreq));
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return NULL;
	}

#ifdef __linux__
	/* Do something with the metric parameter to satisfy the compiler warning */
	metric = 0;
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl (s, SIOCGIFHWADDR, &ifr) <0) {
		logger (LOG_ERR, "ioctl SIOCGIFHWADDR: %s", strerror (errno));
		close (s);
		return NULL;
	}

	switch (ifr.ifr_hwaddr.sa_family) {
		case ARPHRD_ETHER:
		case ARPHRD_IEEE802:
			hwlen = ETHER_ADDR_LEN;
			break;
		case ARPHRD_IEEE1394:
			hwlen = EUI64_ADDR_LEN;
		case ARPHRD_INFINIBAND:
			hwlen = INFINIBAND_ADDR_LEN;
			break;
		default:
			logger (LOG_ERR, "interface is not Ethernet, FireWire, InfiniBand or Token Ring");
			close (s);
			return NULL;
	}

	memcpy (hwaddr, ifr.ifr_hwaddr.sa_data, hwlen);
	family = ifr.ifr_hwaddr.sa_family;
#else
	ifr.ifr_metric = metric;
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl (s, SIOCSIFMETRIC, &ifr) < 0) {
		logger (LOG_ERR, "ioctl SIOCSIFMETRIC: %s", strerror (errno));
		close (s);
		return NULL;
	}
#endif

	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(s, SIOCGIFMTU, &ifr) < 0) {
		logger (LOG_ERR, "ioctl SIOCGIFMTU: %s", strerror (errno));
		close (s);
		return NULL;
	}

	if (ifr.ifr_mtu < MTU_MIN) {
		logger (LOG_DEBUG, "MTU of %d is too low, setting to %d", ifr.ifr_mtu, MTU_MIN);
		ifr.ifr_mtu = MTU_MIN;
		strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
		if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
			logger (LOG_ERR, "ioctl SIOCSIFMTU,: %s", strerror (errno));
			close (s);
			return NULL;
		}
	}
	mtu = ifr.ifr_mtu;

	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		logger (LOG_ERR, "ioctl SIOCGIFFLAGS: %s", strerror (errno));
		close (s);
		return NULL;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		logger (LOG_ERR, "ioctl SIOCSIFFLAGS: %s", strerror (errno));
		close (s);
		return NULL;
	}

	close (s);

	iface = xmalloc (sizeof (interface_t));
	memset (iface, 0, sizeof (interface_t));
	strlcpy (iface->name, ifname, IF_NAMESIZE);
	snprintf (iface->infofile, PATH_MAX, INFOFILE, ifname);
	memcpy (&iface->hwaddr, hwaddr, hwlen);
	iface->hwlen = hwlen;

	iface->family = family;
	iface->arpable = ! (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK));
	iface->mtu = iface->previous_mtu = mtu;

	logger (LOG_INFO, "hardware address = %s",
			hwaddr_ntoa (iface->hwaddr, iface->hwlen));

	/* 0 is a valid fd, so init to -1 */
	iface->fd = -1;

	return iface;
}

int get_mtu (const char *ifname)
{
	struct ifreq ifr;
	int r;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return (-1);
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	r = ioctl (s, SIOCGIFMTU, &ifr);
	close (s);

	if (r < 0) {
		logger (LOG_ERR, "ioctl SIOCGIFMTU: %s", strerror (errno));
		return (-1);
	}

	return (ifr.ifr_mtu);
}

int set_mtu (const char *ifname, short int mtu)
{
	struct ifreq ifr;
	int r;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return (-1);
	}

	memset (&ifr, 0, sizeof (struct ifreq));
	logger (LOG_DEBUG, "setting MTU to %d", mtu);
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_mtu = mtu;
	r = ioctl (s, SIOCSIFMTU, &ifr);
	close (s);

	if (r < 0)
		logger (LOG_ERR, "ioctl SIOCSIFMTU: %s", strerror (errno));

	return (r == 0 ? 0 : -1);
}

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) \
|| defined(__APPLE__)
static int do_address (const char *ifname, struct in_addr address,
					   struct in_addr netmask, struct in_addr broadcast, int del)
{
	int s;
	struct ifaliasreq ifa;

	if (! ifname)
		return -1;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&ifa, 0, sizeof (ifa));
	strlcpy (ifa.ifra_name, ifname, sizeof (ifa.ifra_name));

#define ADDADDR(_var, _addr) { \
		union { struct sockaddr *sa; struct sockaddr_in *sin; } _s; \
		_s.sa = &_var; \
		_s.sin->sin_family = AF_INET; \
		_s.sin->sin_len = sizeof (struct sockaddr_in); \
		memcpy (&_s.sin->sin_addr, &_addr, sizeof (struct in_addr)); \
	}

	ADDADDR (ifa.ifra_addr, address);
	ADDADDR (ifa.ifra_mask, netmask);
	if (! del)
		ADDADDR (ifa.ifra_broadaddr, broadcast);

#undef ADDADDR

	if (ioctl (s, del ? SIOCDIFADDR : SIOCAIFADDR, &ifa) == -1) {
		logger (LOG_ERR, "ioctl %s: %s", del ? "SIOCDIFADDR" : "SIOCAIFADDR",
				strerror (errno));
		close (s);
		return -1;
	}

	close (s);
	return 0;
}

static int do_route (const char *ifname,
					 struct in_addr destination,
					 struct in_addr netmask,
					 struct in_addr gateway,
					 int metric,
					 int change, int del)
{
	int s;
	char *dstd;
	struct rtm 
	{
		struct rt_msghdr hdr;
		struct sockaddr_in destination;
		union
		{
			struct sockaddr sa;
			struct sockaddr_in sin;
			struct sockaddr_dl sdl;
			struct sockaddr_storage sss; /* added to avoid memory overrun */
		} gateway;
		struct sockaddr_in netmask;
	} rtm;
	static int seq;

	if (! ifname)
		return -1;

	/* Do something with metric to satisfy compiler warnings */
	metric = 0;

	dstd = xstrdup (inet_ntoa (destination));
	if (gateway.s_addr == destination.s_addr)
		logger (LOG_INFO, "%s route to %s/%d",
				change ? "changing" : del ? "removing" : "adding",
				dstd, inet_ntocidr (netmask));
	else if (destination.s_addr == INADDR_ANY && netmask.s_addr == INADDR_ANY)
		logger (LOG_INFO, "%s default route via %s",
				change ? "changing" : del ? "removing" : "adding",
				inet_ntoa (gateway));
	else
		logger (LOG_INFO, "%s route to %s/%d via %s",
				change ? "changing" : del ? "removing" : "adding",
				dstd, inet_ntocidr (netmask), inet_ntoa (gateway));
	if (dstd)
		free (dstd);

	if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&rtm, 0, sizeof (struct rtm));

	rtm.hdr.rtm_version = RTM_VERSION;
	rtm.hdr.rtm_seq = ++seq;
	rtm.hdr.rtm_type = change ? RTM_CHANGE : del ? RTM_DELETE : RTM_ADD;

	rtm.hdr.rtm_flags = RTF_UP | RTF_STATIC;
	if (netmask.s_addr == INADDR_BROADCAST) 
		rtm.hdr.rtm_flags |= RTF_HOST;
	else
		rtm.hdr.rtm_flags |= RTF_GATEWAY;

	rtm.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

#define ADDADDR(_var, _addr) \
	_var.sin_family = AF_INET; \
	_var.sin_len = sizeof (struct sockaddr_in); \
	memcpy (&_var.sin_addr, &_addr, sizeof (struct in_addr));

	ADDADDR (rtm.destination, destination);
	if (netmask.s_addr == INADDR_BROADCAST) {
		struct ifaddrs *ifap, *ifa;
		union
		{
			struct sockaddr *sa;
			struct sockaddr_dl *sdl;
		} us;

		if (getifaddrs (&ifap)) {
			logger (LOG_ERR, "getifaddrs: %s", strerror (errno));
			return -1;
		}

		for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr->sa_family != AF_LINK)
				continue;

			if (strcmp (ifname, ifa->ifa_name))
				continue;

			us.sa = ifa->ifa_addr;
			memcpy (&rtm.gateway.sdl, us.sdl, us.sdl->sdl_len);
			break;
		}
		freeifaddrs (ifap);
	} else {
		ADDADDR (rtm.gateway.sin, gateway);
	}

	ADDADDR (rtm.netmask, netmask);

#undef ADDADDR

	rtm.hdr.rtm_msglen = sizeof (rtm);

	if (write(s, &rtm, sizeof (rtm)) < 0) {
		/* Don't report error about routes already existing */
		if (errno != EEXIST)
			logger (LOG_ERR, "write: %s", strerror (errno));
		close (s);
		return -1;
	}

	close (s);
	return 0;
}

#elif __linux__
/* This netlink stuff is overly compex IMO.
   The BSD implementation is much cleaner and a lot less code.
   send_netlink handles the actual transmission so we can work out
   if there was an error or not.

   As always throughout this code, credit is due :)
   This blatently taken from libnetlink.c from the iproute2 package
   which is the only good source of netlink code.
   */
static int send_netlink(struct nlmsghdr *hdr)
{
	int s;
	pid_t mypid = getpid ();
	struct sockaddr_nl nl;
	struct iovec iov;
	struct msghdr msg;
	static unsigned int seq;
	char buffer[256];
	int bytes;
	union
	{
		char *buffer;
		struct nlmsghdr *nlm;
	} h;

	if ((s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&nl, 0, sizeof (struct sockaddr_nl));
	nl.nl_family = AF_NETLINK;
	if (bind (s, (struct sockaddr *) &nl, sizeof (nl)) < 0) {
		logger (LOG_ERR, "bind: %s", strerror (errno));
		close (s);
		return -1;
	}

	memset (&iov, 0, sizeof (struct iovec));
	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;

	memset (&msg, 0, sizeof (struct msghdr));
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof (nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Request a reply */
	hdr->nlmsg_flags |= NLM_F_ACK;
	hdr->nlmsg_seq = ++seq;

	if (sendmsg (s, &msg, 0) < 0) {
		logger (LOG_ERR, "write: %s", strerror (errno));
		close (s);
		return -1;
	}

	memset (buffer, 0, sizeof (buffer));
	iov.iov_base = buffer;

	while (1) {
		iov.iov_len = sizeof (buffer);
		bytes = recvmsg(s, &msg, 0);

		if (bytes < 0) {
			if (errno != EINTR)
				logger (LOG_ERR, "netlink: overrun");
			continue;
		}

		if (bytes == 0) {
			logger (LOG_ERR, "netlink: EOF");
			goto eexit;
		}

		if (msg.msg_namelen != sizeof (nl)) {
			logger (LOG_ERR, "netlink: sender address length mismatch");
			goto eexit;
		}

		for (h.buffer = buffer; bytes >= (signed) sizeof (*h.nlm); ) {
			int len = h.nlm->nlmsg_len;
			int l = len - sizeof (*h.nlm);

			if (l < 0 || len > bytes) {
				if (msg.msg_flags & MSG_TRUNC)
					logger (LOG_ERR, "netlink: truncated message");
				else
					logger (LOG_ERR, "netlink: malformed message");
				goto eexit;
			}

			if (nl.nl_pid != 0 ||
				(pid_t) h.nlm->nlmsg_pid != mypid ||
				h.nlm->nlmsg_seq != seq)
				/* Message isn't for us, so skip it */
				goto next;

			/* We get an NLMSG_ERROR back with a code of zero for success */
			if (h.nlm->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h.nlm);
				if ((unsigned) l < sizeof (struct nlmsgerr))
					logger (LOG_ERR, "netlink: truncated error message");
				else {
					errno = -err->error;
					if (errno == 0) {
						close (s);
						return 0;
					}

					/* Don't report on something already existing */
					if (errno != EEXIST)
						logger (LOG_ERR, "netlink: %s", strerror (errno));
				}
				goto eexit;
			}

			logger (LOG_ERR, "netlink: unexpected reply");
next:
			bytes -= NLMSG_ALIGN (len);
			h.buffer += NLMSG_ALIGN (len);
		}

		if (msg.msg_flags & MSG_TRUNC) {
			logger (LOG_ERR, "netlink: truncated message");
			continue;
		}

		if (bytes) {
			logger (LOG_ERR, "netlink: remnant of size %d", bytes);
			goto eexit;
		}
	}

eexit:
	close (s);
	return -1;
}

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((ptrdiff_t) (nmsg)) + NLMSG_ALIGN ((nmsg)->nlmsg_len)))

static int add_attr_l(struct nlmsghdr *n, unsigned int maxlen, int type,
					  const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen) {
		logger (LOG_ERR, "add_attr_l: message exceeded bound of %d\n", maxlen);
		return -1;
	}

	rta = NLMSG_TAIL (n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);

	return 0;
}

static int add_attr_32(struct nlmsghdr *n, unsigned int maxlen, int type,
					   uint32_t data)
{
	int len = RTA_LENGTH (sizeof (uint32_t));
	struct rtattr *rta;

	if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen) {
		logger (LOG_ERR, "add_attr32: message exceeded bound of %d\n", maxlen);
		return -1;
	}

	rta = NLMSG_TAIL (n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), &data, sizeof (uint32_t));
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

	return 0;
}

static int do_address(const char *ifname,
					  struct in_addr address, struct in_addr netmask,
					  struct in_addr broadcast, int del)
{
	struct
	{
		struct nlmsghdr hdr;
		struct ifaddrmsg ifa;
		char buffer[64];
	}
	nlm;

	if (!ifname)
		return -1;

	memset (&nlm, 0, sizeof (nlm));

	nlm.hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	if (! del)
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	nlm.hdr.nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
	if (! (nlm.ifa.ifa_index = if_nametoindex (ifname))) {
		logger (LOG_ERR, "if_nametoindex: Couldn't find index for interface `%s'",
				ifname);
		return -1;
	}
	nlm.ifa.ifa_family = AF_INET;

	nlm.ifa.ifa_prefixlen = inet_ntocidr (netmask);
	add_attr_l (&nlm.hdr, sizeof (nlm), IFA_LOCAL, &address.s_addr,
				sizeof (address.s_addr));
	if (! del)
		add_attr_l (&nlm.hdr, sizeof (nlm), IFA_BROADCAST, &broadcast.s_addr,
					sizeof (broadcast.s_addr));

	return send_netlink (&nlm.hdr);
}

static int do_route (const char *ifname,
					 struct in_addr destination,
					 struct in_addr netmask,
					 struct in_addr gateway,
					 int metric, int change, int del)
{
	char *dstd;
	char *gend;
	unsigned int ifindex;
	struct
	{
		struct nlmsghdr hdr;
		struct rtmsg rt;
		char buffer[256];
	}
	nlm;

	if (! ifname)
		return -1;

	dstd = xstrdup (inet_ntoa (destination));
	gend = xstrdup (inet_ntoa (netmask));
	if (gateway.s_addr == destination.s_addr)
		logger (LOG_INFO, "%s route to %s (%s) metric %d",
				change ? "changing" : del ? "removing" : "adding",
				dstd, gend, metric);
	else if (destination.s_addr == INADDR_ANY && netmask.s_addr == INADDR_ANY)
		logger (LOG_INFO, "%s default route via %s metric %d",
				change ? "changing" : del ? "removing" : "adding",
				inet_ntoa (gateway), metric);
	else
		logger (LOG_INFO, "%s route to %s (%s) via %s metric %d",
				change ? "changing" : del ? "removing" : "adding",
				dstd, gend, inet_ntoa (gateway), metric);
	if (dstd)
		free (dstd);
	if (gend)
		free (gend);

	memset (&nlm, 0, sizeof (nlm));

	nlm.hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
	if (change)
		nlm.hdr.nlmsg_flags = NLM_F_REPLACE;
	else if (! del)
		nlm.hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	nlm.hdr.nlmsg_flags |= NLM_F_REQUEST;
	nlm.hdr.nlmsg_type = del ? RTM_DELROUTE : RTM_NEWROUTE;
	nlm.rt.rtm_family = AF_INET;
	nlm.rt.rtm_table = RT_TABLE_MAIN;

	if (del)
		nlm.rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		nlm.rt.rtm_protocol = RTPROT_BOOT;
		if (gateway.s_addr == INADDR_ANY ||
			netmask.s_addr == INADDR_BROADCAST)
			nlm.rt.rtm_scope = RT_SCOPE_LINK;
		else
			nlm.rt.rtm_scope = RT_SCOPE_UNIVERSE;
		nlm.rt.rtm_type = RTN_UNICAST;
	}

	nlm.rt.rtm_dst_len = inet_ntocidr (netmask);
	add_attr_l (&nlm.hdr, sizeof (nlm), RTA_DST, &destination.s_addr,
				sizeof (destination.s_addr));
	if (gateway.s_addr != INADDR_ANY && gateway.s_addr != destination.s_addr)
		add_attr_l (&nlm.hdr, sizeof (nlm), RTA_GATEWAY, &gateway.s_addr,
					sizeof (gateway.s_addr));


	if (! (ifindex = if_nametoindex (ifname))) {
		logger (LOG_ERR, "if_nametoindex: Couldn't find index for interface `%s'",
				ifname);
		return -1;
	}

	add_attr_32 (&nlm.hdr, sizeof (nlm), RTA_OIF, ifindex);
	add_attr_32 (&nlm.hdr, sizeof (nlm), RTA_PRIORITY, metric);

	return send_netlink (&nlm.hdr);
}

#else
#error "Platform not supported!"
#error "We currently support BPF and Linux sockets."
#error "Other platforms may work using BPF. If yours does, please let me know"
#error "so I can add it to our list."
#endif


int add_address (const char *ifname, struct in_addr address,
				 struct in_addr netmask, struct in_addr broadcast)
{
	logger (LOG_INFO, "adding IP address %s/%d",
			inet_ntoa (address), inet_ntocidr (netmask));

	return (do_address (ifname, address, netmask, broadcast, 0));
}

int del_address (const char *ifname,
				 struct in_addr address, struct in_addr netmask)
{
	struct in_addr t;

	logger (LOG_INFO, "deleting IP address %s/%d",
			inet_ntoa (address), inet_ntocidr (netmask));

	memset (&t, 0, sizeof (t));
	return (do_address (ifname, address, netmask, t, 1));
}

int add_route (const char *ifname, struct in_addr destination,
			   struct in_addr netmask, struct in_addr gateway, int metric)
{
	return (do_route (ifname, destination, netmask, gateway, metric, 0, 0));
}

int change_route (const char *ifname, struct in_addr destination,
				  struct in_addr netmask, struct in_addr gateway, int metric)
{
	return (do_route (ifname, destination, netmask, gateway, metric, 1, 0));
}

int del_route (const char *ifname, struct in_addr destination,
			   struct in_addr netmask, struct in_addr gateway, int metric)
{
	return (do_route (ifname, destination, netmask, gateway, metric, 0, 1));
}

#ifdef HAVE_IFADDRS_H
int flush_addresses (const char *ifname)
{
	struct ifaddrs *ifap;
	struct ifaddrs *p;
	int retval = 0;

	if (! ifname)
		return -1;
	if (getifaddrs (&ifap) != 0)
		return -1;

	for (p = ifap; p; p = p->ifa_next) {
		union
		{
			struct sockaddr *sa;
			struct sockaddr_in *sin;
		} us_a, us_m;

		if (strcmp (p->ifa_name, ifname) != 0)
			continue;

		us_a.sa = p->ifa_addr;
		us_m.sa = p->ifa_netmask;

		if (us_a.sin->sin_family == AF_INET)
			if (del_address (ifname, us_a.sin->sin_addr, us_m.sin->sin_addr) < 0)
				retval = -1;
	}
	freeifaddrs (ifap);

	return retval;
}
#else
int flush_addresses (const char *ifname)
{
	int s;
	struct ifconf ifc;
	int retval = 0;
	int i;
	void *ifrs;
	int nifs;
	struct ifreq *ifr;

	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&ifc, 0, sizeof (struct ifconf));
	ifc.ifc_buf = NULL;
	if (ioctl (s, SIOCGIFCONF, &ifc) < 0) {
		logger (LOG_ERR, "ioctl SIOCGIFCONF: %s", strerror (errno));
		close (s);
	}

	ifrs = xmalloc (ifc.ifc_len);
	ifc.ifc_buf = ifrs;
	if (ioctl (s, SIOCGIFCONF, &ifc) < 0) {
		logger (LOG_ERR, "ioctl SIOCGIFCONF: %s", strerror (errno));
		close (s);
		free (ifrs);
		return -1;
	}

	close (s);

	nifs = ifc.ifc_len / sizeof (struct ifreq);
	ifr = ifrs;
	for (i = 0; i < nifs; i++) {
		struct sockaddr_in *addr = (struct sockaddr_in *) &ifr->ifr_addr;
		struct sockaddr_in *netm = (struct sockaddr_in *) &ifr->ifr_netmask;

		if (ifr->ifr_addr.sa_family == AF_INET
			&& strcmp (ifname, ifr->ifr_name) == 0)
			if (del_address (ifname, addr->sin_addr, netm->sin_addr) < 0)
				retval = -1;
		ifr++;
	}

	free (ifrs);
	return retval;
}
#endif
