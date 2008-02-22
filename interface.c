/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <arpa/inet.h>

/* Netlink suff */
#ifdef __linux__
#include <asm/types.h> /* Needed for 2.4 kernels */
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"

void free_address (struct address_head *addresses)
{
	address_t *p;
	address_t *n;

	if (! addresses)
		return;

	p = STAILQ_FIRST (addresses);
	while (p) {
		n = STAILQ_NEXT (p, entries); 
		free (p);
		p = n;
	}
}

void free_route (struct route_head *routes)
{
	route_t *p;
	route_t *n;

	if (! routes)
		return;

	p = STAILQ_FIRST (routes);
	while (p) {
		n = STAILQ_NEXT (p, entries);
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

int inet_cidrtoaddr (int cidr, struct in_addr *addr) {
	int ocets;

	if (cidr < 0 || cidr > 32) {
		errno = EINVAL;
		return (-1);
	}
	ocets = (cidr + 7) / 8;

	memset (addr, 0, sizeof (*addr));
	if (ocets > 0) {
		memset (&addr->s_addr, 255, (size_t) ocets - 1);
		memset ((unsigned char *) &addr->s_addr + (ocets - 1),
			(256 - (1 << (32 - cidr) % 8)), 1);
	}

	return (0);
}

uint32_t get_netmask (uint32_t addr)
{
	uint32_t dst;

	if (addr == 0)
		return (0);

	dst = htonl (addr);
	if (IN_CLASSA (dst))
		return (ntohl (IN_CLASSA_NET));
	if (IN_CLASSB (dst))
		return (ntohl (IN_CLASSB_NET));
	if (IN_CLASSC (dst))
		return (ntohl (IN_CLASSC_NET));

	return (0);
}

char *hwaddr_ntoa (const unsigned char *hwaddr, size_t hwlen)
{
	static char buffer[(HWADDR_LEN * 3) + 1];
	char *p = buffer;
	size_t i;

	for (i = 0; i < hwlen && i < HWADDR_LEN; i++) {
		if (i > 0)
			*p ++= ':';
		p += snprintf (p, 3, "%.2x", hwaddr[i]);
	}

	*p ++= '\0';

	return (buffer);
}

size_t hwaddr_aton (unsigned char *buffer, const char *addr)
{
	char c[3];
	const char *p = addr;
	unsigned char *bp = buffer;
	size_t len = 0;

	c[2] = '\0';
	while (*p) {
		c[0] = *p++;
		c[1] = *p++;
		/* Ensure that next data is EOL or a seperator with data */
		if (! (*p == '\0' || (*p == ':' && *(p + 1) != '\0'))) {
			errno = EINVAL;
			return (0);
		}
		/* Ensure that digits are hex */
		if (isxdigit ((int) c[0]) == 0 || isxdigit ((int) c[1]) == 0) {
			errno = EINVAL;
			return (0);
		}
		p++;
		if (bp)
			*bp++ = (unsigned char) strtol (c, NULL, 16);
		else
			len++;
	}

	if (bp)
		return (bp - buffer);
	return (len);
}

static int _do_interface (const char *ifname,
			  _unused unsigned char *hwaddr, _unused size_t *hwlen,
			  struct in_addr *addr,
			  bool flush, bool get)
{
	int s;
	struct ifconf ifc;
	int retval = 0;
	int len = 10 * sizeof (struct ifreq);
	int lastlen = 0;
	char *p;

	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	/* Not all implementations return the needed buffer size for
	 * SIOGIFCONF so we loop like so for all until it works */
	memset (&ifc, 0, sizeof (ifc));
	for (;;) {
		ifc.ifc_len = len;
		ifc.ifc_buf = xmalloc ((size_t) len);
		if (ioctl (s, SIOCGIFCONF, &ifc) == -1) {
			if (errno != EINVAL || lastlen != 0) {
				logger (LOG_ERR, "ioctl SIOCGIFCONF: %s",
					strerror (errno));
				close (s);
				free (ifc.ifc_buf);	
				return -1;
			}
		} else {
			if (ifc.ifc_len == lastlen)
				break;
			lastlen = ifc.ifc_len;
		}

		free (ifc.ifc_buf);
		ifc.ifc_buf = NULL;
		len *= 2;
	}

	for (p = ifc.ifc_buf; p < ifc.ifc_buf + ifc.ifc_len;) {
		union {
			char *buffer;
			struct ifreq *ifr;
		} ifreqs;
		struct sockaddr_in address;
		struct ifreq *ifr;

		/* Cast the ifc buffer to an ifreq cleanly */
		ifreqs.buffer = p;
		ifr = ifreqs.ifr;

#ifdef __linux__
		p += sizeof (*ifr);
#else
		p += offsetof (struct ifreq, ifr_ifru) + ifr->ifr_addr.sa_len;
#endif

		if (strcmp (ifname, ifr->ifr_name) != 0)
			continue;

#ifdef AF_LINK
		if (hwaddr && hwlen && ifr->ifr_addr.sa_family == AF_LINK) {
			struct sockaddr_dl sdl;

			memcpy (&sdl, &ifr->ifr_addr, sizeof (sdl));
			*hwlen = sdl.sdl_alen;
			memcpy (hwaddr, sdl.sdl_data + sdl.sdl_nlen,
				(size_t) sdl.sdl_alen);
			retval = 1;
			break;
		}
#endif

		if (ifr->ifr_addr.sa_family == AF_INET)	{
			memcpy (&address, &ifr->ifr_addr, sizeof (address));
			if (flush) {
				struct sockaddr_in netmask;

				if (ioctl (s, SIOCGIFNETMASK, ifr) == -1) {
					logger (LOG_ERR,
						"ioctl SIOCGIFNETMASK: %s",
						strerror (errno));
					continue;
				}
				memcpy (&netmask, &ifr->ifr_addr,
					sizeof (netmask));

				if (del_address (ifname,
						 address.sin_addr,
						 netmask.sin_addr) == -1)
					retval = -1;
			} else if (get) {
				addr->s_addr = address.sin_addr.s_addr;
				retval = 1;
				break;
			} else if (address.sin_addr.s_addr == addr->s_addr) {
				retval = 1;
				break;
			}
		}

	}

	close (s);
	free (ifc.ifc_buf);
	return retval;
}

interface_t *read_interface (const char *ifname, _unused int metric)
{
	int s;
	struct ifreq ifr;
	interface_t *iface = NULL;
	unsigned char *hwaddr = NULL;
	size_t hwlen = 0;
	sa_family_t family = 0;
	unsigned short mtu;
#ifdef __linux__
	char *p;
#endif

	if (! ifname)
		return NULL;

	memset (&ifr, 0, sizeof (ifr));
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));

	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return NULL;
	}

#ifdef __linux__
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl (s, SIOCGIFHWADDR, &ifr) == -1) {
		logger (LOG_ERR, "ioctl SIOCGIFHWADDR: %s", strerror (errno));
		goto exit;
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
			logger (LOG_ERR,
				"interface is not Ethernet, FireWire, " \
				"InfiniBand or Token Ring");
			goto exit;
	}

	hwaddr = xmalloc (sizeof (unsigned char) * HWADDR_LEN);
	memcpy (hwaddr, ifr.ifr_hwaddr.sa_data, hwlen);
	family = ifr.ifr_hwaddr.sa_family;
#else
	ifr.ifr_metric = metric;
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl (s, SIOCSIFMETRIC, &ifr) == -1) {
		logger (LOG_ERR, "ioctl SIOCSIFMETRIC: %s", strerror (errno));
		goto exit;
	}

	hwaddr = xmalloc (sizeof (unsigned char) * HWADDR_LEN);
	if (_do_interface (ifname, hwaddr, &hwlen, NULL, false, false) != 1) {
		logger (LOG_ERR, "could not find interface %s", ifname);
		goto exit;
	}

	family = ARPHRD_ETHER;
#endif

	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	if (ioctl (s, SIOCGIFMTU, &ifr) == -1) {
		logger (LOG_ERR, "ioctl SIOCGIFMTU: %s", strerror (errno));
		goto exit;
	}

	if (ifr.ifr_mtu < MTU_MIN) {
		logger (LOG_DEBUG, "MTU of %d is too low, setting to %d",
			ifr.ifr_mtu, MTU_MIN);
		ifr.ifr_mtu = MTU_MIN;
		strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
		if (ioctl (s, SIOCSIFMTU, &ifr) == -1) {
			logger (LOG_ERR, "ioctl SIOCSIFMTU,: %s",
				strerror (errno));
			goto exit;
		}
	}
	mtu = ifr.ifr_mtu;

	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
#ifdef __linux__
	/* We can only bring the real interface up */
	if ((p = strchr (ifr.ifr_name, ':')))
		*p = '\0';
#endif
	if (ioctl (s, SIOCGIFFLAGS, &ifr) == -1) {
		logger (LOG_ERR, "ioctl SIOCGIFFLAGS: %s", strerror (errno));
		goto exit;
	}

	if (! (ifr.ifr_flags & IFF_UP) || ! (ifr.ifr_flags & IFF_RUNNING)) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl (s, SIOCSIFFLAGS, &ifr) != 0) {
			logger (LOG_ERR, "ioctl SIOCSIFFLAGS: %s",
				strerror (errno));
			goto exit;
		}
	}

	iface = xzalloc (sizeof (*iface));
	strlcpy (iface->name, ifname, IF_NAMESIZE);
#ifdef ENABLE_INFO
	snprintf (iface->infofile, PATH_MAX, INFOFILE, ifname);
#endif
	memcpy (&iface->hwaddr, hwaddr, hwlen);
	iface->hwlen = hwlen;

	iface->family = family;
	iface->arpable = ! (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK));
	iface->mtu = iface->previous_mtu = mtu;

	logger (LOG_INFO, "hardware address = %s",
		hwaddr_ntoa (iface->hwaddr, iface->hwlen));

	/* 0 is a valid fd, so init to -1 */
	iface->fd = -1;
#ifdef __linux__
	iface->listen_fd = -1;
#endif

exit:
	close (s);
	free (hwaddr);
	return iface;
}

int get_mtu (const char *ifname)
{
	struct ifreq ifr;
	int r;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return (-1);
	}

	memset (&ifr, 0, sizeof (ifr));
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	r = ioctl (s, SIOCGIFMTU, &ifr);
	close (s);

	if (r == -1) {
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

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return (-1);
	}

	memset (&ifr, 0, sizeof (ifr));
	logger (LOG_DEBUG, "setting MTU to %d", mtu);
	strlcpy (ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	ifr.ifr_mtu = mtu;
	r = ioctl (s, SIOCSIFMTU, &ifr);
	close (s);

	if (r == -1)
		logger (LOG_ERR, "ioctl SIOCSIFMTU: %s", strerror (errno));

	return (r == 0 ? 0 : -1);
}

static void log_route (struct in_addr destination,
		       struct in_addr netmask,
		       struct in_addr gateway,
		       _unused int metric,
		       int change, int del)
{
	char *dstd = xstrdup (inet_ntoa (destination));

#ifdef __linux__
#define METRIC " metric %d"
#else
#define METRIC ""
#endif

	if (gateway.s_addr == destination.s_addr ||
	    gateway.s_addr == INADDR_ANY)
		logger (LOG_INFO, "%s route to %s/%d" METRIC,
			change ? "changing" : del ? "removing" : "adding",
			dstd, inet_ntocidr (netmask)
#ifdef __linux__
			, metric
#endif
		       );
	else if (destination.s_addr == INADDR_ANY)
		logger (LOG_INFO, "%s default route via %s" METRIC,
			change ? "changing" : del ? "removing" : "adding",
			inet_ntoa (gateway)

#ifdef __linux__
			, metric
#endif
		       );
	else
		logger (LOG_INFO, "%s route to %s/%d via %s" METRIC,
			change ? "changing" : del ? "removing" : "adding",
			dstd, inet_ntocidr (netmask), inet_ntoa (gateway)
#ifdef __linux__
			, metric
#endif
		       );

	free (dstd);
}

#if defined(BSD) || defined(__FreeBSD_kernel__)

/* Darwin doesn't define this for some very odd reason */
#ifndef SA_SIZE
# define SA_SIZE(sa)						\
	(  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?	\
	   sizeof(long)		:				\
	   1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

static int do_address (const char *ifname, struct in_addr address,
		       struct in_addr netmask, struct in_addr broadcast,
		       int del)
{
	int s;
	struct ifaliasreq ifa;

	if (! ifname)
		return -1;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&ifa, 0, sizeof (ifa));
	strlcpy (ifa.ifra_name, ifname, sizeof (ifa.ifra_name));

#define ADDADDR(_var, _addr) { \
	union { struct sockaddr *sa; struct sockaddr_in *sin; } _s; \
	_s.sa = &_var; \
	_s.sin->sin_family = AF_INET; \
	_s.sin->sin_len = sizeof (*_s.sin); \
	memcpy (&_s.sin->sin_addr, &_addr, sizeof (_s.sin->sin_addr)); \
}

	ADDADDR (ifa.ifra_addr, address);
	ADDADDR (ifa.ifra_mask, netmask);
if (! del)
	ADDADDR (ifa.ifra_broadaddr, broadcast);

#undef ADDADDR

	if (ioctl (s, del ? SIOCDIFADDR : SIOCAIFADDR, &ifa) == -1) {
		logger (LOG_ERR, "ioctl %s: %s",
			del ? "SIOCDIFADDR" : "SIOCAIFADDR",
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
	static int seq;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_in sin;
#ifdef INET6
		struct sockaddr_in6 sin6;
#endif
		struct sockaddr_dl sdl;
		struct sockaddr_storage ss;
	} su;
	struct rtm 
	{
		struct rt_msghdr hdr;
		char buffer[sizeof (su) * 3];
	} rtm;
	char *bp = rtm.buffer;
	size_t l;

	if (! ifname)
		return -1;

	log_route (destination, netmask, gateway, metric, change, del);

	if ((s = socket (PF_ROUTE, SOCK_RAW, 0)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&rtm, 0, sizeof (rtm));

	rtm.hdr.rtm_version = RTM_VERSION;
	rtm.hdr.rtm_seq = ++seq;
	rtm.hdr.rtm_type = change ? RTM_CHANGE : del ? RTM_DELETE : RTM_ADD;
	rtm.hdr.rtm_flags = RTF_UP | RTF_STATIC;

	/* This order is important */
	rtm.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

#define ADDADDR(_addr) \
	memset (&su, 0, sizeof (su)); \
	su.sin.sin_family = AF_INET; \
	su.sin.sin_len = sizeof (su.sin); \
	memcpy (&su.sin.sin_addr, &_addr, sizeof (su.sin.sin_addr)); \
	l = SA_SIZE (&(su.sa)); \
	memcpy (bp, &(su), l); \
	bp += l;

	ADDADDR (destination);

	if (netmask.s_addr == INADDR_BROADCAST ||
	    gateway.s_addr == INADDR_ANY)
	{
		/* Make us a link layer socket */
		unsigned char *hwaddr;
		size_t hwlen = 0;

		if (netmask.s_addr == INADDR_BROADCAST) 
			rtm.hdr.rtm_flags |= RTF_HOST;

		hwaddr = xmalloc (sizeof (unsigned char) * HWADDR_LEN);
		_do_interface (ifname, hwaddr, &hwlen, NULL, false, false);
		memset (&su, 0, sizeof (su));
		su.sdl.sdl_len = sizeof (su.sdl);
		su.sdl.sdl_family = AF_LINK;
		su.sdl.sdl_nlen = strlen (ifname);
		memcpy (&su.sdl.sdl_data, ifname, (size_t) su.sdl.sdl_nlen);
		su.sdl.sdl_alen = hwlen;
		memcpy (((unsigned char *) &su.sdl.sdl_data) + su.sdl.sdl_nlen,
			hwaddr, (size_t) su.sdl.sdl_alen);

		l = SA_SIZE (&(su.sa));
		memcpy (bp, &su, l);
		bp += l;
		free (hwaddr);
	} else {
		rtm.hdr.rtm_flags |= RTF_GATEWAY;
		ADDADDR (gateway);
	}

	ADDADDR (netmask);
#undef ADDADDR

	rtm.hdr.rtm_msglen = l = bp - (char *)&rtm;
	if (write (s, &rtm, l) == -1) {
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
 * The BSD implementation is much cleaner and a lot less code.
 * send_netlink handles the actual transmission so we can work out
 * if there was an error or not. */
#define BUFFERLEN 256
int send_netlink (struct nlmsghdr *hdr, netlink_callback callback, void *arg)
{
	int s;
	pid_t mypid = getpid ();
	struct sockaddr_nl nl;
	struct iovec iov;
	struct msghdr msg;
	static unsigned int seq;
	char *buffer;
	ssize_t bytes;
	union
	{
		char *buffer;
		struct nlmsghdr *nlm;
	} h;

	if ((s = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
		logger (LOG_ERR, "socket: %s", strerror (errno));
		return -1;
	}

	memset (&nl, 0, sizeof (nl));
	nl.nl_family = AF_NETLINK;
	if (bind (s, (struct sockaddr *) &nl, sizeof (nl)) == -1) {
		logger (LOG_ERR, "bind: %s", strerror (errno));
		close (s);
		return -1;
	}

	memset (&iov, 0, sizeof (iov));
	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;

	memset (&msg, 0, sizeof (msg));
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof (nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Request a reply */
	hdr->nlmsg_flags |= NLM_F_ACK;
	hdr->nlmsg_seq = ++seq;

	if (sendmsg (s, &msg, 0) == -1) {
		logger (LOG_ERR, "write: %s", strerror (errno));
		close (s);
		return -1;
	}

	buffer = xzalloc (sizeof (char) * BUFFERLEN);
	iov.iov_base = buffer;

	for (;;) {
		iov.iov_len = BUFFERLEN;
		bytes = recvmsg (s, &msg, 0);

		if (bytes == -1) {
			if (errno != EINTR)
				logger (LOG_ERR, "recvmsg: %s",
					strerror (errno));
			continue;
		}

		if (bytes == 0) {
			logger (LOG_ERR, "netlink: EOF");
			goto eexit;
		}

		if (msg.msg_namelen != sizeof (nl)) {
			logger (LOG_ERR,
				"netlink: sender address length mismatch");
			goto eexit;
		}

		for (h.buffer = buffer; bytes >= (signed) sizeof (*h.nlm); ) {
			int len = h.nlm->nlmsg_len;
			int l = len - sizeof (*h.nlm);
			struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h.nlm);

			if (l < 0 || len > bytes) {
				if (msg.msg_flags & MSG_TRUNC)
					logger (LOG_ERR, "netlink: truncated message");
				else
					logger (LOG_ERR, "netlink: malformed message");
				goto eexit;
			}

			/* Ensure it's our message */
			if (nl.nl_pid != 0 ||
			    (pid_t) h.nlm->nlmsg_pid != mypid ||
			    h.nlm->nlmsg_seq != seq)
			{
				/* Next Message */
				bytes -= NLMSG_ALIGN (len);
				h.buffer += NLMSG_ALIGN (len);
				continue;
			}

			/* We get an NLMSG_ERROR back with a code of zero for success */
			if (h.nlm->nlmsg_type != NLMSG_ERROR) {
				logger (LOG_ERR, "netlink: unexpected reply %d",
				       	h.nlm->nlmsg_type);
				goto eexit;
			}

			if ((unsigned) l < sizeof (*err)) {
				logger (LOG_ERR, "netlink: error truncated");
				goto eexit;
			}

			if (err->error == 0) {
				int retval = 0;

				close (s);
				if (callback) {
					if ((retval = callback (hdr, arg)) == -1)
						logger (LOG_ERR, "netlink: callback failed");
				}
				free (buffer);
				return (retval);
			}

			errno = -err->error;
			/* Don't report on something already existing */
			if (errno != EEXIST)
				logger (LOG_ERR, "netlink: %s",
					strerror (errno));
			goto eexit;
		}
	}

eexit:
	close (s);
	free (buffer);
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
		logger (LOG_ERR, "add_attr_l: message exceeded bound of %d\n",
			maxlen);
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
	int len = RTA_LENGTH (sizeof (data));
	struct rtattr *rta;

	if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen) {
		logger (LOG_ERR, "add_attr32: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}

	rta = NLMSG_TAIL (n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), &data, sizeof (data));
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

	return 0;
}

struct nlma
{
	struct nlmsghdr hdr;
	struct ifaddrmsg ifa; 
	char buffer[64];
};

struct nlmr
{
	struct nlmsghdr hdr;
	struct rtmsg rt;
	char buffer[256];
};

static int do_address(const char *ifname,
		      struct in_addr address, struct in_addr netmask,
		      struct in_addr broadcast, int del)
{
	struct nlma *nlm;
	int retval;

	if (!ifname)
		return -1;

	nlm = xzalloc (sizeof (*nlm));
	nlm->hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
	nlm->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (! del)
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	nlm->hdr.nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
	if (! (nlm->ifa.ifa_index = if_nametoindex (ifname))) {
		logger (LOG_ERR, "if_nametoindex: no index for interface `%s'",
			ifname);
		free (nlm);
		return -1;
	}
	nlm->ifa.ifa_family = AF_INET;

	nlm->ifa.ifa_prefixlen = inet_ntocidr (netmask);

	/* This creates the aliased interface */
	add_attr_l (&nlm->hdr, sizeof (*nlm), IFA_LABEL,
		    ifname, strlen (ifname) + 1);

	add_attr_l (&nlm->hdr, sizeof (*nlm), IFA_LOCAL,
		    &address.s_addr, sizeof (address.s_addr));
	if (! del)
		add_attr_l (&nlm->hdr, sizeof (*nlm), IFA_BROADCAST,
			    &broadcast.s_addr, sizeof (broadcast.s_addr));

	retval = send_netlink (&nlm->hdr, NULL, NULL);
	free (nlm);
	return retval;
}

static int do_route (const char *ifname,
		     struct in_addr destination,
		     struct in_addr netmask,
		     struct in_addr gateway,
		     int metric, int change, int del)
{
	struct nlmr *nlm;
	unsigned int ifindex;
	int retval;

	if (! ifname)
		return -1;

	log_route (destination, netmask, gateway, metric, change, del);

	if (! (ifindex = if_nametoindex (ifname))) {
		logger (LOG_ERR, "if_nametoindex: no index for interface `%s'",
			ifname);
		return -1;
	}

	nlm = xzalloc (sizeof (*nlm));
	nlm->hdr.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
	if (change)
		nlm->hdr.nlmsg_flags = NLM_F_REPLACE;
	else if (! del)
		nlm->hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	nlm->hdr.nlmsg_flags |= NLM_F_REQUEST;
	nlm->hdr.nlmsg_type = del ? RTM_DELROUTE : RTM_NEWROUTE;
	nlm->rt.rtm_family = AF_INET;
	nlm->rt.rtm_table = RT_TABLE_MAIN;

	if (del)
		nlm->rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		nlm->rt.rtm_protocol = RTPROT_BOOT;
		if (netmask.s_addr == INADDR_BROADCAST ||
		    gateway.s_addr == INADDR_ANY)
			nlm->rt.rtm_scope = RT_SCOPE_LINK;
		else
			nlm->rt.rtm_scope = RT_SCOPE_UNIVERSE;
		nlm->rt.rtm_type = RTN_UNICAST;
	}

	nlm->rt.rtm_dst_len = inet_ntocidr (netmask);
	add_attr_l (&nlm->hdr, sizeof (*nlm), RTA_DST,
		    &destination.s_addr, sizeof (destination.s_addr));
	if (netmask.s_addr != INADDR_BROADCAST &&
	    destination.s_addr != gateway.s_addr)
		add_attr_l (&nlm->hdr, sizeof (*nlm), RTA_GATEWAY,
			    &gateway.s_addr, sizeof (gateway.s_addr));

	add_attr_32 (&nlm->hdr, sizeof (*nlm), RTA_OIF, ifindex);
	add_attr_32 (&nlm->hdr, sizeof (*nlm), RTA_PRIORITY, metric);

	retval = send_netlink (&nlm->hdr, NULL, NULL);
	free (nlm);
	return retval;
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

	logger (LOG_INFO, "removing IP address %s/%d",
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


int flush_addresses (const char *ifname)
{
	return (_do_interface (ifname, NULL, NULL, NULL, true, false));
}

in_addr_t get_address (const char *ifname)
{
	struct in_addr address;
	if (_do_interface (ifname, NULL, NULL, &address, false, true) > 0)
		return (address.s_addr);
	return (0);
}

int has_address (const char *ifname, struct in_addr address)
{
	return (_do_interface (ifname, NULL, NULL, &address, false, false));
}
