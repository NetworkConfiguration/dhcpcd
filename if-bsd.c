/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2009 Roy Marples <roy@marples.name>
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

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net80211/ieee80211_ioctl.h>

#include <errno.h>
#include <fnmatch.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#include "if-options.h"
#include "net.h"

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* Darwin doesn't define this for some very odd reason */
#ifndef SA_SIZE
# define SA_SIZE(sa)						\
	(  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?	\
	   sizeof(long)		:				\
	   1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

static int a_fd = -1;
static int r_fd = -1;

int
init_socket(void)
{
	if ((a_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;
	set_cloexec(a_fd);
	if ((r_fd = socket(PF_ROUTE, SOCK_RAW, 0)) == -1)
		return -1;
	set_cloexec(a_fd);
	return 0;
}

int
getifssid(const char *ifname, char *ssid)
{
	int retval = -1;
#if defined(SIOCG80211NWID)
	struct ifreq ifr;
	struct ieee80211_nwid nwid;
#elif defined(IEEE80211_IOC_SSID)
	struct ieee80211req ireq;
	char nwid[IEEE80211_NWID_LEN + 1];
#endif

#if defined(SIOCG80211NWID) /* NetBSD */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	memset(&nwid, 0, sizeof(nwid));
	ifr.ifr_data = (void *)&nwid;
	if (ioctl(a_fd, SIOCG80211NWID, &ifr) == 0) {
		retval = nwid.i_len;
		memcpy(ssid, nwid.i_nwid, nwid.i_len);
		ssid[nwid.i_len] = '\0';
	}
#elif defined(IEEE80211_IOC_SSID) /* FreeBSD */
	memset(&ireq, 0, sizeof(ireq));
	strlcpy(ireq.i_name, ifname, sizeof(ireq.i_name));
	ireq.i_type = IEEE80211_IOC_SSID;
	ireq.i_val = -1;
	ireq.i_data = &nwid;
	if (ioctl(a_fd, SIOCG80211, &ireq) == 0) {
		retval = ireq.i_len;
		memcpy(ssid, nwid, ireq.i_len);
		ssid[ireq.i_len] = '\0';
	}
#endif
	return retval;
}

int
if_address(const struct interface *iface, const struct in_addr *address,
	   const struct in_addr *netmask, const struct in_addr *broadcast,
	   int action)
{
	int retval;
	struct ifaliasreq ifa;
	union {
		struct sockaddr *sa;
		struct sockaddr_in *sin;
	} _s;

	memset(&ifa, 0, sizeof(ifa));
	strlcpy(ifa.ifra_name, iface->name, sizeof(ifa.ifra_name));

#define ADDADDR(_var, _addr) { \
	_s.sa = &_var; \
	_s.sin->sin_family = AF_INET; \
	_s.sin->sin_len = sizeof(*_s.sin); \
	memcpy(&_s.sin->sin_addr, _addr, sizeof(_s.sin->sin_addr)); \
}

	ADDADDR(ifa.ifra_addr, address);
	ADDADDR(ifa.ifra_mask, netmask);
	if (action >= 0 && broadcast) {
		ADDADDR(ifa.ifra_broadaddr, broadcast);
	}
#undef ADDADDR

	if (action < 0)
		retval = ioctl(a_fd, SIOCDIFADDR, &ifa);
	else
		retval = ioctl(a_fd, SIOCAIFADDR, &ifa);
	return retval;
}

/* ARGSUSED4 */
int
if_route(const struct interface *iface, const struct in_addr *dest,
	 const struct in_addr *net, const struct in_addr *gate,
	 _unused int metric, int action)
{
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
		char buffer[sizeof(su) * 4];
	} rtm;
	char *bp = rtm.buffer, *p;
	size_t l;
	int retval = 0;

#define ADDSU(_su) { \
	l = SA_SIZE(&(_su.sa)); \
	memcpy(bp, &(_su), l); \
	bp += l; \
} 
#define ADDADDR(_addr) { \
	memset (&su, 0, sizeof(su)); \
	su.sin.sin_family = AF_INET; \
	su.sin.sin_len = sizeof(su.sin); \
	memcpy (&su.sin.sin_addr, _addr, sizeof(su.sin.sin_addr)); \
	ADDSU(su); \
}

	memset(&rtm, 0, sizeof(rtm));
	rtm.hdr.rtm_version = RTM_VERSION;
	rtm.hdr.rtm_seq = 1;
	if (action == 0)
		rtm.hdr.rtm_type = RTM_CHANGE;
	else if (action > 0)
		rtm.hdr.rtm_type = RTM_ADD;
	else
		rtm.hdr.rtm_type = RTM_DELETE;
	rtm.hdr.rtm_flags = RTF_UP;
	/* None interface subnet routes are static. */
	if (gate->s_addr != INADDR_ANY ||
	    net->s_addr != iface->net.s_addr ||
	    dest->s_addr != (iface->addr.s_addr & iface->net.s_addr))
		rtm.hdr.rtm_flags |= RTF_STATIC;
	rtm.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;
	if (dest->s_addr == gate->s_addr && net->s_addr == INADDR_BROADCAST)
		rtm.hdr.rtm_flags |= RTF_HOST;
	else {
		rtm.hdr.rtm_addrs |= RTA_NETMASK;
		if (rtm.hdr.rtm_flags & RTF_STATIC)
			rtm.hdr.rtm_flags |= RTF_GATEWAY;
		if (action >= 0)
			rtm.hdr.rtm_addrs |= RTA_IFA;
	}

	ADDADDR(dest);
	if (rtm.hdr.rtm_flags & RTF_HOST || !(rtm.hdr.rtm_flags & RTF_STATIC)) {
		/* Make us a link layer socket for the host gateway */
		memset(&su, 0, sizeof(su));
		su.sdl.sdl_len = sizeof(struct sockaddr_dl);
		link_addr(iface->name, &su.sdl);
		ADDSU(su);
	} else
		ADDADDR(gate);

	if (rtm.hdr.rtm_addrs & RTA_NETMASK) {
		/* Ensure that netmask is set correctly */
		memset(&su, 0, sizeof(su));
		su.sin.sin_family = AF_INET;
		su.sin.sin_len = sizeof(su.sin);
		memcpy(&su.sin.sin_addr, &net->s_addr, sizeof(su.sin.sin_addr));
		p = su.sa.sa_len + (char *)&su;
		for (su.sa.sa_len = 0; p > (char *)&su;)
			if (*--p != 0) {
				su.sa.sa_len = 1 + p - (char *)&su;
				break;
			}
		ADDSU(su);
	}

	if (rtm.hdr.rtm_addrs & RTA_IFA)
		ADDADDR(&iface->addr);

	rtm.hdr.rtm_msglen = l = bp - (char *)&rtm;
	if (write(r_fd, &rtm, l) == -1)
		retval = -1;
	return retval;
}

int
arp_flush(void)
{
	int mib[6], retval = 0;
	size_t buffer_len = 0;
	char *buffer, *e, *p;
	struct rt_msghdr *rtm;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;
	if (sysctl(mib, 6, NULL, &buffer_len, NULL, 0) == -1)
		return -1;
	if (buffer_len == 0)
		return 0;
	buffer = xmalloc(buffer_len);
	if (sysctl(mib, 6, buffer, &buffer_len, NULL, 0) == -1)
		return -1;
	e = buffer + buffer_len;
	for (p = buffer; p < e; p += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(void *)p;
		/* Don't delete manually added entries. */
		if (rtm->rtm_flags & RTF_STATIC)
			continue;
		rtm->rtm_type = RTM_DELETE;
		if (write(r_fd, rtm, rtm->rtm_msglen) == -1) {
			retval = -1;
			break;
		}
	}
	free(buffer);
	return retval;
}

int
open_link_socket(void)
{
	int fd;

	fd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (fd != -1) {
		set_cloexec(fd);
		set_nonblock(fd);
	}
	return fd;
}

#define BUFFER_LEN	2048
int
manage_link(int fd,
	    void (*if_carrier)(const char *),
	    void (*if_add)(const char *),
	    void (*if_remove)(const char *))
{
	char buffer[2048], *p, *e;
	char ifname[IF_NAMESIZE];
	ssize_t bytes;
	struct rt_msghdr *rtm;
	struct if_announcemsghdr *ifa;
	struct if_msghdr *ifm;
	struct in_addr dst, net, gate;
	struct sockaddr *sa;
	struct sockaddr_in *sin;

	for (;;) {
		bytes = read(fd, buffer, BUFFER_LEN);
		if (bytes == -1) {
			if (errno == EAGAIN)
				return 0;
			if (errno == EINTR)
				continue;
			return -1;
		}
		e = buffer + bytes;
		for (p = buffer; p < e; p += rtm->rtm_msglen) {
			rtm = (struct rt_msghdr *)(void *)p;
			switch(rtm->rtm_type) {
			case RTM_IFANNOUNCE:
				ifa = (struct if_announcemsghdr *)(void *)p;
				switch(ifa->ifan_what) {
				case IFAN_ARRIVAL:
					if_add(ifa->ifan_name);
					break;
				case IFAN_DEPARTURE:
					if_remove(ifa->ifan_name);
					break;
				}
				break;
			case RTM_IFINFO:
				ifm = (struct if_msghdr *)(void *)p;
				memset(ifname, 0, sizeof(ifname));
				if (if_indextoname(ifm->ifm_index, ifname))
					if_carrier(ifname);
				break;
			case RTM_DELETE:
				if (!(rtm->rtm_addrs & RTA_DST) ||
				    !(rtm->rtm_addrs & RTA_GATEWAY) ||
				    !(rtm->rtm_addrs & RTA_NETMASK))
					break;
				if (rtm->rtm_pid == getpid())
					break;
				sa = (struct sockaddr *)(rtm + 1);
				if (sa->sa_family != AF_INET)
					break;
				sin = (struct sockaddr_in *)sa;
				memcpy(&dst.s_addr, &sin->sin_addr.s_addr,
					sizeof(dst.s_addr));
				sa = (struct sockaddr *)
				    (ROUNDUP(sa->sa_len) + (char *)sa);
				sin = (struct sockaddr_in *)sa;
				memcpy(&gate.s_addr, &sin->sin_addr.s_addr,
					sizeof(gate.s_addr));
				sa = (struct sockaddr *)
				    (ROUNDUP(sa->sa_len) + (char *)sa);
				sin = (struct sockaddr_in *)sa;
				memcpy(&net.s_addr, &sin->sin_addr.s_addr,
					sizeof(net.s_addr));
				route_deleted(&dst, &net, &gate);
				break;
			}
		}
	}
}

static void
discover_link(struct interface **ifs, int argc, char * const *argv,
	      struct ifreq *ifr)
{
	struct interface *ifp, *ifl = NULL;
	struct sockaddr_dl *sdl;
	int n;

	if (ifr->ifr_addr.sa_family != AF_LINK)
		return;
	for (ifp = *ifs; ifp; ifp = ifp->next) {
		if (strcmp(ifp->name, ifr->ifr_name) == 0)
			return;
		ifl = ifp;
	}
	if (argc > 0) {
		for (n = 0; n < argc; n++)
			if (strcmp(ifr->ifr_name, argv[n]) == 0)
				break;
		if (n == argc)
			return;
	} else {
		for (n = 0; n < ifdc; n++)
			if (fnmatch(ifdv[n], ifr->ifr_name, 0) == 0)
				return;
		for (n = 0; n < ifac; n++)
			if (fnmatch(ifav[n], ifr->ifr_name, 0) == 0)
				break;
		if (ifac && n == ifac)
			return;
	}
	if (!(ifp = init_interface(ifr->ifr_name)))
		return;
	sdl = (struct sockaddr_dl *)(void *)&ifr->ifr_addr;
	switch(sdl->sdl_type) {
	case IFT_ETHER:
		ifp->family = ARPHRD_ETHER;
		ifp->hwlen = sdl->sdl_alen;
		memcpy(ifp->hwaddr, LLADDR(sdl), sdl->sdl_alen);
		break;
	default:
		/* Don't needlessly spam console on startup */
		if (!(options & DHCPCD_MASTER &&
		    !(options & DHCPCD_DAEMONISED) &&
		    options & DHCPCD_QUIET))
			syslog(LOG_ERR, "%s: unsupported interface type",
			       ifr->ifr_name);
		free(ifp);
		ifp = NULL;
		break;
	}
	if (ifl)
		ifl->next = ifp;
	else
		*ifs = ifp;
}

struct interface *
discover_interfaces(int argc, char * const *argv)
{
	struct interface *ifs = NULL;

	do_interface(NULL, discover_link, &ifs, argc, argv, NULL, NULL, 2);
	return ifs;
}
