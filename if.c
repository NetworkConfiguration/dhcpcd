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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#ifdef AF_LINK
# include <net/if_dl.h>
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
#include "if.h"

int
inet_ntocidr(struct in_addr address)
{
	int cidr = 0;
	uint32_t mask = htonl(address.s_addr);

	while (mask) {
		cidr++;
		mask <<= 1;
	}

	return cidr;
}

int
inet_cidrtoaddr (int cidr, struct in_addr *addr)
{
	int ocets;

	if (cidr < 0 || cidr > 32) {
		errno = EINVAL;
		return -1;
	}
	ocets = (cidr + 7) / 8;

	addr->s_addr = 0;
	if (ocets > 0) {
		memset(&addr->s_addr, 255, (size_t)ocets - 1);
		memset((unsigned char *)&addr->s_addr + (ocets - 1),
		       (256 - (1 << (32 - cidr) % 8)), 1);
	}

	return 0;
}

uint32_t
get_netmask(uint32_t addr)
{
	uint32_t dst;

	if (addr == 0)
		return 0;

	dst = htonl(addr);
	if (IN_CLASSA(dst))
		return ntohl(IN_CLASSA_NET);
	if (IN_CLASSB (dst))
		return ntohl(IN_CLASSB_NET);
	if (IN_CLASSC (dst))
		return ntohl(IN_CLASSC_NET);

	return 0;
}

char *
hwaddr_ntoa(const unsigned char *hwaddr, size_t hwlen)
{
	static char buffer[(HWADDR_LEN * 3) + 1];
	char *p = buffer;
	size_t i;

	for (i = 0; i < hwlen && i < HWADDR_LEN; i++) {
		if (i > 0)
			*p ++= ':';
		p += snprintf(p, 3, "%.2x", hwaddr[i]);
	}

	*p ++= '\0';

	return buffer;
}

size_t
hwaddr_aton(unsigned char *buffer, const char *addr)
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
		if (!(*p == '\0' || (*p == ':' && *(p + 1) != '\0'))) {
			errno = EINVAL;
			return 0;
		}
		/* Ensure that digits are hex */
		if (isxdigit ((int)c[0]) == 0 || isxdigit((int)c[1]) == 0) {
			errno = EINVAL;
			return 0;
		}
		p++;
		if (bp)
			*bp++ = (unsigned char)strtol(c, NULL, 16);
		else
			len++;
	}

	if (bp)
		return bp - buffer;
	return len;
}

int
do_interface(const char *ifname,
	     _unused unsigned char *hwaddr, _unused size_t *hwlen,
	     struct in_addr *addr, bool flush, bool get)
{
	int s;
	struct ifconf ifc;
	int retval = 0;
	int len = 10 * sizeof(struct ifreq);
	int lastlen = 0;
	char *p;
	union {
		char *buffer;
		struct ifreq *ifr;
	} ifreqs;
	struct sockaddr_in address;
	struct ifreq *ifr;
	struct sockaddr_in netmask;

#ifdef AF_LINK
	struct sockaddr_dl sdl;
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;

	/* Not all implementations return the needed buffer size for
	 * SIOGIFCONF so we loop like so for all until it works */
	memset(&ifc, 0, sizeof(ifc));
	for (;;) {
		ifc.ifc_len = len;
		ifc.ifc_buf = xmalloc((size_t)len);
		if (ioctl(s, SIOCGIFCONF, &ifc) == -1) {
			if (errno != EINVAL || lastlen != 0) {
				close(s);
				free(ifc.ifc_buf);	
				return -1;
			}
		} else {
			if (ifc.ifc_len == lastlen)
				break;
			lastlen = ifc.ifc_len;
		}

		free(ifc.ifc_buf);
		ifc.ifc_buf = NULL;
		len *= 2;
	}

	for (p = ifc.ifc_buf; p < ifc.ifc_buf + ifc.ifc_len;) {
		/* Cast the ifc buffer to an ifreq cleanly */
		ifreqs.buffer = p;
		ifr = ifreqs.ifr;

#ifdef __linux__
		p += sizeof(*ifr);
#else
		p += offsetof(struct ifreq, ifr_ifru) + ifr->ifr_addr.sa_len;
#endif

		if (strcmp(ifname, ifr->ifr_name) != 0)
			continue;

#ifdef AF_LINK
		if (hwaddr && hwlen && ifr->ifr_addr.sa_family == AF_LINK) {
			memcpy(&sdl, &ifr->ifr_addr, sizeof(sdl));
			*hwlen = sdl.sdl_alen;
			memcpy(hwaddr, sdl.sdl_data + sdl.sdl_nlen,
			       (size_t)sdl.sdl_alen);
			retval = 1;
			break;
		}
#endif

		if (ifr->ifr_addr.sa_family == AF_INET)	{
			memcpy(&address, &ifr->ifr_addr, sizeof(address));
			if (flush) {
				if (ioctl(s, SIOCGIFNETMASK, ifr) == -1)
					continue;
				memcpy(&netmask, &ifr->ifr_addr,
				       sizeof(netmask));

				if (del_address(ifname,
						&address.sin_addr,
						&netmask.sin_addr) == -1)
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

	close(s);
	free(ifc.ifc_buf);
	return retval;
}

struct interface *
read_interface(const char *ifname, _unused int metric)
{
	int s;
	struct ifreq ifr;
	struct interface *iface = NULL;
	unsigned char *hwaddr = NULL;
	size_t hwlen = 0;
	sa_family_t family = 0;
	unsigned short mtu;
#ifdef __linux__
	char *p;
#endif

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return NULL;

#ifdef __linux__
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1)
		goto eexit;

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
	}

	hwaddr = xmalloc(sizeof(unsigned char) * HWADDR_LEN);
	memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, hwlen);
	family = ifr.ifr_hwaddr.sa_family;
#else
	ifr.ifr_metric = metric;
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCSIFMETRIC, &ifr) == -1)
		goto eexit;

	hwaddr = xmalloc(sizeof(unsigned char) * HWADDR_LEN);
	if (do_interface(ifname, hwaddr, &hwlen, NULL, false, false) != 1)
		goto eexit;

	family = ARPHRD_ETHER;
#endif

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFMTU, &ifr) == -1)
		goto eexit;

	/* Ensure that the MTU is big enough for DHCP */
	if (ifr.ifr_mtu < MTU_MIN) {
		ifr.ifr_mtu = MTU_MIN;
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCSIFMTU, &ifr) == -1)
			goto eexit;
	}
	mtu = ifr.ifr_mtu;

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
#ifdef __linux__
	/* We can only bring the real interface up */
	if ((p = strchr(ifr.ifr_name, ':')))
		*p = '\0';
#endif
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
		goto eexit;

	if (!(ifr.ifr_flags & IFF_UP) || !(ifr.ifr_flags & IFF_RUNNING)) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0)
			goto eexit;
	}

	iface = xzalloc(sizeof(*iface));
	strlcpy(iface->name, ifname, IF_NAMESIZE);
#ifdef ENABLE_INFO
	snprintf(iface->infofile, PATH_MAX, INFOFILE, ifname);
#endif
	memcpy(&iface->hwaddr, hwaddr, hwlen);
	iface->hwlen = hwlen;

	iface->family = family;
	iface->arpable = !(ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK));
	iface->mtu = iface->previous_mtu = mtu;

	/* 0 is a valid fd, so init to -1 */
	iface->fd = -1;
#ifdef __linux__
	iface->listen_fd = -1;
#endif

eexit:
	close(s);
	free(hwaddr);
	return iface;
}

int
do_mtu(const char *ifname, short int mtu)
{
	struct ifreq ifr;
	int r;
	int s;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;
	r = ioctl(s, mtu ? SIOCSIFMTU : SIOCGIFMTU, &ifr);
	close(s);
	if (r == -1)
		return -1;
	return ifr.ifr_mtu;
}


in_addr_t
get_address(const char *ifname)
{
	struct in_addr address;
	int retval;

	retval = do_interface(ifname, NULL, NULL, &address, false, true);
	if (retval > 0)
		return address.s_addr;
	return retval;
}
