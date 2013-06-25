/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2013 Roy Marples <roy@marples.name>
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

#include <asm/types.h> /* Needed for 2.4 kernels */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Support older kernels */
#ifndef IFLA_WIRELESS
# define IFLA_WIRELESS (IFLA_MASTER + 1)
#endif

/* For some reason, glibc doesn't include newer flags from linux/if.h
 * However, we cannot include linux/if.h directly as it conflicts
 * with the glibc version. D'oh! */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/
#endif

#include <errno.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "net.h"

static int sock_fd;
static struct sockaddr_nl sock_nl;

int
if_init(struct interface *iface)
{
	char path[PATH_MAX];
	FILE *fp;
	int n;

	/* We enable promote_secondaries so that we can do this
	 * add 192.168.1.2/24
	 * add 192.168.1.3/24
	 * del 192.168.1.2/24
	 * and the subnet mask moves onto 192.168.1.3/24
	 * This matches the behaviour of BSD which makes coding dhcpcd
	 * a little easier as there's just one behaviour. */
	snprintf(path, sizeof(path),
	    "/proc/sys/net/ipv4/conf/%s/promote_secondaries",
	    iface->name);

	fp = fopen(path, "w");
	if (fp == NULL)
		return errno == ENOENT ? 0 : -1;
	n = fprintf(fp, "1");
	fclose(fp);
	return n == -1 ? -1 : 0;
}

int
if_conf(struct interface *iface)
{
	char path[PATH_MAX], buf[1];
	FILE *fp;

	/* Some qeth setups require the use of the broadcast flag. */
	snprintf(path, sizeof(path),
	    "/sys/class/net/%s/device/layer2",
	    iface->name);

	fp = fopen(path, "r");
	if (fp == NULL)
		return errno == ENOENT ? 0 : -1;
	if (fgets(buf, sizeof(buf), fp) != NULL && buf[0] == '0')
		iface->options->options |= DHCPCD_BROADCAST;
	fclose(fp);
	return 0;
}

static int
_open_link_socket(struct sockaddr_nl *nl)
{
	int fd;

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
		return -1;
	nl->nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)nl, sizeof(*nl)) == -1)
		return -1;
	set_cloexec(fd);
	return fd;
}

int
open_sockets(void)
{
	if ((socket_afnet = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;
	set_cloexec(socket_afnet);
	sock_fd = _open_link_socket(&sock_nl);
	set_cloexec(sock_fd);
	return sock_fd;
}

int
open_link_socket(void)
{
	struct sockaddr_nl snl;

	memset(&snl, 0, sizeof(snl));
	snl.nl_groups = RTMGRP_LINK;

#ifdef INET
	snl.nl_groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR;
#endif
#ifdef INET6
	snl.nl_groups |= RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;
#endif

	return _open_link_socket(&snl);
}

static int
get_netlink(int fd, int flags,
    int (*callback)(struct nlmsghdr *))
{
	char *buf = NULL, *nbuf;
	ssize_t buflen = 0, bytes;
	struct nlmsghdr *nlm;
	struct sockaddr_nl nladdr;
	socklen_t nladdr_len = sizeof(nladdr);
	int r = -1;

	for (;;) {
		bytes = recv(fd, NULL, 0,
		    flags | MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				r = 0;
				goto eexit;
			}
			if (errno == EINTR)
				continue;
			goto eexit;
		} else if (bytes == buflen) {
			/* Support kernels older than 2.6.22 */
			if (bytes == 0)
				bytes = 512;
			else
				bytes *= 2;
		}
		if (buflen < bytes) {
			/* Alloc 1 more so we work with older kernels */
			buflen = bytes + 1;
			nbuf = realloc(buf, buflen);
			if (nbuf == NULL)
				goto eexit;
			buf = nbuf;
		}
		bytes = recvfrom(fd, buf, buflen, flags,
		    (struct sockaddr *)&nladdr, &nladdr_len);
		if (bytes == -1) {
			if (errno == EAGAIN) {
				r = 0;
				goto eexit;
			}
			if (errno == EINTR)
				continue;
			goto eexit;
		}

		/* Check sender */
		if (nladdr_len != sizeof(nladdr)) {
			errno = EINVAL;
			goto eexit;
		}
		/* Ignore message if it is not from kernel */
		if (nladdr.nl_pid != 0)
			continue;

		for (nlm = (struct nlmsghdr *)(void *)buf;
		     NLMSG_OK(nlm, (size_t)bytes);
		     nlm = NLMSG_NEXT(nlm, bytes))
		{
			r = callback(nlm);
			if (r != 0)
				goto eexit;
		}
	}

eexit:
	free(buf);
	return r;
}

static int
err_netlink(struct nlmsghdr *nlm)
{
	struct nlmsgerr *err;
	int l;

	if (nlm->nlmsg_type != NLMSG_ERROR)
		return 0;
	l = nlm->nlmsg_len - sizeof(*nlm);
	if ((size_t)l < sizeof(*err)) {
		errno = EBADMSG;
		return -1;
	}
	err = (struct nlmsgerr *)NLMSG_DATA(nlm);
	if (err->error == 0)
		return l;
	errno = -err->error;
	return -1;
}

static int
link_route(struct nlmsghdr *nlm)
{
	int len, idx, metric;
	struct rtattr *rta;
	struct rtmsg *rtm;
	struct rt rt;
	char ifn[IF_NAMESIZE + 1];

	if (nlm->nlmsg_type != RTM_DELROUTE)
		return 0;

	len = nlm->nlmsg_len - sizeof(*nlm);
	if ((size_t)len < sizeof(*rtm)) {
		errno = EBADMSG;
		return -1;
	}
	rtm = NLMSG_DATA(nlm);
	if (rtm->rtm_type != RTN_UNICAST ||
	    rtm->rtm_table != RT_TABLE_MAIN ||
	    rtm->rtm_family != AF_INET ||
	    nlm->nlmsg_pid == (uint32_t)getpid())
		return 1;
	rta = (struct rtattr *)(void *)((char *)rtm +NLMSG_ALIGN(sizeof(*rtm)));
	len = NLMSG_PAYLOAD(nlm, sizeof(*rtm));
	memset(&rt, 0, sizeof(rt));
	rt.dest.s_addr = INADDR_ANY;
	rt.net.s_addr = INADDR_ANY;
	rt.gate.s_addr = INADDR_ANY;
	metric = 0;
	while (RTA_OK(rta, len)) {
		switch (rta->rta_type) {
		case RTA_DST:
			memcpy(&rt.dest.s_addr, RTA_DATA(rta),
			    sizeof(rt.dest.s_addr));
			break;
		case RTA_GATEWAY:
			memcpy(&rt.gate.s_addr, RTA_DATA(rta),
			    sizeof(rt.gate.s_addr));
			break;
		case RTA_OIF:
			idx = *(int *)RTA_DATA(rta);
			if (if_indextoname(idx, ifn))
				rt.iface = find_interface(ifn);
			break;
		case RTA_PRIORITY:
			metric = *(int *)RTA_DATA(rta);
			break;
		}
		rta = RTA_NEXT(rta, len);
	}
	if (rt.iface != NULL) {
		if (metric == rt.iface->metric) {
#ifdef INET
			inet_cidrtoaddr(rtm->rtm_dst_len, &rt.net);
			ipv4_routedeleted(&rt);
#endif
		}
	}
	return 1;
}

static int
link_addr(struct nlmsghdr *nlm)
{
	int len;
	struct rtattr *rta;
	struct ifaddrmsg *ifa;
	char ifn[IF_NAMESIZE + 1];
	struct interface *iface;
#ifdef INET
	struct in_addr addr, net, dest;
#endif
#ifdef INET6
	struct in6_addr addr6;
#endif

	if (nlm->nlmsg_type != RTM_DELADDR && nlm->nlmsg_type != RTM_NEWADDR)
		return 0;

	len = nlm->nlmsg_len - sizeof(*nlm);
	if ((size_t)len < sizeof(*ifa)) {
		errno = EBADMSG;
		return -1;
	}
//	if (nlm->nlmsg_pid == (uint32_t)getpid())
//		return 1;
	ifa = NLMSG_DATA(nlm);
	if (if_indextoname(ifa->ifa_index, ifn) == NULL)
		return -1;
	iface = find_interface(ifn);
	if (iface == NULL)
		return 1;
	rta = (struct rtattr *) IFA_RTA(ifa);
	len = NLMSG_PAYLOAD(nlm, sizeof(*ifa));
	switch (ifa->ifa_family) {
#ifdef INET
	case AF_INET:
		addr.s_addr = dest.s_addr = INADDR_ANY;
		dest.s_addr = INADDR_ANY;
		inet_cidrtoaddr(ifa->ifa_prefixlen, &net);
		while (RTA_OK(rta, len)) {
			switch (rta->rta_type) {
			case IFA_ADDRESS:
				if (iface->flags & IFF_POINTOPOINT) {
					memcpy(&dest.s_addr, RTA_DATA(rta),
					       sizeof(addr.s_addr));
				}
				break;
			case IFA_LOCAL:
				memcpy(&addr.s_addr, RTA_DATA(rta),
				       sizeof(addr.s_addr));
				break;
			}
			rta = RTA_NEXT(rta, len);
		}
		ipv4_handleifa(nlm->nlmsg_type, ifn, &addr, &net, &dest);
		break;
#endif
#ifdef INET6
	case AF_INET6:
		memset(&addr6, 0, sizeof(addr6));
		while (RTA_OK(rta, len)) {
			switch (rta->rta_type) {
			case IFA_ADDRESS:
				memcpy(&addr6.s6_addr, RTA_DATA(rta),
				       sizeof(addr6.s6_addr));
				break;
			}
			rta = RTA_NEXT(rta, len);
		}
		ipv6_handleifa(nlm->nlmsg_type, NULL, ifn,
		    &addr6, ifa->ifa_flags);
		break;
#endif
	}
	return 1;
}

static short l2addr_len(unsigned short if_type)
{

	switch (if_type) {
	case ARPHRD_ETHER: /* FALLTHROUGH */
	case ARPHRD_IEEE802: /*FALLTHROUGH */
	case ARPHRD_IEEE80211:
		return 6;
	case ARPHRD_IEEE1394:
		return 8;
	case ARPHRD_INFINIBAND:
		return 20;
	default:
		return -1;
	}
}

static int
link_netlink(struct nlmsghdr *nlm)
{
	int len;
	struct rtattr *rta, *hwaddr;
	struct ifinfomsg *ifi;
	char ifn[IF_NAMESIZE + 1];

	len = link_route(nlm);
	if (len != 0)
		return len;
	len = link_addr(nlm);
	if (len != 0)
		return len;

	if (nlm->nlmsg_type != RTM_NEWLINK && nlm->nlmsg_type != RTM_DELLINK)
		return 0;
	len = nlm->nlmsg_len - sizeof(*nlm);
	if ((size_t)len < sizeof(*ifi)) {
		errno = EBADMSG;
		return -1;
	}
	ifi = NLMSG_DATA(nlm);
	if (ifi->ifi_flags & IFF_LOOPBACK)
		return 1;
	rta = (struct rtattr *)(void *)((char *)ifi +NLMSG_ALIGN(sizeof(*ifi)));
	len = NLMSG_PAYLOAD(nlm, sizeof(*ifi));
	*ifn = '\0';
	hwaddr = NULL;
	while (RTA_OK(rta, len)) {
		switch (rta->rta_type) {
		case IFLA_WIRELESS:
			/* Ignore wireless messages */
			if (nlm->nlmsg_type == RTM_NEWLINK &&
			    ifi->ifi_change == 0)
				return 1;
			break;
		case IFLA_IFNAME:
			strlcpy(ifn, RTA_DATA(rta), sizeof(ifn));
			break;
		case IFLA_ADDRESS:
			hwaddr = rta;
			break;
		}
		rta = RTA_NEXT(rta, len);
	}

	if (nlm->nlmsg_type == RTM_DELLINK) {
		handle_interface(-1, ifn);
		return 1;
	}

	/* Bridge interfaces set IFF_LOWER_UP when they have a valid
	 * hardware address. To trigger a valid hardware address pickup
	 * we need to pretend that that don't exist until they have
	 * IFF_LOWER_UP set. */
	if (ifi->ifi_flags & IFF_MASTER && !(ifi->ifi_flags & IFF_LOWER_UP)) {
		handle_interface(-1, ifn);
		return 1;
	}

	/* Re-read hardware address and friends */
	if (!(ifi->ifi_flags & IFF_UP) && hwaddr) {
		len = l2addr_len(ifi->ifi_type);
		if (hwaddr->rta_len == RTA_LENGTH(len))
			handle_hwaddr(ifn, RTA_DATA(hwaddr), len);
	}

	handle_carrier(ifi->ifi_flags & IFF_RUNNING ? LINK_UP : LINK_DOWN,
	    ifi->ifi_flags, ifn);
	return 1;
}

int
manage_link(int fd)
{
	return get_netlink(fd, MSG_DONTWAIT, &link_netlink);
}

static int
send_netlink(struct nlmsghdr *hdr)
{
	int r;
	struct iovec iov;
	struct msghdr msg;
	static unsigned int seq;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sock_nl;
	msg.msg_namelen = sizeof(sock_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	/* Request a reply */
	hdr->nlmsg_flags |= NLM_F_ACK;
	hdr->nlmsg_seq = ++seq;

	if (sendmsg(sock_fd, &msg, 0) != -1)
		r = get_netlink(sock_fd, 0, &err_netlink);
	else
		r = -1;
	return r;
}

#define NLMSG_TAIL(nmsg)						\
	((struct rtattr *)(((ptrdiff_t)(nmsg))+NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int
add_attr_l(struct nlmsghdr *n, unsigned int maxlen, int type,
    const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static int
add_attr_32(struct nlmsghdr *n, unsigned int maxlen, int type, uint32_t data)
{
	int len = RTA_LENGTH(sizeof(data));
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, sizeof(data));
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

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

#ifdef INET
int
if_address(const struct interface *iface,
    const struct in_addr *address, const struct in_addr *netmask,
    const struct in_addr *broadcast, int action)
{
	struct nlma *nlm;
	int retval = 0;

	nlm = calloc(1, sizeof(*nlm));
	if (nlm == NULL)
		return -1;
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlm->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action >= 0) {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		nlm->hdr.nlmsg_type = RTM_NEWADDR;
	} else
		nlm->hdr.nlmsg_type = RTM_DELADDR;
	nlm->ifa.ifa_index = iface->index;
	nlm->ifa.ifa_family = AF_INET;
	nlm->ifa.ifa_prefixlen = inet_ntocidr(*netmask);
	/* This creates the aliased interface */
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LABEL,
	    iface->name, strlen(iface->name) + 1);
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LOCAL,
	    &address->s_addr, sizeof(address->s_addr));
	if (action >= 0 && broadcast)
		add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_BROADCAST,
		    &broadcast->s_addr, sizeof(broadcast->s_addr));

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
}

int
if_route(const struct rt *rt, int action)
{
	struct nlmr *nlm;
	int retval = 0;
	struct dhcp_state *state;

	nlm = calloc(1, sizeof(*nlm));
	if (nlm == NULL)
		return -1;
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlm->hdr.nlmsg_type = RTM_NEWROUTE;
	if (action == 0)
		nlm->hdr.nlmsg_flags = NLM_F_REPLACE;
	else if (action == 1)
		nlm->hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	else
		nlm->hdr.nlmsg_type = RTM_DELROUTE;
	nlm->hdr.nlmsg_flags |= NLM_F_REQUEST;
	nlm->rt.rtm_family = AF_INET;
	nlm->rt.rtm_table = RT_TABLE_MAIN;

	state = D_STATE(rt->iface);
	if (action == -1 || action == -2)
		nlm->rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		/* We only change route metrics for kernel routes */
		if (rt->dest.s_addr ==
		    (state->addr.s_addr & state->net.s_addr) &&
		    rt->net.s_addr == state->net.s_addr)
			nlm->rt.rtm_protocol = RTPROT_KERNEL;
		else
			nlm->rt.rtm_protocol = RTPROT_BOOT;
		if (rt->gate.s_addr == INADDR_ANY ||
		    (rt->gate.s_addr == rt->dest.s_addr &&
			rt->net.s_addr == INADDR_BROADCAST))
			nlm->rt.rtm_scope = RT_SCOPE_LINK;
		else
			nlm->rt.rtm_scope = RT_SCOPE_UNIVERSE;
		nlm->rt.rtm_type = RTN_UNICAST;
	}

	nlm->rt.rtm_dst_len = inet_ntocidr(rt->net);
	add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_DST,
	    &rt->dest.s_addr, sizeof(rt->dest.s_addr));
	if (nlm->rt.rtm_protocol == RTPROT_KERNEL) {
		add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_PREFSRC,
		    &state->addr.s_addr, sizeof(state->addr.s_addr));
	}
	/* If destination == gateway then don't add the gateway */
	if (rt->dest.s_addr != rt->gate.s_addr ||
	    rt->net.s_addr != INADDR_BROADCAST)
		add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_GATEWAY,
		    &rt->gate.s_addr, sizeof(rt->gate.s_addr));

	if (rt->gate.s_addr != htonl(INADDR_LOOPBACK))
		add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_OIF, rt->iface->index);
	add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_PRIORITY, rt->metric);

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
}
#endif

#ifdef INET6
int
if_address6(const struct ipv6_addr *ap, int action)
{
	struct nlma *nlm;
	struct ifa_cacheinfo cinfo;
	int retval = 0;

	nlm = calloc(1, sizeof(*nlm));
	if (nlm == NULL)
		return -1;
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlm->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action >= 0) {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		nlm->hdr.nlmsg_type = RTM_NEWADDR;
	} else
		nlm->hdr.nlmsg_type = RTM_DELADDR;
	nlm->ifa.ifa_index = ap->iface->index;
	nlm->ifa.ifa_family = AF_INET6;
	nlm->ifa.ifa_prefixlen = ap->prefix_len;
	/* This creates the aliased interface */
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LABEL,
	    ap->iface->name, strlen(ap->iface->name) + 1);
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LOCAL,
	    &ap->addr.s6_addr, sizeof(ap->addr.s6_addr));

	if (action >= 0) {
		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = ap->prefix_pltime;
		cinfo.ifa_valid = ap->prefix_vltime;
		add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_CACHEINFO,
		    &cinfo, sizeof(cinfo));
	}

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
}

static int
rta_add_attr_32(struct rtattr *rta, unsigned int maxlen,
    int type, uint32_t data)
{
	unsigned int len = RTA_LENGTH(sizeof(data));
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, sizeof(data));
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
	return 0;
}

int
if_route6(const struct rt6 *rt, int action)
{
	struct nlmr *nlm;
	char metricsbuf[32];
	struct rtattr *metrics = (void *)metricsbuf;
	int retval = 0;

	nlm = calloc(1, sizeof(*nlm));
	if (nlm == NULL)
		return -1;
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlm->hdr.nlmsg_type = RTM_NEWROUTE;
	nlm->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action == 0)
		nlm->hdr.nlmsg_flags |= NLM_F_REPLACE;
	else if (action == 1)
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	else
		nlm->hdr.nlmsg_type = RTM_DELROUTE;
	nlm->rt.rtm_family = AF_INET6;
	nlm->rt.rtm_table = RT_TABLE_MAIN;

	if (action == -1 || action == -2)
		nlm->rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		/* None interface subnet routes are static. */
		if (IN6_IS_ADDR_UNSPECIFIED(&rt->gate)) {
			nlm->rt.rtm_protocol = RTPROT_KERNEL;
			nlm->rt.rtm_scope = RT_SCOPE_LINK;
		} else
			nlm->rt.rtm_protocol = RTPROT_BOOT;
		nlm->rt.rtm_type = RTN_UNICAST;
	}

	nlm->rt.rtm_dst_len = ipv6_prefixlen(&rt->net);
	add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_DST,
	    &rt->dest.s6_addr, sizeof(rt->dest.s6_addr));

	/* If destination == gateway then don't add the gateway */
	if (!IN6_IS_ADDR_UNSPECIFIED(&rt->gate) &&
	    !IN6_ARE_ADDR_EQUAL(&rt->dest, &rt->gate))
		add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_GATEWAY,
		    &rt->gate.s6_addr, sizeof(rt->gate.s6_addr));

	add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_OIF, rt->iface->index);
	add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_PRIORITY, rt->metric);

	if (rt->mtu) {
		metrics->rta_type = RTA_METRICS;
		metrics->rta_len = RTA_LENGTH(0);
		rta_add_attr_32(metrics, sizeof(metricsbuf), RTAX_MTU, rt->mtu);
		add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_METRICS,
		    RTA_DATA(metrics), RTA_PAYLOAD(metrics));
	}

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
	errno = ENOTSUP;
	return -1;
}

int
in6_addr_flags(__unused const char *ifname,
    __unused const struct in6_addr *addr)
{

	/* How do I get IPv6 address flags on Linux? */
	return 0;
}
#endif
