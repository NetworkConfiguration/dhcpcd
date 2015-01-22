/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2015 Roy Marples <roy@marples.name>
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

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <net/route.h>

/* Support older kernels */
#ifndef IFLA_WIRELESS
# define IFLA_WIRELESS (IFLA_MASTER + 1)
#endif

/* Linux has these in an enum and there is just no way to work
 * out of they exist at compile time. Silly silly silly. */
#define IFLA_AF_SPEC			26
#define IFLA_INET6_ADDR_GEN_MODE	8
#define IN6_ADDR_GEN_MODE_NONE		1

/* For some reason, glibc doesn't include newer flags from linux/if.h
 * However, we cannot include linux/if.h directly as it conflicts
 * with the glibc version. D'oh! */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/
#endif

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dev.h"
#include "dhcp.h"
#include "if.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipv6nd.h"

#ifdef HAVE_NL80211_H
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#endif
int if_getssid_wext(const char *ifname, uint8_t *ssid);

#define bpf_insn		sock_filter
#define BPF_SKIPTYPE
#define BPF_ETHCOOK		-ETH_HLEN
#define BPF_WHOLEPACKET	0x0fffffff /* work around buggy LPF filters */

#include "bpf-filter.h"

/* Broadcast address for IPoIB */
static const uint8_t ipv4_bcast_addr[] = {
	0x00, 0xff, 0xff, 0xff,
	0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

#define PROC_INET6	"/proc/net/if_inet6"
#define PROC_PROMOTE	"/proc/sys/net/ipv4/conf/%s/promote_secondaries"
#define SYS_LAYER2	"/sys/class/net/%s/device/layer2"

static const char *mproc =
#if defined(__alpha__)
	"system type"
#elif defined(__arm__)
	"Hardware"
#elif defined(__avr32__)
	"cpu family"
#elif defined(__bfin__)
	"BOARD Name"
#elif defined(__cris__)
	"cpu model"
#elif defined(__frv__)
	"System"
#elif defined(__i386__) || defined(__x86_64__)
	"vendor_id"
#elif defined(__ia64__)
	"vendor"
#elif defined(__hppa__)
	"model"
#elif defined(__m68k__)
	"MMU"
#elif defined(__mips__)
	"system type"
#elif defined(__powerpc__) || defined(__powerpc64__)
	"machine"
#elif defined(__s390__) || defined(__s390x__)
	"Manufacturer"
#elif defined(__sh__)
	"machine"
#elif defined(sparc) || defined(__sparc__)
	"cpu"
#elif defined(__vax__)
	"cpu"
#else
	NULL
#endif
	;

int
if_machinearch(char *str, size_t len)
{
	FILE *fp;
	char buf[256];

	if (mproc == NULL) {
		errno = EINVAL;
		return -1;
	}

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL)
		return -1;

	while (fscanf(fp, "%255s : ", buf) != EOF) {
		if (strncmp(buf, mproc, strlen(mproc)) == 0 &&
		    fscanf(fp, "%255s", buf) == 1)
		{
		        fclose(fp);
			return snprintf(str, len, ":%s", buf);
		}
	}
	fclose(fp);
	errno = ESRCH;
	return -1;
}

static int
check_proc_int(const char *path)
{
	FILE *fp;
	int i;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;
	if (fscanf(fp, "%d", &i) != 1)
		i = -1;
	fclose(fp);
	return i;
}

static ssize_t
write_path(const char *path, const char *val)
{
	FILE *fp;
	ssize_t r;

	fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	r = fprintf(fp, "%s\n", val);
	fclose(fp);
	return r;
}

int
if_init(struct interface *ifp)
{
	char path[sizeof(PROC_PROMOTE) + IF_NAMESIZE];
	int n;

	/* We enable promote_secondaries so that we can do this
	 * add 192.168.1.2/24
	 * add 192.168.1.3/24
	 * del 192.168.1.2/24
	 * and the subnet mask moves onto 192.168.1.3/24
	 * This matches the behaviour of BSD which makes coding dhcpcd
	 * a little easier as there's just one behaviour. */
	snprintf(path, sizeof(path), PROC_PROMOTE, ifp->name);
	n = check_proc_int(path);
	if (n == -1)
		return errno == ENOENT ? 0 : -1;
	if (n == 1)
		return 0;
	return write_path(path, "1") == -1 ? -1 : 0;
}

int
if_conf(struct interface *ifp)
{
	char path[sizeof(SYS_LAYER2) + IF_NAMESIZE];
	int n;

	/* Some qeth setups require the use of the broadcast flag. */
	snprintf(path, sizeof(path), SYS_LAYER2, ifp->name);
	n = check_proc_int(path);
	if (n == -1)
		return errno == ENOENT ? 0 : -1;
	if (n == 0)
		ifp->options->options |= DHCPCD_BROADCAST;
	return 0;
}

/* XXX work out Virtal Interface Masters */
int
if_vimaster(__unused const char *ifname)
{

	return 0;
}

static int
_open_link_socket(struct sockaddr_nl *nl, int flags, int protocol)
{
	int fd;

#ifdef SOCK_CLOEXEC
	if (flags)
		flags = SOCK_CLOEXEC;
	fd = socket(AF_NETLINK, SOCK_RAW | flags, protocol);
	if (fd == -1)
		return -1;
#else
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd == -1)
		return -1;
	if (flags &&
	    (flags = fcntl(fd, F_GETFD, 0)) == -1 ||
	    fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
	{
		close(fd);
	        return -1;
	}
#endif
	nl->nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)nl, sizeof(*nl)) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

int
if_openlinksocket(void)
{
	struct sockaddr_nl snl;

	memset(&snl, 0, sizeof(snl));
	snl.nl_groups = RTMGRP_LINK;

#ifdef INET
	snl.nl_groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR;
#endif
#ifdef INET6
	snl.nl_groups |= RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_NEIGH;
#endif

	return _open_link_socket(&snl, 1, NETLINK_ROUTE);
}

static int
err_netlink(struct nlmsghdr *nlm)
{
	struct nlmsgerr *err;
	size_t len;

	if (nlm->nlmsg_type != NLMSG_ERROR)
		return 0;
	len = nlm->nlmsg_len - sizeof(*nlm);
	if (len < sizeof(*err)) {
		errno = EBADMSG;
		return -1;
	}
	err = (struct nlmsgerr *)NLMSG_DATA(nlm);
	if (err->error == 0)
		return (int)len;
	errno = -err->error;
	return -1;
}

static int
get_netlink(struct dhcpcd_ctx *ctx, struct interface *ifp, int fd, int flags,
    int (*callback)(struct dhcpcd_ctx *, struct interface *,struct nlmsghdr *))
{
	char *buf = NULL, *nbuf;
	ssize_t bytes;
	size_t buflen;
	struct nlmsghdr *nlm;
	struct sockaddr_nl nladdr;
	socklen_t nladdr_len = sizeof(nladdr);
	int r;

	buflen = 0;
	r = -1;
	for (;;) {
		bytes = recv(fd, NULL, 0,
		    flags | MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC);
		if (bytes == -1)
			goto eexit;
		if ((size_t)bytes == buflen) {
			/* Support kernels older than 2.6.22 */
			if (bytes == 0)
				bytes = 512;
			else
				bytes *= 2;
		}
		if (buflen < (size_t)bytes) {
			/* Alloc 1 more so we work with older kernels */
			buflen = (size_t)bytes + 1;
			nbuf = realloc(buf, buflen);
			if (nbuf == NULL)
				goto eexit;
			buf = nbuf;
		}
		bytes = recvfrom(fd, buf, buflen, flags,
		    (struct sockaddr *)&nladdr, &nladdr_len);
		if (bytes == -1 || bytes == 0)
			goto eexit;

		/* Check sender */
		if (nladdr_len != sizeof(nladdr)) {
			errno = EINVAL;
			goto eexit;
		}
		/* Ignore message if it is not from kernel */
		if (nladdr.nl_pid != 0)
			continue;

		for (nlm = (struct nlmsghdr *)(void *)buf;
		     nlm && NLMSG_OK(nlm, (size_t)bytes);
		     nlm = NLMSG_NEXT(nlm, bytes))
		{
			r = err_netlink(nlm);
			if (r == -1)
				goto eexit;
			if (r)
				continue;
			if (callback) {
				r = callback(ctx, ifp, nlm);
				if (r != 0)
					goto eexit;
			}
		}
	}

eexit:
	free(buf);
	return r;
}

/* Work out the maximum pid size */
static inline long long
get_max_pid_t()
{

	if (sizeof(pid_t) == sizeof(short))		return SHRT_MAX;
	if (sizeof(pid_t) == sizeof(int))		return INT_MAX;
	if (sizeof(pid_t) == sizeof(long))		return LONG_MAX;
	if (sizeof(pid_t) == sizeof(long long))		return LLONG_MAX;
	abort();
}

static int
link_route(struct dhcpcd_ctx *ctx, __unused struct interface *ifp,
    struct nlmsghdr *nlm)
{
	size_t len;
	unsigned int metric;
	struct rtattr *rta;
	struct rtmsg *rtm;
#ifdef INET
	struct rt rt;
#endif
#ifdef INET6
	struct rt6 rt6;
#endif

	if (nlm->nlmsg_type != RTM_DELROUTE)
		return 0;

	len = nlm->nlmsg_len - sizeof(*nlm);
	if (len < sizeof(*rtm)) {
		errno = EBADMSG;
		return -1;
	}
	rtm = NLMSG_DATA(nlm);
	if (rtm->rtm_type != RTN_UNICAST ||
	    rtm->rtm_table != RT_TABLE_MAIN ||
	    (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6))
		return 1;
	/* Ignore messages generated by us.
	 * For some reason we get messages generated by us
	 * with a very large value in nlmsg_pid that seems to be
	 * sequentially changing. Is there a better test for this? */
	if (nlm->nlmsg_pid > get_max_pid_t())
		return 1;

	rta = (struct rtattr *)(void *)((char *)rtm +NLMSG_ALIGN(sizeof(*rtm)));
	len = NLMSG_PAYLOAD(nlm, sizeof(*rtm));
#ifdef INET
	if (rtm->rtm_family == AF_INET)
		memset(&rt, 0, sizeof(rt));
#endif
#ifdef INET6
	if (rtm->rtm_family == AF_INET6)
		memset(&rt6, 0, sizeof(rt6));
#endif
	metric = 0;
	while (RTA_OK(rta, len)) {
		switch (rtm->rtm_family) {
#ifdef INET
		case AF_INET:
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
				rt.iface = if_findindex(ctx,
				    *(unsigned int *)RTA_DATA(rta));
				break;
			}
			break;
#endif
#ifdef INET6
		case AF_INET6:
			switch (rta->rta_type) {
			case RTA_DST:
				memcpy(&rt6.dest.s6_addr, RTA_DATA(rta),
				    sizeof(rt6.dest.s6_addr));
				break;
			case RTA_GATEWAY:
				memcpy(&rt6.gate.s6_addr, RTA_DATA(rta),
				    sizeof(rt6.gate.s6_addr));
				break;
			case RTA_OIF:
				rt6.iface = if_findindex(ctx,
				    *(unsigned int *)RTA_DATA(rta));
				break;
			}
			break;
#endif
		}
		switch (rta->rta_type) {
		case RTA_PRIORITY:
			metric = *(unsigned int *)RTA_DATA(rta);
			break;
		}
		rta = RTA_NEXT(rta, len);
	}

	switch (rtm->rtm_family) {
#ifdef INET
		case AF_INET:
			if (rt.iface != NULL && metric == rt.iface->metric) {
				inet_cidrtoaddr(rtm->rtm_dst_len, &rt.net);
				ipv4_routedeleted(ctx, &rt);
			}
			break;
#endif
#ifdef INET6
		case AF_INET6:
			if (rt6.iface != NULL && metric == rt6.iface->metric) {
				ipv6_mask(&rt6.net, rtm->rtm_dst_len);
				ipv6_routedeleted(ctx, &rt6);
			}
			break;
#endif
	}
	return 1;
}

static int
link_addr(struct dhcpcd_ctx *ctx, struct interface *ifp, struct nlmsghdr *nlm)
{
	size_t len;
	struct rtattr *rta;
	struct ifaddrmsg *ifa;
#ifdef INET
	struct in_addr addr, net, dest;
#endif
#ifdef INET6
	struct in6_addr addr6;
#endif

	if (nlm->nlmsg_type != RTM_DELADDR && nlm->nlmsg_type != RTM_NEWADDR)
		return 0;

	len = nlm->nlmsg_len - sizeof(*nlm);
	if (len < sizeof(*ifa)) {
		errno = EBADMSG;
		return -1;
	}
	ifa = NLMSG_DATA(nlm);
	if ((ifp = if_findindex(ctx, ifa->ifa_index)) == NULL) {
		/* We don't know about the interface the address is for
		 * so it's not really an error */
		return 1;
	}
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
				if (ifp->flags & IFF_POINTOPOINT) {
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
		ipv4_handleifa(ctx, nlm->nlmsg_type, NULL, ifp->name,
		    &addr, &net, &dest);
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
		ipv6_handleifa(ctx, nlm->nlmsg_type, NULL, ifp->name,
		    &addr6, ifa->ifa_prefixlen, ifa->ifa_flags);
		break;
#endif
	}
	return 1;
}

static uint8_t
l2addr_len(unsigned short if_type)
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
	}

	/* Impossible */
	return 0;
}

static int
handle_rename(struct dhcpcd_ctx *ctx, unsigned int ifindex, const char *ifname)
{
	struct interface *ifp;

	TAILQ_FOREACH(ifp, ctx->ifaces, next) {
		if (ifp->index == ifindex && strcmp(ifp->name, ifname)) {
			dhcpcd_handleinterface(ctx, -1, ifp->name);
			/* Let dev announce the interface for renaming */
			if (!dev_listening(ctx))
				dhcpcd_handleinterface(ctx, 1, ifname);
			return 1;
		}
	}
	return 0;
}

#ifdef INET6
static int
link_neigh(struct dhcpcd_ctx *ctx, __unused struct interface *ifp,
    struct nlmsghdr *nlm)
{
	struct ndmsg *r;
	struct rtattr *rta;
	size_t len;
	struct in6_addr addr6;
	int flags;

	if (nlm->nlmsg_type != RTM_NEWNEIGH && nlm->nlmsg_type != RTM_DELNEIGH)
		return 0;
	if (nlm->nlmsg_len < sizeof(*r))
		return -1;

	r = NLMSG_DATA(nlm);
	rta = (struct rtattr *)RTM_RTA(r);
	len = RTM_PAYLOAD(nlm);
        if (r->ndm_family == AF_INET6) {
		flags = 0;
		if (r->ndm_flags & NTF_ROUTER)
			flags |= IPV6ND_ROUTER;
		if (nlm->nlmsg_type == RTM_NEWNEIGH &&
		    r->ndm_state &
		    (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE |
		     NUD_PERMANENT))
		        flags |= IPV6ND_REACHABLE;
		memset(&addr6, 0, sizeof(addr6));
		while (RTA_OK(rta, len)) {
			switch (rta->rta_type) {
			case NDA_DST:
				memcpy(&addr6.s6_addr, RTA_DATA(rta),
				       sizeof(addr6.s6_addr));
				break;
			}
			rta = RTA_NEXT(rta, len);
		}
		ipv6nd_neighbour(ctx, &addr6, flags);
	}

	return 1;
}
#endif

static int
link_netlink(struct dhcpcd_ctx *ctx, struct interface *ifp,
    struct nlmsghdr *nlm)
{
	int r;
	size_t len;
	struct rtattr *rta, *hwaddr;
	struct ifinfomsg *ifi;
	char ifn[IF_NAMESIZE + 1];

	r = link_route(ctx, ifp, nlm);
	if (r != 0)
		return r;
	r = link_addr(ctx, ifp, nlm);
	if (r != 0)
		return r;
#ifdef INET6
	r = link_neigh(ctx, ifp, nlm);
	if (r != 0)
		return r;
#endif

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
		dhcpcd_handleinterface(ctx, -1, ifn);
		return 1;
	}

	/* Virtual interfaces may not get a valid hardware address
	 * at this point.
	 * To trigger a valid hardware address pickup we need to pretend
	 * that that don't exist until they have one. */
	if (ifi->ifi_flags & IFF_MASTER && !hwaddr) {
		dhcpcd_handleinterface(ctx, -1, ifn);
		return 1;
	}

	/* Check for interface name change */
	if (handle_rename(ctx, (unsigned int)ifi->ifi_index, ifn))
		    return 1;

	/* Check for a new interface */
	ifp = if_find(ctx, ifn);
	if (ifp == NULL) {
		/* If are listening to a dev manager, let that announce
		 * the interface rather than the kernel. */
		if (dev_listening(ctx) < 1)
			dhcpcd_handleinterface(ctx, 1, ifn);
		return 1;
	}

	/* Re-read hardware address and friends */
	if (!(ifi->ifi_flags & IFF_UP) && hwaddr) {
		uint8_t l;

		l = l2addr_len(ifi->ifi_type);
		if (hwaddr->rta_len == RTA_LENGTH(l))
			dhcpcd_handlehwaddr(ctx, ifn, RTA_DATA(hwaddr), l);
	}

	dhcpcd_handlecarrier(ctx,
	    ifi->ifi_flags & IFF_RUNNING ? LINK_UP : LINK_DOWN,
	    ifi->ifi_flags, ifn);
	return 1;
}

int
if_managelink(struct dhcpcd_ctx *ctx)
{

	return get_netlink(ctx, NULL,
	    ctx->link_fd, MSG_DONTWAIT, &link_netlink);
}

static int
send_netlink(struct dhcpcd_ctx *ctx, struct interface *ifp,
    int protocol, struct nlmsghdr *hdr,
    int (*callback)(struct dhcpcd_ctx *, struct interface *,struct nlmsghdr *))
{
	int s, r;
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	static unsigned int seq;

	memset(&snl, 0, sizeof(snl));
	if ((s = _open_link_socket(&snl, 0, protocol)) == -1)
		return -1;
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	/* Request a reply */
	hdr->nlmsg_flags |= NLM_F_ACK;
	hdr->nlmsg_seq = ++seq;

	if (sendmsg(s, &msg, 0) != -1)
		r = get_netlink(ctx, ifp, s, 0, callback);
	else
		r = -1;
	close(s);
	return r;
}

#define NLMSG_TAIL(nmsg)						\
	((struct rtattr *)(((ptrdiff_t)(nmsg))+NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int
add_attr_l(struct nlmsghdr *n, unsigned short maxlen, unsigned short type,
    const void *data, unsigned short alen)
{
	unsigned short len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static int
add_attr_32(struct nlmsghdr *n, unsigned short maxlen, unsigned short type,
    uint32_t data)
{
	unsigned short len = RTA_LENGTH(sizeof(data));
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

#ifdef HAVE_NL80211_H
static struct nlattr *
nla_next(struct nlattr *nla, size_t *rem)
{

	*rem -= NLA_ALIGN(nla->nla_len);
	return (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
}

#define NLA_TYPE(nla) ((nla)->nla_type & NLA_TYPE_MASK)
#define NLA_LEN(nla) ((nla)->nla_len - NLA_HDRLEN)
#define NLA_OK(nla, rem) \
	((rem) >= sizeof(struct nlattr) && \
	(nla)->nla_len >= sizeof(struct nlattr) && \
	(nla)->nla_len <= rem)
#define NLA_DATA(nla) ((char *)(nla) + NLA_HDRLEN)
#define NLA_FOR_EACH_ATTR(pos, head, len, rem) \
	for (pos = head, rem = len; NLA_OK(pos, rem); pos = nla_next(pos, &(rem)))

struct nlmg
{
	struct nlmsghdr hdr;
	struct genlmsghdr ghdr;
	char buffer[64];
};

static int
nla_put_32(struct nlmsghdr *n, unsigned short maxlen,
    unsigned short type, uint32_t data)
{
	unsigned short len;
	struct nlattr *nla;

	len = NLA_ALIGN(NLA_HDRLEN + sizeof(data));
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	nla = (struct nlattr *)NLMSG_TAIL(n);
	nla->nla_type = type;
	nla->nla_len = len;
	memcpy(NLA_DATA(nla), &data, sizeof(data));
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

static int
nla_put_string(struct nlmsghdr *n, unsigned short maxlen,
    unsigned short type, const char *data)
{
	struct nlattr *nla;
	size_t len, sl;

	sl = strlen(data) + 1;
	len = NLA_ALIGN(NLA_HDRLEN + sl);
	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	nla = (struct nlattr *)NLMSG_TAIL(n);
	nla->nla_type = type;
	nla->nla_len = (unsigned short)len;
	memcpy(NLA_DATA(nla), data, sl);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + (unsigned short)len;
	return 0;
}

static int
gnl_parse(struct nlmsghdr *nlm, struct nlattr *tb[], int maxtype)
{
	struct genlmsghdr *ghdr;
	struct nlattr *head, *nla;
	size_t len, rem;
	int type;

	memset(tb, 0, sizeof(*tb) * ((unsigned int)maxtype + 1));
	ghdr = NLMSG_DATA(nlm);
	head = (struct nlattr *)((char *) ghdr + GENL_HDRLEN);
	len = nlm->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN;
	NLA_FOR_EACH_ATTR(nla, head, len, rem) {
		type = NLA_TYPE(nla);
		if (type > maxtype)
			continue;
		tb[type] = nla;
	}
	return 0;
}

static int
_gnl_getfamily(__unused struct dhcpcd_ctx *ctx, __unused struct interface *ifp,
    struct nlmsghdr *nlm)
{
	struct nlattr *tb[CTRL_ATTR_FAMILY_ID + 1];
	uint16_t family;

	if (gnl_parse(nlm, tb, CTRL_ATTR_FAMILY_ID) == -1)
		return -1;
	if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
		errno = ENOENT;
		return -1;
	}
	family = *(uint16_t *)NLA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
	return (int)family;
}

static int
gnl_getfamily(struct dhcpcd_ctx *ctx, const char *name)
{
	struct nlmg nlm;

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	nlm.hdr.nlmsg_type = GENL_ID_CTRL;
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlm.ghdr.cmd = CTRL_CMD_GETFAMILY;
	nlm.ghdr.version = 1;
	if (nla_put_string(&nlm.hdr, sizeof(nlm),
	    CTRL_ATTR_FAMILY_NAME, name) == -1)
		return -1;
	return send_netlink(ctx, NULL, NETLINK_GENERIC, &nlm.hdr,
	    &_gnl_getfamily);
}

static int
_if_getssid(__unused struct dhcpcd_ctx *ctx, struct interface *ifp,
    struct nlmsghdr *nlm)
{
	struct nlattr *tb[NL80211_ATTR_SSID + 1];

	if (gnl_parse(nlm, tb, NL80211_ATTR_SSID) == -1)
		return -1;

	if (tb[NL80211_ATTR_SSID] == NULL) {
		/* If the SSID is not found then it means that
		 * we're not associated to an AP. */
		ifp->ssid_len = 0;
		goto out;
	}

	ifp->ssid_len = NLA_LEN(tb[NL80211_ATTR_SSID]);
	if (ifp->ssid_len > sizeof(ifp->ssid)) {
		errno = ENOBUFS;
		ifp->ssid_len = 0;
		return -1;
	}
	memcpy(ifp->ssid, NLA_DATA(tb[NL80211_ATTR_SSID]), ifp->ssid_len);

out:
	ifp->ssid[ifp->ssid_len] = '\0';
	return (int)ifp->ssid_len;
}

static int
if_getssid_nl80211(struct interface *ifp)
{
	int family;
	struct nlmg nlm;

	errno = 0;
	family = gnl_getfamily(ifp->ctx, "nl80211");
	if (family == -1)
		return -1;
	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	nlm.hdr.nlmsg_type = (unsigned short)family;
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlm.ghdr.cmd = NL80211_CMD_GET_INTERFACE;
	nla_put_32(&nlm.hdr, sizeof(nlm), NL80211_ATTR_IFINDEX, ifp->index);

	return send_netlink(ifp->ctx, ifp,
	    NETLINK_GENERIC, &nlm.hdr, &_if_getssid);
}
#endif

int
if_getssid(struct interface *ifp)
{
	int r;

	r = if_getssid_wext(ifp->name, ifp->ssid);
	if (r != -1)
		ifp->ssid_len = (unsigned int)r;
#ifdef HAVE_NL80211_H
	else if (r == -1)
		r = if_getssid_nl80211(ifp);
#endif
	return r;
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
const char *if_pfname = "Packet Socket";

int
if_openrawsocket(struct interface *ifp, int protocol)
{
	int s;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	struct sock_fprog pf;
#ifdef PACKET_AUXDATA
	int n;
#endif

#ifdef SOCK_CLOEXEC
	if ((s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    htons(protocol))) == -1)
		return -1;
#else
	int flags;

	if ((s = socket(PF_PACKET, SOCK_DGRAM, htons(protocol))) == -1)
		return -1;
	if ((flags = fcntl(s, F_GETFD, 0)) == -1 ||
	    fcntl(s, F_SETFD, flags | FD_CLOEXEC) == -1)
	{
		close(s);
	        return -1;
	}
	if ((flags = fcntl(s, F_GETFL, 0)) == -1 ||
	    fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		close(s);
	        return -1;
	}
#endif
	/* Install the DHCP filter */
	memset(&pf, 0, sizeof(pf));
	if (protocol == ETHERTYPE_ARP) {
		pf.filter = UNCONST(arp_bpf_filter);
		pf.len = arp_bpf_filter_len;
	} else {
		pf.filter = UNCONST(dhcp_bpf_filter);
		pf.len = dhcp_bpf_filter_len;
	}
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;
#ifdef PACKET_AUXDATA
	n = 1;
	if (setsockopt(s, SOL_PACKET, PACKET_AUXDATA, &n, sizeof(n)) != 0) {
		if (errno != ENOPROTOOPT)
			goto eexit;
	}
#endif

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = PF_PACKET;
	su.sll.sll_protocol = htons(protocol);
	su.sll.sll_ifindex = (int)ifp->index;
	if (bind(s, &su.sa, sizeof(su.sll)) == -1)
		goto eexit;
	return s;

eexit:
	close(s);
	return -1;
}

ssize_t
if_sendrawpacket(const struct interface *ifp, int protocol,
    const void *data, size_t len)
{
	const struct dhcp_state *state;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	int fd;

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = AF_PACKET;
	su.sll.sll_protocol = htons(protocol);
	su.sll.sll_ifindex = (int)ifp->index;
	su.sll.sll_hatype = htons(ifp->family);
	su.sll.sll_halen = (unsigned char)ifp->hwlen;
	if (ifp->family == ARPHRD_INFINIBAND)
		memcpy(&su.sll.sll_addr,
		    &ipv4_bcast_addr, sizeof(ipv4_bcast_addr));
	else
		memset(&su.sll.sll_addr, 0xff, ifp->hwlen);
	state = D_CSTATE(ifp);
	if (protocol == ETHERTYPE_ARP)
		fd = state->arp_fd;
	else
		fd = state->raw_fd;

	return sendto(fd, data, len, 0, &su.sa, sizeof(su.sll));
}

ssize_t
if_readrawpacket(struct interface *ifp, int protocol,
    void *data, size_t len, int *flags)
{
	struct iovec iov = {
		.iov_base = data,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct dhcp_state *state;
#ifdef PACKET_AUXDATA
	unsigned char cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
	struct cmsghdr *cmsg;
	struct tpacket_auxdata *aux;
#endif

	ssize_t bytes;
	int fd = -1;

#ifdef PACKET_AUXDATA
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
#endif

	state = D_STATE(ifp);
	if (protocol == ETHERTYPE_ARP)
		fd = state->arp_fd;
	else
		fd = state->raw_fd;
	bytes = recvmsg(fd, &msg, 0);
	if (bytes == -1)
		return -1;
	*flags = RAW_EOF; /* We only ever read one packet */
	if (bytes) {
#ifdef PACKET_AUXDATA
		for (cmsg = CMSG_FIRSTHDR(&msg);
		     cmsg;
		     cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			if (cmsg->cmsg_level == SOL_PACKET &&
			    cmsg->cmsg_type == PACKET_AUXDATA) {
				aux = (void *)CMSG_DATA(cmsg);
				if (aux->tp_status & TP_STATUS_CSUMNOTREADY)
					*flags |= RAW_PARTIALCSUM;
			}
		}
#endif
	}
	return bytes;
}

int
if_address(const struct interface *iface,
    const struct in_addr *address, const struct in_addr *netmask,
    const struct in_addr *broadcast, int action)
{
	struct nlma nlm;
	int retval = 0;

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action >= 0) {
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		nlm.hdr.nlmsg_type = RTM_NEWADDR;
	} else
		nlm.hdr.nlmsg_type = RTM_DELADDR;
	nlm.ifa.ifa_index = iface->index;
	nlm.ifa.ifa_family = AF_INET;
	nlm.ifa.ifa_prefixlen = inet_ntocidr(*netmask);
	/* This creates the aliased interface */
	add_attr_l(&nlm.hdr, sizeof(nlm), IFA_LABEL,
	    iface->alias, (unsigned short)(strlen(iface->alias) + 1));
	add_attr_l(&nlm.hdr, sizeof(nlm), IFA_LOCAL,
	    &address->s_addr, sizeof(address->s_addr));
	if (action >= 0 && broadcast)
		add_attr_l(&nlm.hdr, sizeof(nlm), IFA_BROADCAST,
		    &broadcast->s_addr, sizeof(broadcast->s_addr));

	if (send_netlink(iface->ctx, NULL, NETLINK_ROUTE, &nlm.hdr, NULL) == -1)
		retval = -1;
	return retval;
}

int
if_route(const struct rt *rt, int action)
{
	struct nlmr nlm;
	int retval = 0;
	struct dhcp_state *state;

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlm.hdr.nlmsg_type = RTM_NEWROUTE;
	if (action == 0)
		nlm.hdr.nlmsg_flags = NLM_F_REPLACE;
	else if (action == 1)
		nlm.hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	else
		nlm.hdr.nlmsg_type = RTM_DELROUTE;
	nlm.hdr.nlmsg_flags |= NLM_F_REQUEST;
	nlm.rt.rtm_family = AF_INET;
	nlm.rt.rtm_table = RT_TABLE_MAIN;

	state = D_STATE(rt->iface);
	if (action == -1 || action == -2)
		nlm.rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		/* We only change route metrics for kernel routes */
		if (rt->dest.s_addr ==
		    (state->addr.s_addr & state->net.s_addr) &&
		    rt->net.s_addr == state->net.s_addr)
			nlm.rt.rtm_protocol = RTPROT_KERNEL;
		else
			nlm.rt.rtm_protocol = RTPROT_BOOT;
		if (rt->iface->flags & IFF_LOOPBACK)
			nlm.rt.rtm_scope = RT_SCOPE_HOST;
		else if (rt->gate.s_addr == INADDR_ANY ||
		    (rt->gate.s_addr == rt->dest.s_addr &&
			rt->net.s_addr == INADDR_BROADCAST))
			nlm.rt.rtm_scope = RT_SCOPE_LINK;
		else
			nlm.rt.rtm_scope = RT_SCOPE_UNIVERSE;
		nlm.rt.rtm_type = RTN_UNICAST;
	}

	nlm.rt.rtm_dst_len = inet_ntocidr(rt->net);
	add_attr_l(&nlm.hdr, sizeof(nlm), RTA_DST,
	    &rt->dest.s_addr, sizeof(rt->dest.s_addr));
	if (nlm.rt.rtm_protocol == RTPROT_KERNEL) {
		add_attr_l(&nlm.hdr, sizeof(nlm), RTA_PREFSRC,
		    &state->addr.s_addr, sizeof(state->addr.s_addr));
	}
	/* If destination == gateway then don't add the gateway */
	if (rt->dest.s_addr != rt->gate.s_addr ||
	    rt->net.s_addr != INADDR_BROADCAST)
		add_attr_l(&nlm.hdr, sizeof(nlm), RTA_GATEWAY,
		    &rt->gate.s_addr, sizeof(rt->gate.s_addr));

	if (rt->gate.s_addr != htonl(INADDR_LOOPBACK))
		add_attr_32(&nlm.hdr, sizeof(nlm), RTA_OIF, rt->iface->index);
	add_attr_32(&nlm.hdr, sizeof(nlm), RTA_PRIORITY, rt->metric);

	if (send_netlink(rt->iface->ctx, NULL,
	    NETLINK_ROUTE, &nlm.hdr, NULL) == -1)
		retval = -1;
	return retval;
}
#endif

#ifdef INET6
int
if_address6(const struct ipv6_addr *ap, int action)
{
	struct nlma nlm;
	struct ifa_cacheinfo cinfo;
	int retval = 0;
/* IFA_FLAGS is not a define, but is was added at the same time
 * IFA_F_NOPREFIXROUTE was do use that. */
#ifdef IFA_F_NOPREFIXROUTE
	uint32_t flags = 0;
#endif

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action >= 0) {
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		nlm.hdr.nlmsg_type = RTM_NEWADDR;
	} else
		nlm.hdr.nlmsg_type = RTM_DELADDR;
	nlm.ifa.ifa_index = ap->iface->index;
	nlm.ifa.ifa_family = AF_INET6;
	if (ap->addr_flags & IFA_F_TEMPORARY) {
#ifdef IFA_F_NOPREFIXROUTE
		flags |= IFA_F_TEMPORARY;
#else
		nlm.ifa.ifa_flags |= IFA_F_TEMPORARY;
#endif
	}
#ifdef IFA_F_MANAGETEMPADDR
	else if (ap->flags & IPV6_AF_AUTOCONF &&
	    ip6_use_tempaddr(ap->iface->name))
		flags |= IFA_F_MANAGETEMPADDR;
#endif

	/* Add as /128 if no IFA_F_NOPREFIXROUTE ? */
	nlm.ifa.ifa_prefixlen = ap->prefix_len;
	/* This creates the aliased interface */
	add_attr_l(&nlm.hdr, sizeof(nlm), IFA_LABEL,
	    ap->iface->alias, (unsigned short)(strlen(ap->iface->alias) + 1));
	add_attr_l(&nlm.hdr, sizeof(nlm), IFA_LOCAL,
	    &ap->addr.s6_addr, sizeof(ap->addr.s6_addr));

	if (action >= 0) {
		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = ap->prefix_pltime;
		cinfo.ifa_valid = ap->prefix_vltime;
		add_attr_l(&nlm.hdr, sizeof(nlm), IFA_CACHEINFO,
		    &cinfo, sizeof(cinfo));
	}

#ifdef IFA_F_NOPREFIXROUTE
	if (!IN6_IS_ADDR_LINKLOCAL(&ap->addr))
		flags |= IFA_F_NOPREFIXROUTE;
#endif
#ifdef IFA_F_NOPREFIXROUTE
	if (flags)
		add_attr_32(&nlm.hdr, sizeof(nlm), IFA_FLAGS, flags);
#endif

	if (send_netlink(ap->iface->ctx, NULL,
	    NETLINK_ROUTE, &nlm.hdr, NULL) == -1)
		retval = -1;
	return retval;
}

static int
rta_add_attr_32(struct rtattr *rta, unsigned short maxlen,
    unsigned short type, uint32_t data)
{
	unsigned short len = RTA_LENGTH(sizeof(data));
	struct rtattr *subrta;

	if (RTA_ALIGN(rta->rta_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	memcpy(RTA_DATA(subrta), &data, sizeof(data));
	rta->rta_len = (unsigned short)(NLMSG_ALIGN(rta->rta_len) + len);
	return 0;
}

int
if_route6(const struct rt6 *rt, int action)
{
	struct nlmr nlm;
	char metricsbuf[32];
	struct rtattr *metrics = (void *)metricsbuf;
	int retval = 0;

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlm.hdr.nlmsg_type = RTM_NEWROUTE;
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	if (action == 0)
		nlm.hdr.nlmsg_flags |= NLM_F_REPLACE;
	else if (action == 1)
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	else
		nlm.hdr.nlmsg_type = RTM_DELROUTE;
	nlm.rt.rtm_family = AF_INET6;
	nlm.rt.rtm_table = RT_TABLE_MAIN;

	if (action == -1 || action == -2)
		nlm.rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm.hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		/* None interface subnet routes are static. */
		if (rt->iface->flags & IFF_LOOPBACK)
			nlm.rt.rtm_scope = RT_SCOPE_HOST;
		else if (IN6_IS_ADDR_UNSPECIFIED(&rt->gate)) {
			nlm.rt.rtm_protocol = RTPROT_KERNEL;
			nlm.rt.rtm_scope = RT_SCOPE_LINK;
		} else
			nlm.rt.rtm_protocol = RTPROT_BOOT;
		if (rt->flags & RTF_REJECT)
			nlm.rt.rtm_type = RTN_UNREACHABLE;
		else
			nlm.rt.rtm_type = RTN_UNICAST;
	}

	nlm.rt.rtm_dst_len = ipv6_prefixlen(&rt->net);
	add_attr_l(&nlm.hdr, sizeof(nlm), RTA_DST,
	    &rt->dest.s6_addr, sizeof(rt->dest.s6_addr));

	if (action >= 0 && !IN6_IS_ADDR_UNSPECIFIED(&rt->gate))
		add_attr_l(&nlm.hdr, sizeof(nlm), RTA_GATEWAY,
		    &rt->gate.s6_addr, sizeof(rt->gate.s6_addr));

	if (!(rt->flags & RTF_REJECT)) {
		add_attr_32(&nlm.hdr, sizeof(nlm), RTA_OIF, rt->iface->index);
		add_attr_32(&nlm.hdr, sizeof(nlm), RTA_PRIORITY, rt->metric);
	}

	if (rt->mtu) {
		metrics->rta_type = RTA_METRICS;
		metrics->rta_len = RTA_LENGTH(0);
		rta_add_attr_32(metrics, sizeof(metricsbuf), RTAX_MTU, rt->mtu);
		add_attr_l(&nlm.hdr, sizeof(nlm), RTA_METRICS,
		    RTA_DATA(metrics), RTA_PAYLOAD(metrics));
	}

	if (send_netlink(rt->iface->ctx, NULL,
	    NETLINK_ROUTE, &nlm.hdr, NULL) == -1)
		retval = -1;
	return retval;
}

int
if_addrflags6(const struct in6_addr *addr, const struct interface *ifp)
{
	FILE *fp;
	char *p, ifaddress[33], address[33], name[IF_NAMESIZE + 1];
	unsigned int ifindex;
	int prefix, scope, flags, i;

	fp = fopen(PROC_INET6, "r");
	if (fp == NULL)
		return -1;

	p = ifaddress;
	for (i = 0; i < (int)sizeof(addr->s6_addr); i++) {
		p += snprintf(p, 3, "%.2x", addr->s6_addr[i]);
	}
	*p = '\0';

	while (fscanf(fp, "%32[a-f0-9] %x %x %x %x %"TOSTRING(IF_NAMESIZE)"s\n",
	    address, &ifindex, &prefix, &scope, &flags, name) == 6)
	{
		if (strlen(address) != 32) {
			fclose(fp);
			errno = ENOTSUP;
			return -1;
		}
		if (strcmp(name, ifp->name) == 0 &&
		    strcmp(ifaddress, address) == 0)
		{
			fclose(fp);
			return flags;
		}
	}

	fclose(fp);
	errno = ESRCH;
	return -1;
}

int
if_getlifetime6(__unused struct ipv6_addr *ia)
{

	/* God knows how to work out address lifetimes on Linux */
	errno = ENOTSUP;
	return -1;
}

struct nlml
{
	struct nlmsghdr hdr;
	struct ifinfomsg i;
	char buffer[32];
};

static int
add_attr_8(struct nlmsghdr *n, unsigned short maxlen, unsigned short type,
    uint8_t data)
{

	return add_attr_l(n, maxlen, type, &data, sizeof(data));
}

static struct rtattr *
add_attr_nest(struct nlmsghdr *n, unsigned short maxlen, unsigned short type)
{
	struct rtattr *nest;

	nest = NLMSG_TAIL(n);
	add_attr_l(n, maxlen, type, NULL, 0);
	return nest;
}

static void
add_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{

	nest->rta_len = (unsigned short)((char *)NLMSG_TAIL(n) - (char *)nest);
}

static int
if_disable_autolinklocal(struct dhcpcd_ctx *ctx, int ifindex)
{
	struct nlml nlm;
	struct rtattr *afs, *afs6;

	memset(&nlm, 0, sizeof(nlm));
	nlm.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlm.hdr.nlmsg_type = RTM_NEWLINK;
	nlm.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlm.i.ifi_family = AF_INET6;
	nlm.i.ifi_index = ifindex;
	afs = add_attr_nest(&nlm.hdr, sizeof(nlm), IFLA_AF_SPEC);
	afs6 = add_attr_nest(&nlm.hdr, sizeof(nlm), AF_INET6);
	add_attr_8(&nlm.hdr, sizeof(nlm), IFLA_INET6_ADDR_GEN_MODE,
	    IN6_ADDR_GEN_MODE_NONE);
	add_attr_nest_end(&nlm.hdr, afs6);
	add_attr_nest_end(&nlm.hdr, afs);

	return send_netlink(ctx, NULL, NETLINK_ROUTE, &nlm.hdr, NULL);
}

static const char *prefix = "/proc/sys/net/ipv6/conf";

int
if_checkipv6(struct dhcpcd_ctx *ctx, const struct interface *ifp, int own)
{
	const char *ifname;
	int ra;
	char path[256];

	if (ifp == NULL)
		ifname = "all";
	else if (own) {
		if (if_disable_autolinklocal(ctx, (int)ifp->index) == -1)
			syslog(LOG_DEBUG, "%s: if_disable_autolinklocal: %m",
			    ifp->name);
	}
	if (ifp)
		ifname = ifp->name;

	snprintf(path, sizeof(path), "%s/%s/autoconf", prefix, ifname);
	ra = check_proc_int(path);
	if (ra != 1) {
		if (!own)
			syslog(LOG_WARNING,
			    "%s: IPv6 kernel autoconf disabled", ifname);
	} else if (ra != -1 && own) {
		if (write_path(path, "0") == -1) {
			syslog(LOG_ERR, "write_path: %s: %m", path);
			return -1;
		}
	}

	snprintf(path, sizeof(path), "%s/%s/accept_ra", prefix, ifname);
	ra = check_proc_int(path);
	if (ra == -1)
		/* The sysctl probably doesn't exist, but this isn't an
		 * error as such so just log it and continue */
		syslog(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
		    "%s: %m", path);
	else if (ra != 0 && own) {
		syslog(LOG_DEBUG, "%s: disabling kernel IPv6 RA support",
		    ifname);
		if (write_path(path, "0") == -1) {
			syslog(LOG_ERR, "write_path: %s: %m", path);
			return ra;
		}
		return 0;
	}

	return ra;
}

int
ip6_use_tempaddr(const char *ifname)
{
	char path[256];
	int val;

	if (ifname == NULL)
		ifname = "all";
	snprintf(path, sizeof(path), "%s/%s/use_tempaddr", prefix, ifname);
	val = check_proc_int(path);
	return val == -1 ? 0 : val;
}

int
ip6_temp_preferred_lifetime(const char *ifname)
{
	char path[256];
	int val;

	if (ifname == NULL)
		ifname = "all";
	snprintf(path, sizeof(path), "%s/%s/temp_prefered_lft", prefix,
	    ifname);
	val = check_proc_int(path);
	return val < 0 ? TEMP_PREFERRED_LIFETIME : val;
}

int
ip6_temp_valid_lifetime(const char *ifname)
{
	char path[256];
	int val;

	if (ifname == NULL)
		ifname = "all";
	snprintf(path, sizeof(path), "%s/%s/temp_valid_lft", prefix, ifname);
	val = check_proc_int(path);
	return val < 0 ? TEMP_VALID_LIFETIME : val;
}
#endif
