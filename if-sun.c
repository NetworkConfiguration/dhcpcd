/*
 * Solaris interface driver for dhcpcd
 * Copyright (c) 2016 Roy Marples <roy@marples.name>
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

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libdlpi.h>
#include <stddef.h>
#include <stdlib.h>
#include <stropts.h>
#include <string.h>
#include <unistd.h>

#include <inet/ip.h>

/* private interface we can hook into to get
 * a better getifaddrs(3). */
#include <libsocket_priv.h>

#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include <sys/ioctl.h>
#include <sys/pfmod.h>
#include <sys/tihdr.h>
#include <sys/utsname.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "if.h"
#include "if-options.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipv6nd.h"

#ifndef ARP_MOD_NAME
#  define ARP_MOD_NAME        "arp"
#endif

#ifndef RT_ROUNDUP
#define RT_ROUNDUP(a)							      \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define RT_ADVANCE(x, n) (x += RT_ROUNDUP(salen(n)))
#endif

#define COPYOUT(sin, sa) do {						      \
	if ((sa) && ((sa)->sa_family == AF_INET))			      \
		(sin) = ((const struct sockaddr_in *)(const void *)	      \
		    (sa))->sin_addr;					      \
	} while (0)

#define COPYOUT6(sin, sa) do {						      \
	if ((sa) && ((sa)->sa_family == AF_INET6))			      \
		(sin) = ((const struct sockaddr_in6 *)(const void *)	      \
		    (sa))->sin6_addr;					      \
	} while (0)

#ifndef CLLADDR
#  define CLLADDR(s) (const void *)((s)->sdl_data + (s)->sdl_nlen)
#endif

#ifdef INET
/* Instead of using DLPI directly, we use libdlpi which is
 * Solaris sepcific. */
struct dl_if {
	TAILQ_ENTRY(dl_if)	next;
	struct interface	*iface;
	int			fd;
	dlpi_handle_t		dh;
	uint8_t			broadcast[DLPI_PHYSADDR_MAX];
};
TAILQ_HEAD(dl_if_head, dl_if);
#endif

struct priv {
#ifdef INET
	struct dl_if_head dl_ifs;
#endif
#ifdef INET6
	int pf_inet6_fd;
#endif
};

int
if_init(__unused struct interface *ifp)
{

	return 0;
}

int
if_conf(__unused struct interface *ifp)
{

	return 0;
}

int
if_opensockets_os(struct dhcpcd_ctx *ctx)
{
	struct priv		*priv;

	if ((priv = malloc(sizeof(*priv))) == NULL)
		return -1;
	ctx->priv = priv;
#ifdef INET
	TAILQ_INIT(&priv->dl_ifs);
#endif

#ifdef INET6
	priv->pf_inet6_fd = xsocket(PF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	/* Don't return an error so we at least work on kernels witout INET6
	 * even though we expect INET6 support.
	 * We will fail noisily elsewhere anyway. */
#endif

	ctx->link_fd = socket(PF_ROUTE,
	    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#ifdef INET
	if (ctx->link_fd == -1)
		free(ctx->priv);
#endif
	return ctx->link_fd == -1 ? -1 : 0;
}

void
if_closesockets_os(struct dhcpcd_ctx *ctx)
{
#ifdef INET6
	struct priv		*priv;

	priv = (struct priv *)ctx->priv;
	if (priv->pf_inet6_fd != -1)
		close(priv->pf_inet6_fd);
#endif

	/* each interface should have closed itself */
	free(ctx->priv);
}

int
if_getssid(struct interface *ifp)
{

	UNUSED(ifp);
	errno = ENOTSUP;
	return -1;
}

int
if_vimaster(__unused const struct dhcpcd_ctx *ctx, __unused const char *ifname)
{

	return 0;
}

int
if_machinearch(__unused char *str, __unused size_t len)
{

	/* There is no extra data really.
	 * isainfo -v does return amd64, but also i386. */
	return 0;
}

struct linkwalk {
	struct ifaddrs		*lw_ifa;
	int			lw_error;
};

static boolean_t
if_newaddr(const char *ifname, void *arg)
{
	struct linkwalk		*lw = arg;
	struct ifaddrs		*ifa;
	dlpi_handle_t		dh;
	dlpi_info_t		dlinfo;
	uint8_t			pa[DLPI_PHYSADDR_MAX];
	size_t			pa_len;
	struct sockaddr_dl	*sdl;

	ifa = NULL;
	if (dlpi_open(ifname, &dh, 0) != DLPI_SUCCESS)
		goto failed1;
	if (dlpi_info(dh, &dlinfo, 0) != DLPI_SUCCESS)
		goto failed;

	/* For some reason, dlpi_info won't return the
	 * physical address, it's all zero's.
	 * So cal dlpi_get_physaddr. */
	pa_len = DLPI_PHYSADDR_MAX;
	if (dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR,
	    pa, &pa_len) != DLPI_SUCCESS)
		goto failed;

	if ((ifa = calloc(1, sizeof(*ifa))) == NULL)
		goto failed;
	if ((ifa->ifa_name = strdup(ifname)) == NULL)
		goto failed;
	if ((sdl = calloc(1, sizeof(*sdl))) == NULL)
		goto failed;

	ifa->ifa_addr = (struct sockaddr *)sdl;
	sdl->sdl_index = if_nametoindex(ifname);
	sdl->sdl_family = AF_LINK;
	switch (dlinfo.di_mactype) {
	case DL_ETHER:
		sdl->sdl_type = IFT_ETHER;
		break;
	case DL_IB:
		sdl->sdl_type = IFT_IB;
		break;
	default:
		sdl->sdl_type = IFT_OTHER;
		break;
	}

	sdl->sdl_alen = pa_len;
	memcpy(sdl->sdl_data, pa, pa_len);

	ifa->ifa_next = lw->lw_ifa;
	lw->lw_ifa = ifa;
	dlpi_close(dh);
	return (B_FALSE);

failed:
	dlpi_close(dh);
	if (ifa != NULL) {
		free(ifa->ifa_name);
		free(ifa->ifa_addr);
		free(ifa);
	}
failed1:
	lw->lw_error = errno;
	return (B_TRUE);
}

/* Creates an empty sockaddr_dl for lo0. */
static struct ifaddrs *
if_ifa_lo0(void)
{
	struct ifaddrs		*ifa;
	struct sockaddr_dl	*sdl;

	if ((ifa = calloc(1, sizeof(*ifa))) == NULL)
		return NULL;
	if ((sdl = calloc(1, sizeof(*sdl))) == NULL) {
		free(ifa);
		return NULL;
	}
	if ((ifa->ifa_name = strdup("lo0")) == NULL) {
		free(ifa);
		free(sdl);
		return NULL;
	}

	ifa->ifa_addr = (struct sockaddr *)sdl;
	ifa->ifa_flags = IFF_LOOPBACK;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = if_nametoindex("lo0");

	return ifa;
}

/* getifaddrs(3) does not support AF_LINK, strips aliases and won't
 * report addresses that are not UP.
 * As such it's just totally useless, so we need to roll our own. */
int
if_getifaddrs(struct ifaddrs **ifap)
{
	struct linkwalk		lw;
	struct ifaddrs		*ifa;

	/* Private libc function which we should not have to call
	 * to get non UP addresses. */
	if (getallifaddrs(AF_UNSPEC, &lw.lw_ifa, 0) == -1)
		return -1;

	/* Start with some AF_LINK addresses. */
	lw.lw_error = 0;
	dlpi_walk(if_newaddr, &lw, 0);
	if (lw.lw_error != 0) {
		freeifaddrs(lw.lw_ifa);
		errno = lw.lw_error;
		return -1;
	}

	/* lo0 doesn't appear in dlpi_walk, so fudge it. */
	if ((ifa = if_ifa_lo0()) == NULL) {
		freeifaddrs(lw.lw_ifa);
		return -1;
	}
	ifa->ifa_next = lw.lw_ifa;

	*ifap = ifa;
	return 0;
}

static int
salen(const struct sockaddr *sa)
{

	switch (sa->sa_family) {
	case AF_LINK:
		return sizeof(struct sockaddr_dl);
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return sizeof(struct sockaddr);
	}
}

static void
if_linkaddr(struct sockaddr_dl *sdl, const struct interface *ifp)
{

	memset(sdl, 0, sizeof(*sdl));
	sdl->sdl_family = AF_LINK;
	sdl->sdl_nlen = sdl->sdl_alen = sdl->sdl_slen = 0;
	sdl->sdl_index = (unsigned short)ifp->index;
}

static int
get_addrs(int type, const void *data, const struct sockaddr **sa)
{
	const char *cp;
	int i;

	cp = data;
	for (i = 0; i < RTAX_MAX; i++) {
		if (type & (1 << i)) {
			sa[i] = (const struct sockaddr *)cp;
			RT_ADVANCE(cp, sa[i]);
		} else
			sa[i] = NULL;
	}
	return 0;
}

static struct interface *
if_findsdl(struct dhcpcd_ctx *ctx, const struct sockaddr_dl *sdl)
{

	if (sdl->sdl_index)
		return if_findindex(ctx->ifaces, sdl->sdl_index);

	if (sdl->sdl_nlen) {
		char ifname[IF_NAMESIZE];

		memcpy(ifname, sdl->sdl_data, sdl->sdl_nlen);
		ifname[sdl->sdl_nlen] = '\0';
		return if_find(ctx->ifaces, ifname);
	}
	if (sdl->sdl_alen) {
		struct interface *ifp;

		TAILQ_FOREACH(ifp, ctx->ifaces, next) {
			if (ifp->hwlen == sdl->sdl_alen &&
			    memcmp(ifp->hwaddr,
			    sdl->sdl_data, sdl->sdl_alen) == 0)
				return ifp;
		}
	}

	errno = ENOENT;
	return NULL;
}

static struct interface *
if_findsa(struct dhcpcd_ctx *ctx, const struct sockaddr *sa)
{
	if (sa == NULL) {
		errno = EINVAL;
		return NULL;
	}

	switch (sa->sa_family) {
	case AF_LINK:
	{
		const struct sockaddr_dl *sdl;

		sdl = (const void *)sa;
		return if_findsdl(ctx, sdl);
	}
#ifdef INET
	case AF_INET:
	{
		const struct sockaddr_in *sin;
		struct ipv4_addr *ia;

		sin = (const void *)sa;
		if ((ia = ipv4_findmaskaddr(ctx, &sin->sin_addr)))
			return ia->iface;
		break;
	}
#endif
#ifdef INET6
	case AF_INET6:
	{
		const struct sockaddr_in6 *sin;
		struct ipv6_addr *ia;

		sin = (const void *)sa;
		if ((ia = ipv6_findmaskaddr(ctx, &sin->sin6_addr)))
			return ia->iface;
		break;
	}
#endif
	default:
		errno = EAFNOSUPPORT;
		return NULL;
	}

	errno = ENOENT;
	return NULL;
}

#ifdef INET
static void
if_finishrt(struct rt *rt)
{

	/* Solaris has a subnet route with the gateway
	 * of the owning address.
	 * dhcpcd has a blank gateway here to indicate a
	 * subnet route. */
	if (rt->gate.s_addr != ntohl(INADDR_ANY) &&
	    ipv4_iffindaddr(UNCONST(rt->iface), &rt->gate, NULL))
		rt->gate.s_addr = ntohl(INADDR_ANY);

	/* Solaris likes to set route MTU to match
	 * interface MTU when adding routes.
	 * This confuses dhcpcd as it expects MTU to be 0
	 * when no explicit MTU has been set. */
	if (rt->mtu == (unsigned int)if_getmtu(rt->iface))
		rt->mtu = 0;
}

static int
if_copyrt(struct dhcpcd_ctx *ctx, struct rt *rt, const struct rt_msghdr *rtm)
{
	const struct sockaddr *sa, *rti_info[RTAX_MAX];

	sa = (const void *)(rtm + 1);
	if (sa->sa_family != AF_INET)
		return -1;
	if (~rtm->rtm_addrs & (RTA_DST | RTA_GATEWAY))
		return -1;

	get_addrs(rtm->rtm_addrs, sa, rti_info);
	memset(rt, 0, sizeof(*rt));
	rt->flags = (unsigned int)rtm->rtm_flags;
	COPYOUT(rt->dest, rti_info[RTAX_DST]);
	if (rtm->rtm_addrs & RTA_NETMASK)
		COPYOUT(rt->mask, rti_info[RTAX_NETMASK]);
	else
		rt->mask.s_addr = INADDR_BROADCAST;
	COPYOUT(rt->gate, rti_info[RTAX_GATEWAY]);
	COPYOUT(rt->src, rti_info[RTAX_SRC]);
	rt->mtu = (unsigned int)rtm->rtm_rmx.rmx_mtu;

	if (rtm->rtm_index)
		rt->iface = if_findindex(ctx->ifaces, rtm->rtm_index);
	else if (rtm->rtm_addrs & RTA_IFP)
		rt->iface = if_findsa(ctx, rti_info[RTAX_IFP]);
	else if (rtm->rtm_addrs & RTA_GATEWAY)
		rt->iface = if_findsa(ctx, rti_info[RTAX_GATEWAY]);

	/* If we don't have an interface and it's a host route, it maybe
	 * to a local ip via the loopback interface. */
	if (rt->iface == NULL &&
	    !(~rtm->rtm_flags & (RTF_HOST | RTF_GATEWAY)))
	{
		struct ipv4_addr *ia;

		if ((ia = ipv4_findaddr(ctx, &rt->dest)))
			rt->iface = ia->iface;
	}

	if (rt->iface == NULL) {
		errno = ESRCH;
		return -1;
	}

	if_finishrt(rt);

	return 0;
}
#endif

#ifdef INET6
static void
if_finishrt6(struct rt6 *rt)
{

	/* Solaris has a subnet route with the gateway
	 * of the owning address.
	 * dhcpcd has a blank gateway here to indicate a
	 * subnet route. */
	if (!IN6_IS_ADDR_UNSPECIFIED(&rt->gate) &&
	    ipv6_iffindaddr(UNCONST(rt->iface), &rt->gate, 0))
		rt->gate = in6addr_any;

	/* Solarais likes to set route MTU to match
	 * interface MTU when adding routes.
	 * This confuses dhcpcd as it expects MTU to be 0
	 * when no explicit MTU has been set. */
	if (rt->mtu == (unsigned int)if_getmtu(rt->iface))
		rt->mtu = 0;
}

static int
if_copyrt6(struct dhcpcd_ctx *ctx, struct rt6 *rt, const struct rt_msghdr *rtm)
{
	const struct sockaddr *sa, *rti_info[RTAX_MAX];

	sa = (const void *)(rtm + 1);
	if (sa->sa_family != AF_INET6)
		return -1;
	if (~rtm->rtm_addrs & (RTA_DST | RTA_GATEWAY))
		return -1;

	get_addrs(rtm->rtm_addrs, sa, rti_info);
	memset(rt, 0, sizeof(*rt));
	rt->flags = (unsigned int)rtm->rtm_flags;
	COPYOUT6(rt->dest, rti_info[RTAX_DST]);
	if (rtm->rtm_addrs & RTA_NETMASK)
		COPYOUT6(rt->mask, rti_info[RTAX_NETMASK]);
	else
		ipv6_mask(&rt->mask, 128);
	COPYOUT6(rt->gate, rti_info[RTAX_GATEWAY]);
	rt->mtu = (unsigned int)rtm->rtm_rmx.rmx_mtu;

	if (rtm->rtm_index)
		rt->iface = if_findindex(ctx->ifaces, rtm->rtm_index);
	else if (rtm->rtm_addrs & RTA_IFP)
		rt->iface = if_findsa(ctx, rti_info[RTAX_IFP]);
	else if (rtm->rtm_addrs & RTA_GATEWAY)
		rt->iface = if_findsa(ctx, rti_info[RTAX_GATEWAY]);

	/* If we don't have an interface and it's a host route, it maybe
	 * to a local ip via the loopback interface. */
	if (rt->iface == NULL &&
	    !(~rtm->rtm_flags & (RTF_HOST | RTF_GATEWAY)))
	{
		struct ipv6_addr *ia;

		if ((ia = ipv6_findaddr(ctx, &rt->dest, 0)))
			rt->iface = ia->iface;
	}

	if (rt->iface == NULL) {
		errno = ESRCH;
		return -1;
	}

	if_finishrt6(rt);

	return 0;
}
#endif

static void
if_rtm(struct dhcpcd_ctx *ctx, const struct rt_msghdr *rtm)
{
	const struct sockaddr *sa;

	/* Ignore messages generated by us */
	if (rtm->rtm_pid == getpid()) {
		ctx->options &= ~DHCPCD_RTM_PPID;
		return;
	}

	/* Ignore messages sent by the parent after forking */
	if ((ctx->options &
	    (DHCPCD_RTM_PPID | DHCPCD_DAEMONISED)) ==
	    (DHCPCD_RTM_PPID | DHCPCD_DAEMONISED) &&
	    rtm->rtm_pid == ctx->ppid)
	{
		/* If this is the last successful message sent,
		 * clear the check flag as it's possible another
		 * process could re-use the same pid and also
		 * manipulate therouting table. */
		if (rtm->rtm_seq == ctx->pseq)
			ctx->options &= ~DHCPCD_RTM_PPID;
		return;
	}

	sa = (const void *)(rtm + 1);
	switch (sa->sa_family) {
#ifdef INET
	case AF_INET:
	{
		struct rt rt;

		if (if_copyrt(ctx, &rt, rtm) == 0)
			ipv4_handlert(ctx, rtm->rtm_type, &rt, 0);
		break;
	}
#endif
#ifdef INET6
	case AF_INET6:
	{
		struct rt6 rt6;

		if (~rtm->rtm_addrs & (RTA_DST | RTA_GATEWAY))
			break;
		/*
		 * BSD announces host routes.
		 * But does this work on Solaris?
		 * As such, we should be notified of reachability by its
		 * existance with a hardware address.
		 */
		if (rtm->rtm_flags & (RTF_HOST)) {
			const struct sockaddr *rti_info[RTAX_MAX];
			struct in6_addr dst6;
			struct sockaddr_dl sdl;

			get_addrs(rtm->rtm_addrs, sa, rti_info);
			COPYOUT6(dst6, rti_info[RTAX_DST]);
			if (rti_info[RTAX_GATEWAY]->sa_family == AF_LINK)
				memcpy(&sdl, rti_info[RTAX_GATEWAY],
				    sizeof(sdl));
			else
				sdl.sdl_alen = 0;
			ipv6nd_neighbour(ctx, &dst6,
			    rtm->rtm_type != RTM_DELETE && sdl.sdl_alen ?
			    IPV6ND_REACHABLE : 0);
			break;
		}

		if (if_copyrt6(ctx, &rt6, rtm) == 0)
			ipv6_handlert(ctx, rtm->rtm_type, &rt6);
		break;
	}
#endif
	}
}

static void
if_ifa(struct dhcpcd_ctx *ctx, const struct ifa_msghdr *ifam)
{
	struct interface *ifp;
	const struct sockaddr *sa, *rti_info[RTAX_MAX];

	/* XXX We have no way of knowing who generated these
	 * messages wich truely sucks because we want to
	 * avoid listening to our own delete messages. */
	if ((ifp = if_findindex(ctx->ifaces, ifam->ifam_index)) == NULL)
		return;
	sa = (const void *)(ifam + 1);
	get_addrs(ifam->ifam_addrs, sa, rti_info);
	if (rti_info[RTAX_IFA] == NULL)
		return;
	switch (rti_info[RTAX_IFA]->sa_family) {
	case AF_LINK:
	{
		struct sockaddr_dl sdl;

		if (ifam->ifam_type != RTM_CHGADDR &&
		    ifam->ifam_type != RTM_NEWADDR)
			break;
		memcpy(&sdl, rti_info[RTAX_IFA], sizeof(sdl));
		dhcpcd_handlehwaddr(ctx, ifp->name, CLLADDR(&sdl),sdl.sdl_alen);
		break;
	}
#ifdef INET
	case AF_INET:
	{
		struct in_addr addr, mask, bcast;

		COPYOUT(addr, rti_info[RTAX_IFA]);
		COPYOUT(mask, rti_info[RTAX_NETMASK]);
		COPYOUT(bcast, rti_info[RTAX_BRD]);
		ipv4_handleifa(ctx,
		    ifam->ifam_type == RTM_CHGADDR ?
		    RTM_NEWADDR : ifam->ifam_type,
		    NULL, ifp->name, &addr, &mask, &bcast);
		break;
	}
#endif
#ifdef INET6
	case AF_INET6:
	{
		struct in6_addr addr6, mask6;
		const struct sockaddr_in6 *sin6;

		sin6 = (const void *)rti_info[RTAX_IFA];
		addr6 = sin6->sin6_addr;
		sin6 = (const void *)rti_info[RTAX_NETMASK];
		mask6 = sin6->sin6_addr;
		ipv6_handleifa(ctx,
		    ifam->ifam_type == RTM_CHGADDR ?
		    RTM_NEWADDR : ifam->ifam_type,
		    NULL, ifp->name, &addr6, ipv6_prefixlen(&mask6));
		break;
	}
#endif
	}
}

static void
if_ifinfo(struct dhcpcd_ctx *ctx, const struct if_msghdr *ifm)
{
	struct interface *ifp;
	int state;

	if ((ifp = if_findindex(ctx->ifaces, ifm->ifm_index)) == NULL)
		return;
	if (ifm->ifm_flags & IFF_OFFLINE)
		state = LINK_DOWN;
	else
		state = LINK_UP;
	dhcpcd_handlecarrier(ctx, state,
	    (unsigned int)ifm->ifm_flags, ifp->name);
}

static void
if_dispatch(struct dhcpcd_ctx *ctx, const struct rt_msghdr *rtm)
{

	switch(rtm->rtm_type) {
	case RTM_IFINFO:
		if_ifinfo(ctx, (const void *)rtm);
		break;
	case RTM_ADD:		/* FALLTHROUGH */
	case RTM_CHANGE:	/* FALLTHROUGH */
	case RTM_DELETE:
		if_rtm(ctx, (const void *)rtm);
		break;
	case RTM_CHGADDR:	/* FALLTHROUGH */
	case RTM_DELADDR:	/* FALLTHROUGH */
	case RTM_NEWADDR:
		if_ifa(ctx, (const void *)rtm);
		break;
	}
}

int
if_handlelink(struct dhcpcd_ctx *ctx)
{
	char buf[2048];
	const char *p, *e;
	size_t msglen;
	ssize_t bytes;
	const struct rt_msghdr *rtm;

	if ((bytes = read(ctx->link_fd, buf, sizeof(buf))) == -1)
		return -1;
	e = buf + bytes;
	for (p = buf; p < e; p += msglen) {
		rtm = (const  void *)p;
		msglen = rtm->rtm_msglen;
		if_dispatch(ctx, rtm);
	}
	return 0;
}

static void
if_octetstr(char *buf, const Octet_t *o, ssize_t len)
{
	int			i;
	char			*p;

	p = buf;
	for (i = 0; i < o->o_length; i++) {
		if ((p + 1) - buf < len)
			*p++ = o->o_bytes[i];
		else
			break;
	}
	*p = '\0';
}

static int
if_parsert(struct dhcpcd_ctx *ctx, unsigned int level, unsigned int name,
    int (*walkrt)(struct dhcpcd_ctx *, char *, size_t))
{
	int			s, retval, code, flags;
	uintptr_t		buf[512 / sizeof(uintptr_t)];
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;

	if ((s = open("/dev/arp", O_RDWR)) == -1)
		return -1;

	/* Assume we are erroring. */
	retval = -1;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;

	req = (struct opthdr *)&tor[1];
	req->level = EXPER_IP_AND_ALL_IRES;
	req->name = 0;
	req->len = 1;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	if (putmsg(s, &ctlbuf, NULL, 0) == 1)
		goto out;

	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof(buf);

	/* Create a reasonable buffer to start with */
	databuf.maxlen = BUFSIZ * 2;
	if ((databuf.buf = malloc(databuf.maxlen)) == NULL)
		goto out;

	for (;;) {
		flags = 0;
		if ((code = getmsg(s, &ctlbuf, 0, &flags)) == -1)
			break;
		if (code == 0 &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    (size_t)ctlbuf.len >= sizeof(struct T_optmgmt_ack))
		{
			/* End of messages, so return success! */
			retval = 0;
			break;
		}
		if (tea->PRIM_type == T_ERROR_ACK) {
			errno = tea->TLI_error == TSYSERR ?
			    tea->UNIX_error : EPROTO;
			break;
		}
		if (code != MOREDATA ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS)
		{
			errno = ENOMSG;
			break;
		}

		/* Try to ensure out buffer is big enough
		 * for future messages as well. */
		if ((size_t)databuf.maxlen < req->len) {
			size_t newlen;

			free(databuf.buf);
			newlen = roundup(req->len, BUFSIZ);
			if ((databuf.buf = malloc(newlen)) == NULL)
				break;
			databuf.maxlen = newlen;
		}

		flags = 0;
		if (getmsg(s, NULL, &databuf, &flags) == -1)
			break;

		/* We always have to get the data before moving onto
		 * the next item, so don't move this test higher up
		 * to avoid the buffer allocation and getmsg calls. */
		if (req->level == level && req->name == name) {
			if (walkrt(ctx, databuf.buf, req->len) == -1)
				break;
		}
	}

	free(databuf.buf);
out:
	close(s);
	return retval;
}

static int
if_addaddr(int fd, const char *ifname,
    struct sockaddr_storage *addr, struct sockaddr_storage *mask)
{
	struct lifreq		lifr;

	memset(&lifr, 0, sizeof(lifr));
	strlcpy(lifr.lifr_name, ifname, sizeof(lifr.lifr_name));

	/* First assign the netmask. */
	lifr.lifr_addr = *mask;
	if (ioctl(fd, SIOCSLIFNETMASK, &lifr) == -1)
		return -1;

	/* Then assign the address. */
	lifr.lifr_addr = *addr;
	if (ioctl(fd, SIOCSLIFADDR, &lifr) == -1)
		return -1;

	/* Now bring it up. */
	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1)
		return -1;
	if (!(lifr.lifr_flags & IFF_UP)) {
		lifr.lifr_flags |= IFF_UP;
		if (ioctl(fd, SIOCSLIFFLAGS, &lifr) == -1)
			return -1;
	}
	return 0;
}

static int
if_plumblif(int cmd, const struct dhcpcd_ctx *ctx, int af, const char *ifname)
{
	struct lifreq		lifr;
	int			s;

	memset(&lifr, 0, sizeof(lifr));
	strlcpy(lifr.lifr_name, ifname, sizeof(lifr.lifr_name));
	lifr.lifr_addr.ss_family = af;
	if (af == AF_INET)
		s = ctx->pf_inet_fd;
	else {
		struct priv	*priv;

		priv = (struct priv *)ctx->priv;
		s = priv->pf_inet6_fd;
	}
	return ioctl(s,
	    cmd == RTM_NEWADDR ? SIOCLIFADDIF : SIOCLIFREMOVEIF,
	    &lifr) == -1 && errno != EEXIST ? -1 : 0;
}

static int
if_plumbif(const struct dhcpcd_ctx *ctx, int af, const char *ifname)
{
	dlpi_handle_t		dh;
	int			fd, af_fd, mux_fd, retval;
	struct lifreq		lifr;
	const char		*udp_dev;

	memset(&lifr, 0, sizeof(lifr));
	switch (af) {
	case AF_INET:
		lifr.lifr_flags = IFF_IPV4;
		af_fd = ctx->pf_inet_fd;
		udp_dev = UDP_DEV_NAME;
		break;
	case AF_INET6:
	{
		struct priv *priv;

		/* We will take care of setting the link local address. */
		lifr.lifr_flags = IFF_IPV6 | IFF_NOLINKLOCAL;
		priv = (struct priv *)ctx->priv;
		af_fd = priv->pf_inet6_fd;
		udp_dev = UDP6_DEV_NAME;
		break;
	}
	default:
		errno = EPROTONOSUPPORT;
		return -1;
	}

	if (dlpi_open(ifname, &dh, DLPI_NOATTACH) != DLPI_SUCCESS) {
		errno = EINVAL;
		return -1;
	}

	fd = dlpi_fd(dh);
	retval = -1;
	mux_fd = -1;
	if (ioctl(fd, I_PUSH, IP_MOD_NAME) == -1)
		goto out;
	strlcpy(lifr.lifr_name, ifname, sizeof(lifr.lifr_name));
	if (ioctl(fd, SIOCSLIFNAME, &lifr) == -1)
		goto out;

	/* Get full flags. */
	if (ioctl(af_fd, SIOCGLIFFLAGS, &lifr) == -1)
		goto out;

	/* Open UDP as a multiplexor to PLINK the interface stream.
	 * UDP is used because STREAMS will not let you PLINK a driver
	 * under itself and IP is generally  at the bottom of the stream. */
	if ((mux_fd = open(udp_dev, O_RDWR)) == -1)
		goto out;
	/* POP off all undesired modules. */
	while (ioctl(mux_fd, I_POP, 0) != -1)
		;
	if (errno != EINVAL)
		goto out;

	if (lifr.lifr_flags & IFF_IPV4 && !(lifr.lifr_flags & IFF_NOARP)) {
		if (ioctl(mux_fd, I_PUSH, ARP_MOD_NAME) == -1)
			goto out;
	}

	/* PLINK the interface stream so it persists. */
	if (ioctl(mux_fd, I_PLINK, fd) == -1)
		goto out;

	retval = 0;

out:
	dlpi_close(dh);
	if (mux_fd != -1)
		close(mux_fd);
	return retval;
}

static int
if_unplumbif(const struct dhcpcd_ctx *ctx, int af, const char *ifname)
{
	struct sockaddr_storage addr, mask;

	/* For the time being, don't unplumb the interface, just
	 * set the address to zero. */
	memset(&addr, 0, sizeof(addr));
	addr.ss_family = af;
	memset(&mask, 0, sizeof(mask));
	mask.ss_family = af;
	return if_addaddr(ctx->pf_inet_fd, ifname , &addr, &mask);
}

static int
if_plumb(int cmd, const struct dhcpcd_ctx *ctx, int af, const char *ifname)
{
	struct if_spec		spec;

	if (if_nametospec(ifname, &spec) == -1)
		return -1;
	if (spec.lun != -1)
		return if_plumblif(cmd, ctx, af, ifname);
	if (cmd == RTM_NEWADDR)
		return if_plumbif(ctx, af, ifname);
	else
		return if_unplumbif(ctx, af, ifname);
}

static int
if_rtmsg(unsigned char cmd, const struct interface *ifp,
    int addrs, int flags,
    const struct sockaddr *dst, const struct sockaddr *mask,
    const struct sockaddr *gate, const struct sockaddr *src,
    uint32_t mtu)
{
	struct rtm
	{
		struct rt_msghdr hdr;
		char buffer[sizeof(struct sockaddr_storage) * RTAX_MAX];
	} rtm;
	char *bp = rtm.buffer;
	size_t l;

	/* WARNING: Solaris will not allow you to delete RTF_KERNEL routes.
	 * This includes subnet/prefix routes. */

	if ((cmd == RTM_ADD || cmd == RTM_DELETE || cmd == RTM_CHANGE) &&
	    ifp->ctx->options & DHCPCD_DAEMONISE &&
	    !(ifp->ctx->options & DHCPCD_DAEMONISED))
		ifp->ctx->options |= DHCPCD_RTM_PPID;

#define ADDSA(sa) {							      \
		l = RT_ROUNDUP(salen((sa)));				      \
		memcpy(bp, (sa), l);					      \
		bp += l;						      \
	}

	memset(&rtm, 0, sizeof(rtm));
	rtm.hdr.rtm_version = RTM_VERSION;
	rtm.hdr.rtm_type = cmd;
	rtm.hdr.rtm_seq = ++ifp->ctx->seq;
	rtm.hdr.rtm_flags = flags;
	rtm.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | addrs;

	if (cmd == RTM_ADD || cmd == RTM_CHANGE) {
		rtm.hdr.rtm_flags |= RTF_UP;
		if (!(rtm.hdr.rtm_flags & RTF_REJECT) ||
		    !(rtm.hdr.rtm_flags & RTF_GATEWAY))
			rtm.hdr.rtm_addrs |= RTA_IFP;
		if (mtu != 0) {
			rtm.hdr.rtm_inits |= RTV_MTU;
			rtm.hdr.rtm_rmx.rmx_mtu = mtu;
		}
	}

	ADDSA(dst);
	ADDSA(gate);
	if (rtm.hdr.rtm_addrs & RTA_NETMASK)
		ADDSA(mask);

	if (rtm.hdr.rtm_addrs & RTA_IFP) {
		struct sockaddr_dl sdl;

		if_linkaddr(&sdl, ifp);
		ADDSA((struct sockaddr *)&sdl);
	}

/* This no workie :/ */
#if 0
	/* route(1M) says RTA_IFA is accepted but ignored
	 * it's unclear how RTA_SRC is different. */
	if (rtm.hdr.rtm_addrs & RTA_IFA) {
		rtm.hdr.rtm_addrs &= ~RTA_IFA;
		rtm.hdr.rtm_addrs |= RTA_SRC;
	}
	if (rtm.hdr.rtm_addrs & RTA_SRC)
		ADDSA(src);
#endif

#undef ADDSA

	rtm.hdr.rtm_msglen = (unsigned short)(bp - (char *)&rtm);
	if (write(ifp->ctx->link_fd, &rtm, rtm.hdr.rtm_msglen) == -1)
		return -1;
	ifp->ctx->sseq = ifp->ctx->seq;
	return 0;
}

static int
if_addrflags0(int fd, const char *ifname)
{
	struct lifreq		lifr;

	memset(&lifr, 0, sizeof(lifr));
	strlcpy(lifr.lifr_name, ifname, sizeof(lifr.lifr_name));
	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1)
		return -1;

	return lifr.lifr_flags;
}

#ifdef INET
const char *if_pfname = "DLPI";

static struct dl_if *
if_findraw(struct interface *ifp, int fd)
{
	struct dl_if		*di;
	struct priv		*priv;

	priv = (struct priv *)ifp->ctx->priv;
	TAILQ_FOREACH(di, &priv->dl_ifs, next) {
		if (di->fd == fd)
			return di;
	}
	errno = ENXIO;
	return NULL;
}

void
if_closeraw(struct interface *ifp, int fd)
{
	struct dl_if		*di;

	if ((di = if_findraw(ifp, fd)) != NULL) {
		struct priv	*priv;

		priv = (struct priv *)ifp->ctx->priv;
		TAILQ_REMOVE(&priv->dl_ifs, di, next);
		dlpi_close(di->dh);
		free(di);
	}
}

int
if_openraw(struct interface *ifp, uint16_t protocol)
{
	dlpi_handle_t		dh;
	struct priv		*priv;
	struct dl_if		*di;
	dlpi_info_t		dlinfo;
	struct packetfilt	pf;
	ushort_t		*pfp;
	struct strioctl		sioc;

	if (dlpi_open(ifp->name, &dh, 0) != DLPI_SUCCESS)
		return -1;

	/* We need to register pfmod, which is similar to BPF
	 * so the kernel can filter out the packets we don't need. */
	if (dlpi_info(dh, &dlinfo, 0) != DLPI_SUCCESS ||
	    dlpi_bind(dh, protocol, NULL) != DLPI_SUCCESS ||
	    (di = malloc(sizeof(*di))) == NULL)
		goto failed1;

	di->iface	= ifp;
	di->dh		= dh;
	di->fd		= dlpi_fd(dh);
	memcpy(di->broadcast, dlinfo.di_bcastaddr, dlinfo.di_bcastaddrlen);
	priv = (struct priv *)ifp->ctx->priv;

	pf.Pf_Priority = 0;
	pfp = pf.Pf_Filter;
	/* pfmod operates on 16 bits, so divide offsets by 2.
	 * When working on a 8 bits, mask off the bits not teested. */
	switch (protocol) {
	case ETHERTYPE_IP:
		/* Filter fragments. */
		*pfp++ = ENF_PUSHWORD + (offsetof(struct ip, ip_off) / 2);
		*pfp++ = ENF_PUSHLIT | ENF_AND;
		*pfp++ = htons(0x1fff | IP_MF);
		*pfp++ = ENF_PUSHZERO | ENF_CAND;

		/* Filter UDP. */
		*pfp++ = ENF_PUSHWORD + (offsetof(struct ip, ip_p) / 2);
		*pfp++ = ENF_PUSHFF00 | ENF_AND;
		*pfp++ = ENF_PUSHLIT | ENF_CAND;
		*pfp++ = htons(IPPROTO_UDP);

		/* Filter BOOTPC. */
		*pfp++ = ENF_PUSHWORD +
		    ((sizeof(struct ip) +
		    offsetof(struct udphdr, uh_dport)) / 2);
		*pfp++ = ENF_PUSHLIT | ENF_CAND;
		*pfp++ = htons(BOOTPC);
		break;

	case ETHERTYPE_ARP:
		/* We are only interested in IP. */
		*pfp++ = ENF_PUSHWORD + (offsetof(struct arphdr, ar_hrd) / 2);
		*pfp++ = ENF_PUSHLIT | ENF_CAND;
		*pfp++ = htons(ARPHRD_ETHER);

		/* Must be REQUEST or REPLY. */
		*pfp++ = ENF_PUSHWORD + (offsetof(struct arphdr, ar_op) / 2);
		*pfp++ = ENF_PUSHLIT | ENF_CNAND;
		*pfp++ = htons(ARPOP_REQUEST);
		*pfp++ = ENF_PUSHWORD + (offsetof(struct arphdr, ar_op) / 2);
		*pfp++ = ENF_PUSHLIT | ENF_CAND;
		*pfp++ = htons(ARPOP_REPLY);
		break;

	default:
		errno = EPROTOTYPE;
		goto failed;
	}
	pf.Pf_FilterLen = pfp - pf.Pf_Filter;

	sioc.ic_cmd	= PFIOCSETF;
	sioc.ic_timout	= INFTIM;
	sioc.ic_len	= sizeof(pf);
	sioc.ic_dp	= (void *)&pf;

	/* Install the filter and then flush the stream. */
	if (ioctl(di->fd, I_PUSH, "pfmod") == -1 ||
	    ioctl(di->fd, I_STR, &sioc) == -1 ||
	    ioctl(di->fd, I_FLUSH, FLUSHR) == -1)
		goto failed;

	TAILQ_INSERT_TAIL(&priv->dl_ifs, di, next);
	return di->fd;

failed:
	free(di);
failed1:
	dlpi_close(dh);
	return -1;
}

ssize_t
if_sendraw(const struct interface *cifp, int fd, __unused uint16_t protocol,
    const void *data, size_t len)
{
	struct dl_if		*di;
	int			r;
	struct interface	*ifp = UNCONST(cifp);

	if ((di = if_findraw(ifp, fd)) == NULL)
		return -1;
	r = dlpi_send(di->dh, di->broadcast, ifp->hwlen, data, len, NULL);
	return r == DLPI_SUCCESS ? (ssize_t)len : -1;
}

ssize_t
if_readraw(struct interface *ifp, int fd,
    void *data, size_t len, int *flags)
{
	struct dl_if		*di;
	int			r;
	size_t			mlen;

	if ((di = if_findraw(ifp, fd)) == NULL)
		return -1;
	*flags = RAW_EOF; /* We only ever read one packet. */
	mlen = len;
	*flags = RAW_EOF; /* We only ever read one packet. */
	r = dlpi_recv(di->dh, NULL, NULL, data, &mlen, -1, NULL);
	return r == DLPI_SUCCESS ? (ssize_t)mlen : -1;
}

int
if_address(unsigned char cmd, const struct ipv4_addr *ia)
{
	struct sockaddr_storage	ss_addr, ss_mask;
	struct sockaddr_in	*sin_addr, *sin_mask;

	/* Either remove the alias or ensure it exists. */
	if (if_plumb(cmd, ia->iface->ctx, AF_INET, ia->alias) == -1)
		return -1;

	if (cmd == RTM_DELADDR)
		return 0;

	if (cmd != RTM_NEWADDR) {
		errno = EINVAL;
		return -1;
	}

	sin_addr = (struct sockaddr_in *)&ss_addr;
	sin_addr->sin_family = AF_INET;
	sin_addr->sin_addr = ia->addr;
	sin_mask = (struct sockaddr_in *)&ss_mask;
	sin_mask->sin_family = AF_INET;
	sin_mask->sin_addr = ia->mask;
	return if_addaddr(ia->iface->ctx->pf_inet_fd,
	    ia->alias, &ss_addr, &ss_mask);
}

int
if_addrflags(const struct ipv4_addr *ia)
{
	int		flags, aflags;

	aflags = if_addrflags0(ia->iface->ctx->pf_inet_fd, ia->alias);
	if (aflags == -1)
		return -1;
	flags = 0;
	if (aflags & IFF_DUPLICATE)
		flags |= IN_IFF_DUPLICATED;
	return flags;
}

int
if_route(unsigned char cmd, const struct rt *rt)
{
	struct sockaddr_in	dst = {
		.sin_family = AF_INET,
		.sin_addr = rt->dest
	};
	struct sockaddr_in	mask = {
		.sin_family = AF_INET,
		.sin_addr = rt->mask
	};
	struct sockaddr_in	gate = {
		.sin_family = AF_INET,
		.sin_addr = rt->gate
	};
	struct sockaddr_in	src = {
		.sin_family = AF_INET,
		.sin_addr = rt->src
	};
	struct sockaddr_in	*g;
	int			addrs, flags;

	addrs = 0;
	flags = 0;

	if (cmd == RTM_ADD || cmd == RTM_CHANGE) {
		addrs |= RTA_GATEWAY | RTA_IFP;
		/* Subnet routes are cloning or connected if supported.
		 * All other routes are static. */
		if (rt->gate.s_addr != ntohl(INADDR_ANY))
			flags |= RTF_STATIC;
		if (rt->src.s_addr != ntohl(INADDR_ANY))
			addrs |= RTA_IFA;
	}

	if (rt->mask.s_addr == htonl(INADDR_BROADCAST) &&
	    rt->gate.s_addr == htonl(INADDR_ANY))
	{
		flags |= RTF_HOST;
	} else if (rt->gate.s_addr == htonl(INADDR_LOOPBACK) &&
	    rt->mask.s_addr == htonl(INADDR_BROADCAST))
	{
		flags |= RTF_HOST | RTF_GATEWAY;
		/* Going via lo0 so remove the interface flags */
		addrs &= ~(RTA_IFA | RTA_IFP);
	} else {
		addrs |= RTA_NETMASK;
		if (flags & RTF_STATIC)
			flags |= RTF_GATEWAY;
		if (rt->mask.s_addr == htonl(INADDR_BROADCAST))
			flags |= RTF_HOST;
	}

	if ((flags & RTF_HOST && rt->gate.s_addr == htonl(INADDR_ANY)) ||
	    !(flags & RTF_STATIC))
		g = &src;
	else
		g = &gate;
	return if_rtmsg(cmd, rt->iface, addrs, flags,
	    (struct sockaddr *)&dst, (struct sockaddr *)&mask,
	    (struct sockaddr *)g, (struct sockaddr *)&src, rt->mtu);
}

static int
if_walkrt(struct dhcpcd_ctx *ctx, char *data, size_t len)
{
	mib2_ipRouteEntry_t *re, *e;
	struct rt rt;
	char ifname[IF_NAMESIZE];

	if (len % sizeof(*re) != 0) {
		errno = EINVAL;
		return -1;
	}

	re = (mib2_ipRouteEntry_t *)data;
	e = (mib2_ipRouteEntry_t *)(data + len);
	do {
		/* Skip route types we don't want. */
		switch (re->ipRouteInfo.re_ire_type) {
		case IRE_IF_CLONE:
		case IRE_BROADCAST:
		case IRE_MULTICAST:
		case IRE_NOROUTE:
		case IRE_LOCAL:
			continue;
		default:
			break;
		}
		memset(&rt, 0, sizeof(rt));
		rt.dest.s_addr = re->ipRouteDest;
		rt.mask.s_addr = re->ipRouteMask;
		rt.gate.s_addr = re->ipRouteNextHop;
		rt.flags = re->ipRouteInfo.re_flags;
		rt.src.s_addr = re->ipRouteInfo.re_src_addr;
		rt.mtu = re->ipRouteInfo.re_max_frag;

		if_octetstr(ifname, &re->ipRouteIfIndex, sizeof(ifname));
		rt.iface = if_find(ctx->ifaces, ifname);
		if (rt.iface != NULL) {
			if_finishrt(&rt);
			ipv4_handlert(ctx, RTM_ADD, &rt, 1);
		} else {
			char		destbuf[INET6_ADDRSTRLEN];
			char		gatebuf[INET6_ADDRSTRLEN];
			const char	*dest, *gate;

			dest = inet_ntop(AF_INET, &rt.dest,
			    destbuf, INET6_ADDRSTRLEN);
			gate = inet_ntop(AF_INET, &rt.gate,
			    gatebuf, INET6_ADDRSTRLEN);
			logger(ctx, LOG_ERR,
			    "no iface (%s) for route to %s via %s",
			    ifname, dest, gate);
		}
	} while (++re < e);
	return 0;
}

int
if_initrt(struct dhcpcd_ctx *ctx)
{

	ipv4_freerts(ctx->ipv4_kroutes);
	return if_parsert(ctx, MIB2_IP,MIB2_IP_ROUTE, if_walkrt);
}
#endif

#ifdef INET6
int
if_address6(unsigned char cmd, const struct ipv6_addr *ia)
{
	struct sockaddr_storage	ss_addr, ss_mask;
	struct sockaddr_in6	*sin6_addr, *sin6_mask;
	struct priv		*priv;
	int			r;

	/* Either remove the alias or ensure it exists. */
	if (if_plumb(cmd, ia->iface->ctx, AF_INET6, ia->alias) == -1)
		return -1;

	if (cmd == RTM_DELADDR)
		return 0;

	if (cmd != RTM_NEWADDR) {
		errno = EINVAL;
		return -1;
	}

	priv = (struct priv *)ia->iface->ctx->priv;
	sin6_addr = (struct sockaddr_in6 *)&ss_addr;
	sin6_addr->sin6_family = AF_INET6;
	sin6_addr->sin6_addr = ia->addr;
	sin6_mask = (struct sockaddr_in6 *)&ss_mask;
	sin6_mask->sin6_family = AF_INET6;
	ipv6_mask(&sin6_mask->sin6_addr, ia->prefix_len);
	r = if_addaddr(priv->pf_inet6_fd,
	    ia->alias, &ss_addr, &ss_mask);
	if (r == -1 && errno == EEXIST)
		return 0;
	return r;
}

int
if_addrflags6(const struct ipv6_addr *ia)
{
	struct priv		*priv;
	int			aflags, flags;

	priv = (struct priv *)ia->iface->ctx->priv;
	aflags = if_addrflags0(priv->pf_inet6_fd, ia->alias);
	flags = 0;
	if (aflags & IFF_DUPLICATE)
		flags |= IN6_IFF_DUPLICATED;
	return flags;
}

int
if_getlifetime6(struct ipv6_addr *addr)
{

	UNUSED(addr);
	errno = ENOTSUP;
	return -1;
}

int
if_route6(unsigned char cmd, const struct rt6 *rt)
{
	struct sockaddr_in6	dst = {
		.sin6_family = AF_INET6,
		.sin6_addr = rt->dest
	};
	struct sockaddr_in6	mask = {
		.sin6_family = AF_INET6,
		.sin6_addr = rt->mask
	};
	struct sockaddr_in6	gate = {
		.sin6_family = AF_INET6,
		.sin6_addr = rt->gate
	};
	struct sockaddr_in6	src = {
		.sin6_family = AF_INET6,
		.sin6_addr = rt->src
	};
	struct sockaddr_in6	*g;
	int			addrs, flags;

	addrs = RTA_NETMASK;
	flags = 0;

	if (IN6_IS_ADDR_UNSPECIFIED(&rt->gate)) {
		/* XXX FIXME: How to tell kernel route is subnet? */
	} else
		flags |= RTF_GATEWAY | RTF_STATIC;

	if (IN6_IS_ADDR_UNSPECIFIED(&rt->gate))
		g = &src;
	else
		g = &gate;

	return if_rtmsg(cmd, rt->iface, addrs, flags,
	    (struct sockaddr *)&dst, (struct sockaddr *)&mask,
	    (struct sockaddr *)g, (struct sockaddr *)&src, rt->mtu);
}

static int
if_walkrt6(struct dhcpcd_ctx *ctx, char *data, size_t len)
{
	mib2_ipv6RouteEntry_t *re, *e;
	struct rt6 rt;
	char ifname[IF_NAMESIZE];

	if (len % sizeof(*re) != 0) {
		errno = EINVAL;
		return -1;
	}

	re = (mib2_ipv6RouteEntry_t *)data;
	e = (mib2_ipv6RouteEntry_t *)(data + len);

	do {
		/* Skip route types we don't want. */
		switch (re->ipv6RouteInfo.re_ire_type) {
		case IRE_IF_CLONE:
		case IRE_BROADCAST:
		case IRE_MULTICAST:
		case IRE_NOROUTE:
		case IRE_LOCAL:
			continue;
		default:
			break;
		}
		memset(&rt, 0, sizeof(rt));
		rt.dest = re->ipv6RouteDest;
		ipv6_mask(&rt.mask, re->ipv6RoutePfxLength);
		rt.gate = re->ipv6RouteNextHop;
		rt.mtu = re->ipv6RouteInfo.re_max_frag;

		if_octetstr(ifname, &re->ipv6RouteIfIndex, sizeof(ifname));
		rt.iface = if_find(ctx->ifaces, ifname);
		if (rt.iface != NULL) {
			if_finishrt6(&rt);
			ipv6_handlert(ctx, RTM_ADD, &rt);
		} else {
			char destbuf[INET6_ADDRSTRLEN];
			char gatebuf[INET6_ADDRSTRLEN];
			const char *dest, *gate;

			dest = inet_ntop(AF_INET6, &rt.dest,
			    destbuf, INET6_ADDRSTRLEN);
			gate = inet_ntop(AF_INET6, &rt.gate,
			    gatebuf, INET6_ADDRSTRLEN);
			logger(ctx, LOG_ERR,
			    "no iface (%s) for route to %s via %s",
			    ifname, dest, gate);
		}
	} while (++re < e);
	return 0;
}

int
if_initrt6(struct dhcpcd_ctx *ctx)
{

	ipv6_freerts(&ctx->ipv6->kroutes);
	return if_parsert(ctx, MIB2_IP6, MIB2_IP6_ROUTE, if_walkrt6);
}

int
if_checkipv6(__unused struct dhcpcd_ctx *ctx,
    __unused const struct interface *ifp, int __unused own)
{

	return 0;
}
#endif
