/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2016 Roy Marples <roy@marples.name>
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
#include <sys/tihdr.h>
#include <sys/utsname.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libdlpi.h>
#include <stdlib.h>
#include <stropts.h>
#include <string.h>
#include <unistd.h>

#include <inet/ip.h>

#include <net/if_dl.h>
#include <net/if_types.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "if.h"
#include "if-options.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipv6nd.h"

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

	ctx->link_fd = socket(PF_ROUTE,
	    SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	return ctx->link_fd == -1 ? -1 : 0;
}

void
if_closesockets_os(struct dhcpcd_ctx *ctx)
{

	UNUSED(ctx);
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
if_managelink(struct dhcpcd_ctx *ctx)
{

	UNUSED(ctx);
	errno = ENOTSUP;
	return -1;
}

int
if_machinearch(char *str, size_t len)
{

	UNUSED(str);
	UNUSED(len);
	errno = ENOTSUP;
	return -1;
}

struct linkwalk {
	struct ifaddrs	*lw_ifa;
	int		lw_error;
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
	struct ifaddrs *ifa;
	struct sockaddr_dl *sdl;

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

	return ifa;
}

/* all getifaddrs(3) should support AF_LINK, but hey ho */
int
if_getifaddrs(struct ifaddrs **ifap)
{
	struct linkwalk		lw;

	/* lo0 doesn't appear in dlpi_walk, so fudge it. */
	if ((lw.lw_ifa = if_ifa_lo0()) == NULL)
		return -1;

	lw.lw_error = 0;
	dlpi_walk(if_newaddr, &lw, 0);
	if (lw.lw_error != 0) {
		freeifaddrs(lw.lw_ifa);
		errno = lw.lw_error;
		return -1;
	}

	*ifap = lw.lw_ifa;
	return 0;
}

static void
if_octetstr(char *buf, const Octet_t *o, ssize_t len)
{
	int i;
	char *p;

	p = buf;
	for (i = 0; i < o->o_length; i++) {
		if ((p + 1) - buf < len)
			*p++ = o->o_bytes[i];
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

#ifdef INET
const char *if_pfname = "SunOS";

void
if_closeraw(int fd)
{

	UNUSED(fd);
}

int
if_openraw(struct interface *ifp, uint16_t protocol)
{

	UNUSED(ifp);
	UNUSED(protocol);
	errno = ENOTSUP;
	return -1;
}

ssize_t
if_sendraw(const struct interface *ifp, int fd, uint16_t protocol,
    const void *data, size_t len)
{

	UNUSED(ifp);
	UNUSED(fd);
	UNUSED(protocol);
	UNUSED(data);
	UNUSED(len);
	errno = ENOTSUP;
	return -1;
}

ssize_t
if_readraw(struct interface *ifp, int fd,
    void *data, size_t len, int *flags)
{

	UNUSED(ifp);
	UNUSED(fd);
	UNUSED(data);
	UNUSED(len);
	UNUSED(flags);
	errno = ENOTSUP;
	return -1;
}

int
if_address(const struct interface *ifp, const struct in_addr *addr,
    const struct in_addr *net, const struct in_addr *bcast,
    int action)
{

	UNUSED(ifp);
	UNUSED(addr);
	UNUSED(net);
	UNUSED(bcast);
	UNUSED(action);
	errno = ENOTSUP;
	return -1;
}

int
if_addrflags(const struct in_addr *addr, const struct interface *ifp)
{

	UNUSED(addr);
	UNUSED(ifp);
	errno = ENOTSUP;
	return -1;
}

int
if_route(unsigned char cmd, const struct rt *rt)
{

	UNUSED(cmd);
	UNUSED(rt);
	errno = ENOTSUP;
	return -1;
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
		rt.net.s_addr = re->ipRouteMask;
		rt.gate.s_addr = re->ipRouteNextHop;
		rt.flags = re->ipRouteInfo.re_flags;
		rt.src.s_addr = re->ipRouteInfo.re_src_addr;
		rt.mtu = re->ipRouteInfo.re_max_frag;

		if_octetstr(ifname, &re->ipRouteIfIndex, sizeof(ifname));
		rt.iface = if_find(ctx->ifaces, ifname);
		if (rt.iface != NULL)
			ipv4_handlert(ctx, RTM_ADD, &rt, 1);
		else {
			char destbuf[INET6_ADDRSTRLEN];
			char gatebuf[INET6_ADDRSTRLEN];
			const char *dest, *gate;

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
if_address6(const struct ipv6_addr *addr, int action)
{

	UNUSED(addr);
	UNUSED(action);
	errno = ENOTSUP;
	return -1;
}

int
if_addrflags6(const struct in6_addr *addr, const struct interface *ifp)
{

	UNUSED(addr);
	UNUSED(ifp);
	errno = ENOTSUP;
	return -1;
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

	UNUSED(cmd);
	UNUSED(rt);
	errno = ENOTSUP;
	return -1;
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
		ipv6_mask(&rt.net, re->ipv6RoutePfxLength);
		rt.gate = re->ipv6RouteNextHop;
		rt.mtu = re->ipv6RouteInfo.re_max_frag;

		if_octetstr(ifname, &re->ipv6RouteIfIndex, sizeof(ifname));
		rt.iface = if_find(ctx->ifaces, ifname);
		if (rt.iface != NULL)
			ipv6_handlert(ctx, RTM_ADD, &rt);
		else {
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
