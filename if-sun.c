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
#include <sys/utsname.h>

#include <errno.h>
#include <ifaddrs.h>
#include <libdlpi.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

	return 0;
}

void
if_closesockets_os(struct dhcpcd_ctx *ctx)
{

}

int
if_getssid(struct interface *ifp)
{

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

	errno = ENOTSUP;
	return -1;
}

int
if_machinearch(char *str, size_t len)
{

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
	unsigned int		pa_len;
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
	if ((ifa->ifa_addr = calloc(1, sizeof(struct sockaddr_dl))) == NULL)
		goto failed;

	if ((ifa->ifa_name = strdup(ifname)) == NULL)
		goto failed;

	sdl = (struct sockaddr_dl *)ifa->ifa_addr;

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

/* all getifaddrs(3) should support AF_LINK, but hey ho */
int
if_getifaddrs(struct ifaddrs **ifap)
{
	struct linkwalk	lw = { NULL, 0 };
	int error;

	error = 0;
	dlpi_walk(if_newaddr, &lw, 0);
	if (lw.lw_error != 0) {
		freeifaddrs(lw.lw_ifa);
		errno = lw.lw_error;
		return -1;
	}

	*ifap = lw.lw_ifa;
	return 0;
}

#ifdef INET
const char *if_pfname = "SunOS";

int
if_openrawsocket(struct interface *ifp, uint16_t protocol)
{

	errno = ENOTSUP;
	return -1;
}

ssize_t
if_sendrawpacket(const struct interface *ifp, uint16_t protocol,
    const void *data, size_t len)
{

	errno = ENOTSUP;
	return -1;
}

ssize_t
if_readrawpacket(struct interface *ifp, uint16_t protocol,
    void *data, size_t len, int *flags)
{

	errno = ENOTSUP;
	return -1;
}

int
if_address(const struct interface *iface, const struct in_addr *addr,
    const struct in_addr *net, const struct in_addr *bcast,
    int action)
{

	errno = ENOTSUP;
	return -1;
}

int
if_addrflags(const struct in_addr *addr, const struct interface *ifp)
{

	errno = ENOTSUP;
	return -1;
}

int
if_route(unsigned char cmd, const struct rt *rt)
{

	errno = ENOTSUP;
	return -1;
}

int
if_initrt(struct interface *ifp)
{

	errno = ENOTSUP;
	return -1;
}
#endif

#ifdef INET6
int
if_address6(const struct ipv6_addr *a, int action)
{

	errno = ENOTSUP;
	return -1;
}

int
if_addrflags6(const struct in6_addr *addr, const struct interface *ifp)
{

	errno = ENOTSUP;
	return -1;
}

int
if_getlifetime6(struct ipv6_addr *addr)
{

	errno = ENOTSUP;
	return -1;
}

int
if_route6(unsigned char cmd, const struct rt6 *rt)
{

	errno = ENOTSUP;
	return -1;
}

int
if_initrt6(struct interface *ifp)
{

	errno = ENOTSUP;
	return -1;
}

int
if_checkipv6(struct dhcpcd_ctx *ctx, const struct interface *ifp, int own)
{

	errno = ENOTSUP;
	return -1;
}
#endif
