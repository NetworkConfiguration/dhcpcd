/*
 * Hurd interface driver for dhcpcd
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Roy Marples <roy@marples.name>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* We use a hook script to configure pfinet */

#include <sys/ioctl.h>

#include <errno.h>
#include <string.h>

#include "dhcpcd.h"
#include "if.h"
#include "logerr.h"

int
os_init(void)
{
	return 0;
}

int
if_machinearch(__unused char *str, __unused size_t len)
{
	/* nothing more beyond uname by the looks of it. */
	return 0;
}

int
if_opensockets_os(__unused struct dhcpcd_ctx *ctx)
{
#warning OS has no mechanism of reporting interface, address or route changes
	/* Hurd does not have any mechanism like route(4) yet */
	ctx->link_fd = -1;
	return 0;
}

void
if_closesockets_os(__unused struct dhcpcd_ctx *ctx)
{
	/* Nothing to do, as link_fd is not initialized */
}

int
if_init(struct interface *ifp)
{
	struct ifreq ifr;
	int s = ifp->ctx->pf_inet_fd;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifp->name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
		logerr("%s: SIOCGIFINDEX", ifp->name);
		return -1;
	}
	ifp->index = (unsigned int)ifr.ifr_ifindex;

	if (ifp->flags & IFF_LOOPBACK)
		return 0;

	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
		logerr("%s: SIOCGIFHWADDR", ifp->name);
		return -1;
	}
	ifp->hwtype = ifr.ifr_hwaddr.sa_family; /* family abuse */
	ifp->hwlen = ifr.ifr_hwaddr.sa_len;
	if (ifp->hwlen == 0)
		ifp->hwlen = IFHWADDRLEN; /* pfinet bug */
	memcpy(ifp->hwaddr, ifr.ifr_hwaddr.sa_data, ifp->hwlen);

	return 0;
}
int
if_init_os(__unused struct interface *ifp)
{
	return 0;
}

int
if_handlelink(__unused struct dhcpcd_ctx *ctx)
{
	errno = ENOSYS;
	return -1;
}

int
if_setmac(__unused struct interface *ifp, __unused void *mac,
    __unused uint8_t maclen)
{
	errno = EOPNOTSUPP;
	return -1;
}

unsigned short
if_vlanid(__unused const struct interface *ifp)
{
	return 0;
}

int
if_carrier(__unused struct interface *ifp, __unused const void *ifadata)
{
	/* No link fd so carrier change reporting is pointless */
	return LINK_UNKNOWN;
}

bool
if_ignore(__unused struct dhcpcd_ctx *ctx, __unused const char *ifname)
{
	return false;
}

int
if_vimaster(__unused struct dhcpcd_ctx *ctx, __unused const char *ifname)
{
	errno = EOPNOTSUPP;
	return -1;
}

int
if_getssid(__unused struct interface *ifp)
{
	errno = EOPNOTSUPP;
	return -1;
}

bool
if_roaming(__unused struct interface *ifp)
{
	return false;
}

int
if_conf(__unused struct interface *ifp)
{
	return 0;
}

int
if_initrt(__unused struct dhcpcd_ctx *ctx, __unused rb_tree_t *routes,
    __unused int af)
{
	return 0;
}

int
if_route(__unused unsigned char cmd, __unused const struct rt *rt)
{
	return 0;
}

#ifdef INET
/* PFINET hook script will configure the address */
int
if_address(__unused unsigned char cmd, __unused const struct ipv4_addr *ia)
{
	return 0;
}

int
if_addrflags(__unused const struct interface *ifp,
    __unused const struct in_addr *addr, __unused const char *alias)
{
	return 0;
}
#endif

#ifdef INET6
/* PFINET hook script will configure the address */
int
if_address6(__unused unsigned char cmd, __unused const struct ipv6_addr *ia)
{
	return 0;
}

int
if_getlifetime6(__unused struct ipv6_addr *addr)
{
	return 0;
}

int
if_addrflags6(__unused const struct interface *ifp,
    __unused const struct in6_addr *addr, __unused const char *alias)
{
	return 0;
}

void
if_setup_inet6(__unused const struct interface *ifp)
{
}

int
if_applyra(__unused const struct ra *rap)
{
	errno = ENOSYS;
	return -1;
}
#endif
