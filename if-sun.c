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

#include <sys/utsname.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

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

	errno = ENOTSUP;
	return -1;
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

if_machinearch(char *str, size_t len)
{

	errno = ENOTSUP;
	return -1;
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
