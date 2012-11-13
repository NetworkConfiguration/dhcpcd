/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2012 Roy Marples <roy@marples.name>
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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "arp.h"
#include "common.h"
#include "dhcpcd.h"
#include "eloop.h"
#include "if-options.h"
#include "ipv4ll.h"
#include "net.h"

static struct dhcp_message *
ipv4ll_make_lease(uint32_t addr)
{
	uint32_t u32;
	struct dhcp_message *dhcp;
	uint8_t *p;

	dhcp = xzalloc(sizeof(*dhcp));
	/* Put some LL options in */
	dhcp->yiaddr = addr;
	p = dhcp->options;
	*p++ = DHO_SUBNETMASK;
	*p++ = sizeof(u32);
	u32 = htonl(LINKLOCAL_MASK);
	memcpy(p, &u32, sizeof(u32));
	p += sizeof(u32);
	*p++ = DHO_BROADCAST;
	*p++ = sizeof(u32);
	u32 = htonl(LINKLOCAL_BRDC);
	memcpy(p, &u32, sizeof(u32));
	p += sizeof(u32);
	*p++ = DHO_END;

	return dhcp;
}

static struct dhcp_message *
ipv4ll_find_lease(uint32_t old_addr)
{
	uint32_t addr;

	for (;;) {
		addr = htonl(LINKLOCAL_ADDR |
		    (((uint32_t)abs((int)arc4random())
			% 0xFD00) + 0x0100));
		if (addr != old_addr &&
		    IN_LINKLOCAL(ntohl(addr)))
			break;
	}
	return ipv4ll_make_lease(addr);
}

void
ipv4ll_start(void *arg)
{
	struct interface *ifp = arg;
	uint32_t addr;

	eloop_timeout_delete(NULL, ifp);
	ifp->state->probes = 0;
	ifp->state->claims = 0;
	if (ifp->addr.s_addr) {
		ifp->state->conflicts = 0;
		if (IN_LINKLOCAL(htonl(ifp->addr.s_addr))) {
			send_arp_announce(ifp);
			return;
		}
	}

	if (ifp->state->offer == NULL)
		addr = 0;
	else {
		addr = ifp->state->offer->yiaddr;
		free(ifp->state->offer);
	}
	/* We maybe rebooting an IPv4LL address. */
	if (!IN_LINKLOCAL(htonl(addr))) {
		syslog(LOG_INFO, "%s: probing for an IPv4LL address",
		    ifp->name);
		addr = 0;
	}
	if (addr == 0)
		ifp->state->offer = ipv4ll_find_lease(addr);
	else
		ifp->state->offer = ipv4ll_make_lease(addr);
	ifp->state->lease.frominfo = 0;
	send_arp_probe(ifp);
}

void
ipv4ll_handle_failure(void *arg)
{
	struct interface *ifp = arg;
	time_t up;

	if (ifp->state->fail.s_addr == ifp->addr.s_addr) {
		up = uptime();
		if (ifp->state->defend + DEFEND_INTERVAL > up) {
			syslog(LOG_DEBUG,
			    "%s: IPv4LL %d second defence failed",
			    ifp->name, DEFEND_INTERVAL);
			drop_dhcp(ifp, "EXPIRE");
			ifp->state->conflicts = -1;
		} else {
			syslog(LOG_DEBUG, "%s: defended IPv4LL address",
			    ifp->name);
			ifp->state->defend = up;
			return;
		}
	}

	close_sockets(ifp);
	free(ifp->state->offer);
	ifp->state->offer = NULL;
	eloop_timeout_delete(NULL, ifp);
	if (++ifp->state->conflicts > MAX_CONFLICTS) {
		syslog(LOG_ERR, "%s: failed to acquire an IPv4LL address",
		    ifp->name);
		ifp->state->interval = RATE_LIMIT_INTERVAL / 2;
		start_discover(ifp);
	} else {
		eloop_timeout_add_sec(PROBE_WAIT, ipv4ll_start, ifp);
	}
}
