/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2014 Roy Marples <roy@marples.name>
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

#define ELOOP_QUEUE 2
#include "config.h"
#include "arp.h"
#include "common.h"
#include "dhcp.h"
#include "eloop.h"
#include "if.h"
#include "if-options.h"
#include "ipv4ll.h"

static struct dhcp_message *
ipv4ll_make_lease(uint32_t addr)
{
	uint32_t u32;
	struct dhcp_message *dhcp;
	uint8_t *p;

	dhcp = calloc(1, sizeof(*dhcp));
	if (dhcp == NULL)
		return NULL;
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
ipv4ll_find_lease(const struct interface *ifp)
{
	uint32_t addr;
	struct interface *ifp2;
	const struct dhcp_state *state;

	for (;;) {
		/* RFC 3927 Section 2.1 states that the first 256 and
		 * last 256 addresses are reserved for future use.
		 * See ipv4ll_start for why we don't use arc4_random. */
		addr = ntohl(LINKLOCAL_ADDR | ((random() % 0xFD00) + 0x0100));

		state = D_CSTATE(ifp);
		/* No point using a failed address */
		if (addr == state->fail.s_addr)
			continue;

		/* Ensure we don't have the address on another interface */
		TAILQ_FOREACH(ifp2, ifp->ctx->ifaces, next) {
			state = D_CSTATE(ifp2);
			if (state && state->addr.s_addr == addr)
				break;
		}

		/* Yay, this should be a unique and workable IPv4LL address */
		if (ifp2 == NULL)
			break;
	}
	return ipv4ll_make_lease(addr);
}

void
ipv4ll_claimed(void *arg)
{
	struct interface *ifp = arg;
	struct dhcp_state *state = D_STATE(ifp);

	state->conflicts = 0;
}

void
ipv4ll_start(void *arg)
{
	struct interface *ifp = arg;
	struct dhcp_state *state = D_STATE(ifp);
	uint32_t addr;

	/* RFC 3927 Section 2.1 states that the random number generator
	 * SHOULD be seeded with a value derived from persistent information
	 * such as the IEEE 802 MAC address so that it usually picks
	 * the same address without persistent storage. */
	if (state->conflicts == 0) {
		unsigned int seed;

		if (sizeof(seed) > ifp->hwlen) {
			seed = 0;
			memcpy(&seed, ifp->hwaddr, ifp->hwlen);
		} else
			memcpy(&seed, ifp->hwaddr + ifp->hwlen - sizeof(seed),
			    sizeof(seed));
		initstate(seed, state->randomstate, sizeof(state->randomstate));
	}

	eloop_timeout_delete(ifp->ctx->eloop, NULL, ifp);
	state->probes = 0;
	state->claims = 0;
	if (state->addr.s_addr) {
		if (IN_LINKLOCAL(htonl(state->addr.s_addr))) {
			arp_announce(ifp);
			return;
		}
	}

	if (state->offer == NULL)
		addr = 0;
	else {
		addr = state->offer->yiaddr;
		free(state->offer);
	}

	state->state = DHS_INIT_IPV4LL;
	setstate(state->randomstate);
	/* We maybe rebooting an IPv4LL address. */
	if (!IN_LINKLOCAL(htonl(addr))) {
		syslog(LOG_INFO, "%s: probing for an IPv4LL address",
		    ifp->name);
		addr = 0;
	}
	if (addr == 0)
		state->offer = ipv4ll_find_lease(ifp);
	else
		state->offer = ipv4ll_make_lease(addr);
	if (state->offer == NULL) {
		syslog(LOG_ERR, "%s: %m", __func__);
		return;
	}
	state->lease.frominfo = 0;
	arp_probe(ifp);
}

void
ipv4ll_handle_failure(void *arg)
{
	struct interface *ifp = arg;
	struct dhcp_state *state = D_STATE(ifp);
	time_t up;

	if (state->fail.s_addr == state->addr.s_addr) {
		/* RFC 3927 Section 2.5 */
		up = uptime();
		if (state->defend + DEFEND_INTERVAL > up) {
			syslog(LOG_WARNING,
			    "%s: IPv4LL %d second defence failed for %s",
			    ifp->name, DEFEND_INTERVAL, inet_ntoa(state->addr));
			dhcp_drop(ifp, "EXPIRE");
		} else {
			syslog(LOG_DEBUG, "%s: defended IPv4LL address %s",
			    ifp->name, inet_ntoa(state->addr));
			state->defend = up;
			return;
		}
	}

	free(state->offer);
	state->offer = NULL;
	eloop_timeout_delete(ifp->ctx->eloop, NULL, ifp);
	if (++state->conflicts >= MAX_CONFLICTS) {
		syslog(LOG_ERR, "%s: failed to acquire an IPv4LL address",
		    ifp->name);
		if (ifp->options->options & DHCPCD_DHCP) {
			state->interval = RATE_LIMIT_INTERVAL / 2;
			dhcp_discover(ifp);
		} else
			eloop_timeout_add_sec(ifp->ctx->eloop,
			    RATE_LIMIT_INTERVAL, ipv4ll_start, ifp);
	} else {
		eloop_timeout_add_sec(ifp->ctx->eloop,
		    PROBE_WAIT, ipv4ll_start, ifp);
	}
}
