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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "arp.h"
#include "bind.h"
#include "common.h"
#include "dhcpcd.h"
#include "eloop.h"
#include "if-options.h"
#include "ipv4ll.h"
#include "logger.h"
#include "net.h"

static void
handle_arp_failure(struct interface *iface)
{
	if (IN_LINKLOCAL(htonl(iface->state->fail.s_addr))) {
		handle_ipv4ll_failure(iface);
		return;
	}
	send_decline(iface);
	close_sockets(iface);
	add_timeout_sec(DHCP_ARP_FAIL, start_interface, iface);
}

static void
handle_arp_packet(void *arg)
{
	struct interface *iface = arg;
	struct arphdr reply;
	uint32_t reply_s;
	uint32_t reply_t;
	uint8_t arp_reply[sizeof(reply) + 2 * sizeof(reply_s) + 2 * HWADDR_LEN];
	uint8_t *hw_s, *hw_t;
	ssize_t bytes;
	struct if_state *state = iface->state;

	state->fail.s_addr = 0;
	for(;;) {
		bytes = get_raw_packet(iface, ETHERTYPE_ARP,
				       arp_reply, sizeof(arp_reply));
		if (bytes == 0 || bytes == -1)
			return;
		/* We must have a full ARP header */
		if ((size_t)bytes < sizeof(reply))
			continue;
		memcpy(&reply, arp_reply, sizeof(reply));
		/* Protocol must be IP. */
		if (reply.ar_pro != htons(ETHERTYPE_IP))
			continue;
		if (reply.ar_pln != sizeof(reply_s))
			continue;
		/* Only these types are recognised */
		if (reply.ar_op != htons(ARPOP_REPLY) &&
		    reply.ar_op != htons(ARPOP_REQUEST))
			continue;

		/* Get pointers to the hardware addreses */
		hw_s = arp_reply + sizeof(reply);
		hw_t = hw_s + reply.ar_hln + reply.ar_pln;
		/* Ensure we got all the data */
		if ((hw_t + reply.ar_hln + reply.ar_pln) - arp_reply > bytes)
			continue;
		/* Ignore messages from ourself */
		if (reply.ar_hln == iface->hwlen &&
		    memcmp(hw_s, iface->hwaddr, iface->hwlen) == 0)
			continue;
		/* Copy out the IP addresses */
		memcpy(&reply_s, hw_s + reply.ar_hln, reply.ar_pln);
		memcpy(&reply_t, hw_t + reply.ar_hln, reply.ar_pln);

		/* Check for conflict */
		if (state->offer && 
		    (reply_s == state->offer->yiaddr ||
		     (reply_s == 0 && reply_t == state->offer->yiaddr)))
			state->fail.s_addr = state->offer->yiaddr;

		/* Handle IPv4LL conflicts */
		if (IN_LINKLOCAL(htonl(iface->addr.s_addr)) &&
		    (reply_s == iface->addr.s_addr ||
		     (reply_s == 0 && reply_t == iface->addr.s_addr)))
			state->fail.s_addr = iface->addr.s_addr;

		if (state->fail.s_addr) {
			logger(LOG_ERR, "%s: hardware address %s claims %s",
			       iface->name,
			       hwaddr_ntoa((unsigned char *)hw_s,
					   (size_t)reply.ar_hln),
			       inet_ntoa(state->fail));
			errno = EEXIST;
			handle_arp_failure(iface);
			return;
		}
	}
}

void
send_arp_announce(void *arg)
{
	struct interface *iface = arg;
	struct if_state *state = iface->state;
	struct timeval tv;

	if (iface->arp_fd == -1) {
		open_socket(iface, ETHERTYPE_ARP);
		add_event(iface->arp_fd, handle_arp_packet, iface);
	}
	if (++state->claims < ANNOUNCE_NUM)	
		logger(LOG_DEBUG,
		       "%s: sending ARP announce (%d of %d), "
		       "next in %d.00 seconds",
		       iface->name, state->claims, ANNOUNCE_NUM, ANNOUNCE_WAIT);
	else
		logger(LOG_DEBUG,
		       "%s: sending ARP announce (%d of %d)",
		       iface->name, state->claims, ANNOUNCE_NUM);
	if (send_arp(iface, ARPOP_REQUEST,
		     state->new->yiaddr, state->new->yiaddr) == -1)
		logger(LOG_ERR, "send_arp: %s", strerror(errno));
	if (state->claims < ANNOUNCE_NUM) {
		add_timeout_sec(ANNOUNCE_WAIT, send_arp_announce, iface);
		return;
	}
	if (IN_LINKLOCAL(htonl(state->new->yiaddr))) {
		/* We should pretend to be at the end
		 * of the DHCP negotation cycle */
		state->interval = 64;
		state->probes = 0;
		state->claims = 0;
		tv.tv_sec = state->interval - DHCP_RAND_MIN;
		tv.tv_usec = arc4random() % (DHCP_RAND_MAX_U - DHCP_RAND_MIN_U);
		tv.tv_sec = 3; /* test easier */
		timernorm(&tv);
		add_timeout_tv(&tv, start_discover, iface);
	} else {
		delete_event(iface->arp_fd);
		close(iface->arp_fd);
		iface->arp_fd = -1;
	}
}

void
send_arp_probe(void *arg)
{
	struct interface *iface = arg;
	struct if_state *state = iface->state;
	struct in_addr addr;
	struct timeval tv;

	if (iface->arp_fd == -1) {
		open_socket(iface, ETHERTYPE_ARP);
		add_event(iface->arp_fd, handle_arp_packet, iface);
	}
	if (state->probes == 0) {
		addr.s_addr = state->offer->yiaddr;
		logger(LOG_INFO, "%s: checking %s is available"
				" on attached networks",
				iface->name, inet_ntoa(addr));
	}
	if (++state->probes < PROBE_NUM) {
		tv.tv_sec = PROBE_MIN;
		tv.tv_usec = arc4random() % (PROBE_MAX_U - PROBE_MIN_U);
		timernorm(&tv);
		add_timeout_tv(&tv, send_arp_probe, iface);
	} else {
		tv.tv_sec = ANNOUNCE_WAIT;
		tv.tv_usec = 0;
		if (IN_LINKLOCAL(htonl(state->offer->yiaddr)))
			add_timeout_tv(&tv, bind_interface, iface);
		else
			add_timeout_tv(&tv, send_request, iface);
	}
	logger(LOG_DEBUG,
		"%s: sending ARP probe (%d of %d), next in %0.2f seconds",
		iface->name, state->probes, PROBE_NUM,  timeval_to_double(&tv));
	if (send_arp(iface, ARPOP_REQUEST, 0, state->offer->yiaddr) == -1)
		logger(LOG_ERR, "send_arp: %s", strerror(errno));
}
