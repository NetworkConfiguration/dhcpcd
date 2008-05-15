/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
 *
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
# include <asm/types.h> /* needed for 2.4 kernels for the below header */
# include <linux/filter.h>
# include <netpacket/packet.h>
# define bpf_insn sock_filter
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "net.h"
#include "bpf-filter.h"

/* A suitably large buffer for all transactions. */
#define BUFFER_LENGTH 4096

/* Broadcast address for IPoIB */
static const uint8_t ipv4_bcast_addr[] = {
	0x00, 0xff, 0xff, 0xff,
	0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

void
setup_packet_filters(void)
{
#ifdef __linux__
	/* We need to massage the filters for Linux cooked packets */
	dhcp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
	dhcp_bpf_filter[2].k -= ETH_HLEN;
	dhcp_bpf_filter[4].k -= ETH_HLEN;
	dhcp_bpf_filter[6].k -= ETH_HLEN;
	dhcp_bpf_filter[7].k -= ETH_HLEN;

	arp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
	arp_bpf_filter[2].k -= ETH_HLEN;

	/* Some buggy Linux kernels do not work with ~0U.
	 * 65536 should be enough for anyone ;) */
	dhcp_bpf_filter[9].k = 65536;
	arp_bpf_filter[5].k = 65536;
#endif
}

int
open_socket(struct interface *iface, int protocol)
{
	int s;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	struct sock_fprog pf;

	if ((s = socket(PF_PACKET, SOCK_DGRAM, htons(protocol))) == -1)
		return -1;

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = PF_PACKET;
	su.sll.sll_protocol = htons(protocol);
	if (!(su.sll.sll_ifindex = if_nametoindex(iface->name))) {
		errno = ENOENT;
		goto eexit;
	}

	/* Install the DHCP filter */
	memset(&pf, 0, sizeof(pf));
	if (protocol == ETHERTYPE_ARP) {
		pf.filter = arp_bpf_filter;
		pf.len = arp_bpf_filter_len;
	} else {
		pf.filter = dhcp_bpf_filter;
		pf.len = dhcp_bpf_filter_len;
	}
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;

	if (bind(s, &su.sa, sizeof(su)) == -1)
		goto eexit;
	if (close_on_exec(s) == -1)
		goto eexit;
	if (iface->fd > -1)
		close(iface->fd);
	iface->fd = s;
	iface->socket_protocol = protocol;
	if (iface->buffer == NULL) {
		iface->buffer_size = BUFFER_LENGTH;
		iface->buffer = xmalloc(iface->buffer_size);
		iface->buffer_len = iface->buffer_pos = 0;
	}
	return s;

eexit:
	close(s);
	return -1;
}

ssize_t
send_raw_packet(const struct interface *iface, int type,
		const void *data, ssize_t len)
{
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = AF_PACKET;
	su.sll.sll_protocol = htons(type);
	if (!(su.sll.sll_ifindex = if_nametoindex(iface->name))) {
		errno = ENOENT;
		return -1;
	}
	su.sll.sll_hatype = htons(iface->family);
	su.sll.sll_halen = iface->hwlen;
	if (iface->family == ARPHRD_INFINIBAND)
		memcpy(&su.sll.sll_addr,
		       &ipv4_bcast_addr, sizeof(ipv4_bcast_addr));
	else
		memset(&su.sll.sll_addr, 0xff, iface->hwlen);

	return sendto(iface->fd, data, len, 0, &su.sa, sizeof(su));
}

ssize_t
get_packet(struct interface *iface, void *data, ssize_t len)
{
	ssize_t bytes;
	const uint8_t *p;

	if (iface->buffer_pos > iface->buffer_len) {
		iface->buffer_len = iface->buffer_pos = 0;
		return 0;
	}

	bytes = read(iface->fd, iface->buffer, iface->buffer_size);

	if (bytes == -1)
		return errno == EAGAIN ? 0 : -1;

	/* So our loops to us work correctly */
	iface->buffer_len = bytes;
	iface->buffer_pos = iface->buffer_len + 1;

	/* If it's an ARP reply, then just send it back */
	if (iface->socket_protocol == ETHERTYPE_ARP)
		return bytes;

	if (valid_udp_packet(iface->buffer) != 0)
		return -1;

	bytes = get_udp_data(&p, iface->buffer);
	if (bytes > len)
		bytes = len;
	memcpy(data, p, bytes);
	return bytes;
}
