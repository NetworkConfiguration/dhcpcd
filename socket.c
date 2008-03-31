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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
# include <asm/types.h> /* needed for 2.4 kernels for the below header */
# include <linux/filter.h>
# include <netpacket/packet.h>
# define bpf_insn sock_filter
#endif

#include "config.h"
#include "dhcp.h"
#include "if.h"
#include "socket.h"
#include "bpf-filter.h"

/* A suitably large buffer for all transactions.
 * BPF buffer size is set by the kernel, so no define. */
#ifdef __linux__
# define BUFFER_LENGTH 4096
#endif

/* Broadcast address for IPoIB */
static const uint8_t ipv4_bcast_addr[] = {
	0x00, 0xff, 0xff, 0xff,
	0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};


void
setup_packet_filters(void)
{
	/* We need to massage the filters for Linux cooked packets */
	dhcp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
	dhcp_bpf_filter[2].k -= ETH_HLEN;
	dhcp_bpf_filter[4].k -= ETH_HLEN;
	dhcp_bpf_filter[6].k -= ETH_HLEN;
	dhcp_bpf_filter[7].k -= ETH_HLEN;

	arp_bpf_filter[1].jf = 0; /* skip the IP packet type check */
	arp_bpf_filter[2].k -= ETH_HLEN;
}

static int open_listen_socket(struct interface *iface)
{
	int fd;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_in sin;
	} su;
	struct ifreq ifr;
	int n = 1;

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return -1;

	memset(&su, 0, sizeof(su));
	su.sin.sin_family = AF_INET;
	su.sin.sin_port = htons(DHCP_CLIENT_PORT);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n)) == -1)
		goto eexit;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == -1)
		goto eexit;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
		goto eexit;
	if (bind(fd, &su.sa, sizeof(su)) == -1)
		goto eexit;

	iface->listen_fd = fd;
	close_on_exec(fd);
	return 0;

eexit:
	close(fd);
	return -1;
}

int
open_socket(struct interface *iface, int protocol)
{
	int fd;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	struct sock_fprog pf;

	/* We need to bind to a port, otherwise Linux generate ICMP messages
	 * that cannot contect the port when we have an address.
	 * We don't actually use this fd at all, instead using our packet
	 * filter socket. */
	if (iface->listen_fd == -1 && protocol == ETHERTYPE_IP)
		if (open_listen_socket(iface) == -1)
			return -1;

	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(protocol))) == -1)
		return -1;
	
	close_on_exec(fd);
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
		pf.len = sizeof(arp_bpf_filter) / sizeof(arp_bpf_filter[0]);
	} else {
		pf.filter = dhcp_bpf_filter;
		pf.len = sizeof(dhcp_bpf_filter) / sizeof(dhcp_bpf_filter[0]);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;

	if (bind(fd, &su.sa, sizeof(su)) == -1)
		goto eexit;

	if (iface->fd > -1)
		close(iface->fd);
	iface->fd = fd;
	iface->socket_protocol = protocol;
	iface->buffer_length = BUFFER_LENGTH;

	return fd;

eexit:
	close(fd);
	return -1;
}

ssize_t
send_packet(const struct interface *iface, int type,
	    const unsigned char *data, ssize_t len)
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

	return sendto(iface->fd, data, len,0,&su.sa,sizeof(su));
}

/* Linux has no need for the buffer as we can read as much as we want.
 * We only have the buffer listed to keep the same API. */
ssize_t
get_packet(const struct interface *iface, unsigned char *data,
	   unsigned char *buffer, ssize_t *buffer_len, ssize_t *buffer_pos)
{
	ssize_t bytes;
	union
	{
		unsigned char *buffer;
		struct udp_dhcp_packet *packet;
	} pay;
	struct timespec ts;

	/* We don't use the given buffer, but we need to rewind the position */
	*buffer_pos = 0;

	memset(buffer, 0, iface->buffer_length);
	bytes = read(iface->fd, buffer, iface->buffer_length);

	if (bytes == -1) {
		ts.tv_sec = 3;
		ts.tv_nsec = 0;
		nanosleep(&ts, NULL);
		return -1;
	}

	*buffer_len = bytes;
	/* If it's an ARP reply, then just send it back */
	if (iface->socket_protocol == ETHERTYPE_ARP) {
		memcpy(data, buffer, bytes);
		return bytes;
	}

	if ((unsigned)bytes < (sizeof(pay.packet->ip) +sizeof(pay.packet->udp)))
	{
		errno = EBADMSG;
		return -1;
	}

	pay.buffer = buffer;
	if (bytes < ntohs(pay.packet->ip.ip_len)) {
		errno = EBADMSG;
		return -1;
	}

	if (valid_dhcp_packet(buffer) == -1)
		return -1;

	bytes = ntohs(pay.packet->ip.ip_len) -
		(sizeof(pay.packet->ip) + sizeof(pay.packet->udp));
	memcpy(data, &pay.packet->dhcp, bytes);
	return bytes;
}
