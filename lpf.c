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
# define BPF_SKIPTYPE
# define BPF_ETHCOOK		-ETH_HLEN
# define BPF_WHOLEPACKET	0x0fffffff /* work around buggy LPF filters */
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

/* Broadcast address for IPoIB */
static const uint8_t ipv4_bcast_addr[] = {
	0x00, 0xff, 0xff, 0xff,
	0xff, 0x12, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

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
	int *fd;

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
#ifdef ENABLE_ARP
	if (protocol == ETHERTYPE_ARP) {
		pf.filter = UNCONST(arp_bpf_filter);
		pf.len = arp_bpf_filter_len;
	} else
#endif
	{
		pf.filter = UNCONST(dhcp_bpf_filter);
		pf.len = dhcp_bpf_filter_len;
	}
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;
	if (set_cloexec(s) == -1)
		goto eexit;
	if (set_nonblock(s) == -1)
		goto eexit;
	if (bind(s, &su.sa, sizeof(su)) == -1)
		goto eexit;
#ifdef ENABLE_ARP
	if (protocol == ETHERTYPE_ARP)
		fd = &iface->arp_fd;
	else
#endif
		fd = &iface->fd;
	if (*fd != -1)
		close(*fd);
	*fd = s;
	return s;

eexit:
	close(s);
	return -1;
}

ssize_t
send_raw_packet(const struct interface *iface, int protocol,
		const void *data, ssize_t len)
{
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	int fd;

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = AF_PACKET;
	su.sll.sll_protocol = htons(protocol);
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
#ifdef ENABLE_ARP
	if (protocol == ETHERTYPE_ARP)
		fd = iface->arp_fd;
	else
#endif
		fd = iface->fd;

	return sendto(fd, data, len, 0, &su.sa, sizeof(su));
}

ssize_t
get_raw_packet(struct interface *iface, int protocol, void *data, ssize_t len)
{
	ssize_t bytes;
	int fd = -1;

	if (protocol == ETHERTYPE_ARP) {
#ifdef ENABLE_ARP
		fd = iface->arp_fd;
#endif
	} else
		fd = iface->fd;
	bytes = read(fd, data, len);
	if (bytes == -1)
		return errno == EAGAIN ? 0 : -1;
	return bytes;
}
