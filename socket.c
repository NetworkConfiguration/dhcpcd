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
#define __FAVOR_BSD /* Nasty hack so we can use BSD semantics for UDP */
#include <netinet/udp.h>
#undef __FAVOR_BSD
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(BSD) || defined(__FreeBSD_kernel__)
# include <net/bpf.h>
#elif __linux__
# include <asm/types.h> /* needed for 2.4 kernels for the below header */
# include <linux/filter.h>
# include <netpacket/packet.h>
# define bpf_insn sock_filter
#endif

#include "config.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"
#include "socket.h"

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

/* Credit where credit is due :)
 * The below BPF filter is taken from ISC DHCP */
static struct bpf_insn dhcp_bpf_filter [] = {
	/* Make sure this is an IP packet... */
	BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

	/* Make sure it's a UDP packet... */
	BPF_STMT (BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

	/* Make sure this isn't a fragment... */
	BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP (BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

	/* Get the IP header length... */
	BPF_STMT (BPF_LDX + BPF_B + BPF_MSH, 14),

	/* Make sure it's to the right port... */
	BPF_STMT (BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, DHCP_CLIENT_PORT, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT (BPF_RET + BPF_K, ~0U),

	/* Otherwise, drop it. */
	BPF_STMT (BPF_RET + BPF_K, 0),
};

static struct bpf_insn arp_bpf_filter [] = {
	/* Make sure this is an ARP packet... */
	BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 3),

	/* Make sure this is an ARP REPLY... */
	BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT (BPF_RET + BPF_K, ~0U),

	/* Otherwise, drop it. */
	BPF_STMT (BPF_RET + BPF_K, 0),
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
#endif
}

static uint16_t
checksum(unsigned char *addr, uint16_t len)
{
	uint32_t sum = 0;
	union
	{
		unsigned char *addr;
		uint16_t *i;
	} p;
	uint16_t nleft = len;
	uint8_t a = 0;

	p.addr = addr;
	while (nleft > 1) {
		sum += *p.i++;
		nleft -= 2;
	}

	if (nleft == 1) {
		memcpy(&a, p.i, 1);
		sum += ntohs(a) << 8;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

void
make_dhcp_packet(struct udp_dhcp_packet *packet,
		 const unsigned char *data, size_t length,
		 struct in_addr source, struct in_addr dest)
{
	struct ip *ip = &packet->ip;
	struct udphdr *udp = &packet->udp;

	/* OK, this is important :)
	 * We copy the data to our packet and then create a small part of the
	 * ip structure and an invalid ip_len (basically udp length).
	 * We then fill the udp structure and put the checksum
	 * of the whole packet into the udp checksum.
	 * Finally we complete the ip structure and ip checksum.
	 * If we don't do the ordering like so then the udp checksum will be
	 * broken, so find another way of doing it! */

	memcpy(&packet->dhcp, data, length);

	ip->ip_p = IPPROTO_UDP;
	ip->ip_src.s_addr = source.s_addr;
	if (dest.s_addr == 0)
		ip->ip_dst.s_addr = INADDR_BROADCAST;
	else
		ip->ip_dst.s_addr = dest.s_addr;

	udp->uh_sport = htons(DHCP_CLIENT_PORT);
	udp->uh_dport = htons(DHCP_SERVER_PORT);
	udp->uh_ulen = htons(sizeof(*udp) + length);
	ip->ip_len = udp->uh_ulen;
	udp->uh_sum = checksum((unsigned char *)packet, sizeof(*packet));

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = htons (sizeof(*ip) + sizeof(*udp) + length);
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF); /* Don't fragment */
	ip->ip_ttl = IPDEFTTL;

	ip->ip_sum = checksum((unsigned char *)ip, sizeof(*ip));
}

static int
valid_dhcp_packet(unsigned char *data)
{
	union
	{
		unsigned char *data;
		struct udp_dhcp_packet *packet;
	} d;
	uint16_t bytes;
	uint16_t ipsum;
	uint16_t iplen;
	uint16_t udpsum;
	struct in_addr source;
	struct in_addr dest;
	int retval = 0;

	d.data = data;
	bytes = ntohs(d.packet->ip.ip_len);
	ipsum = d.packet->ip.ip_sum;
	iplen = d.packet->ip.ip_len;
	udpsum = d.packet->udp.uh_sum;

	d.data = data;
	d.packet->ip.ip_sum = 0;
	if (ipsum != checksum((unsigned char *)&d.packet->ip,
			      sizeof(d.packet->ip)))
	{
		logger(LOG_DEBUG, "bad IP header checksum, ignoring");
		retval = -1;
		goto eexit;
	}

	memcpy(&source, &d.packet->ip.ip_src, sizeof(d.packet->ip.ip_src));
	memcpy(&dest, &d.packet->ip.ip_dst, sizeof(d.packet->ip.ip_dst));
	memset(&d.packet->ip, 0, sizeof(d.packet->ip));
	d.packet->udp.uh_sum = 0;

	d.packet->ip.ip_p = IPPROTO_UDP;
	memcpy(&d.packet->ip.ip_src, &source, sizeof(d.packet->ip.ip_src));
	memcpy(&d.packet->ip.ip_dst, &dest, sizeof(d.packet->ip.ip_dst));
	d.packet->ip.ip_len = d.packet->udp.uh_ulen;
	if (udpsum && udpsum != checksum(d.data, bytes)) {
		logger(LOG_ERR, "bad UDP checksum, ignoring");
		retval = -1;
	}

eexit:
	d.packet->ip.ip_sum = ipsum;
	d.packet->ip.ip_len = iplen;
	d.packet->udp.uh_sum = udpsum;

	return retval;
}

#if defined(BSD) || defined(__FreeBSD_kernel__)
int
open_socket(struct interface *iface, int protocol)
{
	int n = 0;
	int fd = -1;
	char *device;
	int flags;
	struct ifreq ifr;
	int buf = 0;
	struct bpf_program pf;

	device = xmalloc(sizeof(char) * PATH_MAX);
	do {
		snprintf(device, PATH_MAX, "/dev/bpf%d",  n++);
		fd = open(device, O_RDWR);
	} while (fd == -1 && errno == EBUSY);
	free(device);

	if (fd == -1) {
		logger(LOG_ERR, "unable to open a BPF device");
		return -1;
	}

	close_on_exec(fd);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
		logger(LOG_ERR,
		       "cannot attach interface `%s' to bpf device `%s': %s",
		       iface->name, device, strerror(errno));
		close(fd);
		return -1;
	}

	/* Get the required BPF buffer length from the kernel. */
	if (ioctl(fd, BIOCGBLEN, &buf) == -1) {
		logger (LOG_ERR, "ioctl BIOCGBLEN: %s", strerror(errno));
		close(fd);
		return -1;
	}
	iface->buffer_length = buf;

	flags = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &flags) == -1) {
		logger(LOG_ERR, "ioctl BIOCIMMEDIATE: %s", strerror(errno));
		close(fd);
		return -1;
	}

	/* Install the DHCP filter */
	if (protocol == ETHERTYPE_ARP) {
		pf.bf_insns = arp_bpf_filter;
		pf.bf_len = sizeof(arp_bpf_filter) / sizeof(arp_bpf_filter[0]);
	} else {
		pf.bf_insns = dhcp_bpf_filter;
		pf.bf_len = sizeof(dhcp_bpf_filter)/sizeof(dhcp_bpf_filter[0]);
	}
	if (ioctl(fd, BIOCSETF, &pf) == -1) {
		logger(LOG_ERR, "ioctl BIOCSETF: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (iface->fd > -1)
		close(iface->fd);
	iface->fd = fd;

	return fd;
}

ssize_t
send_packet(const struct interface *iface, int type,
	    const unsigned char *data, size_t len)
{
	ssize_t retval = -1;
	struct iovec iov[2];
	struct ether_header hw;

	if (iface->family == ARPHRD_ETHER) {
		memset(&hw, 0, sizeof(hw));
		memset(&hw.ether_dhost, 0xff, ETHER_ADDR_LEN);
		hw.ether_type = htons(type);

		iov[0].iov_base = &hw;
		iov[0].iov_len = sizeof(hw);
	} else {
		logger(LOG_ERR, "unsupported interace type %d", iface->family);
		return -1;
	}
	iov[1].iov_base = (unsigned char *)data;
	iov[1].iov_len = len;

	if ((retval = writev(iface->fd, iov, 2)) == -1)
		logger(LOG_ERR, "writev: %s", strerror(errno));

	return retval;
}

/* BPF requires that we read the entire buffer.
 * So we pass the buffer in the API so we can loop on >1 dhcp packet. */
ssize_t
get_packet(const struct interface *iface, unsigned char *data,
	   unsigned char *buffer, size_t *buffer_len, size_t *buffer_pos)
{
	union
	{
		unsigned char *buffer;
		struct bpf_hdr *packet;
	} bpf;
	union
	{
		unsigned char *buffer;
		struct ether_header *hw;
	} hdr;
	union
	{
		unsigned char *buffer;
		struct udp_dhcp_packet *packet;
	} pay;
	struct timespec ts;
	size_t len;
	unsigned char *payload;
	bool have_data;

	bpf.buffer = buffer;

	if (*buffer_pos < 1) {
		memset(bpf.buffer, 0, iface->buffer_length);
		*buffer_len = read(iface->fd, bpf.buffer, iface->buffer_length);
		*buffer_pos = 0;
		if (*buffer_len < 1) {
			logger(LOG_ERR, "read: %s", strerror(errno));
			ts.tv_sec = 3;
			ts.tv_nsec = 0;
			nanosleep(&ts, NULL);
			return -1;
		}
	} else
		bpf.buffer += *buffer_pos;

	while (bpf.packet) {
		len = 0;
		have_data = false;

		/* Ensure that the entire packet is in our buffer */
		if (*buffer_pos +
		    bpf.packet->bh_hdrlen +
		    bpf.packet->bh_caplen > (unsigned)*buffer_len)
			break;

		hdr.buffer = bpf.buffer + bpf.packet->bh_hdrlen;
		payload = hdr.buffer + sizeof(*hdr.hw);

		/* If it's an ARP reply, then just send it back */
		if (hdr.hw->ether_type == htons (ETHERTYPE_ARP)) {
			len = bpf.packet->bh_caplen - sizeof(*hdr.hw);
			memcpy(data, payload, len);
			have_data = true;
		} else {
			if (valid_dhcp_packet(payload) >= 0) {
				pay.buffer = payload;
				len = ntohs(pay.packet->ip.ip_len) -
					sizeof(pay.packet->ip) -
					sizeof(pay.packet->udp);
				memcpy(data, &pay.packet->dhcp, len);
				have_data = true;
			}
		}

		/* Update the buffer_pos pointer */
		bpf.buffer += BPF_WORDALIGN(bpf.packet->bh_hdrlen +
					    bpf.packet->bh_caplen);
		if ((unsigned)(bpf.buffer - buffer) < *buffer_len)
			*buffer_pos = bpf.buffer - buffer;
		else
			*buffer_pos = 0;

		if (have_data)
			return len;

		if (*buffer_pos == 0)
			break;
	}

	/* No valid packets left, so return */
	*buffer_pos = 0;
	return -1;
}

#elif __linux__

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
	struct ifreq ifr;
	int n = 1;

	/* We need to bind to a port, otherwise Linux generate ICMP messages
	 * that cannot contect the port when we have an address.
	 * We don't actually use this fd at all, instead using our packet
	 * filter socket. */
	if (iface->listen_fd == -1 && protocol == ETHERTYPE_IP) {
		if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
			logger(LOG_ERR, "socket: %s", strerror(errno));
		} else {
			memset(&su, 0, sizeof(su));
			su.sin.sin_family = AF_INET;
			su.sin.sin_port = htons(DHCP_CLIENT_PORT);
			if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				       &n, sizeof(n)) == -1)
				logger(LOG_ERR, "SO_REUSEADDR: %s",
				       strerror(errno));
			if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
				       &n, sizeof(n)) == -1)
				logger(LOG_ERR, "SO_RCVBUF: %s",
				       strerror(errno));
			memset (&ifr, 0, sizeof(ifr));
			strncpy (ifr.ifr_name, iface->name,
				 sizeof(ifr.ifr_name));
			if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				       &ifr, sizeof(ifr)) == -1)
				logger(LOG_ERR, "SO_SOBINDTODEVICE: %s",
				       strerror(errno));
			if (bind(fd, &su.sa, sizeof(su)) == -1) {
				logger(LOG_ERR, "bind: %s", strerror(errno));
				close(fd);
			} else {
				iface->listen_fd = fd;
				close_on_exec(fd);
			}
		}
	}

	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(protocol))) == -1) {
		logger(LOG_ERR, "socket: %s", strerror(errno));
		return -1;
	}
	close_on_exec(fd);

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = PF_PACKET;
	su.sll.sll_protocol = htons(protocol);
	if (!(su.sll.sll_ifindex = if_nametoindex(iface->name))) {
		logger(LOG_ERR,
		       "if_nametoindex: no index for interface `%s'",
		       iface->name);
		close(fd);
		return -1;
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
	{
		logger(LOG_ERR, "SO_ATTACH_FILTER: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (bind(fd, &su.sa, sizeof(su)) == -1) {
		logger(LOG_ERR, "bind: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (iface->fd > -1)
		close(iface->fd);
	iface->fd = fd;
	iface->socket_protocol = protocol;
	iface->buffer_length = BUFFER_LENGTH;

	return fd;
}

ssize_t
send_packet(const struct interface *iface, int type,
	    const unsigned char *data, size_t len)
{
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	ssize_t retval;

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = AF_PACKET;
	su.sll.sll_protocol = htons(type);

	if (!(su.sll.sll_ifindex = if_nametoindex(iface->name))) {
		logger(LOG_ERR, "if_nametoindex: no index for interface `%s'",
		       iface->name);
		return -1;
	}

	su.sll.sll_hatype = htons(iface->family);
	su.sll.sll_halen = iface->hwlen;
	if (iface->family == ARPHRD_INFINIBAND)
		memcpy(&su.sll.sll_addr,
		       &ipv4_bcast_addr, sizeof(ipv4_bcast_addr));
	else
		memset(&su.sll.sll_addr, 0xff, iface->hwlen);

	if ((retval = sendto(iface->fd, data, len,0,&su.sa,sizeof(su))) == -1)
		logger(LOG_ERR, "sendto: %s", strerror(errno));
	return retval;
}

/* Linux has no need for the buffer as we can read as much as we want.
 * We only have the buffer listed to keep the same API. */
ssize_t
get_packet(const struct interface *iface, unsigned char *data,
	   unsigned char *buffer, size_t *buffer_len, size_t *buffer_pos)
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
		logger(LOG_ERR, "read: %s", strerror(errno));
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
		logger(LOG_DEBUG, "message too short, ignoring");
		return -1;
	}

	pay.buffer = buffer;
	if (bytes < ntohs(pay.packet->ip.ip_len)) {
		logger(LOG_DEBUG, "truncated packet, ignoring");
		return -1;
	}

	if (valid_dhcp_packet(buffer) == -1)
		return -1;

	bytes = ntohs(pay.packet->ip.ip_len) -
		(sizeof(pay.packet->ip) + sizeof(pay.packet->udp));
	memcpy(data, &pay.packet->dhcp, bytes);
	return bytes;
}

#else
 #error "Platform not supported!"
 #error "We currently support BPF and Linux sockets."
 #error "Other platforms may work using BPF. If yours does, please let me know"
 #error "so I can add it to our list."
#endif
