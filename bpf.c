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

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "dhcp.h"
#include "if.h"
#include "socket.h"
#include "bpf-filter.h"

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

	if (fd == -1)
		return -1;

	close_on_exec(fd);
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
		close(fd);
		return -1;
	}

	/* Get the required BPF buffer length from the kernel. */
	if (ioctl(fd, BIOCGBLEN, &buf) == -1) {
		close(fd);
		return -1;
	}
	iface->buffer_length = buf;

	flags = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &flags) == -1) {
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
	struct iovec iov[2];
	struct ether_header hw;

	memset(&hw, 0, sizeof(hw));
	memset(&hw.ether_dhost, 0xff, ETHER_ADDR_LEN);
	hw.ether_type = htons(type);
	iov[0].iov_base = &hw;
	iov[0].iov_len = sizeof(hw);
	iov[1].iov_base = (unsigned char *)data;
	iov[1].iov_len = len;

	return writev(iface->fd, iov, 2);
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
