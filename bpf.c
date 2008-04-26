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
#include <sys/uio.h>

#include <net/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "logger.h"
#include "net.h"
#include "bpf-filter.h"

int
open_socket(struct interface *iface, int protocol)
{
	int fd = -1;
	int flags;
	struct ifreq ifr;
	int buf = 0;
	struct bpf_version pv;
	struct bpf_program pf;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char *device;
	int n = 0;

	device = xmalloc(sizeof(char) * PATH_MAX);
	do {
		snprintf(device, PATH_MAX, "/dev/bpf%d", n++);
		fd = open(device, O_RDWR);
	} while (fd == -1 && errno == EBUSY);
	free(device);
#endif

	if (fd == -1)
		return -1;

	if (ioctl(fd, BIOCVERSION, &pv) == -1)
		goto eexit;
	if (pv.bv_major != BPF_MAJOR_VERSION ||
	    pv.bv_minor < BPF_MINOR_VERSION) {
		logger(LOG_ERR, "BPF version mismatch - recompile " PACKAGE);
		goto eexit;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		goto eexit;

	/* Get the required BPF buffer length from the kernel. */
	if (ioctl(fd, BIOCGBLEN, &buf) == -1)
		goto eexit;
	iface->buffer_length = buf;

	flags = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &flags) == -1)
		goto eexit;

	/* Install the DHCP filter */
	if (protocol == ETHERTYPE_ARP) {
		pf.bf_insns = arp_bpf_filter;
		pf.bf_len = sizeof(arp_bpf_filter) / sizeof(arp_bpf_filter[0]);
	} else {
		pf.bf_insns = dhcp_bpf_filter;
		pf.bf_len = sizeof(dhcp_bpf_filter)/sizeof(dhcp_bpf_filter[0]);
	}
	if (ioctl(fd, BIOCSETF, &pf) == -1)
		goto eexit;

	if (iface->fd > -1)
		close(iface->fd);

	close_on_exec(fd);
	iface->fd = fd;

	return fd;

eexit:
	close(fd);
	return -1;
}

ssize_t
send_raw_packet(const struct interface *iface, int type,
		const unsigned char *data, ssize_t len)
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
	   unsigned char *buffer, ssize_t *buffer_len, ssize_t *buffer_pos)
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
	struct timespec ts;
	ssize_t len;
	unsigned char *payload;
	const uint8_t *d;

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

	for (; bpf.buffer - buffer < *buffer_len; 
	     bpf.buffer += BPF_WORDALIGN(bpf.packet->bh_hdrlen +
					 bpf.packet->bh_caplen),
	     *buffer_pos = bpf.buffer - buffer)
	{
		/* Ensure we have the whole packet */
		if (bpf.packet->bh_caplen != bpf.packet->bh_datalen)
			continue;

		hdr.buffer = bpf.buffer + bpf.packet->bh_hdrlen;
		payload = hdr.buffer + sizeof(*hdr.hw);

		/* If it's an ARP reply, then just send it back */
		if (hdr.hw->ether_type == htons (ETHERTYPE_ARP)) {
			len = bpf.packet->bh_caplen - sizeof(*hdr.hw);
			memcpy(data, payload, len);
			return len;
		} else {
			if (valid_udp_packet(payload) >= 0) {
				len = get_udp_data(&d, payload);
				memcpy(data, d, len);
				return len;
			}
		}
	}

	/* No valid packets left, so return */
	*buffer_pos = 0;
	return -1;
}
