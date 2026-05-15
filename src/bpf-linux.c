/*
 * BPF Linux interface
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2006-2025 Roy Marples <roy@marples.name>
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
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"

const char *bpf_name = "Packet Socket";

struct bpf *
bpf_open(const struct interface *ifp,
    int (*filter)(const struct bpf *, const struct in_addr *),
    const struct in_addr *ia)
{
	struct bpf *bpf;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su = { .sll = {
		     .sll_family = PF_PACKET,
		     .sll_protocol = htons(ETH_P_ALL),
		     .sll_ifindex = (int)ifp->index,
		 } };
#ifdef PACKET_AUXDATA
	int n;
#endif

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL)
		return NULL;
	bpf->bpf_ifp = ifp;
	bpf->bpf_flags = BPF_EOF;

	/* Allocate a suitably large buffer for a single packet. */
	bpf->bpf_size = ETH_FRAME_LEN;
	bpf->bpf_buffer = malloc(bpf->bpf_size);
	if (bpf->bpf_buffer == NULL)
		goto eexit;

	bpf->bpf_fd = xsocket(PF_PACKET, SOCK_RAW | SOCK_CXNB,
	    htons(ETH_P_ALL));
	if (bpf->bpf_fd == -1)
		goto eexit;

	/* We cannot validate the correct interface,
	 * so we MUST set this first. */
	if (bind(bpf->bpf_fd, &su.sa, sizeof(su.sll)) == -1)
		goto eexit;

	if (filter(bpf, ia) != 0)
		goto eexit;

	/* In the ideal world, this would be set before the bind and filter. */
#ifdef PACKET_AUXDATA
	n = 1;
	if (setsockopt(bpf->bpf_fd, SOL_PACKET, PACKET_AUXDATA, &n,
		sizeof(n)) != 0) {
		if (errno != ENOPROTOOPT)
			goto eexit;
	}
#endif

	/*
	 * At this point we could have received packets for the wrong
	 * interface or which don't pass the filter.
	 * Linux should flush upon setting the filter like every other OS.
	 * There is no way of flushing them from userland.
	 * As such, consumers need to inspect each packet to ensure it's valid.
	 * Or to put it another way, don't trust the Linux BPF filter.
	 */

	return bpf;

eexit:
	if (bpf->bpf_fd != -1)
		close(bpf->bpf_fd);
	free(bpf->bpf_buffer);
	free(bpf);
	return NULL;
}

/* BPF requires that we read the entire buffer.
 * So we pass the buffer in the API so we can loop on >1 packet. */
ssize_t
bpf_read(struct bpf *bpf, void *data, size_t len)
{
	ssize_t bytes;
	struct iovec iov = {
		.iov_base = bpf->bpf_buffer,
		.iov_len = bpf->bpf_size,
	};
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
#ifdef PACKET_AUXDATA
	union {
		struct cmsghdr hdr;
		uint8_t buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
	} cmsgbuf = { .buf = { 0 } };
	struct cmsghdr *cmsg;
	struct tpacket_auxdata *aux;
#endif

#ifdef PACKET_AUXDATA
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
#endif

	bytes = recvmsg(bpf->bpf_fd, &msg, 0);
	if (bytes == -1)
		return -1;
	bpf->bpf_flags |= BPF_EOF; /* We only ever read one packet. */
	bpf->bpf_flags &= ~BPF_PARTIALCSUM;
	if (bytes) {
		if (bpf_frame_bcast(bpf->bpf_ifp, bpf->bpf_buffer) == 0)
			bpf->bpf_flags |= BPF_BCAST;
		else
			bpf->bpf_flags &= ~BPF_BCAST;
		if ((size_t)bytes > len)
			bytes = (ssize_t)len;
		memcpy(data, bpf->bpf_buffer, (size_t)bytes);
#ifdef PACKET_AUXDATA
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_PACKET &&
			    cmsg->cmsg_type == PACKET_AUXDATA) {
				aux = (void *)CMSG_DATA(cmsg);
				if (aux->tp_status & TP_STATUS_CSUMNOTREADY)
					bpf->bpf_flags |= BPF_PARTIALCSUM;
			}
		}
#endif
	}
	return bytes;
}

int
bpf_setfilter(const struct bpf *bpf, void *filter, unsigned int filter_len)
{
	struct sock_fprog pf = {
		.filter = filter,
		.len = (unsigned short)filter_len,
	};
	int s = bpf->bpf_fd;

	/* Install the filter. */
	return setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf));
}

int
bpf_setwfilter(__unused const struct bpf *bpf, __unused void *filter, __unused unsigned int filter_len)
{
#warning A compromised PF_PACKET socket can be used as a raw socket

	errno = ENOSYS;
	return -1;
}

int
bpf_lock(const struct bpf *bpf)
{
#ifdef SO_LOCK_FILTER
	int fd = bpf->bpf_fd, on = 1;

	return setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &on, sizeof(on));
#else
	UNUSED(bpf);
	errno = ENOSYS;
	return -1;
#endif
}

ssize_t
bpf_writev(const struct bpf *bpf, struct iovec *iov, int iovcnt)
{
	return writev(bpf->bpf_fd, iov, iovcnt);
}

void
bpf_close(struct bpf *bpf)
{
	close(bpf->bpf_fd);
	free(bpf->bpf_buffer);
	free(bpf);
}

