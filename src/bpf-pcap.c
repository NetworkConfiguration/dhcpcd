/*
 * BPF libpcap interface
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2025 Joan Lledó <jlledom@member.fsf.org>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/ioctl.h>

#include <errno.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "logerr.h"

#define PCAP_CHECK(call, name)                                         \
	do {                                                           \
		int status = (call);                                   \
		if (status < 0) {                                      \
			logerrx("%s: %s failed: %s", __func__, name,   \
			    pcap_statustostr(status));                 \
			goto eexit;                                    \
		} else if (status > 0)                                 \
			logwarnx("%s: %s warning: %s", __func__, name, \
			    pcap_statustostr(status));                 \
	} while (0)

#define ETH_MTU 1500

const char *bpf_name = "Berkeley Packet Filter (libpcap)";

struct bpf *
bpf_open(const struct interface *ifp,
    int (*filter)(const struct bpf *, const struct in_addr *),
    const struct in_addr *ia)
{
	int err;
	struct bpf *bpf;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int mtu;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL)
		return NULL;

	mtu = ifp->mtu ? ifp->mtu : ETH_MTU;
	bpf->bpf_ifp = ifp;
	bpf->bpf_size = bpf_frame_header_len(ifp) + (size_t)mtu;
	bpf->bpf_buffer = malloc(bpf->bpf_size);
	if (bpf->bpf_buffer == NULL)
		goto eexit;
	bpf->bpf_len = 0;
	bpf->bpf_pos = 0;
	bpf->bpf_flags = BPF_EOF;

	bpf->bpf_handle = handle = pcap_create(ifp->name, errbuf);
	if (handle == NULL) {
		logerrx("%s: pcap_create: %s", __func__, errbuf);
		goto eexit;
	}

	PCAP_CHECK(pcap_set_snaplen(handle, (int)bpf->bpf_size),
	    "pcap_set_snaplen");
	PCAP_CHECK(pcap_set_promisc(handle, 0), "pcap_set_promisc");
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	PCAP_CHECK(pcap_set_immediate_mode(handle, 1),
#endif
	    "pcap_set_immediate_mode");

	err = pcap_activate(handle);
	if (err != 0) {
		if (err < 0) {
			logerrx("%s: pcap_activate failed: %s", __func__,
			    pcap_statustostr(err));
			goto eexit;
		}
		logwarnx("%s: pcap_activate warning: %s", __func__,
		    pcap_statustostr(err));
	}

	bpf->bpf_fd = pcap_get_selectable_fd(handle);
	if (bpf->bpf_fd < 0) {
		logerrx("%s: pcap_get_selectable_fd failed", __func__);
		goto eexit;
	}

	if (filter(bpf, ia) != 0)
		goto eexit;

	return bpf;

eexit:
	bpf_close(bpf);
	return NULL;
}

ssize_t
bpf_read(struct bpf *bpf, void *data, size_t len)
{
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	size_t cap_len;
	int err;

	bpf->bpf_flags |= BPF_EOF; /* We only read one packet per call */

	err = pcap_next_ex(bpf->bpf_handle, &pkt_header, &pkt_data);

	if (err == 0)
		return 0;
	if (err < 0)
		return -1;

	/* Packet read successfully */
	cap_len = pkt_header->caplen;
	if (cap_len > len)
		cap_len = len;
	memcpy(data, pkt_data, cap_len);

	if (bpf_frame_bcast(bpf->bpf_ifp, pkt_data) == 0)
		bpf->bpf_flags |= BPF_BCAST;
	else
		bpf->bpf_flags &= ~BPF_BCAST;

	return (ssize_t)cap_len;
}

ssize_t
bpf_writev(const struct bpf *bpf, struct iovec *iov, int iovcnt)
{
	int i;
	size_t len = 0;
	uint8_t *bp = bpf->bpf_buffer;

	for (i = 0; i < iovcnt; i++) {
		/* This should be impossible. */
		if (iov[i].iov_len > bpf->bpf_size - len) {
			errno = ENOBUFS;
			return -1;
		}

		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
		len += iov[i].iov_len;
	}

	i = pcap_inject(bpf->bpf_handle, bpf->bpf_buffer, len);
	if (i < 0) {
		logerrx("%s: %s", __func__, pcap_geterr(bpf->bpf_handle));
		return -1;
	}
	return i;
}

int
bpf_setfilter(const struct bpf *bpf, void *filter, unsigned int filter_len)
{
	struct bpf_program pf = { .bf_insns = filter, .bf_len = filter_len };

	/* Install the filter. */
	return pcap_setfilter(bpf->bpf_handle, &pf);
}

int
bpf_setwfilter(const struct bpf *bpf, void *filter, unsigned int filter_len)
{
#ifdef HAVE_PCAP_SETWRITEFILTER
	struct bpf_program pf = { .bf_insns = filter, .bf_len = filter_len };

	return pcap_setwritefilter(bpf->bpf_handle, &pf);
#elif defined(BIOCSETWF)
	struct bpf_program pf = { .bf_insns = filter, .bf_len = filter_len };
	int fd = pcap_fileno(bpf->bpf_handle);

	if (fd == -1) {
		errno = EBADF;
		return -1;
	}
	return ioctl(fd, BIOCSETWF, &pf);
#else
#warning No BIOCSETWF support - a compromised BPF can be used as a raw socket
	UNUSED(bpf);
	UNUSED(filter);
	UNUSED(filter_len);
	errno = ENOSYS;
	return -1;
#endif
}

int
bpf_lockfilter(const struct bpf *bpf)
{
#ifdef HAVE_PCAP_LOCKFILTER
	return pcap_lockfilter(bpf->bpf_handle);
#elif defined(BIOCLOCK)
	int fd = pcap_fileno(bpf->bpf_handle);

	if (fd == -1) {
		errno = EBADF;
		return -1;
	}
	return ioctl(fd, BIOCLOCK);
#else
	UNUSED(bpf);
	errno = ENOSYS;
	return -1;
#endif
}

void
bpf_close(struct bpf *bpf)
{
	if (bpf->bpf_handle != NULL)
		pcap_close(bpf->bpf_handle);
	free(bpf->bpf_buffer);
	free(bpf);
}
