/*
 * BPF DLPI interface
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

#include <sys/types.h>

#include <net/if.h>
#include <netinet/if_ether.h>

#include <errno.h>
#include <libdlpi.h>
#include <stdlib.h>
#include <string.h>

#include "bpf-dlpi.h"
#include "bpf.h"

struct bpf_dlpi {
	dlpi_handle_t bd_handle;
	void *bd_buffer;
	size_t bd_bufferlen;
};

int
bpf_dlpi_open(struct bpf *bpf)
{
	const struct interface *ifp = bpf->bpf_ifp;
	struct bpf_dlpi *bd;
	int mtu;

	bd = calloc(1, sizeof(*bd));
	if (bd == NULL)
		return -1;

	if (dlpi_open(ifp->name, &bd->bd_handle, DLPI_RAW) != DLPI_SUCCESS) {
		free(bd);
		return -1;
	}

	bpf->bpf_handle = bd;

	if (dlpi_bind(bd->bd_handle, DLPI_ANY_SAP, NULL) != DLPI_SUCCESS)
		return -1;

	mtu = ifp->mtu ? ifp->mtu : ETHERMTU;
	bd->bd_bufferlen = bpf_frame_header_len(ifp) + (size_t)mtu;
	bd->bd_buffer = malloc(bd->bd_bufferlen);
	if (bpf->bpf_buffer == NULL)
		return -1;

	return 0;
}

ssize_t
bpf_writev(const struct bpf *bpf, struct iovec *iov, int iovcnt)
{
	struct bpf_dlpi *bd = bpf->bpf_handle;
	int i;
	size_t len = 0;
	uint8_t *bp = bd->bd_buffer;

	for (i = 0; i < iovcnt; i++) {
		/* This should be impossible. */
		if (iov[i].iov_len > bd->bd_bufferlen - len) {
			errno = ENOBUFS;
			return -1;
		}

		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
		len += iov[i].iov_len;
	}

	i = dlpi_send(bd->bd_handle, NULL, 0, bd->bd_buffer, len, NULL);
	return i == DLPI_SUCCESS ? (ssize_t)len : -1;
}

void
bpf_dlpi_close(struct bpf *bpf)
{
	struct bpf_dlpi *bd = bpf->bpf_handle;

	if (bd == NULL)
		return;

	dlpi_close(bd->bd_handle);
	free(bd->bd_buffer);
	free(bd);
}
