/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Priviledge Separation for dhcpcd, Linux driver
 * Copyright (c) 2006-2020 Roy Marples <roy@marples.name>
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "if.h"
#include "logerr.h"
#include "privsep.h"

static ssize_t
ps_root_dosendnetlink(int protocol, struct msghdr *msg)
{
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	int s;
	unsigned char buf[16 * 1024];
	struct iovec riov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};

	if ((s = if_linksocket(&snl, protocol)) == -1)
		return -1;

	if (sendmsg(s, msg, 0) == -1)
		return -1;

	return if_getnetlink(NULL, &riov, s, 0, NULL, NULL);
}

static ssize_t
ps_root_dowritepathuint(const void *data, size_t len)
{
	const char *path = data;
	FILE *fp;
	ssize_t r;
	size_t plen;
	unsigned int val;

	if (len < sizeof(plen)) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&plen, path, sizeof(plen));
	path += sizeof(plen);
	if (sizeof(plen) + plen + sizeof(val) > len) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&val, path + plen, sizeof(val));

	fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	r = fprintf(fp, "%u\n", val);
	fclose(fp);
	return r;
}

ssize_t
ps_root_os(struct ps_msghdr *psm, struct msghdr *msg)
{
	struct iovec *iov = msg->msg_iov;
	void *data = iov->iov_base;
	size_t len = iov->iov_len;

	switch (psm->ps_cmd) {
	case PS_ROUTE:
		return ps_root_dosendnetlink((int)psm->ps_flags, msg);
	case PS_WRITEPATHUINT:
		return ps_root_dowritepathuint(data, len);
	default:
		errno = ENOTSUP;
		return -1;
	}
}

ssize_t
ps_root_sendnetlink(struct dhcpcd_ctx *ctx, int protocol, struct msghdr *msg)
{

	if (ps_sendmsg(ctx, ctx->ps_root_fd, PS_ROUTE,
	    (unsigned long)protocol, msg) == -1)
		return -1;
	return ps_root_readerror(ctx);
}

ssize_t
ps_root_writepathuint(struct dhcpcd_ctx *ctx, const char *path,
    unsigned int val)
{
	char buf[PS_BUFLEN];
	size_t plen = strlen(path) + 1;
	size_t len = sizeof(plen) + plen + sizeof(val);

	return 0;

	if (len > sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}

	memcpy(buf, &plen, sizeof(plen));
	memcpy(buf + sizeof(plen), path, plen);
	memcpy(buf + sizeof(plen) + plen, &val, sizeof(val));

	return ps_sendcmd(ctx, ctx->ps_root_fd, PS_WRITEPATHUINT, 0, buf, len);
}
