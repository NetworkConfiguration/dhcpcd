/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Privilege Separation for dhcpcd, Linux driver
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
#include <fcntl.h>
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
	ssize_t retval;

	if ((s = if_linksocket(&snl, protocol, 0)) == -1)
		return -1;

	if (sendmsg(s, msg, 0) == -1) {
		retval = -1;
		goto out;
	}

	retval = if_getnetlink(NULL, &riov, s, 0, NULL, NULL);
out:
	close(s);
	return retval;
}

ssize_t
ps_root_os(struct ps_msghdr *psm, struct msghdr *msg,
    __unused void **rdata, __unused size_t *rlen)
{

	switch (psm->ps_cmd) {
	case PS_ROUTE:
		return ps_root_dosendnetlink((int)psm->ps_flags, msg);
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
	return ps_root_readerror(ctx, NULL, 0);
}
