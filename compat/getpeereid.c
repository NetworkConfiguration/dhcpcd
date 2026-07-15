/*
 * compat: getpeereid
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2006-2026 Roy Marples <roy@marples.name>
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
#include <sys/socket.h>

#ifdef __sun
#include <ucred.h>
#endif

#include "getpeereid.h"

int
getpeereid(int fd, uid_t *uid, gid_t *gid)
{
#if defined(SO_PEERCRED)
	struct ucred creds;
	socklen_t creds_len = sizeof(creds);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &creds_len) == -1)
		return -1;

	*uid = creds.uid;
	*gid = creds.gid;
#elif defined(__sun)
	ucred_t *ucred = NULL;

	if (getpeerucred(fd, &ucred) == -1)
		return -1;

	*uid = ucred_geteuid(ucred);
	*gid = ucred_getegid(ucred);
	ucred_free(ucred);
#else
#error OS has no getpeereid support!
#endif

	return 0;
}
