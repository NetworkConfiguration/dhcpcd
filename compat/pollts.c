/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2013 Roy Marples <roy@marples.name>
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

#include <sys/time.h>
#include <sys/types.h>

#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include "pollts.h"

#warning "This pollts(2) implementation is not entirely race condition safe."
#warning "Only operating system support for pollts(2) can correct this."

int
pollts(struct pollfd *__restrict fds, nfds_t nfds,
    const struct timespec *__restrict ts, const sigset_t *__restrict sigmask)
{
	int r, timeout;
	sigset_t oldset;

	if (ts == NULL)
		timeout = -1;
	else if (ts->tv_sec > INT_MAX / 1000 ||
	    (ts->tv_sec == INT_MAX / 1000 &&
	    (ts->tv_nsec + 999999) / 1000000 > INT_MAX % 1000000))
		timeout = INT_MAX;
	else
		timeout = ts->tv_sec * 1000 + (ts->tv_nsec + 999999) / 1000000;
	if (sigmask && sigprocmask(SIG_SETMASK, sigmask, &oldset) == -1)
		return -1;
	r = poll(fds, nfds, timeout);
	if (sigmask && sigprocmask(SIG_SETMASK, &oldset, NULL) == -1)
		return -1;

	return r;
}
