/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2012 Roy Marples <roy@marples.name>
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

#include <signal.h>
#include <unistd.h>

#include "pselect.h"

#warning "This pselect(2) implementation is not entirely race condition safe."
#warning "Only operating system support for pselect(2) can correct this."

int
pselect(int nfds,
    fd_set *restrict readfds, 
    fd_set *restrict writefds,
    fd_set *restrict errorfds,
    const struct timespec *restrict timeout,
    const sigset_t *restrict newset)
{
	int r;
	sigset_t oldset;
	struct timeval saved_timeout;

	if (newset && sigprocmask(SIG_SETMASK, newset, &oldset) == -1)
		return -1;

	if (timeout) {
		saved_timeout.tv_sec = timeout->tv_sec;
		saved_timeout.tv_usec = timeout->tv_nsec / 1000;
		r = select(nfds, readfds, writefds, errorfds, &saved_timeout);
	} else
		r = select(nfds, readfds, writefds, errorfds, NULL);

	if (newset && sigprocmask(SIG_SETMASK, &oldset, NULL) == -1)
		return -1;

	return r;
}
