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

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"
#include "signals.h"

const int handle_sigs[] = {
	SIGALRM,
	SIGHUP,
	SIGINT,
	SIGPIPE,
	SIGTERM,
	SIGUSR1,
	0
};

static int
signal_handle(void (*func)(int), sigset_t *oldset)
{
	unsigned int i;
	struct sigaction sa;
	sigset_t newset;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = func;
	sigemptyset(&sa.sa_mask);

	if (oldset)
		sigemptyset(&newset);

	for (i = 0; handle_sigs[i]; i++) {
		if (sigaction(handle_sigs[i], &sa, NULL) == -1)
			return -1;
		if (oldset)
			sigaddset(&newset, handle_sigs[i]);
	}
	if (oldset)
		return sigprocmask(SIG_BLOCK, &newset, oldset);
	return 0;
}

int
signal_setup(void (*func)(int), sigset_t *oldset)
{

	return signal_handle(func, oldset);
}

int
signal_reset(void)
{

	return signal_handle(SIG_DFL, NULL);
}
