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
#include "eloop.h"
#include "signals.h"

static int signal_pipe[2];
static void (*signal_callback)(int);

const int handle_sigs[] = {
	SIGALRM,
	SIGHUP,
	SIGINT,
	SIGPIPE,
	SIGTERM,
	SIGUSR1,
	0
};

static void
signal_handler(int sig)
{
	int serrno = errno;

	if (write(signal_pipe[1], &sig, sizeof(sig)) != sizeof(sig))
		syslog(LOG_ERR, "%s: write: %m", __func__);
	errno = serrno;
}

static void
signal_read(_unused void *arg)
{
	int sig = -1;
	char buf[16];
	ssize_t bytes;

	memset(buf, 0, sizeof(buf));
	bytes = read(signal_pipe[0], buf, sizeof(buf));
	if (signal_callback && bytes >= 0 && (size_t)bytes >= sizeof(sig)) {
		memcpy(&sig, buf, sizeof(sig));
		signal_callback(sig);
	}
}

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
signal_init(void (*func)(int), sigset_t *oldset)
{

	if (pipe(signal_pipe) == -1)
		return -1;
	if (set_nonblock(signal_pipe[0]) == -1)
		return -1;
	if (set_cloexec(signal_pipe[0]) == -1 ||
	    set_cloexec(signal_pipe[1] == -1))
		return -1;

	/* Because functions we need to reboot/reconf out interfaces
	 * are not async signal safe, we need to setup a signal pipe
	 * so that the actual handler is executed in our event loop. */
	signal_callback = func;
	eloop_event_add(signal_pipe[0], signal_read, NULL);
	return signal_handle(signal_handler, oldset);
}
