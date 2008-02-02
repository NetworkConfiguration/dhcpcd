/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
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
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "signal.h"

static int signal_pipe[2];
static int signals[5];

static const int handle_sigs[] = {
	SIGHUP,
	SIGALRM,
	SIGTERM,
	SIGINT
};

static void signal_handler (int sig)
{
	unsigned int i = 0;
	int serrno = errno;

	/* Add a signal to our stack */
	while (signals[i])
		i++;
	if (i > sizeof (signals) / sizeof (signals[0]))
		logger (LOG_ERR, "signal buffer overrun");
	else
		signals[i] = sig;

	if (write (signal_pipe[1], &sig, sizeof (sig)) == -1)
		logger (LOG_ERR, "Could not send signal: %s", strerror (errno));

	/* Restore errno */
	errno = serrno;
}

/* Add the signal pipe to an fd set */
int signal_fd_set (fd_set *rset, int fd)
{
	FD_ZERO (rset);
	FD_SET (signal_pipe[0], rset);
	if (fd >= 0)
		FD_SET (fd, rset);
	return (signal_pipe[0] > fd ? signal_pipe[0] : fd);
}

/* Check if we have a signal or not */
int signal_exists (const fd_set *rset)
{
	if (signals[0] || (rset && FD_ISSET (signal_pipe[0], rset)))
		return (0);
	return (-1);
}

/* Read a signal from the signal pipe. Returns 0 if there is
 * no signal, -1 on error (and sets errno appropriately), and
 * your signal on success */
int signal_read (fd_set *rset)
{
	int sig = -1;

	/* Pop a signal off the our stack */

	if (signals[0]) {
		unsigned int i = 0;
		sig = signals[0];
		while (i < (sizeof (signals) / sizeof (signals[0])) - 1) {
			signals[i] = signals[i + 1];
			if (! signals[++i])
				break;
		}
	}

	if (rset && FD_ISSET (signal_pipe[0], rset)) {
		char buf[16];
		size_t bytes;

		memset (buf, 0, sizeof (buf));
		bytes = read (signal_pipe[0], buf, sizeof (buf));

		if (bytes >= sizeof (sig))
			memcpy (&sig, buf, sizeof (sig));

		/* We need to clear us from rset if nothing left in the buffer
		 * in case we are called many times */
		if (bytes == sizeof (sig))
			FD_CLR (signal_pipe[0], rset);
	}

	return (sig);
}

/* Call this before doing anything else. Sets up the socket pair
 * and installs the signal handler */
int signal_init (void)
{
	unsigned int i;
	int flags;
	struct sigaction sa;

	if (pipe (signal_pipe) == -1) {
		logger (LOG_ERR, "pipe: %s", strerror (errno));
		return (-1);
	}

	/* Stop any scripts from inheriting us */
	for (i = 0; i < 2; i++)
		if ((flags = fcntl (signal_pipe[i], F_GETFD, 0)) == -1 ||
		    fcntl (signal_pipe[i], F_SETFD, flags | FD_CLOEXEC) == -1)
			logger (LOG_ERR ,"fcntl: %s", strerror (errno));

	/* Ignore child signals and don't make zombies.
	 * Because we do this, we don't need to be in signal_setup */
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT;
	if (sigaction (SIGCHLD, &sa, NULL) == -1) {
		logger (LOG_ERR, "sigaction: %s", strerror (errno));
		return (-1);
	}

	memset (signals, 0, sizeof (signals));
	return (0);
}

int signal_setup (void)
{
	unsigned int i;
	struct sigaction sa;

	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = signal_handler;
	sigemptyset (&sa.sa_mask);

	for (i = 0; i < sizeof (handle_sigs) / sizeof (handle_sigs[0]); i++)
		if (sigaction (handle_sigs[i], &sa, NULL) == -1) {
			logger (LOG_ERR, "sigaction: %s", strerror (errno));
			return (-1);
		}
	
	return (0);
}

int signal_reset (void)
{
	struct sigaction sa;
	unsigned int i;

	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset (&sa.sa_mask);

	for (i = 0; i < sizeof (handle_sigs) / sizeof (handle_sigs[0]); i++)
		if (sigaction (handle_sigs[i], &sa, NULL) == -1) {
			logger (LOG_ERR, "sigaction: %s", strerror (errno));
			return (-1);
		}

	return (0);
}
