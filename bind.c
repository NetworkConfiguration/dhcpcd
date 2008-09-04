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

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "arp.h"
#include "bind.h"
#include "common.h"
#include "configure.h"
#include "dhcpcd.h"
#include "dhcpf.h"
#include "eloop.h"
#include "if-options.h"
#include "logger.h"
#include "net.h"
#include "signals.h"

static int daemonised = 0;
int can_daemonise = 1;

#ifndef THERE_IS_NO_FORK
pid_t
daemonise(void)
{
	pid_t pid;
	sigset_t full;
	sigset_t old;
	char buf = '\0';
	int sidpipe[2];

	if (daemonised || !can_daemonise)
		return 0;
	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);
	/* Setup a signal pipe so parent knows when to exit. */
	if (pipe(sidpipe) == -1) {
		logger(LOG_ERR, "pipe: %s", strerror(errno));
		return -1;
	}
	logger(LOG_INFO, "forking to background");
	switch (pid = fork()) {
		case -1:
			logger(LOG_ERR, "fork: %s", strerror(errno));
			exit(EXIT_FAILURE);
			/* NOTREACHED */
		case 0:
			setsid();
			/* Notify parent it's safe to exit as we've detached. */
			close(sidpipe[0]);
			write(sidpipe[1], &buf, 1);
			close(sidpipe[1]);
			close_fds();
			break;
		default:
			signal_reset();
			/* Wait for child to detach */
			close(sidpipe[1]);
			read(sidpipe[0], &buf, 1);
			close(sidpipe[0]);
			break;
	}
	/* Done with the fd now */
	if (pid != 0) {
		writepid(pidfd, pid);
		close(pidfd);
		pidfd = -1;
		exit(EXIT_SUCCESS);
	}
	daemonised = 1;
	sigprocmask(SIG_SETMASK, &old, NULL);
	return pid;
}
#endif

void
bind_interface(void *arg)
{
	struct interface *iface = arg;
	struct if_state *state = iface->state;
	struct if_options *ifo = state->options;
	struct dhcp_lease *lease = &state->lease;
	struct timeval tv;
	const char *reason = NULL;

	delete_timeout(handle_exit_timeout, NULL);
	if (clock_monotonic)
		get_monotonic(&lease->boundtime);
	state->state = DHS_BOUND;
	state->xid = 0;
	free(state->old);
	state->old = state->new;
	state->new = state->offer;
	state->offer = NULL;
	get_lease(lease, state->new);
	if (IN_LINKLOCAL(htonl(state->new->yiaddr))) {
		logger(LOG_INFO, "%s: using IPv4LL address %s",
		       iface->name, inet_ntoa(lease->addr));
		lease->leasetime = ~0U;
		reason = "IPV4LL";
	} else if (ifo->options & DHCPCD_INFORM) {
		if (ifo->request_address.s_addr != 0)
			lease->addr.s_addr = ifo->request_address.s_addr;
		else
			lease->addr.s_addr = iface->addr.s_addr;
		logger(LOG_INFO, "%s: received approval for %s", iface->name,
		       inet_ntoa(lease->addr));
		lease->leasetime = ~0U;
		reason = "INFORM";
	} else {
		if (gettimeofday(&tv, NULL) == 0)
			lease->leasedfrom = tv.tv_sec;
		if (lease->frominfo)
			reason = "TIMEOUT";
		if (lease->leasetime == ~0U) {
			lease->renewaltime = lease->rebindtime = lease->leasetime;
			logger(LOG_INFO, "%s: leased %s for infinity",
			       iface->name, inet_ntoa(lease->addr));
		} else {
			if (lease->rebindtime >= lease->leasetime) {
				lease->rebindtime = lease->leasetime * T2;
				logger(LOG_ERR,
				       "%s: rebind time greater than lease "
				       "time, forcing to %u seconds",
				       iface->name, lease->rebindtime);
			}
			if (lease->renewaltime > lease->rebindtime) {
				lease->renewaltime = lease->leasetime * T1;
				logger(LOG_ERR,
				       "%s: renewal time greater than rebind "
				       "time, forcing to %u seconds",
				       iface->name, lease->renewaltime);
			}
			if (!lease->renewaltime)
				lease->renewaltime = lease->leasetime * T1;
			if (!lease->rebindtime)
				lease->rebindtime = lease->leasetime * T2;
			logger(LOG_INFO,
			       "%s: leased %s for %u seconds", iface->name,
			       inet_ntoa(lease->addr), lease->leasetime);
		}
	}
	if (!reason) {
		if (state->old) {
			if (state->old->yiaddr == state->new->yiaddr &&
			    lease->server.s_addr)
				reason = "RENEW";
			else
				reason = "REBIND";
		} else
			reason = "BOUND";
	}
	if (lease->leasetime == ~0U)
		lease->renewaltime = lease->rebindtime = lease->leasetime;
	else {
		add_timeout_sec(lease->renewaltime, start_renew, iface);
		add_timeout_sec(lease->rebindtime, start_rebind, iface);
		add_timeout_sec(lease->leasetime, start_expire, iface);
	}
	configure(iface, reason);
	daemonise();
	if (ifo->options & DHCPCD_ARP) {
		state->claims = 0;
		send_arp_announce(iface);
	}
}
