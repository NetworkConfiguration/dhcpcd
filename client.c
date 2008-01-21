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

#ifdef __linux__
# define _BSD_SOURCE
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <arpa/inet.h>
#ifdef __linux__
# include <netinet/ether.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#ifdef ENABLE_ARP
# include "arp.h"
#endif
#include "client.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcpcd.h"
#include "info.h"
#include "interface.h"
#ifdef ENABLE_IPV4LL
# include "ipv4ll.h"
#endif
#include "logger.h"
#include "signal.h"
#include "socket.h"

#ifdef ENABLE_DUID
# include "duid.h"
#endif

#ifdef ENABLE_INFO
# include "info.h"
#endif

#ifdef THERE_IS_NO_FORK
# ifndef ENABLE_INFO
#  error "Non MMU requires ENABLE_INFO to work"
# endif
#endif

/* We need this for our maximum timeout as FreeBSD's select cannot handle
   any higher than this. Is there a better way of working this out? */
#define SELECT_MAX              100000000

/* This is out mini timeout.
   Basically we resend the last request every TIMEOUT_MINI seconds. */
#define TIMEOUT_MINI            3
/* Except for an infinite timeout. We keep adding TIMEOUT_MINI to
   ourself until TIMEOUT_MINI_INF is reached. */
#define TIMEOUT_MINI_INF        60

#define STATE_INIT              0
#define STATE_REQUESTING        1
#define STATE_BOUND             2
#define STATE_RENEWING          3
#define STATE_REBINDING         4
#define STATE_REBOOT            5
#define STATE_RENEW_REQUESTED   6
#define STATE_RELEASED          7

/* We should define a maximum for the NAK exponential backoff */ 
#define NAKOFF_MAX              60

#define SOCKET_CLOSED           0
#define SOCKET_OPEN             1

typedef struct _state {
	int *pidfd;
	bool forked;
	int state;
	uint32_t xid;
	dhcp_t *dhcp;
	int socket;
	interface_t *interface;
	time_t start;
	time_t last_sent;
	time_t last_type;
	long timeout;
	long nakoff;
	bool daemonised;
	bool persistent;
	unsigned char *buffer;
	ssize_t buffer_len;
	ssize_t buffer_pos;
} state_t;

static pid_t daemonise (int *pidfd)
{
	pid_t pid;

#ifndef THERE_IS_NO_FORK
	logger (LOG_DEBUG, "forking to background");
	if ((pid = fork()) == -1) {
		logger (LOG_ERR, "fork: %s", strerror (errno));
		exit (EXIT_FAILURE);
	}

	setsid ();
	close_fds ();
#else
	char **argv;
	int i;

	logger (LOG_INFO, "forking to background");

	/* We need to add --daemonise to our options */
	argv = xmalloc (sizeof (char *) * (dhcpcd_argc + 4));
	argv[0] = dhcpcd;
	for (i = 1; i < dhcpcd_argc; i++)
		argv[i] = dhcpcd_argv[i];
	argv[i] = (char *) "--daemonised";
	if (dhcpcd_skiproutes) {
		argv[++i] = (char *) "--skiproutes";
		argv[++i] = dhcpcd_skiproutes;
	}
	argv[i + 1] = NULL;

	switch (pid = vfork ()) {
		case -1:
			logger (LOG_ERR, "vfork: %s", strerror (errno));
			_exit (EXIT_FAILURE);
		case 0:
			execvp (dhcpcd, argv);
			logger (LOG_ERR, "execl `%s': %s", dhcpcd,
				strerror (errno));
			_exit (EXIT_FAILURE);
	}

	free (argv);
#endif

	/* Done with the fd now */
	if (pid != 0) {
		writepid (*pidfd, pid);
		close (*pidfd);
		*pidfd = -1;
	}

	return (pid);
}

#ifdef ENABLE_INFO
static bool get_old_lease (state_t *state, const options_t *options)
{
	interface_t *iface = state->interface;
	dhcp_t *dhcp = state->dhcp;
	struct timeval tv;
	unsigned int offset = 0;

	if (! IN_LINKLOCAL (ntohl (iface->previous_address.s_addr)))
		logger (LOG_INFO, "trying to use old lease in `%s'",
			iface->infofile);
	if (! read_info (iface, dhcp))
		return (false);

	/* Vitaly important we remove the server information here */
	memset (&dhcp->serveraddress, 0, sizeof (struct in_addr));
	memset (dhcp->servername, 0, sizeof (dhcp->servername));

#ifdef ENABLE_ARP
	/* Check that no-one is using the address */
	if ((options->dolastlease || 
	     (IN_LINKLOCAL (ntohl (dhcp->address.s_addr)) &&
	      (! options->doipv4ll ||
	       arp_claim (iface, dhcp->address)))))
	{
		memset (&dhcp->address, 0, sizeof (struct in_addr));
		memset (&dhcp->netmask, 0, sizeof (struct in_addr));
		memset (&dhcp->broadcast, 0, sizeof (struct in_addr));
		return (false);
	}

	/* Ok, lets use this */
	if (IN_LINKLOCAL (dhcp->address.s_addr))
		return (true);
#endif

	/* Ensure that we can still use the lease */
	if (gettimeofday (&tv, NULL) == -1) {
		logger (LOG_ERR, "gettimeofday: %s", strerror (errno));
		return (false);
	}

	offset = tv.tv_sec - dhcp->leasedfrom;
	if (dhcp->leasedfrom &&
	    tv.tv_sec - dhcp->leasedfrom > dhcp->leasetime)
	{
		logger (LOG_ERR, "lease expired %u seconds ago",
			offset + dhcp->leasetime);
		return (false);
	}

	if (dhcp->leasedfrom == 0)
		offset = 0;
	state->timeout = dhcp->renewaltime - offset;
	iface->start_uptime = uptime ();
	return (true);
}
#endif

#ifdef THERE_IS_NO_FORK
static void remove_skiproutes (dhcp_t *dhcp, interface_t *iface)
{
	int i = -1;
	route_t *route;
	route_t *iroute = NULL;

	free_route (iface->previous_routes);

	for (route = dhcp->routes; route; route = route->next) {
		i++;

		/* Check that we did add this route or not */
		if (dhcpcd_skiproutes) {
			char *sk = xstrdup (dhcpcd_skiproutes);
			char *skp = sk;
			char *token;
			bool found = false;

			while ((token = strsep (&skp, ","))) {
				if (isdigit (*token) && atoi (token) == i) {
					found = true;
					break;
				}
			}
			free (sk);
			if (found)
				continue;
		}

		if (! iroute)
			iroute = iface->previous_routes =
				xmalloc (sizeof (route_t));

		memcpy (iroute, route, sizeof (route_t));
		if (route->next) {
			iroute->next = xmalloc (sizeof (route_t));
			iroute = iroute->next;
		}
	}

	/* We no longer need this argument */
	free (dhcpcd_skiproutes);
	dhcpcd_skiproutes = NULL;
}
#endif

static bool client_setup (state_t *state, const options_t *options)
{
	dhcp_t *dhcp = state->dhcp;
	interface_t *iface = state->interface;

	state->state = STATE_INIT;
	state->last_type = DHCP_DISCOVER;
	state->nakoff = 1;
	state->daemonised = options->daemonised;
	state->persistent = options->persistent;

#ifdef ENABLE_DUID
	if (options->clientid_len == 0) {
		get_duid (iface);
		if (iface->duid_length > 0)
			logger (LOG_INFO, "DUID = %s",
				hwaddr_ntoa (iface->duid, iface->duid_length));
	}
#endif

	if (options->request_address.s_addr == 0 &&
	    (options->doinform || options->dorequest || options->daemonised))
	{
#ifdef ENABLE_INFO
		if (! get_old_lease (state, options))
#endif
		{
			free (dhcp);
			return (false);
		}
		state->timeout = 0;

		if (! options->daemonised &&
		    IN_LINKLOCAL (ntohl (dhcp->address.s_addr)))
		{
			logger (LOG_ERR, "cannot request a link local address");
			return (false);
		}
#ifdef THERE_IS_NO_FORK
		if (options->daemonised) {
			state->state = STATE_BOUND;
			state->timeout = dhcp->renewaltime;
			iface->previous_address = dhcp->address;
			iface->previous_netmask = dhcp->netmask;
			remove_skiproutes (dhcp, iface);
		}
#endif

	} else {
		dhcp->address = options->request_address;
		dhcp->netmask = options->request_netmask;
		if (dhcp->netmask.s_addr == 0)
			dhcp->netmask.s_addr = get_netmask (dhcp->address.s_addr);
		dhcp->broadcast.s_addr = dhcp->address.s_addr |
			~dhcp->netmask.s_addr;
	}

	/* Remove all existing addresses.
	 * After all, we ARE a DHCP client whose job it is to configure the
	 * interface. We only do this on start, so persistent addresses
	 * can be added afterwards by the user if needed. */
	if (! options->test && ! options->daemonised) {
		if (! options->doinform) {
			flush_addresses (iface->name);
		} else {
			/* The inform address HAS to be configured for it to
			 * work with most DHCP servers */
			if (options->doinform &&
			    has_address (iface->name, dhcp->address) < 1)
			{
				add_address (iface->name, dhcp->address,
					     dhcp->netmask, dhcp->broadcast);
				iface->previous_address = dhcp->address;
				iface->previous_netmask = dhcp->netmask;
			}
		}
	}

	return (true);
}

static bool do_socket (state_t *state, int mode)
{
	if (state->interface->fd >= 0)
		close (state->interface->fd);

	state->interface->fd = -1; 
	if (mode == SOCKET_OPEN) 
		if (open_socket (state->interface, false) == -1)
			return (false);
	state->socket = mode;
	return (true);
}

static bool _send_message (state_t *state, int type, const options_t *options)
{
	ssize_t retval;

	state->last_type = type;
	state->last_sent = uptime ();
	retval = send_message (state->interface, state->dhcp, state->xid,
			       type, options);
	return (retval == -1 ? false : true);
}

static void drop_config (state_t *state, const options_t *options)
{
	if (! state->persistent)
		configure (options, state->interface, state->dhcp, false);

	free_dhcp (state->dhcp);
	memset (state->dhcp, 0, sizeof (dhcp_t));
}

static int wait_for_packet (fd_set *rset, state_t *state,
			    const options_t *options)
{
	dhcp_t *dhcp = state->dhcp;
	interface_t *iface = state->interface;
	int retval = 0;
	struct timeval tv;
	int maxfd;

	if (! (state->timeout > 0 ||
	       (options->timeout == 0 &&
		(state->state != STATE_INIT || state->xid))))
		return (0);

	if ((options->timeout == 0 && state->xid) ||
	    (dhcp->leasetime == (unsigned) -1 &&
	     state->state == STATE_BOUND))
	{
		int retry = 0;

		logger (LOG_DEBUG, "waiting on select for infinity");
		while (retval == 0)	{
			maxfd = signal_fd_set (rset, iface->fd);
			if (iface->fd == -1)
				retval = select (maxfd + 1, rset,
						 NULL, NULL, NULL);
			else {
				/* Slow down our requests */
				if (retry < TIMEOUT_MINI_INF)
					retry += TIMEOUT_MINI;
				else if (retry > TIMEOUT_MINI_INF)
					retry = TIMEOUT_MINI_INF;

				tv.tv_sec = retry;
				tv.tv_usec = 0;
				retval = select (maxfd + 1, rset,
						 NULL, NULL, &tv);
				if (retval == 0)
					_send_message (state, state->last_type, options);
			}
		}

		return (retval);
	}

	/* Resend our message if we're getting loads of packets
	   that aren't for us. This mainly happens on Linux as it
	   doesn't have a nice BPF filter. */
	if (iface->fd > -1 && uptime () - state->last_sent >= TIMEOUT_MINI)
		_send_message (state, state->last_type, options);

	logger (LOG_DEBUG, "waiting on select for %ld seconds",
		(unsigned long) state->timeout);
	/* If we're waiting for a reply, then we re-send the last
	   DHCP request periodically in-case of a bad line */
	retval = 0;
	while (state->timeout > 0 && retval == 0) {
		if (iface->fd == -1)
			tv.tv_sec = SELECT_MAX;
		else
			tv.tv_sec = TIMEOUT_MINI;
		if (state->timeout < tv.tv_sec)
			tv.tv_sec = state->timeout;
		tv.tv_usec = 0;
		state->start = uptime ();
		maxfd = signal_fd_set (rset, iface->fd);
		retval = select (maxfd + 1, rset, NULL, NULL, &tv);
		state->timeout -= uptime () - state->start;
		if (retval == 0 && iface->fd != -1 && state->timeout > 0)
			_send_message (state, state->last_type, options);
	}

	return (retval);
}

static bool handle_signal (int sig, state_t *state,  const options_t *options)
{
	switch (sig) {
		case SIGINT:
			logger (LOG_INFO, "received SIGINT, stopping");
			return (false);
		case SIGTERM:
			logger (LOG_INFO, "received SIGTERM, stopping");
			return (false);

		case SIGALRM:
			logger (LOG_INFO, "received SIGALRM, renewing lease");
			switch (state->state) {
				case STATE_BOUND:
				case STATE_RENEWING:
				case STATE_REBINDING:
					state->state = STATE_RENEW_REQUESTED;
					break;
				case STATE_RENEW_REQUESTED:
				case STATE_REQUESTING:
				case STATE_RELEASED:
					state->state = STATE_INIT;
					break;
			}
			state->timeout = 0;
			state->xid = 0;
			return (true);

		case SIGHUP:
			if (state->state != STATE_BOUND &&
			    state->state != STATE_RENEWING &&
			    state->state != STATE_REBINDING)
			{
				logger (LOG_ERR,
					"received SIGHUP, but we no have lease to release");
				return (false);
			}

			logger (LOG_INFO, "received SIGHUP, releasing lease");
			if (! IN_LINKLOCAL (ntohl (state->dhcp->address.s_addr))) {
				do_socket (state, SOCKET_OPEN);
				state->xid = random ();
				if ((open_socket (state->interface, false)) >= 0)
					_send_message (state, DHCP_RELEASE, options);
				do_socket (state, SOCKET_CLOSED);
			}
			unlink (state->interface->infofile);
			return (false);

		default:
			logger (LOG_ERR,
				"received signal %d, but don't know what to do with it",
				sig);
	}

	return (false);
}

static int handle_timeout (state_t *state, const options_t *options)
{
	dhcp_t *dhcp = state->dhcp;
	interface_t *iface = state->interface;

	/* No NAK, so reset the backoff */
	state->nakoff = 1;

	if (state->state == STATE_INIT && state->xid != 0) {
		if (iface->previous_address.s_addr != 0 &&
		    ! IN_LINKLOCAL (ntohl (iface->previous_address.s_addr)) &&
		    ! options->doinform)
		{
			logger (LOG_ERR, "lost lease");
			if (! options->persistent)
				drop_config (state, options);
		} else if (! IN_LINKLOCAL (ntohl (iface->previous_address.s_addr)))
			logger (LOG_ERR, "timed out");

		do_socket (state, SOCKET_CLOSED);
		free_dhcp (dhcp);
		memset (dhcp, 0, sizeof (dhcp_t));

#ifdef ENABLE_INFO
		if (! options->test &&
		    (options->doipv4ll || options->dolastlease))
		{
			errno = 0;
			if (! get_old_lease (state, options))
			{
				if (errno == EINTR)
					return (0);
				if (options->dolastlease)
					return (-1);
				free_dhcp (dhcp);
				memset (dhcp, 0, sizeof (dhcp_t));
			} else if (errno == EINTR)
				return (0);
		}
#endif

#ifdef ENABLE_IPV4LL
		if (! options->test && options->doipv4ll &&
		    (! dhcp->address.s_addr ||
		     (! IN_LINKLOCAL (ntohl (dhcp->address.s_addr)) &&
		      ! options->dolastlease)))
		{
			logger (LOG_INFO, "probing for an IPV4LL address");
			free_dhcp (dhcp);
			memset (dhcp, 0, sizeof (dhcp_t));
			if (ipv4ll_get_address (iface, dhcp) == -1) {
				if (! state->daemonised)
					return (-1);

				/* start over */
				state->xid = 0;
				return (0);
			}
			state->timeout = dhcp->renewaltime;
		}
#endif

#if defined (ENABLE_INFO) || defined (ENABLE_IPV4LL)
		if (dhcp->address.s_addr) {
			if (! state->daemonised &&
			    IN_LINKLOCAL (ntohl (dhcp->address.s_addr)))
				logger (LOG_WARNING, "using IPV4LL address %s",
					inet_ntoa (dhcp->address));
			if (configure (options, iface, dhcp, true) == -1 &&
			    ! state->daemonised)
				return (-1);

			state->state = STATE_BOUND;
			if (! state->daemonised && options->daemonise) {
				switch (daemonise (state->pidfd)) {
					case -1:
						return (-1);
					case 0:
						state->daemonised = true;
						return (0);
					default:
						state->persistent = true;
						state->forked = true;
						return (-1);
				}
			}

			state->timeout = dhcp->renewaltime;
			state->xid = 0;
			return (0);
		}
#endif

		if (! state->daemonised)
			return (-1);
	}

	switch (state->state) {
		case STATE_INIT:
			state->xid = random ();
			do_socket (state, SOCKET_OPEN);
			state->timeout = options->timeout;
			iface->start_uptime = uptime ();
			if (dhcp->address.s_addr == 0) {
				if (! IN_LINKLOCAL (ntohl (iface->previous_address.s_addr)))
					logger (LOG_INFO, "broadcasting for a lease");
				_send_message (state, DHCP_DISCOVER, options);
			} else if (options->doinform) {
				logger (LOG_INFO, "broadcasting inform for %s",
					inet_ntoa (dhcp->address));
				_send_message (state, DHCP_INFORM, options);
				state->state = STATE_REQUESTING;
			} else {
				logger (LOG_INFO, "broadcasting for a lease of %s",
					inet_ntoa (dhcp->address));
				_send_message (state, DHCP_REQUEST, options);
				state->state = STATE_REQUESTING;
			}

			break;
		case STATE_BOUND:
		case STATE_RENEW_REQUESTED:
			if (IN_LINKLOCAL (ntohl (dhcp->address.s_addr))) {
				memset (&dhcp->address, 0, sizeof (struct in_addr));
				state->state = STATE_INIT;
				state->xid = 0;
				break;
			}
			state->state = STATE_RENEWING;
			state->xid = random ();
		case STATE_RENEWING:
			iface->start_uptime = uptime ();
			logger (LOG_INFO, "renewing lease of %s", inet_ntoa
				(dhcp->address));
			do_socket (state, SOCKET_OPEN);
			_send_message (state, DHCP_REQUEST, options);
			state->timeout = dhcp->rebindtime - dhcp->renewaltime;
			state->state = STATE_REBINDING;
			break;
		case STATE_REBINDING:
			logger (LOG_ERR, "lost lease, attemping to rebind");
			memset (&dhcp->address, 0, sizeof (struct in_addr));
			do_socket (state, SOCKET_OPEN);
			if (state->xid == 0)
				state->xid = random ();
			_send_message (state, DHCP_REQUEST, options);
			state->timeout = dhcp->leasetime - dhcp->rebindtime;
			state->state = STATE_REQUESTING;
			break;
		case STATE_REQUESTING:
			state->state = STATE_INIT;
			do_socket (state, SOCKET_CLOSED);
			state->timeout = 0;
			break;

		case STATE_RELEASED:
			dhcp->leasetime = -1;
			break;
	}

	return (0);
}


static int handle_dhcp (state_t *state, int type, const options_t *options)
{
	struct timeval tv;
	interface_t *iface = state->interface;
	dhcp_t *dhcp = state->dhcp;

	/* We should restart on a NAK */
	if (type == DHCP_NAK) {
		logger (LOG_INFO, "received NAK: %s", dhcp->message);
		state->state = STATE_INIT;
		state->timeout = 0;
		state->xid = 0;
		free_dhcp (dhcp);
		memset (dhcp, 0, sizeof (dhcp_t));

		/* If we constantly get NAKS then we should slowly back off */
		if (state->nakoff > 0) {
			logger (LOG_DEBUG, "sleeping for %ld seconds",
				state->nakoff);
			tv.tv_sec = state->nakoff;
			tv.tv_usec = 0;
			state->nakoff *= 2;
			if (state->nakoff > NAKOFF_MAX)
				state->nakoff = NAKOFF_MAX;
			select (0, NULL, NULL, NULL, &tv);
		}

		return (0);
	}

	/* No NAK, so reset the backoff */
	state->nakoff = 1;

	if (type == DHCP_OFFER && state->state == STATE_INIT) {
		char *addr = strdup (inet_ntoa (dhcp->address));
		if (dhcp->servername[0])
			logger (LOG_INFO, "offered %s from %s `%s'",
				addr, inet_ntoa (dhcp->serveraddress),
				dhcp->servername);
		else
			logger (LOG_INFO, "offered %s from %s",
				addr, inet_ntoa (dhcp->serveraddress));
		free (addr);

#ifdef ENABLE_INFO
		if (options->test) {
			write_info (iface, dhcp, options, false);
			errno = 0;
			return (-1);
		}
#endif

		_send_message (state, DHCP_REQUEST, options);
		state->state = STATE_REQUESTING;

		return (0);
	}

	if (type == DHCP_OFFER) {
		logger (LOG_INFO, "got subsequent offer of %s, ignoring ",
			inet_ntoa (dhcp->address));
		return (0);
	}

	/* We should only be dealing with acks */
	if (type != DHCP_ACK) {
		logger (LOG_ERR, "%d not an ACK or OFFER", type);
		return (0);
	}
	    
	switch (state->state) {
		case STATE_RENEW_REQUESTED:
		case STATE_REQUESTING:
		case STATE_RENEWING:
		case STATE_REBINDING:
			break;
		default:
			logger (LOG_ERR, "wrong state %d", state->state);
	}

	do_socket (state, SOCKET_CLOSED);

#ifdef ENABLE_ARP
	if (options->doarp && iface->previous_address.s_addr !=
	    dhcp->address.s_addr)
	{
		errno = 0;
		if (arp_claim (iface, dhcp->address)) {
			do_socket (state, SOCKET_OPEN);
			_send_message (state, DHCP_DECLINE, options);
			do_socket (state, SOCKET_CLOSED);

			free_dhcp (dhcp);
			memset (dhcp, 0, sizeof (dhcp_t));
			state->xid = 0;
			state->timeout = 0;
			state->state = STATE_INIT;

			/* RFC 2131 says that we should wait for 10 seconds
			   before doing anything else */
			logger (LOG_INFO, "sleeping for 10 seconds");
			tv.tv_sec = 10;
			tv.tv_usec = 0;
			select (0, NULL, NULL, NULL, &tv);
			return (0);
		} else if (errno == EINTR)
			return (0);	
	}
#endif

	if (options->doinform) {
		if (options->request_address.s_addr != 0)
			dhcp->address = options->request_address;
		else
			dhcp->address = iface->previous_address;

		logger (LOG_INFO, "received approval for %s",
			inet_ntoa (dhcp->address));
		if (iface->previous_netmask.s_addr != dhcp->netmask.s_addr) {
			add_address (iface->name, dhcp->address,
				     dhcp->netmask, dhcp->broadcast);
			iface->previous_netmask.s_addr = dhcp->netmask.s_addr;
		}
		state->timeout = options->leasetime;
		if (state->timeout == 0)
			state->timeout = DEFAULT_LEASETIME;
		state->state = STATE_INIT;
	} else if (dhcp->leasetime == (unsigned) -1) {
		dhcp->renewaltime = dhcp->rebindtime = dhcp->leasetime;
		state->timeout = 1; /* So we select on infinity */
		logger (LOG_INFO, "leased %s for infinity",
			inet_ntoa (dhcp->address));
		state->state = STATE_BOUND;
	} else {
		if (! dhcp->leasetime) {
			dhcp->leasetime = DEFAULT_LEASETIME;
			logger(LOG_INFO,
			       "no lease time supplied, assuming %d seconds",
			       dhcp->leasetime);
		}
		logger (LOG_INFO, "leased %s for %u seconds",
			inet_ntoa (dhcp->address), dhcp->leasetime);

		if (dhcp->rebindtime >= dhcp->leasetime) {
			dhcp->rebindtime = (dhcp->leasetime * 0.875);
			logger (LOG_ERR,
				"rebind time greater than lease "
				"time, forcing to %u seconds",
				dhcp->rebindtime);
		}

		if (dhcp->renewaltime > dhcp->rebindtime) {
			dhcp->renewaltime = (dhcp->leasetime * 0.5);
			logger (LOG_ERR,
				"renewal time greater than rebind time, "
				"forcing to %u seconds",
				dhcp->renewaltime);
		}

		if (! dhcp->renewaltime) {
			dhcp->renewaltime = (dhcp->leasetime * 0.5);
			logger (LOG_INFO,
				"no renewal time supplied, assuming %d seconds",
				dhcp->renewaltime);
		} else
			logger (LOG_DEBUG, "renew in %u seconds",
				dhcp->renewaltime);

		if (! dhcp->rebindtime) {
			dhcp->rebindtime = (dhcp->leasetime * 0.875);
			logger (LOG_INFO,
				"no rebind time supplied, assuming %d seconds",
				dhcp->rebindtime);
		} else
			logger (LOG_DEBUG, "rebind in %u seconds",
				dhcp->rebindtime);

		state->timeout = dhcp->renewaltime;
		state->state = STATE_BOUND;
	}

	state->xid = 0;

	if (configure (options, iface, dhcp, true) == -1 && 
	    ! state->daemonised)
		return (-1);

	if (! state->daemonised && options->daemonise) {
		switch (daemonise (state->pidfd)) {
			case 0:
				state->daemonised = true;
				return (0);
			case -1:
				return (-1);
			default:
				state->persistent = true;
				state->forked = true;
				return (-1);
		}
	}

	return (0);
}

static int handle_packet (state_t *state, const options_t *options)
{
	interface_t *iface = state->interface;
	bool valid = false;
	int type;
	struct dhcp_t *new_dhcp;
	dhcpmessage_t message;

	/* Allocate our buffer space for BPF.
	   We cannot do this until we have opened our socket as we don't
	   know how much of a buffer we need until then. */
	if (! state->buffer)
		state->buffer = xmalloc (iface->buffer_length);
	state->buffer_len = iface->buffer_length;
	state->buffer_pos = -1;

	/* We loop through until our buffer is empty.
	   The benefit is that if we get >1 DHCP packet in our buffer and
	   the first one fails for any reason, we can use the next. */

	memset (&message, 0, sizeof (struct dhcpmessage_t));
	new_dhcp = xmalloc (sizeof (dhcp_t));

	while (state->buffer_pos != 0) {
		if (get_packet (iface, (unsigned char *) &message,
				state->buffer,
				&state->buffer_len, &state->buffer_pos) == -1)
			break;

		if (state->xid != message.xid) {
			logger (LOG_DEBUG,
				"ignoring packet with xid 0x%x as it's not ours (0x%x)",
				message.xid, state->xid);
			continue;
		}

		logger (LOG_DEBUG, "got a packet with xid 0x%x", message.xid);
		memset (new_dhcp, 0, sizeof (dhcp_t));
		type = parse_dhcpmessage (new_dhcp, &message);
		if (type == -1) {
			logger (LOG_ERR, "failed to parse packet");
			free_dhcp (new_dhcp);
			/* We don't abort on this, so return zero */
			return (0);
		}

		/* If we got here then the DHCP packet is valid and appears to
		   be for us, so let's clear the buffer as we don't care about
		   any more DHCP packets at this point. */
		valid = true;
		break;
	}

	/* No packets for us, so wait until we get one */
	if (! valid) {
		free (new_dhcp);
		return (0);
	}

	/* new_dhcp is now our master DHCP message */
	free_dhcp (state->dhcp);
	free (state->dhcp);
	state->dhcp = new_dhcp;
	new_dhcp = NULL;

	return (handle_dhcp (state, type, options));
}

int dhcp_run (const options_t *options, int *pidfd)
{
	interface_t *iface;
	state_t *state = NULL;
	fd_set rset;
	int retval = -1;
	int sig;

	if (! options)
		return (-1);	

	iface = read_interface (options->interface, options->metric);
	if (! iface)
		goto eexit;


	state = xmalloc (sizeof (state_t));
	memset (state, 0, sizeof (state_t));
	
	state->dhcp = xmalloc (sizeof (dhcp_t));
	memset (state->dhcp, 0, sizeof (dhcp_t));

	state->pidfd = pidfd;
	state->interface = iface;

	if (! client_setup (state, options))
		goto eexit;

	signal_setup ();

	while (1) {
		retval = wait_for_packet (&rset, state, options);

		/* We should always handle our signals first */
		if ((sig = (signal_read (&rset))) != -1) {
			if (! handle_signal (sig, state, options))
				retval = -1;
		} else if (retval == 0)
			retval = handle_timeout (state, options);
		else if (retval > 0 &&
			 state->socket != SOCKET_CLOSED &&
			 FD_ISSET (iface->fd, &rset))
			retval = handle_packet (state, options);
		else if (retval == -1 && errno == EINTR) {
			/* The interupt will be handled above */
			retval = 0;
		} else {
			logger (LOG_ERR, "error on select: %s",
				strerror (errno));
			retval = -1;
		}

		if (retval != 0)
			break;
	}

eexit:
	do_socket (state, SOCKET_CLOSED);
	drop_config (state, options);

	if (iface) {
		free_route (iface->previous_routes);
		free (iface);
	}

	if (state->forked)
		retval = 0;

	if (state->daemonised)
		unlink (options->pidfile);

	free_dhcp (state->dhcp);
	free (state->dhcp);
	free (state->buffer);
	free (state);

	return (retval);
}
