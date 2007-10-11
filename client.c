/*
 * dhcpcd - DHCP client daemon -
 * Copyright 2006-2007 Roy Marples <uberlord@gentoo.org>
 * 
 * dhcpcd is an RFC2131 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#ifdef __linux__
# define _BSD_SOURCE
# define _XOPEN_SOURCE 500 /* needed for pwrite */
#endif

#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
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
#include "signals.h"
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

#define SOCKET_CLOSED           0
#define SOCKET_OPEN             1

#define SOCKET_MODE(_mode) { \
	if (iface->fd >= 0) close (iface->fd); \
	iface->fd = -1; \
	if (_mode == SOCKET_OPEN) \
	if (open_socket (iface, false) == -1) { retval = EXIT_FAILURE; goto eexit; } \
	mode = _mode; \
}

#define SEND_MESSAGE(_type) { \
	last_type = _type; \
	last_send = uptime (); \
	if (send_message (iface, dhcp, xid, _type, options) == (size_t) -1) { \
		retval = -1; \
		goto eexit; \
	} \
}

#define DROP_CONFIG { \
	if (! persistent) \
	configure (options, iface, dhcp, false); \
	free_dhcp (dhcp); \
	memset (dhcp, 0, sizeof (dhcp_t)); \
}

static pid_t daemonise (int *pidfd)
{
	pid_t pid;
	char spid[16];

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
	for (i = 0; i < dhcpcd_argc; i++)
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
			logger (LOG_ERR, "execl `%s': %s", dhcpcd, strerror (errno));
			_exit (EXIT_FAILURE);
	}

	free (argv);
#endif

	if (pid != 0) {
		if (ftruncate (*pidfd, 0) == -1) {
			logger (LOG_ERR, "ftruncate: %s", strerror (errno));
		} else {
			snprintf (spid, sizeof (spid), "%u", pid);
			if (pwrite (*pidfd, spid, strlen (spid), 0) != (ssize_t) strlen (spid))
				logger (LOG_ERR, "pwrite: %s", strerror (errno));
		}
	}

	return (pid);
}

#ifdef ENABLE_INFO
static bool get_old_lease (const options_t *options, interface_t *iface,
						   dhcp_t *dhcp, time_t *timeout)
{
	struct timeval tv;
	unsigned int offset = 0;

	logger (LOG_INFO, "trying to use old lease in `%s'", iface->infofile);
	if (! read_info (iface, dhcp))
		return (false);

	/* Vitaly important we remove the server information here */
	memset (&dhcp->serveraddress, 0, sizeof (struct in_addr));
	memset (dhcp->servername, 0, sizeof (dhcp->servername));

#ifdef ENABLE_ARP
	/* Check that no-one is using the address */
	if ((options->dolastlease || 
		 (IN_LINKLOCAL (dhcp->address.s_addr) &&
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
	if (timeout)
		*timeout = dhcp->renewaltime - offset;
	iface->start_uptime = uptime ();
	return (true);
}
#endif

/* This state machine is based on the one from udhcpc
   written by Russ Dill */
int dhcp_run (const options_t *options, int *pidfd)
{
	interface_t *iface;
	int mode = SOCKET_CLOSED;
	int state = STATE_INIT;
	struct timeval tv;
	int xid = 0;
	time_t timeout = 0;
	fd_set rset;
	int maxfd;
	int retval;
	dhcpmessage_t message;
	dhcp_t *dhcp;
	int type = DHCP_DISCOVER;
	int last_type = DHCP_DISCOVER;
	bool daemonised = options->daemonised;
	bool persistent = options->persistent;
	time_t start = 0;
	time_t last_send = 0;
	int sig;
	unsigned char *buffer = NULL;
	int buffer_len = 0;
	int buffer_pos = 0;

	if (! options || (iface = (read_interface (options->interface,
											   options->metric))) == NULL)
		return (-1);

#ifdef ENABLE_DUID
	if (options->clientid_len == 0) {
		get_duid (iface);
		if (iface->duid_length > 0)
			logger (LOG_INFO, "DUID = %s",
					hwaddr_ntoa (iface->duid, iface->duid_length));
	}
#endif

	dhcp = xmalloc (sizeof (dhcp_t));
	memset (dhcp, 0, sizeof (dhcp_t));

	if (options->request_address.s_addr == 0 &&
		(options->doinform || options->dorequest || options->daemonised))
	{
#ifdef ENABLE_INFO
		if (! get_old_lease (options, iface, dhcp, NULL))
#endif
		{
			free (dhcp);
			return (-1);
		}

#ifdef THERE_IS_NO_FORK
		if (options->daemonised) {
			state = STATE_BOUND;
			timeout = dhcp->renewaltime;
			iface->previous_address = dhcp->address;
			iface->previous_netmask = dhcp->netmask;

			/* FIXME: Some routes may not be added for whatever reason.
			 * This is especially true on BSD platforms where we can only
			 * have one default route. */
			if (dhcp->routes) {
				int i = -1;
				route_t *droute;
				route_t *iroute = NULL;
				
				free_route (iface->previous_routes);

				for (droute = dhcp->routes; droute; droute = droute->next) {
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
						iroute = iface->previous_routes = xmalloc (sizeof (route_t));
					memcpy (iroute, droute, sizeof (route_t));
					if (droute->next) {
						iroute->next = xmalloc (sizeof (route_t));
						iroute = iroute->next;
					}
				}

				/* We no longer need this argument */
				free (dhcpcd_skiproutes);
				dhcpcd_skiproutes = NULL;
			}
		}
#endif

	} else {
		dhcp->address = options->request_address;
		dhcp->netmask = options->request_netmask;
		if (dhcp->netmask.s_addr == 0)
			dhcp->netmask.s_addr = get_netmask (dhcp->address.s_addr);
		dhcp->broadcast.s_addr = dhcp->address.s_addr | ~dhcp->netmask.s_addr;
	}

	/* Remove all existing addresses.
	   After all, we ARE a DHCP client whose job it is to configure the
	   interface. We only do this on start, so persistent addresses can be added
	   afterwards by the user if needed. */
	if (! options->test && ! options->daemonised) {
		if (! options->doinform) {
			flush_addresses (iface->name);
		} else {
			/* The inform address HAS to be configured for it to work with most
			 * DHCP servers */
			if (options->doinform && has_address (iface->name, dhcp->address) < 1) {
				add_address (iface->name, dhcp->address, dhcp->netmask,
							 dhcp->broadcast);
				iface->previous_address = dhcp->address;
				iface->previous_netmask = dhcp->netmask;
			}
		}
	}

	signal_setup ();

	while (1) {
		if (timeout > 0 || (options->timeout == 0 &&
							(state != STATE_INIT || xid)))
		{
			if ((options->timeout == 0 && xid) ||
				(dhcp->leasetime == (unsigned) -1 && state == STATE_BOUND))
			{
				int retry = 0;
				logger (LOG_DEBUG, "waiting on select for infinity");
				retval = 0;
				while (retval == 0)	{
					maxfd = signal_fd_set (&rset, iface->fd);
					if (iface->fd == -1)
						retval = select (maxfd + 1, &rset, NULL, NULL, NULL);
					else {
						/* Slow down our requests */
						if (retry < TIMEOUT_MINI_INF)
							retry += TIMEOUT_MINI;
						else if (retry > TIMEOUT_MINI_INF)
							retry = TIMEOUT_MINI_INF;

						tv.tv_sec = retry;
						tv.tv_usec = 0;
						retval = select (maxfd + 1, &rset, NULL, NULL, &tv);
						if (retval == 0)
							SEND_MESSAGE (last_type);
					}
				}
			} else {
				/* Resend our message if we're getting loads of packets
				   that aren't for us. This mainly happens on Linux as it
				   doesn't have a nice BPF filter. */
				if (iface->fd > -1 && uptime () - last_send >= TIMEOUT_MINI)
					SEND_MESSAGE (last_type);

				logger (LOG_DEBUG, "waiting on select for %ld seconds",
						(unsigned long) timeout);
				/* If we're waiting for a reply, then we re-send the last
				   DHCP request periodically in-case of a bad line */
				retval = 0;
				while (timeout > 0 && retval == 0) {
					if (iface->fd == -1)
						tv.tv_sec = SELECT_MAX;
					else
						tv.tv_sec = TIMEOUT_MINI;
					if (timeout < tv.tv_sec)
						tv.tv_sec = timeout;
					tv.tv_usec = 0;
					start = uptime ();
					maxfd = signal_fd_set (&rset, iface->fd);
					retval = select (maxfd + 1, &rset, NULL, NULL, &tv);
					timeout -= uptime () - start;
					if (retval == 0 && iface->fd != -1 && timeout > 0)
						SEND_MESSAGE (last_type);
				}
			}
		} else
			retval = 0;

		/* We should always handle our signals first */
		if ((sig = (signal_read (NULL))) != -1)
		{
			switch (sig) {
				case SIGINT:
					logger (LOG_INFO, "received SIGINT, stopping");
					retval = (! daemonised);
					goto eexit;

				case SIGTERM:
					logger (LOG_INFO, "received SIGTERM, stopping");
					retval = (! daemonised);
					goto eexit;

				case SIGALRM:

					logger (LOG_INFO, "received SIGALRM, renewing lease");
					switch (state) {
						case STATE_BOUND:
						case STATE_RENEWING:
						case STATE_REBINDING:
							state = STATE_RENEW_REQUESTED;
							break;
						case STATE_RENEW_REQUESTED:
						case STATE_REQUESTING:
						case STATE_RELEASED:
							state = STATE_INIT;
							break;
					}

					timeout = 0;
					xid = 0;
					break;

				case SIGHUP:
					if (state == STATE_BOUND || state == STATE_RENEWING
						|| state == STATE_REBINDING)
					{
						logger (LOG_INFO, "received SIGHUP, releasing lease");
						SOCKET_MODE (SOCKET_OPEN);
						xid = random ();
						if ((open_socket (iface, false)) >= 0)
							SEND_MESSAGE (DHCP_RELEASE);
						SOCKET_MODE (SOCKET_CLOSED);
						unlink (iface->infofile);
					}
					else
						logger (LOG_ERR,
								"received SIGHUP, but we no have lease to release");
					retval = 0;
					goto eexit;

				default:
					logger (LOG_ERR,
							"received signal %d, but don't know what to do with it",
							sig);
			}
		} else if (retval == 0) {
			/* timed out */
			switch (state) {
				case STATE_INIT:
					if (xid != 0) {
						if (iface->previous_address.s_addr != 0 &&
#ifdef ENABLE_IPV4LL
							! IN_LINKLOCAL (iface->previous_address.s_addr) &&
#endif
							! options->doinform)
						{
							logger (LOG_ERR, "lost lease");
							if (! options->persistent)
								DROP_CONFIG;
						} else
							logger (LOG_ERR, "timed out");
						
						SOCKET_MODE (SOCKET_CLOSED);
						free_dhcp (dhcp);
						memset (dhcp, 0, sizeof (dhcp_t));
					
#ifdef ENABLE_INFO
						if (! options->test &&
							(options->doipv4ll || options->dolastlease))
						{
							errno = 0;
							if (! get_old_lease (options, iface, dhcp, &timeout))
							{
								if (errno == EINTR)
									break;
								if (options->dolastlease) {
									retval = EXIT_FAILURE;
									goto eexit;
								}
								free_dhcp (dhcp);
								memset (dhcp, 0, sizeof (dhcp_t));
							} else if (errno == EINTR)
								break;
						}
#endif

#ifdef ENABLE_IPV4LL
						if (! options->test && options->doipv4ll &&
							(! dhcp->address.s_addr ||
							 (! IN_LINKLOCAL (dhcp->address.s_addr) &&
							  ! options->dolastlease)))
						{
							logger (LOG_INFO, "probing for an IPV4LL address");
							free_dhcp (dhcp);
							memset (dhcp, 0, sizeof (dhcp_t));
							if (ipv4ll_get_address (iface, dhcp) == -1) {
								break;
							}
							timeout = dhcp->renewaltime;
						}
#endif

#if defined (ENABLE_INFO) || defined (ENABLE_IPV4LL)
						if (dhcp->address.s_addr)
						{
							if (configure (options, iface, dhcp, true) == -1 &&
								! daemonised)
							{
								retval = EXIT_FAILURE;
								goto eexit;
							}

							state = STATE_BOUND;
							if (! daemonised && options->daemonise) {
								switch (daemonise (pidfd)) {
									case -1:
										retval = EXIT_FAILURE;
										goto eexit;
									case 0:
										daemonised = true;
										break;
									default:
										persistent = true;
										retval = EXIT_SUCCESS;
										goto eexit;
								}
							}

							timeout = dhcp->renewaltime;
							xid = 0;
							break;
						}
#endif

						if (! daemonised) {
							retval = EXIT_FAILURE;
							goto eexit;
						}
					}

					xid = random ();
					SOCKET_MODE (SOCKET_OPEN);
					timeout = options->timeout;
					iface->start_uptime = uptime ();
					if (dhcp->address.s_addr == 0) {
						logger (LOG_INFO, "broadcasting for a lease");
						SEND_MESSAGE (DHCP_DISCOVER);
					} else if (options->doinform) {
						logger (LOG_INFO, "broadcasting inform for %s",
								inet_ntoa (dhcp->address));
						SEND_MESSAGE (DHCP_INFORM);
						state = STATE_REQUESTING;
					} else {
						logger (LOG_INFO, "broadcasting for a lease of %s",
								inet_ntoa (dhcp->address));
						SEND_MESSAGE (DHCP_REQUEST);
						state = STATE_REQUESTING;
					}

					break;
				case STATE_BOUND:
				case STATE_RENEW_REQUESTED:
#ifdef ENABLE_IPV4LL
					if (IN_LINKLOCAL (dhcp->address.s_addr)) {
						memset (&dhcp->address, 0, sizeof (struct in_addr));
						state = STATE_INIT;
						xid = 0;
						break;
					}
#endif
					state = STATE_RENEWING;
					xid = random ();
				case STATE_RENEWING:
					iface->start_uptime = uptime ();
					logger (LOG_INFO, "renewing lease of %s", inet_ntoa
							(dhcp->address));
					SOCKET_MODE (SOCKET_OPEN);
					SEND_MESSAGE (DHCP_REQUEST);
					timeout = dhcp->rebindtime - dhcp->renewaltime;
					state = STATE_REBINDING;
					break;
				case STATE_REBINDING:
					logger (LOG_ERR, "lost lease, attemping to rebind");
					memset (&dhcp->address, 0, sizeof (struct in_addr));
					SOCKET_MODE (SOCKET_OPEN);
					if (xid == 0)
						xid = random ();
					SEND_MESSAGE (DHCP_REQUEST);
					timeout = dhcp->leasetime - dhcp->rebindtime;
					state = STATE_REQUESTING;
					break;
				case STATE_REQUESTING:
					state = STATE_INIT;
					SOCKET_MODE (SOCKET_CLOSED);
					timeout = 0;
					break;

				case STATE_RELEASED:
					dhcp->leasetime = -1;
					break;
			}
		} else if (retval > 0 &&
				   mode != SOCKET_CLOSED &&
				   FD_ISSET(iface->fd, &rset))
		{
			int valid = 0;
			struct dhcp_t *new_dhcp;

			/* Allocate our buffer space for BPF.
			   We cannot do this until we have opened our socket as we don't
			   know how much of a buffer we need until then. */
			if (! buffer)
				buffer = xmalloc (iface->buffer_length);
			buffer_len = iface->buffer_length;
			buffer_pos = -1;

			/* We loop through until our buffer is empty.
			   The benefit is that if we get >1 DHCP packet in our buffer and
			   the first one fails for any reason, we can use the next. */

			memset (&message, 0, sizeof (struct dhcpmessage_t));
			new_dhcp = xmalloc (sizeof (dhcp_t));

			while (buffer_pos != 0) {
				if (get_packet (iface, (unsigned char *) &message, buffer,
								&buffer_len, &buffer_pos) == -1)
					break;

				if (xid != message.xid) {
					logger (LOG_DEBUG,
							"ignoring packet with xid 0x%x as it's not ours (0x%x)",
							message.xid, xid);
					continue;
				}

				logger (LOG_DEBUG, "got a packet with xid 0x%x", message.xid);
				memset (new_dhcp, 0, sizeof (dhcp_t));
				if ((type = parse_dhcpmessage (new_dhcp, &message)) == -1) {
					logger (LOG_ERR, "failed to parse packet");
					free_dhcp (new_dhcp);
					continue;
				}

				/* If we got here then the DHCP packet is valid and appears to
				   be for us, so let's clear the buffer as we don't care about
				   any more DHCP packets at this point. */
				valid = 1;
				break;
			}

			/* No packets for us, so wait until we get one */
			if (! valid) {
				free (new_dhcp);
				continue;
			}

			/* new_dhcp is now our master DHCP message */
			free_dhcp (dhcp);
			free (dhcp);
			dhcp = new_dhcp;
			new_dhcp = NULL;

			/* We should restart on a NAK */
			if (type == DHCP_NAK) {
				logger (LOG_INFO, "received NAK: %s", dhcp->message);
				state = STATE_INIT;
				timeout = 0;
				xid = 0;
				free_dhcp (dhcp);
				memset (dhcp, 0, sizeof (dhcp_t));
				continue;
			}

			switch (state) {
				case STATE_INIT:
					if (type == DHCP_OFFER) {
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
							goto eexit;
						}
#endif
						
						SEND_MESSAGE (DHCP_REQUEST);
						state = STATE_REQUESTING;
					}
					break;

				case STATE_RENEW_REQUESTED:
				case STATE_REQUESTING:
				case STATE_RENEWING:
				case STATE_REBINDING:
					if (type == DHCP_ACK) {
						SOCKET_MODE (SOCKET_CLOSED);
#ifdef ENABLE_ARP
						if (options->doarp && iface->previous_address.s_addr !=
							dhcp->address.s_addr)
						{
							errno = 0;
							if (arp_claim (iface, dhcp->address)) {
								SOCKET_MODE (SOCKET_OPEN);
								SEND_MESSAGE (DHCP_DECLINE);
								SOCKET_MODE (SOCKET_CLOSED);

								free_dhcp (dhcp);
								memset (dhcp, 0, sizeof (dhcp_t));
								xid = 0;
								timeout = 0;
								state = STATE_INIT;

								/* RFC 2131 says that we should wait for 10 seconds
								   before doing anything else */
								logger (LOG_INFO, "sleeping for 10 seconds");
								tv.tv_sec = 10;
								tv.tv_usec = 0;
								select (0, NULL, NULL, NULL, &tv);
								continue;
							} else if (errno == EINTR)
								break;
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
							timeout = options->leasetime;
							if (timeout == 0)
								timeout = DEFAULT_LEASETIME;
							state = STATE_INIT;
						} else if (dhcp->leasetime == (unsigned) -1) {
							dhcp->renewaltime = dhcp->rebindtime = dhcp->leasetime;
							timeout = 1; /* So we select on infinity */
							logger (LOG_INFO, "leased %s for infinity",
									inet_ntoa (dhcp->address));
							state = STATE_BOUND;
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
								logger (LOG_ERR, "rebind time greater than lease "
										"time, forcing to %u seconds",
										dhcp->rebindtime);
							}

							if (dhcp->renewaltime > dhcp->rebindtime) {
								dhcp->renewaltime = (dhcp->leasetime * 0.5);
								logger (LOG_ERR, "renewal time greater than rebind time, "
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

							timeout = dhcp->renewaltime;
							state = STATE_BOUND;
						}

						xid = 0;

						if (configure (options, iface, dhcp, true) == -1 &&
							! daemonised)
						{
							retval = EXIT_FAILURE;
							goto eexit;
						}

						if (! daemonised && options->daemonise) {
							switch (daemonise (pidfd)) {
								case -1:
									retval = EXIT_FAILURE;
									goto eexit;
								case 0:
									daemonised = true;
									break;
								default:
									persistent = true;
									retval = EXIT_SUCCESS;
									goto eexit;
							}
						}
					} else if (type == DHCP_OFFER)
						logger (LOG_INFO, "got subsequent offer of %s, ignoring ",
								inet_ntoa (dhcp->address));
					else
						logger (LOG_ERR,
								"no idea what to do with DHCP type %d at this point",
								type);
					break;
			}
		} else if (retval == -1 && errno == EINTR) {
			/* The interupt will be handled above */
		} else {
			/* An error occured. As we heavily depend on select, we abort. */
			logger (LOG_ERR, "error on select: %s", strerror (errno));
			retval = EXIT_FAILURE;
			goto eexit;
		}
	}

eexit:
	SOCKET_MODE (SOCKET_CLOSED);
	DROP_CONFIG;
	free (dhcp);

	if (iface) {
		free_route (iface->previous_routes);
		free (iface);
	}

	free (buffer);

	if (*pidfd != -1) {
		close (*pidfd);
		*pidfd = -1;
	}

	if (daemonised)
		unlink (options->pidfile);

	return retval;
}

