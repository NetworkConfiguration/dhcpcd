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

#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "arp.h"
#include "client.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcpcd.h"
#include "interface.h"
#include "logger.h"
#include "signals.h"
#include "socket.h"

/* We need this for our maximum timeout as FreeBSD's select cannot handle
   any higher than this. Is there a better way of working this out? */
#define SELECT_MAX 100000000 

/* This is out mini timeout.
   Basically we resend the last request every TIMEOUT_MINI seconds. */
#define TIMEOUT_MINI 		3
/* Except for an infinite timeout. We keep adding TIMEOUT_MINI to
   ourself until TIMEOUT_MINI_INF is reached. */
#define TIMEOUT_MINI_INF	60

#define STATE_INIT		0
#define STATE_REQUESTING	1
#define STATE_BOUND		2
#define STATE_RENEWING	        3
#define STATE_REBINDING		4
#define STATE_REBOOT		5
#define STATE_RENEW_REQUESTED	6
#define STATE_RELEASED		7

#define SOCKET_CLOSED		0
#define SOCKET_OPEN		1

#define SOCKET_MODE(_mode) \
{ \
  if (iface->fd >= 0) close (iface->fd); \
  iface->fd = -1; \
  if (_mode == SOCKET_OPEN) \
  if (open_socket (iface, false) < 0) { retval = -1; goto eexit; } \
  mode = _mode; \
}

#define SEND_MESSAGE(_type) \
{ \
  last_type = _type; \
  last_send = uptime (); \
  send_message (iface, dhcp, xid, _type, options); \
}

static int daemonise (const char *pidfile)
{
  logger (LOG_DEBUG, "forking to background");
  if (daemon (0, 0) < 0)
    {
      logger (LOG_ERR, "daemon: %s", strerror (errno));
      return -1;
    }

  make_pid (pidfile);

  return 0;
}

static unsigned long random_xid (void)
{
  static int initialized;

  if (! initialized)
    {
      int fd;
      unsigned long seed;

      fd = open ("/dev/urandom", 0);
      if (fd < 0 || read (fd,  &seed, sizeof(seed)) < 0)
	{
	  logger (LOG_WARNING, "Could not load seed from /dev/urandom: %s",
		  strerror (errno));
	  seed = time (0);
	}
      if (fd >= 0)
	close(fd);

      srand(seed);
      initialized++;
    }

  return rand();
}

/* This state machine is based on the one from udhcpc
   written by Russ Dill */
int dhcp_run (const options_t *options)
{
  interface_t *iface;
  int mode = SOCKET_CLOSED;
  int state = STATE_INIT;
  struct timeval tv;
  int xid = 0;
  long timeout = 0;
  fd_set rset;
  int maxfd;
  int retval;
  dhcpmessage_t message;
  dhcp_t *dhcp;
  int type = DHCP_DISCOVER;
  int last_type = DHCP_DISCOVER;
  bool daemonised = false;
  unsigned long start = 0;
  unsigned long last_send = 0;
  int sig;
  unsigned char *buffer = NULL;
  int buffer_len = 0;
  int buffer_pos = 0;

  if (! options || (iface = (read_interface (options->interface,
					     options->metric))) == NULL)
    return -1;

  /* Remove all existing addresses.
     After all, we ARE a DHCP client whose job it is to configure the
     interface. We only do this on start, so persistent addresses can be added
     afterwards by the user if needed. */
  flush_addresses (iface->name);

  dhcp = xmalloc (sizeof (dhcp_t));
  memset (dhcp, 0, sizeof (dhcp_t));

  if (options->requestaddress.s_addr != 0)
    dhcp->address.s_addr = options->requestaddress.s_addr;

  signal_setup ();

  while (1)
    {
      if (timeout > 0 || (options->timeout == 0 &&
			  (state != STATE_INIT || xid)))
	{
	  if (options->timeout == 0 ||
	      (dhcp->leasetime == (unsigned) -1 && state == STATE_BOUND))
	    {
	      int retry = 0;
	      logger (LOG_DEBUG, "waiting on select for infinity");
	      retval = 0;
	      while (retval == 0)
		{
		  maxfd = signal_fd_set (&rset, iface->fd);
		  if (iface->fd == -1)
		    retval = select (maxfd + 1, &rset, NULL, NULL, NULL);
		  else
		    {
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
	    }
	  else
	    {
	      /* Resend our message if we're getting loads of packets
		 that aren't for us. This mainly happens on Linux as it
		 doesn't have a nice BPF filter. */
	      if (iface->fd > -1 && uptime () - last_send >= TIMEOUT_MINI)
		SEND_MESSAGE (last_type);

	      logger (LOG_DEBUG, "waiting on select for %d seconds",
		      timeout);
	      /* If we're waiting for a reply, then we re-send the last
		 DHCP request periodically in-case of a bad line */
	      retval = 0;
	      while (timeout > 0 && retval == 0)
		{
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
	}
      else
	retval = 0;

      /* We should always handle our signals first */
      if (retval > 0 && (sig = signal_read (&rset)))
	{
	  switch (sig)
	    {
	    case SIGCHLD:
	      /* Silently ignore this signal and wait for it
		 This stops zombies */
	      wait (0);
	      break;
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
	      switch (state)
		{
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
		  xid = random_xid ();
		  if ((open_socket (iface, false)) >= 0)
		    SEND_MESSAGE (DHCP_RELEASE);
		  SOCKET_MODE (SOCKET_CLOSED);
		  unlink (iface->infofile);
		}
	      else
		logger (LOG_ERR,
			"received SIGHUP, but no we have lease to release");
	      retval = 0;
	      goto eexit;

	    default:
	      logger (LOG_ERR,
		      "received signal %d, but don't know what to do with it",
		      sig);
	    }
	}
      else if (retval == 0) /* timed out */
	{
	  switch (state)
	    {
	    case STATE_INIT:
	      if (iface->previous_address.s_addr != 0)
		{
		  logger (LOG_ERR, "lost lease");
		  xid = 0;
		  SOCKET_MODE (SOCKET_CLOSED);
		  if (! options->persistent)
		    {
		      free_dhcp (dhcp);
		      memset (dhcp, 0, sizeof (dhcp_t));
		      configure (options, iface, dhcp);
		    }
		  if (! daemonised)
		    {
		      retval = -1;
		      goto eexit;
		    }
		  break;
		}

	      if (xid == 0)
		xid = random_xid ();
	      else
		{
		  logger (LOG_ERR, "timed out");
		  if (! daemonised)
		    {
		      retval = -1;
		      goto eexit;
		    }
		}

	      SOCKET_MODE (SOCKET_OPEN);
	      timeout = options->timeout;
	      iface->start_uptime = uptime ();
	      if (dhcp->address.s_addr == 0)
		{
		  logger (LOG_INFO, "broadcasting for a lease");
		  SEND_MESSAGE (DHCP_DISCOVER);
		}
	      else
		{
		  logger (LOG_INFO, "broadcasting for a lease of %s",
			  inet_ntoa (dhcp->address));
		  SEND_MESSAGE (DHCP_REQUEST);
		  state = STATE_REQUESTING;
		}

	      break;
	    case STATE_BOUND:
	    case STATE_RENEW_REQUESTED:
	      state = STATE_RENEWING;
	      xid = random_xid ();
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
	      SOCKET_MODE (SOCKET_OPEN);
	      SEND_MESSAGE (DHCP_DISCOVER);
	      timeout = dhcp->leasetime - dhcp->rebindtime;
	      state = STATE_INIT;
	      break;
	    case STATE_REQUESTING:
	      logger (LOG_ERR, "timed out");
	      if (! daemonised)
		goto eexit;

	      state = STATE_INIT;
	      SOCKET_MODE (SOCKET_CLOSED);
	      timeout = 0;
	      xid = 0;
	      free_dhcp (dhcp);
	      memset (dhcp, 0, sizeof (dhcp_t));
	      break;

	    case STATE_RELEASED:
	      dhcp->leasetime = -1;
	      break;
	    }
	}
      else if (retval > 0 && mode != SOCKET_CLOSED && FD_ISSET(iface->fd, &rset))
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

	  while (buffer_pos != 0)
	    {
	      if (get_packet (iface, (unsigned char *) &message, buffer,
			      &buffer_len, &buffer_pos) < 0)
		break;

	      if (xid != message.xid)
		{
		  logger (LOG_ERR,
			  "ignoring packet with xid %d as it's not ours (%d)",
			  message.xid, xid);
		  continue;
		}

	      logger (LOG_DEBUG, "got a packet with xid %d", message.xid);
	      memset (new_dhcp, 0, sizeof (dhcp_t));
	      if ((type = parse_dhcpmessage (new_dhcp, &message)) < 0)
		{
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
	  if (! valid)
	    {
	      free (new_dhcp);
	      continue;
	    }

	  /* new_dhcp is now our master DHCP message */
	  free_dhcp (dhcp);
	  free (dhcp);
	  dhcp = new_dhcp;
	  new_dhcp = NULL;

	  /* We should restart on a NAK */
	  if (type == DHCP_NAK)
	    {
	      logger (LOG_INFO, "received NAK: %s", dhcp->message);
	      state = STATE_INIT;
	      timeout = 0;
	      xid = 0;
	      free_dhcp (dhcp);
	      memset (dhcp, 0, sizeof (dhcp_t));
	      configure (options, iface, dhcp);
	      continue;
	    }

	  switch (state)
	    {
	    case STATE_INIT:
	      if (type == DHCP_OFFER)
		{
		  char *addr = strdup (inet_ntoa (dhcp->address));
		  if (dhcp->servername)
		    logger (LOG_INFO, "offered %s from %s `%s'",
			    addr, inet_ntoa (dhcp->serveraddress),
			    dhcp->servername);
		  else
		    logger (LOG_INFO, "offered %s from %s",
			    addr, inet_ntoa (dhcp->serveraddress));
		  free (addr);

		  SEND_MESSAGE (DHCP_REQUEST);
		  state = STATE_REQUESTING;
		}
	      break;

	    case STATE_RENEW_REQUESTED:
	    case STATE_REQUESTING:
	    case STATE_RENEWING:
	    case STATE_REBINDING:
	      if (type == DHCP_ACK)
		{
		  SOCKET_MODE (SOCKET_CLOSED);
		  if (options->doarp && iface->previous_address.s_addr !=
		      dhcp->address.s_addr)
		    {
		      if (arp_check (iface, dhcp->address))
			{
			  SOCKET_MODE (SOCKET_OPEN);
			  SEND_MESSAGE (DHCP_DECLINE);
			  SOCKET_MODE (SOCKET_CLOSED);

			  free_dhcp (dhcp);
			  memset (dhcp, 0, sizeof (dhcp_t));
 
			  if (daemonised)
			    configure (options, iface, dhcp);

			  xid = 0;
			  timeout = 0;
			  state = STATE_INIT;
			  /* RFC 2131 says that we should wait for 10 seconds
			     before doing anything else */
			  logger (LOG_INFO, "sleeping for 10 seconds");
			  sleep (10);
			  continue;
			}
		    }

		  if (dhcp->leasetime == (unsigned) -1)
		    {
		      dhcp->renewaltime = dhcp->rebindtime = dhcp->leasetime;
		      timeout = 1; /* So we select on infinity */
		      logger (LOG_INFO, "leased %s for infinity",
			      inet_ntoa (dhcp->address));
		    }
		  else
		    {
		      if (! dhcp->leasetime)
			{
			  dhcp->leasetime = DEFAULT_TIMEOUT;
			  logger(LOG_INFO,
				 "no lease time supplied, assuming %d seconds",
				 dhcp->leasetime);
			}
		      else
			logger (LOG_INFO, "leased %s for %u seconds",
				inet_ntoa (dhcp->address), dhcp->leasetime);

		      if (dhcp->rebindtime >= dhcp->leasetime)
			{
			  dhcp->rebindtime = (dhcp->leasetime * 0.875);
			  logger (LOG_ERR, "rebind time greater than lease "
				  "time, forcing to %u seconds",
				  dhcp->rebindtime);
			}

		      if (dhcp->renewaltime > dhcp->rebindtime)
			{
			
			  dhcp->renewaltime = (dhcp->leasetime * 0.5);
			  logger (LOG_ERR, "renewal time greater than rebind time, "
				  "forcing to %u seconds",
				  dhcp->renewaltime);
			}

		      if (! dhcp->renewaltime) 
			{
			  dhcp->renewaltime = (dhcp->leasetime * 0.5);
			  logger (LOG_INFO,
				  "no renewal time supplied, assuming %d seconds",
				  dhcp->renewaltime);
			}
		      else
			logger (LOG_DEBUG, "renew in %u seconds",
				dhcp->renewaltime);

		      if (! dhcp->rebindtime)
			{
			  dhcp->rebindtime = (dhcp->leasetime * 0.875);
			  logger (LOG_INFO,
				  "no rebind time supplied, assuming %d seconds",
				  dhcp->rebindtime);
			}
		      else
			logger (LOG_DEBUG, "rebind in %u seconds",
				dhcp->rebindtime);

		      timeout = dhcp->renewaltime;
		    }

		  state = STATE_BOUND;
		  xid = 0;

		  if (configure (options, iface, dhcp) < 0 && ! daemonised)
		    {
		      retval = -1;
		      goto eexit;
		    }

		  if (! daemonised)
		    {
		      if ((daemonise (options->pidfile)) < 0 )
			{
			  retval = -1;
			  goto eexit;
			}
		      daemonised = true;
		    }
		}
	      else if (type == DHCP_OFFER)
		logger (LOG_INFO, "got subsequent offer of %s, ignoring ",
			inet_ntoa (dhcp->address));
	      else
		logger (LOG_ERR,
			"no idea what to do with DHCP type %d at this point",
			type);
	      break;
	    }
	}
      else if (retval == -1 && errno == EINTR)
	{
	  /* The interupt will be handled above */
	}
      else 
	{
	  /* An error occured. As we heavily depend on select, we abort. */
	  logger (LOG_ERR, "error on select: %s", strerror (errno));
	  retval = -1;
	  goto eexit;
	}
    }

eexit:
  SOCKET_MODE (SOCKET_CLOSED);

  /* Remove our config if we need to */
  free_dhcp (dhcp);
  memset (dhcp, 0, sizeof (dhcp_t));
  if (iface->previous_address.s_addr != 0 && ! options->persistent && daemonised)
    configure (options, iface, dhcp);
  free (dhcp);

  if (iface)
    {
      if (iface->previous_routes)
	free_route (iface->previous_routes);
      free (iface);
    }

  if (buffer)
    free (buffer);

  logger (LOG_INFO, "exiting");

  /* Unlink our pidfile */
  unlink (options->pidfile);

  return retval;
}

