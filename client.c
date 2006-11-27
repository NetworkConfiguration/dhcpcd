/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2006 Roy Marples <uberlord@gentoo.org>
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

#include <sys/select.h>
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
#include <unistd.h>

#include "arp.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcpcd.h"
#include "interface.h"
#include "logger.h"
#include "signals.h"
#include "socket.h"

/* This is out mini timeout.
   Basically we resend the last request every TIMEOUT_MINI seconds. */
#define TIMEOUT_MINI 		3

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
 if (iface->fd >= 0) close (iface->fd); \
iface->fd = -1; \
if (_mode == SOCKET_OPEN) \
if (open_socket (iface, false) < 0) { retval = -1; goto eexit; } \
mode = _mode;

#define SEND_MESSAGE(_type) \
 memcpy (&last_dhcp, &dhcp, sizeof (struct dhcp_t)); \
last_type = _type; \
send_message (iface, &dhcp, xid, _type, options);

static int daemonise (char *pidfile)
{
  FILE *fp;

  if (daemon (0, 0) < 0)
    {
      logger (LOG_ERR, "unable to daemonise: %s", strerror (errno));
      return -1;
    }

  if ((fp = fopen (pidfile, "w")) == NULL)
    {
      logger (LOG_ERR, "fopen `%s': %m", pidfile);
      return -1;
    }

  fprintf (fp, "%u\n", getpid ());
  fclose (fp);

  return 0;
}

unsigned long random_xid (void)
{
  static int initialized;

  if (! initialized)
    {
      int fd;
      unsigned long seed;

      fd = open ("/dev/urandom", 0);
      if (fd < 0 || read (fd,  &seed, sizeof(seed)) < 0)
	{
	  logger (LOG_WARNING, "Could not load seed from /dev/urandom: %m");
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
int dhcp_run (options_t *options)
{
  interface_t *iface;
  int mode = SOCKET_CLOSED;
  int state = STATE_INIT;
  struct timeval tv;
  int xid = 0;
  unsigned long timeout = 0;
  fd_set rset;
  int maxfd;
  int retval;
  dhcpmessage_t message;
  dhcp_t dhcp;
  dhcp_t last_dhcp;
  int type;
  int last_type = DHCP_REQUEST;
  bool daemonised = false;
  unsigned long start = 0;
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
     afterwards by the user if needed.
     */
  flush_addresses (iface->name);

  memset (&dhcp, 0, sizeof (dhcp_t));
  memset (&last_dhcp, 0, sizeof (dhcp_t));

  dhcp.leasetime = options->leasetime;
  strcpy (dhcp.classid, options->classid);
  if (options->clientid[0])
    strcpy (dhcp.clientid, options->clientid);
  else
    sprintf (dhcp.clientid, "%s", ether_ntoa (&iface->ethernet_address));

  if (options->requestaddress.s_addr != 0)
    memcpy (&dhcp.address, &options->requestaddress, sizeof (struct in_addr));

  signal_setup ();

  while (1)
    {
      int timeout_secs = timeout - uptime();
      tv.tv_sec = timeout - uptime ();
      tv.tv_usec = 0;

      maxfd = signal_fd_set (&rset, iface->fd);

      if (timeout_secs > 0 || (options->timeout == 0 &&
			       (state != STATE_INIT || xid)))
	{
	  if (options->timeout == 0)
	    {
	      logger (LOG_DEBUG, "waiting on select for infinity");
	      retval = select (maxfd + 1, &rset, NULL, NULL, NULL);
	    }
	  else
	    {
	      logger (LOG_DEBUG, "waiting on select for %d seconds",
		      timeout_secs);
	      /* If we're waiting for a reply, then we re-send the last
		 DHCP request periodically in-case of a bad line */
	      if (iface->fd == -1)
		{
		  tv.tv_sec = timeout_secs;
		  tv.tv_usec = 0;
		  retval = select (maxfd + 1, &rset, NULL, NULL, &tv);
		}
	      else
		{
		  while (timeout_secs > 0)
		    {
		      tv.tv_sec = TIMEOUT_MINI;
		      tv.tv_usec = 0;
		      retval = select (maxfd + 1, &rset, NULL, NULL, &tv);
		      if (retval != 0)
			break;
		      send_message (iface, &last_dhcp, xid, last_type, options);
		      timeout_secs -= TIMEOUT_MINI;
		    }
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
	    case SIGINT:
	      logger (LOG_INFO, "receieved SIGINT, stopping");
	      retval = 0;
	      goto eexit;

	    case SIGTERM:
	      logger (LOG_INFO, "receieved SIGTERM, stopping");
	      retval = 0;
	      goto eexit;

	    case SIGALRM:

	      logger (LOG_INFO, "receieved SIGALRM, renewing lease");
	      switch (state)
		{
		case STATE_BOUND:
		  SOCKET_MODE (SOCKET_OPEN);
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
			"receieved SIGUP, but no we have lease to release");
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
		      dhcp.address.s_addr = 0;
		      dhcp.netmask.s_addr = 0;
		      dhcp.broadcast.s_addr = 0;
		      configure (options, iface, &dhcp);
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

	      timeout = uptime () + options->timeout;
	      if (dhcp.address.s_addr == 0)
		logger (LOG_INFO, "broadcasting for lease");
	      else
		logger (LOG_INFO, "broadcasting for lease of %s",
			inet_ntoa (dhcp.address));

	      SOCKET_MODE (SOCKET_OPEN);
	      SEND_MESSAGE (DHCP_DISCOVER);
	      break;
	    case STATE_BOUND:
	      state = STATE_RENEWING;
	    case STATE_RENEWING:
	      logger (LOG_INFO, "renewing lease of %s", inet_ntoa
		      (dhcp.address));
	      SOCKET_MODE (SOCKET_OPEN);
	      xid = random_xid ();
	      SEND_MESSAGE (DHCP_REQUEST);
	      timeout = uptime() + (dhcp.rebindtime - dhcp.renewaltime);
	      state = STATE_REBINDING;
	      break;
	    case STATE_REBINDING:
	      logger (LOG_ERR, "lost lease, attemping to rebind");
	      xid = random_xid ();
	      SEND_MESSAGE (DHCP_DISCOVER);
	      timeout = uptime() + (dhcp.leasetime - dhcp.rebindtime);
	      state = STATE_INIT;
	      break;
	    case STATE_REQUESTING:
	    case STATE_RENEW_REQUESTED:
	      logger (LOG_ERR, "timed out");
	      if (! daemonised)
		{
		  retval = -1;
		  goto eexit;
		}

	      state = STATE_INIT;
	      timeout = uptime();
	      xid = 0;
	      SOCKET_MODE (SOCKET_OPEN);
	      break;

	    case STATE_RELEASED:
	      timeout = 0x7fffffff;
	      break;
	    }
	}
      else if (retval > 0 && mode != SOCKET_CLOSED && FD_ISSET(iface->fd, &rset))
	{

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
	  int valid = 0;
	  while (buffer_pos != 0)
	    {
	      if (get_packet (iface, (unsigned char *) &message, buffer,
			      &buffer_len, &buffer_pos) < 0)
		break;

	      if (xid != message.xid)
		{
		  logger (LOG_ERR, "ignoring transaction %d as it's not ours (%d)",
			  message.xid, xid);
		  continue;
		}

	      logger (LOG_DEBUG, "got packet with transaction %d", message.xid);
	      if ((type = parse_dhcpmessage (&dhcp, &message)) < 0)
		{
		  logger (LOG_ERR, "failed to parse message");
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
	    continue;

	  switch (state)
	    {
	    case STATE_INIT:
	      if (type == DHCP_OFFER)
		{
		  logger (LOG_INFO, "offered lease of %s",
			  inet_ntoa (dhcp.address));

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
		      dhcp.address.s_addr)
		    {
		      if (arp_check (iface, dhcp.address))
			{
			  SOCKET_MODE (SOCKET_OPEN);
			  SEND_MESSAGE (DHCP_DECLINE);
			  SOCKET_MODE (SOCKET_CLOSED);
			  dhcp.address.s_addr = 0;
			  if (daemonised)
			    configure (options, iface, &dhcp);

			  xid = 0;
			  state = STATE_INIT;
			  /* RFC 2131 says that we should wait for 10 seconds
			     before doing anything else */
			  sleep (10);
			  continue;
			}
		    }

		  if (! dhcp.leasetime)
		    {
		      dhcp.leasetime = DEFAULT_TIMEOUT;
		      logger(LOG_INFO,
			     "no lease time supplied, assuming %d seconds",
			     dhcp.leasetime);
		    }

		  if (! dhcp.renewaltime) 
		    {
		      dhcp.renewaltime = dhcp.leasetime / 2;
		      logger (LOG_INFO,
			      "no renewal time supplied, assuming %d seconds",
			      dhcp.renewaltime);
		    }

		  if (! dhcp.rebindtime)
		    {
		      dhcp.rebindtime = (dhcp.leasetime * 0x7) >> 3;
		      logger (LOG_INFO,
			      "no rebind time supplied, assuming %d seconds",
			      dhcp.rebindtime);
		    }

		  logger (LOG_INFO, "leased %s for %d seconds",
			  inet_ntoa (dhcp.address), dhcp.leasetime);
		  state = STATE_BOUND;
		  start = uptime ();
		  timeout = start + dhcp.renewaltime;
		  xid = 0;

		  if (configure (options, iface, &dhcp) < 0 && ! daemonised)
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
	      else if (type == DHCP_NAK)
		logger (LOG_INFO, "received NAK: %s", dhcp.message);
	      else if (type == DHCP_OFFER)
		logger (LOG_INFO, "got subsequent offer of %s, ignoring ",
			inet_ntoa (dhcp.address));
	      else
		logger (LOG_ERR,
			"no idea what to do with DHCP type %d at this point",
			type);
	      break;
	    }
	}
      else if (retval == -1 && errno == EINTR)
	{
	  /* Signal interupt will be handled above */
	}
      else 
	{
	  /* An error occured */
	  logger (LOG_ERR, "error on select: %s", strerror (errno));
	}
    }

eexit:
  SOCKET_MODE (SOCKET_CLOSED);

  /* Remove our config if we need to */
  if (dhcp.address.s_addr != 0 && ! options->persistent && daemonised)
    {
      dhcp.address.s_addr = 0;
      dhcp.netmask.s_addr = 0;
      dhcp.broadcast.s_addr = 0;
      configure (options, iface, &dhcp);
    }

  free_dhcp (&dhcp);

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

