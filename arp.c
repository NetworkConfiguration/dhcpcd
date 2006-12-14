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

/* OK, a lot of this was lifting from iputils as the existing code
   for dhcpcd was kinda klunky and had some issues */

#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#ifdef __linux
#include <netinet/ether.h>
#include <netpacket/packet.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "arp.h"
#include "interface.h"
#include "logger.h"
#include "socket.h"

/* Longer is safer and slower - 2 seconds seems a happy medium */
#define TIMEOUT 2 

/* Linux does not seem to define these handy macros */
#ifndef ar_sha
#define ar_sha(ap) (((unsigned char *) ((ap) + 1)) + 0)
#define ar_spa(ap) (((unsigned char *) ((ap) + 1)) + (ap)->ar_hln)
#define ar_tha(ap) (((unsigned char *) ((ap) + 1)) + (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap) (((unsigned char *) ((ap) + 1)) + 2 * (ap)->ar_hln + (ap)->ar_pln)

#define arphdr_len2(ar_hln, ar_pln) (sizeof (struct arphdr) + 2 * (ar_hln) + 2 * (ar_pln))
#define arphdr_len(ap) (arphdr_len2 ((ap)->ar_hln, (ap)->ar_pln))
#endif

int arp_check (interface_t *iface, struct in_addr address)
{
  if (! iface->arpable)
    {
      logger (LOG_DEBUG, "arp_check: interface `%s' is not ARPable",
	      iface->name);
      return 0;
    }

  unsigned char buf[256];
  struct arphdr *ah = (struct arphdr *) buf;

  memset (buf, 0, sizeof (buf));

  ah->ar_hrd = htons (ARPHRD_ETHER);
  ah->ar_pro = htons (ETHERTYPE_IP);
  ah->ar_hln = ETHER_ADDR_LEN;
  ah->ar_pln = sizeof (struct in_addr);
  ah->ar_op = htons (ARPOP_REQUEST);
  memcpy (ar_sha (ah), &iface->ethernet_address, ah->ar_hln);
  memcpy (ar_tpa (ah), &address, ah->ar_pln);

  logger (LOG_INFO, "checking %s is available on attached networks", inet_ntoa
	  (address));

  open_socket (iface, true);
  send_packet (iface, ETHERTYPE_ARP, (unsigned char *) &buf, arphdr_len(ah));

  unsigned char reply[4096];
  int bytes;
  unsigned char buffer[iface->buffer_length];

  struct timeval tv;
  long timeout = 0;
  fd_set rset;

  timeout = uptime() + TIMEOUT;
  while (1)
    {
      tv.tv_sec = timeout - uptime ();
      tv.tv_usec = 0;

      if (tv.tv_sec < 1)
	break; /* Time out */

      FD_ZERO (&rset);
      FD_SET (iface->fd, &rset);

      if (select (iface->fd + 1, &rset, NULL, NULL, &tv) == 0)
	break;

      if (! FD_ISSET (iface->fd, &rset))
	continue;

      memset (buffer, 0, sizeof (buffer));
      int buflen = sizeof (buffer);
      int bufpos = -1;

      while (bufpos != 0)
	{
	  memset (reply, 0, sizeof (reply));
	  if ((bytes = get_packet (iface, (unsigned char *) &reply, buffer,
				   &buflen, &bufpos)) < 0)
	    break;

	  ah = (struct arphdr *) reply;

	  /* Only these types are recognised */
	  if (ah->ar_op != htons(ARPOP_REPLY)
	      || ah->ar_hrd != htons (ARPHRD_ETHER))
	    continue;

	  /* Protocol must be IP. */
	  if (ah->ar_pro != htons (ETHERTYPE_IP))
	    continue;
	  if (ah->ar_pln != sizeof (struct in_addr))
	    continue;

	  if (ah->ar_hln != ETHER_ADDR_LEN)
	    continue;
	  if ((unsigned) bytes < sizeof (*ah) + 2 * (4 + ah->ar_hln))
	    continue;

	  logger (LOG_ERR, "ARPOP_REPLY received from %s (%s)",
		  inet_ntoa (* (struct in_addr *) ar_spa (ah)),
		  ether_ntoa ((struct ether_addr *) ar_sha (ah)));
	  close (iface->fd);
	  iface->fd = -1;
	  return 1;
	}
    }

  close (iface->fd);
  iface->fd = -1;
  return 0;
}

