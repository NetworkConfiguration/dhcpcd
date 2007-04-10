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
#define ar_tha(ap) (((unsigned char *) ((ap) + 1)) + \
                    (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap) (((unsigned char *) ((ap) + 1)) + \
                    2 * (ap)->ar_hln + (ap)->ar_pln)
#define arphdr_len2(ar_hln, ar_pln) (sizeof (struct arphdr) + \
                                     2 * (ar_hln) + 2 * (ar_pln))
#define arphdr_len(ap) (arphdr_len2 ((ap)->ar_hln, (ap)->ar_pln))
#endif

int arp_check (interface_t *iface, struct in_addr address)
{
  union
    {
      unsigned char buffer[iface->buffer_length];
      struct arphdr ah;
    } arp;

  int bytes;
  struct timeval tv;
  long timeout = 0;
  fd_set rset;

  if (! iface->arpable)
    {
      logger (LOG_DEBUG, "arp_check: interface `%s' is not ARPable",
              iface->name);
      return 0;
    }

  memset (arp.buffer, 0, sizeof (arp.buffer));

  arp.ah.ar_hrd = htons (iface->family);
  arp.ah.ar_pro = htons (ETHERTYPE_IP);
  arp.ah.ar_hln = iface->hwlen;
  arp.ah.ar_pln = sizeof (struct in_addr);
  arp.ah.ar_op = htons (ARPOP_REQUEST);
  memcpy (ar_sha (&arp.ah), &iface->hwaddr, arp.ah.ar_hln);
  memcpy (ar_tpa (&arp.ah), &address, arp.ah.ar_pln);

  logger (LOG_INFO, "checking %s is available on attached networks", inet_ntoa
          (address));

  open_socket (iface, true);
  send_packet (iface, ETHERTYPE_ARP, (unsigned char *) &arp.buffer,
               arphdr_len (&arp.ah));

  timeout = uptime() + TIMEOUT;
  while (1)
    {
      int buflen = sizeof (arp.buffer);
      int bufpos = -1;

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

      memset (arp.buffer, 0, sizeof (arp.buffer));

      while (bufpos != 0)
        {
          union
            {
              unsigned char buffer[buflen];
              struct arphdr hdr;
            } reply;
          union
            {
              unsigned char *c;
              struct in_addr *a;
            } rp;
          union
            {
              unsigned char *c;
              struct ether_addr *a;
            } rh;
          memset (reply.buffer, 0, sizeof (reply.buffer));
          if ((bytes = get_packet (iface, reply.buffer, arp.buffer,
                                   &buflen, &bufpos)) < 0)
            break;

          /* Only these types are recognised */
          if (reply.hdr.ar_op != htons(ARPOP_REPLY))
            continue;

          /* Protocol must be IP. */
          if (reply.hdr.ar_pro != htons (ETHERTYPE_IP))
            continue;
          if (reply.hdr.ar_pln != sizeof (struct in_addr))
            continue;

          if (reply.hdr.ar_hln != ETHER_ADDR_LEN)
            continue;
          if ((unsigned) bytes < sizeof (reply.hdr) + 
              2 * (4 + reply.hdr.ar_hln))
            continue;

          rp.c = (unsigned char *) ar_spa (&reply.hdr);
          rh.c = (unsigned char *) ar_sha (&reply.hdr);
          logger (LOG_ERR, "ARPOP_REPLY received from %s (%s)",
                  inet_ntoa (*rp.a), ether_ntoa (rh.a));
          close (iface->fd);
          iface->fd = -1;
          return 1;
        }
    }

  close (iface->fd);
  iface->fd = -1;
  return 0;
}

