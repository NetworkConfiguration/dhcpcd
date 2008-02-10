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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#ifdef __linux__
#include <netinet/ether.h>
#include <netpacket/packet.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "arp.h"
#include "interface.h"
#include "logger.h"
#include "signal.h"
#include "socket.h"

/* These are really for IPV4LL */
#define NPROBES                 3
#define PROBE_INTERVAL          200
#define NCLAIMS                 2
#define CLAIM_INTERVAL          200

/* Linux does not seem to define these handy macros */
#ifndef ar_sha
#define ar_sha(ap) (((caddr_t) ((ap) + 1)) + 0)
#define ar_spa(ap) (((caddr_t) ((ap) + 1)) + (ap)->ar_hln)
#define ar_tha(ap) (((caddr_t) ((ap) + 1)) + (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap) (((caddr_t) ((ap) + 1)) + 2 * (ap)->ar_hln + (ap)->ar_pln)
#endif

#ifndef arphdr_len
#define arphdr_len2(ar_hln, ar_pln) (sizeof (struct arphdr) + \
				     2 * (ar_hln) + 2 * (ar_pln))
#define arphdr_len(ap) (arphdr_len2 ((ap)->ar_hln, (ap)->ar_pln))
#endif

#ifdef ENABLE_ARP

static int send_arp (const interface_t *iface, int op, struct in_addr sip,
		     const unsigned char *taddr, struct in_addr tip)
{
	struct arphdr *arp;
	size_t arpsize = arphdr_len2 (iface->hwlen, sizeof (sip));
	caddr_t tha;
	int retval;

	arp = xzalloc (arpsize);
	arp->ar_hrd = htons (iface->family);
	arp->ar_pro = htons (ETHERTYPE_IP);
	arp->ar_hln = iface->hwlen;
	arp->ar_pln = sizeof (sip);
	arp->ar_op = htons (op);
	memcpy (ar_sha (arp), iface->hwaddr, (size_t) arp->ar_hln);
	memcpy (ar_spa (arp), &sip, (size_t) arp->ar_pln);
	if (taddr) {
		/* NetBSD can return NULL from ar_tha, which is probably wrong
		 * but we still need to deal with it */
		if (! (tha = ar_tha (arp))) {
			free (arp);
			errno = EINVAL;
			return (-1);
		}
		memcpy (tha, taddr, (size_t) arp->ar_hln);
	}
	memcpy (ar_tpa (arp), &tip, (size_t) arp->ar_pln);

	retval = send_packet (iface, ETHERTYPE_ARP,
			      (unsigned char *) arp, arphdr_len (arp));
	free (arp);
	return (retval);
}

int arp_claim (interface_t *iface, struct in_addr address)
{
	struct arphdr *reply = NULL;
	long timeout = 0;
	unsigned char *buffer;
	int retval = -1;
	int nprobes = 0;
	int nclaims = 0;
	struct in_addr null_address;
	struct pollfd fds[] = {
		{ -1, POLLIN, 0 },
		{ -1, POLLIN, 0 }
	};

	if (! iface)
		return (-1);

	if (! iface->arpable) {
		logger (LOG_DEBUG, "interface `%s' is not ARPable", iface->name);
		return (0);
	}

	if (! IN_LINKLOCAL (ntohl (iface->previous_address.s_addr)) &&
	    ! IN_LINKLOCAL (ntohl (address.s_addr)))
		logger (LOG_INFO,
			"checking %s is available on attached networks",
			inet_ntoa (address));

	if (! open_socket (iface, ETHERTYPE_ARP))
		return (-1);

	fds[0].fd = signal_fd ();
	fds[1].fd = iface->fd;

	memset (&null_address, 0, sizeof (null_address));

	buffer = xmalloc (iface->buffer_length);
	reply = xmalloc (iface->buffer_length);

	for (;;) {
		size_t bufpos = 0;
		size_t buflen = iface->buffer_length;
		int bytes;
		int s = 0;
		struct timeval stopat;
		struct timeval now;

		/* Only poll if we have a timeout */
		if (timeout > 0) {
			s = poll (fds, 2, timeout);
			if (s == -1) {
				if (errno == EINTR) {
					if (signal_exists (NULL) == -1) {
						errno = 0;
						continue;
					} else
						break;
				}

				logger (LOG_ERR, "poll: `%s'",
					strerror (errno));
				break;
			}
		}

		/* Timed out */
		if (s == 0) {
			if (nprobes < NPROBES) {
				nprobes ++;
				timeout = PROBE_INTERVAL;
				logger (LOG_DEBUG, "sending ARP probe #%d",
					nprobes);
				if (send_arp (iface, ARPOP_REQUEST,
					      null_address, NULL,
					      address) == -1)
					break;

				/* IEEE1394 cannot set ARP target address
				 * according to RFC2734 */
				if (nprobes >= NPROBES &&
				    iface->family == ARPHRD_IEEE1394)
					nclaims = NCLAIMS;
			} else if (nclaims < NCLAIMS) {
				nclaims ++;
				timeout = CLAIM_INTERVAL;
				logger (LOG_DEBUG, "sending ARP claim #%d",
					nclaims);
				if (send_arp (iface, ARPOP_REQUEST,
					      address, iface->hwaddr,
					      address) == -1)
					break;
			} else {
				/* No replies, so done */
				retval = 0;
				break;
			}

			/* Setup our stop time */
			if (get_time (&stopat) != 0)
				break;
			stopat.tv_usec += timeout;

			continue;
		}

		/* We maybe ARP flooded, so check our time */
		if (get_time (&now) != 0)
			break;
		if (timercmp (&now, &stopat, >)) {
			timeout = 0;
			continue;
		}

		if (! fds[1].revents & POLLIN)
			continue;

		memset (buffer, 0, buflen);
		do {
			union {
				unsigned char *c;
				struct in_addr *a;
			} rp;
			union {
				unsigned char *c;
				struct ether_addr *a;
			} rh;

			memset (reply, 0, iface->buffer_length);
			if ((bytes = get_packet (iface, (unsigned char *) reply,
						 buffer,
						 &buflen, &bufpos)) == -1)
				break;

			/* Only these types are recognised */
			if (reply->ar_op != htons (ARPOP_REPLY))
				continue;

			/* Protocol must be IP. */
			if (reply->ar_pro != htons (ETHERTYPE_IP))
				continue;
			if (reply->ar_pln != sizeof (address))
				continue;
			if ((unsigned) bytes < sizeof (reply) + 
			    2 * (4 + reply->ar_hln))
				continue;

			rp.c = (unsigned char *) ar_spa (reply);
			rh.c = (unsigned char *) ar_sha (reply);

			/* Ensure the ARP reply is for the our address */
			if (rp.a->s_addr != address.s_addr)
				continue;

			/* Some systems send a reply back from our hwaddress,
			 * which is wierd */
			if (reply->ar_hln == iface->hwlen &&
			    memcmp (rh.c, iface->hwaddr, iface->hwlen) == 0)
				continue;

			logger (LOG_ERR, "ARPOP_REPLY received from %s (%s)",
				inet_ntoa (*rp.a),
				hwaddr_ntoa (rh.c, (size_t) reply->ar_hln));
			retval = -1;
			goto eexit;
		} while (bufpos != 0);
	}

eexit:
	close (iface->fd);
	iface->fd = -1;
	free (buffer);
	free (reply);
	return (retval);
}
#endif
