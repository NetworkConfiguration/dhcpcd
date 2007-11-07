/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#include <errno.h>
#include <stdlib.h>

#include "config.h"
#include "arp.h"
#include "ipv4ll.h"

#ifdef ENABLE_IPV4LL

#ifndef ENABLE_ARP
#error IPV4LL requires ARP
#endif

#define IPV4LL_LEASETIME 20 

int ipv4ll_get_address (interface_t *iface, dhcp_t *dhcp) {
	struct in_addr addr;

	while (1) {
		addr.s_addr = htonl (LINKLOCAL_ADDR |
							 ((abs (random ()) % 0xFD00) + 0x0100));
		errno = 0;
		if (! arp_claim (iface, addr))
			break;
		/* Our ARP may have been interrupted */
		if (errno)
			return (-1);
	}

	dhcp->address.s_addr = addr.s_addr;
	dhcp->netmask.s_addr = htonl (LINKLOCAL_MASK);
	dhcp->broadcast.s_addr = htonl (LINKLOCAL_BRDC);

	/* Finally configure some DHCP like lease times */
	dhcp->leasetime = IPV4LL_LEASETIME;
	dhcp->renewaltime = (dhcp->leasetime * 0.5);
	dhcp->rebindtime = (dhcp->leasetime * 0.875);

	return (0);
}

#endif
