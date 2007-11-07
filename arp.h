/*
 * dhcpcd - DHCP client daemon
 * Copyright 2005 - 2007 Roy Marples <roy@marples.name>
 *
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef ARP_H
#define ARP_H

#ifdef ENABLE_ARP
#include <netinet/in.h>

#include "interface.h"

int arp_claim (interface_t *iface, struct in_addr address);
#endif

#endif
