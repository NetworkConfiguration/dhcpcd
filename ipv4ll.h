/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef IPV4LL_H
#define IPV4LL_H

#ifdef ENABLE_IPV4LL

#include "dhcp.h"
#include "interface.h"

int ipv4ll_get_address (interface_t *iface, dhcp_t *dhcp);

#endif
#endif
