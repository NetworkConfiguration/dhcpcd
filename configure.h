/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef DHCPCONFIG_H
#define DHCPCONFIG_H

#include "dhcpcd.h"
#include "interface.h"
#include "dhcp.h"

int configure (const options_t *options, interface_t *iface,
			   const dhcp_t *dhcp, bool up);

#endif
