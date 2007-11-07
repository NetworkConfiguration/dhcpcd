/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef INFO_H
#define INFO_H

#include "dhcpcd.h"
#include "interface.h"
#include "dhcp.h"

#ifdef ENABLE_INFO
bool write_info (const interface_t *iface, const dhcp_t *dhcp,
				 const options_t *options, bool overwrite);

bool read_info (const interface_t *iface, dhcp_t *dhcp);
#endif

#endif
