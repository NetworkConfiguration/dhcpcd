/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef DUID_H
#define DUID_H

#include "config.h"

#ifdef ENABLE_DUID
#ifndef DUID_LEN
#  define DUID_LEN 128 + 2
#endif

#include "interface.h"

void get_duid (interface_t *iface);
#endif
#endif
