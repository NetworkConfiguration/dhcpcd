/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef CLIENT_H
#define CLIENT_H

#include "dhcpcd.h"

int dhcp_run (const options_t *options, int *pidfd);

#endif
