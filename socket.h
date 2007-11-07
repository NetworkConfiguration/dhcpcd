/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef SOCKET_H
#define SOCKET_H

#include <stdbool.h>

#include "dhcp.h"
#include "interface.h"

void make_dhcp_packet(struct udp_dhcp_packet *packet,
					  const unsigned char *data, int length,
					  struct in_addr source, struct in_addr dest);

int open_socket (interface_t *iface, bool arp);
int send_packet (const interface_t *iface, int type,
				 const unsigned char *data, int len);
int get_packet (const interface_t *iface, unsigned char *data,
				unsigned char *buffer, int *buffer_len, int *buffer_pos);
#endif
