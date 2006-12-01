/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2006 Roy Marples <uberlord@gentoo.org>
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

#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdbool.h>

typedef struct route_t
{
  struct in_addr destination; 
  struct in_addr netmask;
  struct in_addr gateway;
  struct route_t *next;
} route_t;

typedef struct address_t
{
  struct in_addr address;
  struct address_t *next;
} address_t;

typedef struct interface_t
{
  char name[IF_NAMESIZE];
  struct ether_addr ethernet_address;
  bool arpable;

  int fd;
  int buffer_length;

#ifdef __linux__
  int socket_protocol;
#endif

  char infofile[PATH_MAX];

  struct in_addr previous_address;
  route_t *previous_routes;

  long start_uptime;
} interface_t;

void free_address (address_t *addresses);
void free_route (route_t *routes);
interface_t *read_interface (const char *ifname, int metric);

int add_address (const char *ifname, struct in_addr address,
		 struct in_addr netmask, struct in_addr broadcast);
int del_address (const char *ifname, struct in_addr address);
int flush_addresses (const char *ifname);

int add_route (const char *ifname, struct in_addr destination,
	      struct in_addr netmask, struct in_addr gateway, int metric);
int change_route (const char *ifname, struct in_addr destination,
		  struct in_addr netmask, struct in_addr gateway, int metric);
int del_route (const char *ifname, struct in_addr destination,
	      struct in_addr netmask, struct in_addr gateway, int metric);
#endif
