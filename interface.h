/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <limits.h>
#include <stdbool.h>

#include "config.h"
#ifdef ENABLE_DUID
#ifndef DUID_LEN
#  define DUID_LEN				128 + 2
#endif
#endif

#define EUI64_ADDR_LEN			8
#define INFINIBAND_ADDR_LEN		20

/* Linux 2.4 doesn't define this */
#ifndef ARPHRD_IEEE1394
#  define ARPHRD_IEEE1394		24
#endif

/* The BSD's don't define this yet */
#ifndef ARPHRD_INFINIBAND
#  define ARPHRD_INFINIBAND		27
#endif

#define HWADDR_LEN				20

/* Work out if we have a private address or not
 * 10/8
 * 172.16/12
 * 192.168/16
 */
#ifndef IN_PRIVATE
# define IN_PRIVATE(addr) (((ntohl (addr) & IN_CLASSA_NET) == 0x0a000000) || \
						   ((ntohl (addr) & 0xfff00000)    == 0xac100000) || \
						   ((ntohl (addr) & IN_CLASSB_NET) == 0xc0a80000))
#endif

#define LINKLOCAL_ADDR       0xa9fe0000
#define LINKLOCAL_MASK       0xffff0000
#define LINKLOCAL_BRDC		 0xa9feffff

#ifndef IN_LINKLOCAL
# define IN_LINKLOCAL(addr) ((ntohl (addr) & IN_CLASSB_NET) == LINKLOCAL_ADDR)
#endif

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
	sa_family_t family;
	unsigned char hwaddr[HWADDR_LEN];
	int hwlen;
	bool arpable;
	unsigned short mtu;

	int fd;
	int buffer_length;

#ifdef __linux__
	int socket_protocol;
#endif

	char infofile[PATH_MAX];

	unsigned short previous_mtu;
	struct in_addr previous_address;
	struct in_addr previous_netmask;
	route_t *previous_routes;

	time_t start_uptime;

#ifdef ENABLE_DUID
	unsigned char duid[DUID_LEN];
	int duid_length;
#endif
} interface_t;

void free_address (address_t *addresses);
void free_route (route_t *routes);
unsigned long get_netmask (unsigned long addr);
char *hwaddr_ntoa (const unsigned char *hwaddr, int hwlen);

interface_t *read_interface (const char *ifname, int metric);
int get_mtu (const char *ifname);
int set_mtu (const char *ifname, short int mtu);

int add_address (const char *ifname, struct in_addr address,
				 struct in_addr netmask, struct in_addr broadcast);
int del_address (const char *ifname, struct in_addr address,
				 struct in_addr netmask);

int flush_addresses (const char *ifname);
unsigned long get_address (const char *ifname);
int has_address (const char *ifname, struct in_addr address);

int add_route (const char *ifname, struct in_addr destination,
			   struct in_addr netmask, struct in_addr gateway, int metric);
int change_route (const char *ifname, struct in_addr destination,
				  struct in_addr netmask, struct in_addr gateway, int metric);
int del_route (const char *ifname, struct in_addr destination,
			   struct in_addr netmask, struct in_addr gateway, int metric);

int inet_ntocidr (struct in_addr address);
int inet_cidrtoaddr (int cidr, struct in_addr *addr);

#endif
