/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#ifdef __linux__
#  include <asm/types.h> /* needed for 2.4 kernels for the below header */
#  include <linux/netlink.h>
#  include "queue.h" /* not all libc's support queue.h, so include our own */ 
#else
#  include <sys/queue.h>
#endif

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
#  define ARPHRD_INFINIBAND		32
#endif

#define HWADDR_LEN			20

/* Work out if we have a private address or not
 * 10/8
 * 172.16/12
 * 192.168/16
 */
#ifndef IN_PRIVATE
# define IN_PRIVATE(addr) (((addr & IN_CLASSA_NET) == 0x0a000000) || \
			   ((addr & 0xfff00000)    == 0xac100000) || \
			   ((addr & IN_CLASSB_NET) == 0xc0a80000))
#endif

#define LINKLOCAL_ADDR	0xa9fe0000
#define LINKLOCAL_MASK	0xffff0000
#define LINKLOCAL_BRDC	0xa9feffff

#ifndef IN_LINKLOCAL
# define IN_LINKLOCAL(addr) ((addr & IN_CLASSB_NET) == LINKLOCAL_ADDR)
#endif

#define NSTAILQ_FOREACH(var, head, field) \
		if (head) STAILQ_FOREACH (var, head, field)

struct rt
{
	struct in_addr destination; 
	struct in_addr netmask;
	struct in_addr gateway;
	STAILQ_ENTRY (rt) entries;
};
STAILQ_HEAD (route_head, rt);

struct address
{
	struct in_addr address;
	STAILQ_ENTRY (address) entries;
};
STAILQ_HEAD (address_head, address);

struct interface
{
	char name[IF_NAMESIZE];
	sa_family_t family;
	unsigned char hwaddr[HWADDR_LEN];
	size_t hwlen;
	bool arpable;
	unsigned short mtu;

	int fd;
	size_t buffer_length;

#ifdef __linux__
	int listen_fd;
	int socket_protocol;
#endif

	char infofile[PATH_MAX];

	unsigned short previous_mtu;
	struct in_addr previous_address;
	struct in_addr previous_netmask;
	struct route_head *previous_routes;

	time_t start_uptime;

	unsigned char *clientid;
	size_t clientid_len;
};

void free_address(struct address_head *);
void free_route(struct route_head *);
uint32_t get_netmask(uint32_t);
char *hwaddr_ntoa(const unsigned char *, size_t);
size_t hwaddr_aton(unsigned char *, const char *);

struct interface *read_interface(const char *, int);
int get_mtu(const char *);
int set_mtu(const char *, short int);

int add_address(const char *, struct in_addr, struct in_addr, struct in_addr);
int del_address(const char *, struct in_addr, struct in_addr);
int flush_addresses(const char *);
in_addr_t get_address(const char *);
int has_address(const char *, struct in_addr);

int add_route(const char *, struct in_addr, struct in_addr, struct in_addr, int);
int change_route(const char *, struct in_addr, struct in_addr, struct in_addr, int);
int del_route(const char *, struct in_addr, struct in_addr, struct in_addr, int);

int inet_ntocidr(struct in_addr);
int inet_cidrtoaddr(int, struct in_addr *);

#ifdef __linux__
typedef int (*netlink_callback)(struct nlmsghdr *, void *);
int send_netlink(struct nlmsghdr *, netlink_callback, void *);
#endif
#endif
