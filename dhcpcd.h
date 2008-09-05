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

#ifndef DHCPCD_H
#define DHCPCD_H

#include <sys/socket.h>
#include <net/if.h>

#include <limits.h>

#include "dhcp.h"

#define HWADDR_LEN 20

enum DHS {
	DHS_INIT,
	DHS_DISCOVERING,
	DHS_REQUESTING,
	DHS_BOUND,
	DHS_RENEWING,
	DHS_REBINDING,
	DHS_REBOOT,
	DHS_RENEW_REQUESTED,
	DHS_INIT_IPV4LL,
	DHS_PROBING,
	DHS_ANNOUNCING
};

#define LINK_UP 	1
#define LINK_UNKNOWN	0
#define LINK_DOWN 	-1

struct if_state {
	enum DHS state;
	struct if_options *options;
	struct dhcp_message *sent;
	struct dhcp_message *offer;
	struct dhcp_message *new;
	struct dhcp_message *old;
	struct dhcp_lease lease;
	time_t interval;
	time_t nakoff;
	uint32_t xid;
	int socket;
	int carrier;
	int probes;
	int claims;
	int conflicts;
	time_t defend;
	struct in_addr fail;
};

struct interface
{
	char name[IF_NAMESIZE];
	struct if_state *state;

	sa_family_t family;
	unsigned char hwaddr[HWADDR_LEN];
	size_t hwlen;
	int metric;
	int arpable;

	int raw_fd;
	int udp_fd;
	int arp_fd;
	size_t buffer_size, buffer_len, buffer_pos;
	unsigned char *buffer;

	struct in_addr addr;
	struct in_addr net;
	struct rt *routes;

	char leasefile[PATH_MAX];
	time_t start_uptime;

	unsigned char *clientid;

	struct interface *next;
};

extern int pidfd;
extern int options;

int handle_args(int, char **);
void handle_exit_timeout(void *);
void send_request(void *);
void start_interface(void *);
void start_discover(void *);
void start_renew(void *);
void start_rebind(void *);
void start_reboot(struct interface *);
void start_expire(void *);
void send_decline(struct interface *);
void close_sockets(struct interface *);
void drop_config(struct interface *, const char *);

#endif
