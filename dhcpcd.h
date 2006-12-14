/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>
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

#ifndef DHCPCD_H
#define DHCPCD_H

#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdbool.h>

#include "common.h"

#define DEFAULT_TIMEOUT		20
// #define DEFAULT_LEASETIME	0xffffffff      /* infinite lease time */
#define DEFAULT_LEASETIME	3600 		/* 1 hour */

#define CLASS_ID_MAX_LEN	48
#define CLIENT_ID_MAX_LEN	48
#define HOSTNAME_MAX_LEN	255	
#define USERCLASS_MAX_LEN	255	

typedef struct options_t {
  char interface[IF_NAMESIZE];
  char hostname[HOSTNAME_MAX_LEN];
  int fqdn;
  char classid[CLASS_ID_MAX_LEN];
  char clientid[CLIENT_ID_MAX_LEN];
  char userclass[USERCLASS_MAX_LEN];
  int userclass_len;
  unsigned leasetime;
  time_t timeout;
  int metric;
  struct in_addr requestaddress;

  bool doarp;
  bool dodns;
  bool dontp;
  bool donis;
  bool dogateway;
  bool dohostname;
  bool dodomainname;
  int signal;
  bool persistent;

  char *script;
  char pidfile[PATH_MAX];
} options_t;

void make_pid (const char *pidfile);

#endif
