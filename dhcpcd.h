/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
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

#define DEFAULT_TIMEOUT     20
#define DEFAULT_LEASETIME   3600        /* 1 hour */

#define CLASS_ID_MAX_LEN    48
#define CLIENT_ID_MAX_LEN   48
#define USERCLASS_MAX_LEN   255

#ifdef THERE_IS_NO_FORK 
extern char dhcpcd[PATH_MAX];
extern char **dhcpcd_argv;
extern int dhcpcd_argc;
extern char *dhcpcd_skiproutes;
#endif

typedef struct options_t {
	char interface[IF_NAMESIZE];
	char hostname[MAXHOSTNAMELEN];
	int fqdn;
	char classid[CLASS_ID_MAX_LEN];
	int classid_len;
	char clientid[CLIENT_ID_MAX_LEN];
	int clientid_len;
	char userclass[USERCLASS_MAX_LEN];
	int userclass_len;
	unsigned leasetime;
	time_t timeout;
	int metric;

	bool doarp;
	bool dodns;
	bool dodomainname;
	bool dogateway;
	int  dohostname;
	bool domtu;
	bool donis;
	bool dontp;
	bool dolastlease;
	bool doinform;
	bool dorequest;
	bool doipv4ll;

	struct in_addr request_address;
	struct in_addr request_netmask;

	bool persistent;
	bool keep_address;
	bool daemonise;
	bool daemonised;
	bool test;

	char *script;
	char pidfile[PATH_MAX];
} options_t;

#endif
