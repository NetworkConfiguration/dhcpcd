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
	size_t classid_len;
	char clientid[CLIENT_ID_MAX_LEN];
	size_t clientid_len;
	char userclass[USERCLASS_MAX_LEN];
	size_t userclass_len;
	uint32_t leasetime;
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
	bool doduid;
	int domscsr;

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
