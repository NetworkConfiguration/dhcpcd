/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2013 Roy Marples <roy@marples.name>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "dhcpcd.h"
#include "if-options.h"
#include "platform.h"

static const char *mproc =
#if defined(__alpha__)
	"system type"
#elif defined(__arm__)
	"Hardware"
#elif defined(__avr32__)
	"cpu family"
#elif defined(__bfin__)
	"BOARD Name"
#elif defined(__cris__)
	"cpu model"
#elif defined(__frv__)
	"System"
#elif defined(__i386__) || defined(__x86_64__)
	"vendor_id"
#elif defined(__ia64__)
	"vendor"
#elif defined(__hppa__)
	"model"
#elif defined(__m68k__)
	"MMU"
#elif defined(__mips__)
	"system type"
#elif defined(__powerpc__) || defined(__powerpc64__)
	"machine"
#elif defined(__s390__) || defined(__s390x__)
	"Manufacturer"
#elif defined(__sh__)
	"machine"
#elif defined(sparc) || defined(__sparc__)
	"cpu"
#elif defined(__vax__)
	"cpu"
#else
	NULL
#endif
	;

#ifdef INET6
static char **restore;
static ssize_t nrestore;
#endif

char *
hardware_platform(void)
{
	FILE *fp;
	char *buf, *p;

	if (mproc == NULL) {
		errno = EINVAL;
		return NULL;
	}

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL)
		return NULL;

	p = NULL;
	while ((buf = get_line(fp))) {
		if (strncmp(buf, mproc, strlen(mproc)) == 0) {
			p = strchr(buf, ':');
			if (p != NULL && ++p != NULL) {
				while (*p == ' ')
					p++;
				break;
			}
		}
	}
	fclose(fp);

	if (p == NULL)
		errno = ESRCH;
	return p;
}

#ifdef INET6
static int
check_proc_int(const char *path)
{
	FILE *fp;
	char *buf;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;
	buf = get_line(fp);
	fclose(fp);
	if (buf == NULL)
		return -1;
	return atoi(buf);
}

static ssize_t
write_path(const char *path, const char *val)
{
	FILE *fp;
	ssize_t r;

	fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	r = fprintf(fp, "%s\n", val);
	fclose(fp);
	return r;
}

static const char *prefix = "/proc/sys/net/ipv6/conf";

static void
restore_kernel_ra(void)
{
	char path[256];

#ifndef DEBUG_MEMORY
	if (options & DHCPCD_FORKED)
		return;
#endif

	for (nrestore--; nrestore >= 0; nrestore--) {
#ifdef DEBUG_MEMORY
		if (!(options & DHCPCD_FORKED)) {
#endif
		syslog(LOG_INFO, "%s: restoring Kernel IPv6 RA support",
		       restore[nrestore]);
		snprintf(path, sizeof(path), "%s/%s/accept_ra",
			 prefix, restore[nrestore]);
		if (write_path(path, "1") == -1 && errno != ENOENT)
			syslog(LOG_ERR, "write_path: %s: %m", path);
#ifdef DEBUG_MEMORY
		}
		free(restore[nrestore]);
#endif
	}
#ifdef DEBUG_MEMORY
	free(restore);
#endif
}

int
check_ipv6(const char *ifname, int own)
{
	static int ipv6_checked = 0;
	int ra, forward, ex, i;
	char path[256], *p, **nrest;

	if (ifname == NULL) {
		if (ipv6_checked)
			return 1;
		ipv6_checked = 1;
		ifname = "all";
		ex = 1;
	} else
		ex = 0;

	snprintf(path, sizeof(path), "%s/%s/accept_ra", prefix, ifname);
	ra = check_proc_int(path);
	if (ra == -1)
		/* The sysctl probably doesn't exist, but this isn't an
		 * error as such so just log it and continue */
		syslog(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
		    "%s: %m", path);
	else if (ra != 0 && own) {
		syslog(LOG_INFO, "%s: disabling Kernel IPv6 RA support",
		    ifname);
		if (write_path(path, "0") == -1) {
			syslog(LOG_ERR, "write_path: %s: %m", path);
			return ra;
		}
		for (i = 0; i < nrestore; i++)
			if (strcmp(restore[i], ifname) == 0)
				break;
		if (i == nrestore) {
			p = strdup(ifname);
			if (p == NULL) {
				syslog(LOG_ERR, "%s: %m", __func__);
				goto forward;
			}
			nrest = realloc(restore,
			    (nrestore + 1) * sizeof(char *));
			if (nrest == NULL) {
				syslog(LOG_ERR, "%s: %m", __func__);
				goto forward;
			}
			restore = nrest;
			restore[nrestore++] = p;

		}
		if (ex)
			atexit(restore_kernel_ra);
	}

forward:
	if (ra != 2) {
		snprintf(path, sizeof(path), "%s/%s/forwarding",
		    prefix, ifname);
		forward = check_proc_int(path);
		if (forward == -1) {
			/* The sysctl probably doesn't exist, but this isn't an
			 * error as such so just log it and continue */
			syslog(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
			    "%s: %m", path);
		} else if (forward != 0) {
			syslog(LOG_WARNING,
			    "%s: configured as a router, not a host", ifname);
			return 0;
		}
	}
	return ra;
}

int
ipv6_dadtransmits(const char *ifname)
{
	char path[256];
	int r;

	if (ifname == NULL)
		ifname = "default";

	snprintf(path, sizeof(path), "%s/%s/dad_transmits", prefix, ifname);
	r = check_proc_int(path);
	return r < 0 ? 0 : r;
}
#endif
