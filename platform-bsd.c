/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2014 Roy Marples <roy@marples.name>
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

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include <net/if.h>
#ifdef __FreeBSD__ /* Needed so that including netinet6/in6_var.h works */
#  include <net/if_var.h>
#endif
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"
#include "dhcpcd.h"
#include "if-options.h"
#include "platform.h"

#ifndef SYS_NMLN	/* OSX */
#  define SYS_NMLN 256
#endif

#ifndef HW_MACHINE_ARCH
#  ifdef HW_MODEL	/* OpenBSD */
#    define HW_MACHINE_ARCH HW_MODEL
#  endif
#endif

int
hardware_platform(char *str, size_t len)
{
	int mib[2] = { CTL_HW, HW_MACHINE_ARCH };
	char march[SYS_NMLN];
	size_t marchlen = sizeof(march);

	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]),
	    march, &marchlen, NULL, 0) != 0)
		return -1;
	return snprintf(str, len, ":%s", march);
}

#ifdef INET6
#define get_inet6_sysctl(code) inet6_sysctl(code, 0, 0)
#define set_inet6_sysctl(code, val) inet6_sysctl(code, val, 1)
static int
inet6_sysctl(int code, int val, int action)
{
	int mib[] = { CTL_NET, PF_INET6, IPPROTO_IPV6, 0 };
	size_t size;

	mib[3] = code;
	size = sizeof(val);
	if (action) {
		if (sysctl(mib, sizeof(mib)/sizeof(mib[0]),
		    NULL, 0, &val, size) == -1)
			return -1;
		return 0;
	}
	if (sysctl(mib, sizeof(mib)/sizeof(mib[0]), &val, &size, NULL, 0) == -1)
		return -1;
	return val;
}

#define del_if_nd6_flag(ifname, flag) if_nd6_flag(ifname, flag, -1)
#define get_if_nd6_flag(ifname, flag) if_nd6_flag(ifname, flag,  0)
#define set_if_nd6_flag(ifname, flag) if_nd6_flag(ifname, flag,  1)
static int
if_nd6_flag(const char *ifname, unsigned int flag, int set)
{
	int s, error;
	struct in6_ndireq nd;
	unsigned int oflags;

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
		return -1;
	memset(&nd, 0, sizeof(nd));
	strlcpy(nd.ifname, ifname, sizeof(nd.ifname));
	if ((error = ioctl(s, SIOCGIFINFO_IN6, &nd)) == -1)
		goto eexit;
	if (set == 0) {
		close(s);
		return nd.ndi.flags & flag ? 1 : 0;
	}

	oflags = nd.ndi.flags;
	if (set == -1)
		nd.ndi.flags &= ~flag;
	else
		nd.ndi.flags |= flag;
	if (oflags == nd.ndi.flags)
		error = 0;
	else
		error = ioctl(s, SIOCSIFINFO_FLAGS, &nd);

eexit:
	close(s);
	return error;
}

void
restore_kernel_ra(struct dhcpcd_ctx *ctx)
{

	if (ctx->options & DHCPCD_FORKED)
		return;

	for (; ctx->ra_restore_len > 0; ctx->ra_restore_len--) {
		if (!(ctx->options & DHCPCD_FORKED)) {
			syslog(LOG_INFO, "%s: restoring kernel IPv6 RA support",
			    ctx->ra_restore[ctx->ra_restore_len - 1]);
			if (set_if_nd6_flag(
			    ctx->ra_restore[ctx->ra_restore_len -1],
			    ND6_IFF_ACCEPT_RTADV) == -1)
				syslog(LOG_ERR, "%s: del_if_nd6_flag: %m",
				    ctx->ra_restore[ctx->ra_restore_len - 1]);
		}
		free(ctx->ra_restore[ctx->ra_restore_len - 1]);
	}
	free(ctx->ra_restore);
	ctx->ra_restore = NULL;

	if (ctx->ra_kernel_set) {
		syslog(LOG_INFO, "restoring kernel IPv6 RA support");
		if (set_inet6_sysctl(IPV6CTL_ACCEPT_RTADV, 1) == -1)
			syslog(LOG_ERR, "IPV6CTL_ACCEPT_RTADV: %m");
	}
}

static int
ipv6_ra_flush(void)
{
	int s;
	char dummy[IFNAMSIZ + 8];

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s == -1)
		return -1;
	strlcpy(dummy, "lo0", sizeof(dummy));
	if (ioctl(s, SIOCSRTRFLUSH_IN6, (caddr_t)&dummy) == -1)
		syslog(LOG_ERR, "SIOSRTRFLUSH_IN6: %m");
	if (ioctl(s, SIOCSPFXFLUSH_IN6, (caddr_t)&dummy) == -1)
		syslog(LOG_ERR, "SIOSPFXFLUSH_IN6: %m");
	close(s);
	return 0;
}

int
check_ipv6(struct dhcpcd_ctx *ctx, const char *ifname, int own)
{
	int ra;

	if (ifname) {
#ifdef ND6_IFF_ACCEPT_RTADV
		int i;
		char *p, **nrest;
#endif

#ifdef ND_IFF_AUTO_LINKLOCAL
		if (set_if_nd6_flag(ifname, ND6_IFF_AUTO_LINKLOCAL) == -1) {
			syslog(LOG_ERR, "%s: set_if_nd6_flag: %m", ifname);
			return -1;
		}
#endif

		if (del_if_nd6_flag(ifname, ND6_IFF_IFDISABLED) == -1) {
			syslog(LOG_ERR, "%s: del_if_nd6_flag: %m", ifname);
			return -1;
		}

#ifdef ND6_IFF_ACCEPT_RTADV
		ra = get_if_nd6_flag(ifname, ND6_IFF_ACCEPT_RTADV);
		if (ra == -1)
			syslog(LOG_ERR, "%s: get_if_nd6_flag: %m", ifname);
		else if (ra != 0 && own) {
			syslog(LOG_INFO,
			    "%s: disabling Kernel IPv6 RA support",
			    ifname);
			if (del_if_nd6_flag(ifname, ND6_IFF_ACCEPT_RTADV)
			    == -1)
			{
				syslog(LOG_ERR, "%s: del_if_nd6_flag: %m",
				    ifname);
				return ra;
			}
			for (i = 0; i < ctx->ra_restore_len; i++)
				if (strcmp(ctx->ra_restore[i], ifname) == 0)
					break;
			if (i == ctx->ra_restore_len) {
				p = strdup(ifname);
				if (p == NULL) {
					syslog(LOG_ERR, "%s: %m", __func__);
					return 0;
				}
				nrest = realloc(ctx->ra_restore,
				    (ctx->ra_restore_len + 1) * sizeof(char *));
				if (nrest == NULL) {
					syslog(LOG_ERR, "%s: %m", __func__);
					free(p);
					return 0;
				}
				ctx->ra_restore = nrest;
				ctx->ra_restore[ctx->ra_restore_len++] = p;
			}
			return 0;
		}
		return ra;
#else
		return ctx->ra_global;
#endif
	}

	ra = get_inet6_sysctl(IPV6CTL_ACCEPT_RTADV);
	if (ra == -1)
		/* The sysctl probably doesn't exist, but this isn't an
		 * error as such so just log it and continue */
		syslog(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
		    "IPV6CTL_ACCEPT_RTADV: %m");
	else if (ra != 0 && own) {
		syslog(LOG_INFO, "disabling Kernel IPv6 RA support");
		if (set_inet6_sysctl(IPV6CTL_ACCEPT_RTADV, 0) == -1) {
			syslog(LOG_ERR, "IPV6CTL_ACCEPT_RTADV: %m");
			return ra;
		}
		ra = 0;
		ctx->ra_kernel_set = 1;

		/* Flush the kernel knowledge of advertised routers
		 * and prefixes so the kernel does not expire prefixes
		 * and default routes we are trying to own. */
		ipv6_ra_flush();
	}

	ctx->ra_global = ra;
	return ra;
}

int
ipv6_dadtransmits(__unused const char *ifname)
{
	int r;

	r = get_inet6_sysctl(IPV6CTL_DAD_COUNT);
	return r < 0 ? 0 : r;
}
#endif
