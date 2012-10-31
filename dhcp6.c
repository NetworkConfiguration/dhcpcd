/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2012 Roy Marples <roy@marples.name>
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

#include <sys/utsname.h>

#include <netinet/in.h>
#ifdef __linux__
#  define _LINUX_IN6_H
#  include <linux/ipv6.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define ELOOP_QUEUE 2

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcp6.h"
#include "duid.h"
#include "eloop.h"
#include "platform.h"

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(unsigned long)(const void *)(a))
#endif

/* DHCPCD Project has been assigned an IANA PEN of 40712 */
#define DHCPCD_IANA_PEN 40712

/* Unsure if I want this */
//#define VENDOR_SPLIT

static int sock = -1;
static struct sockaddr_in6 allrouters, from;
static struct msghdr sndhdr;
static struct iovec sndiov[2];
static unsigned char *sndbuf;
static struct msghdr rcvhdr;
static struct iovec rcviov[2];
static unsigned char *rcvbuf;
static unsigned char ansbuf[1500];
static unsigned char *duid;
static uint16_t duid_len;
static char ntopbuf[INET6_ADDRSTRLEN];

struct dhcp6_op {
	uint16_t type;
	const char *name;
};

static const struct dhcp6_op dhcp6_ops[] = {
	{ DHCP6_SOLICIT, "SOLICIT6" },
	{ DHCP6_REQUEST, "REQUEST6" },
	{ DHCP6_REPLY, "REPLY6" },
	{ DHCP6_INFORMATION_REQ, "INFORM6" },
	{ 0, NULL }
};

const struct dhcp_opt const dhcp6_opts[] = {
	{ D6_OPTION_CLIENTID,		BINHEX,		"client_id" },
	{ D6_OPTION_SERVERID,		BINHEX,		"server_id" },
	{ D6_OPTION_IA_ADDR,		IPV6 | ARRAY,	"ia_addr" },
	{ D6_OPTION_PREFERENCE,		UINT8,		"preference" },
	{ D6_OPTION_RAPID_COMMIT,	0,		"rapid_commit" },
	{ D6_OPTION_UNICAST,		IPV6,		"unicast" },
	{ D6_OPTION_STATUS_CODE,	SCODE,		"status_code" },
	{ D6_OPTION_SIP_SERVERS_NAME,	RFC3397,	"sip_servers_names" },
	{ D6_OPTION_SIP_SERVERS_ADDRESS,IPV6 | ARRAY,	"sip_servers_addresses" },
	{ D6_OPTION_DNS_SERVERS,	IPV6 | ARRAY,	"name_servers" },
	{ D6_OPTION_DOMAIN_LIST,	RFC3397,	"domain_search" },
	{ D6_OPTION_NIS_SERVERS,	IPV6 | ARRAY,	"nis_servers" },
	{ D6_OPTION_NISP_SERVERS,	IPV6 | ARRAY,	"nisp_servers" },
	{ D6_OPTION_NIS_DOMAIN_NAME,	RFC3397,	"nis_domain_name" },
	{ D6_OPTION_NISP_DOMAIN_NAME,	RFC3397,	"nisp_domain_name" },
	{ D6_OPTION_SNTP_SERVERS,	IPV6 | ARRAY,	"sntp_servers" },
	{ D6_OPTION_INFO_REFRESH_TIME,	UINT32,		"info_refresh_time" },
	{ D6_OPTION_BCMS_SERVER_D,	RFC3397,	"bcms_server_d" },
	{ D6_OPTION_BCMS_SERVER_A,	IPV6 | ARRAY,	"bcms_server_a" },
	{ 0, 0, NULL }
};

#if DEBUG_MEMORY
static void
dhcp6_cleanup(void)
{

	free(sndbuf);
	free(rcvbuf);
	free(duid);
}
#endif

void
dhcp6_printoptions(void)
{
	const struct dhcp_opt *opt;

	for (opt = dhcp6_opts; opt->option; opt++)
		if (opt->var)
			printf("%05d %s\n", opt->option, opt->var);
}

static int
dhcp6_init(void)
{
	int len;

#if DEBUG_MEMORY
	atexit(dhcp6_cleanup);
#endif

	memset(&allrouters, 0, sizeof(allrouters));
	allrouters.sin6_family = AF_INET6;
	allrouters.sin6_port = htons(DHCP6_SERVER_PORT);
#ifdef SIN6_LEN
	allrouters.sin6_len = sizeof(allrouters);
#endif
	if (inet_pton(AF_INET6, ALLROUTERS, &allrouters.sin6_addr.s6_addr) != 1)
		return -1;

	len = CMSG_SPACE(sizeof(struct in6_pktinfo));
	sndbuf = calloc(1, len);
	if (sndbuf == NULL)
		return -1;
	sndhdr.msg_namelen = sizeof(struct sockaddr_in6);
	sndhdr.msg_iov = sndiov;
	sndhdr.msg_iovlen = 1;
	sndhdr.msg_control = sndbuf;
	sndhdr.msg_controllen = len;

	rcvbuf = calloc(1, len);
	if (rcvbuf == NULL) {
		free(sndbuf);
		sndbuf = NULL;
		return -1;
	}
	rcvhdr.msg_name = &from;
	rcvhdr.msg_namelen = sizeof(from);
	rcvhdr.msg_iov = rcviov;
	rcvhdr.msg_iovlen = 1;
	rcvhdr.msg_control = rcvbuf;
	rcvhdr.msg_controllen = len;
	rcviov[0].iov_base = ansbuf;
	rcviov[0].iov_len = sizeof(ansbuf);

	return 0;
}

#ifdef DHCPCD_IANA_PEN
static size_t
dhcp6_makevendor(struct dhcp6_option *o)
{
	size_t len;
	uint8_t *p;
	uint16_t u16;
	uint32_t u32;
	size_t vlen;
#ifdef VENDOR_SPLIT
	const char *platform;
	size_t plen, unl, url, uml, pl;
	struct utsname utn;
#endif

	len = sizeof(uint32_t); /* IANA PEN */

#ifdef VENDOR_SPLIT
	plen = strlen(PACKAGE);
	vlen = strlen(VERSION);
	len += sizeof(uint16_t) + plen + 1 + vlen;
	if (uname(&utn) == 0) {
		unl = strlen(utn.sysname);
		url = strlen(utn.release);
		uml = strlen(utn.machine);
		platform = hardware_platform();
		pl = strlen(platform);
		len += sizeof(uint16_t) + unl + 1 + url;
		len += sizeof(uint16_t) + uml;
		len += sizeof(uint16_t) + pl;
	} else
		unl = 0;
#else
	vlen = strlen(vendor);
	len += sizeof(uint16_t) + vlen;
#endif

	if (o) {
		o->code = htons(D6_OPTION_VENDOR);
		o->len = htons(len);
		p = D6_OPTION_DATA(o);
		u32 = DHCPCD_IANA_PEN;
		memcpy(p, &u32, sizeof(u32));
		p += sizeof(u32);
#ifdef VENDOR_SPLIT
		u16 = htons(plen + 1 + vlen);
		memcpy(p, &u16, sizeof(u16));
		p += sizeof(u16);
		memcpy(p, PACKAGE, plen);
		p += plen;
		*p++ = '-';
		memcpy(p, VERSION, vlen);
		p += vlen;
		if (unl > 0) {
			u16 = htons(unl + 1 + url);
			memcpy(p, &u16, sizeof(u16));
			p += sizeof(u16);
			memcpy(p, utn.sysname, unl);
			p += unl;
			*p++ = '-';
			memcpy(p, utn.release, url);
			p += url;
			u16 = htons(uml);
			memcpy(p, &u16, sizeof(u16));
			p += sizeof(u16);
			memcpy(p, utn.machine, uml);
			p += uml;
			u16 = htons(pl);
			memcpy(p, &u16, sizeof(u16));
			p += sizeof(u16);
			memcpy(p, platform, pl);
		}
#else
		u16 = htons(vlen);
		memcpy(p, &u16, sizeof(u16));
		p += sizeof(u16);
		memcpy(p, vendor, vlen);
#endif
	}

	return len;
}
#endif

static const struct dhcp6_option *
dhcp6_getoption(int code, const struct dhcp6_message *m, ssize_t len)
{
	const struct dhcp6_option *o;

	code = htons(code);
	len -= sizeof(*m);
	for (o = D6_CFIRST_OPTION(m);
	    len > (ssize_t)sizeof(*o);
	    o = D6_CNEXT_OPTION(o))
	{
		if (o->len == 0)
			break;
		len -= sizeof(*o) + ntohs(o->len);
		if (len < 0) {
			errno = EINVAL;
			return NULL;
		}
		if (o->code == code)
			return o;
	}

	errno = ESRCH;
	return NULL;
}


static int
dhcp6_updateelapsed(struct interface *ifp, struct dhcp6_message *m, ssize_t len)
{
	struct dhcp6_state *state;
	const struct dhcp6_option *co;
	struct dhcp6_option *o;
	time_t up;
	uint16_t u16;

	co = dhcp6_getoption(D6_OPTION_ELAPSED, m, len);
	if (co == NULL)
		return -1;

	o = __UNCONST(co);
	state = D6_STATE(ifp);
	up = uptime() - state->start_uptime;
	if (up < 0 || up > (time_t)UINT16_MAX)
		up = (time_t)UINT16_MAX;
	u16 = htons(up);
	memcpy(D6_OPTION_DATA(o), &u16, sizeof(u16));
	return 0;
}

static int
dhcp6_makemessage(struct interface *ifp)
{
	struct dhcp6_state *state;
	struct dhcp6_option *o;
	int xid;
	ssize_t len;
	uint16_t *u16;
	const struct if_options *ifo;
	const struct dhcp_opt *opt;

	state = D6_STATE(ifp);
	if (state->send) {
		free(state->send);
		state->send = NULL;
	}

	/* Work out option size first */
	ifo = ifp->state->options;
	len = 0;
	for (opt = dhcp6_opts; opt->option; opt++) {
		if (!(opt->type & REQUEST ||
		    has_option_mask(ifo->requestmask6, opt->option)))
			continue;
		len += sizeof(*u16);
	}
	if (len == 0)
		len = sizeof(*u16) * 2;
	len += sizeof(*o);

	len += sizeof(state->send);
	len += sizeof(*o) + 14; /* clientid */ 
	len += sizeof(*o) + sizeof(uint16_t); /* elapsed */
#ifdef DHCPCD_IANA_PEN
	len += sizeof(*o) + dhcp6_makevendor(NULL);
#endif

	state->send = calloc(1, len);
	if (state->send == NULL)
		return -1;

	state->send_len = len;
	if (state->state == DH6S_INFORM)
		state->send->type = DHCP6_INFORMATION_REQ;
	else
		state->send->type = DHCP6_SOLICIT;
	xid = arc4random();
	state->send->xid[0] = (xid >> 16) & 0xff;
	state->send->xid[1] = (xid >> 8) & 0xff;
	state->send->xid[2] = xid & 0xff;

	o = D6_FIRST_OPTION(state->send);
	o->code = htons(D6_OPTION_CLIENTID);
	o->len = htons(duid_len);
	memcpy(D6_OPTION_DATA(o), duid, duid_len);

	o = D6_NEXT_OPTION(o);
	o->code = htons(D6_OPTION_ELAPSED);
	o->len = htons(sizeof(uint16_t));
	dhcp6_updateelapsed(ifp, state->send, state->send_len);

#ifdef DHCPCD_IANA_PEN
	o = D6_NEXT_OPTION(o);
	dhcp6_makevendor(o);
#endif

	o = D6_NEXT_OPTION(o);
	o->code = htons(D6_OPTION_ORO);
	o->len = 0;
	u16 = (uint16_t *)(void *)D6_OPTION_DATA(o);
	for (opt = dhcp6_opts; opt->option; opt++) {
		if (!(opt->type & REQUEST ||
		    has_option_mask(ifo->requestmask6, opt->option)))
			continue;
		*u16++ = htons(opt->option);
		o->len += sizeof(*u16);
	}
	if (o->len == 0) {
		*u16++ = htons(D6_OPTION_DNS_SERVERS);
		*u16++ = htons(D6_OPTION_DOMAIN_LIST);
		o->len = sizeof(*u16) * 2;
	}
	o->len = htons(o->len);

	return 0;
}

static const char *
dhcp6_get_op(uint16_t type)
{
	const struct dhcp6_op *d;

	for (d = dhcp6_ops; d->name; d++)
		if (d->type == type)
			return d->name;
	return NULL;
}

static void
dhcp6_sendmessage(struct interface *ifp, void (*callback)(void *))
{
	struct dhcp6_state *state;
	struct timeval tv;
	struct sockaddr_in6 to;
	struct cmsghdr *cm;
	struct in6_pktinfo pi;

	state = D6_STATE(ifp);
	if (!callback)
		syslog(LOG_DEBUG, "%s: sending %s with xid 0x%02x%02x%02x",
		    ifp->name,
		    dhcp6_get_op(state->send->type),
		    state->send->xid[0],
		    state->send->xid[1],
		    state->send->xid[2]);
	else {
		if (state->interval == 0)
			state->interval = 4;
		else {
			state->interval *= 2;
			if (state->interval > 64)
				state->interval = 64;
		}
		tv.tv_sec = state->interval + DHCP_RAND_MIN;
		tv.tv_usec = arc4random() % (DHCP_RAND_MAX_U - DHCP_RAND_MIN_U);
		syslog(LOG_DEBUG,
		    "%s: sending %s (xid 0x%02x%02x%02x), next in %0.2f seconds",
		    ifp->name, dhcp6_get_op(state->send->type),
		    state->send->xid[0],
		    state->send->xid[1],
		    state->send->xid[2],
		    timeval_to_double(&tv));
	}

	to = allrouters;
	sndhdr.msg_name = (caddr_t)&to;
	sndhdr.msg_iov[0].iov_base = (caddr_t)state->send;
	sndhdr.msg_iov[0].iov_len = state->send_len;

	/* Set the outbound interface */
	cm = CMSG_FIRSTHDR(&sndhdr);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(pi));
	memset(&pi, 0, sizeof(pi));
	pi.ipi6_ifindex = ifp->index;
	memcpy(CMSG_DATA(cm), &pi, sizeof(pi));
	
	if (sendmsg(sock, &sndhdr, 0) == -1)
		syslog(LOG_ERR, "%s: sendmsg: %m", ifp->name);

	if (callback)
		add_timeout_tv(&tv, callback, ifp);
}

static void
dhcp6_sendinform(void *arg)
{

	dhcp6_sendmessage(arg, dhcp6_sendinform);
}

/* ARGSUSED */
static void
dhcp6_handledata(_unused void *arg)
{
	ssize_t len;
	struct cmsghdr *cm;
	struct in6_pktinfo pkt;
	struct interface *ifp;
	const char *sfrom, *op;
	struct dhcp6_message *m, *r;
	struct dhcp6_state *state;
	const struct dhcp6_option *o;
	const char *reason;
	const struct dhcp_opt *opt;
	const struct if_options *ifo;

	len = recvmsg(sock, &rcvhdr, 0);
	if (len == -1) {
		syslog(LOG_ERR, "recvmsg: %m");
		return;
	}
	sfrom = inet_ntop(AF_INET6, &from.sin6_addr,
	    ntopbuf, INET6_ADDRSTRLEN);
	if ((size_t)len < sizeof(struct dhcp6_message)) {
		syslog(LOG_ERR, "DHCPv6 RA packet too short from %s", sfrom);
		return;
	}

	pkt.ipi6_ifindex = 0;
	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rcvhdr);
	     cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&rcvhdr, cm))
	{
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;
		switch(cm->cmsg_type) {
		case IPV6_PKTINFO:
			if (cm->cmsg_len == CMSG_LEN(sizeof(pkt)))
				memcpy(&pkt, CMSG_DATA(cm), sizeof(pkt));
			break;
		}
	}

	if (pkt.ipi6_ifindex == 0) {
		syslog(LOG_ERR,
		    "DHCPv6 reply did not contain index from %s",
		    sfrom);
		return;
	}


	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (ifp->index == (unsigned int)pkt.ipi6_ifindex)
			break;
	if (ifp == NULL) {
		syslog(LOG_ERR, "DHCPv6 reply for unexpected interface from %s",
		    sfrom);
		return;
	}
	state = D6_STATE(ifp);
	if (state == NULL || state->send == NULL) {
		syslog(LOG_ERR, "%s: DHCPv6 reply received but not running",
		    ifp->name);
		return;
	}

	m = state->send;
	r = (struct dhcp6_message *)rcvhdr.msg_iov[0].iov_base;
	if (r->xid[0] != m->xid[0] ||
	    r->xid[1] != m->xid[1] ||
	    r->xid[2] != m->xid[2])
	{
		syslog(LOG_ERR,
		    "%s: wrong xid 0x%02x%02x%02x (expecting 0x%02x%02x%02x) from %s",
		    ifp->name,
		    r->xid[0], r->xid[1], r->xid[2],
		    r->xid[0], r->xid[1], r->xid[2],
		    sfrom);
		return;
	}

	if (dhcp6_getoption(D6_OPTION_SERVERID, r, len) == NULL) {
		syslog(LOG_ERR, "%s: no DHCPv6 server ID from %s",
		    ifp->name, sfrom);
		return;
	}

	o = dhcp6_getoption(D6_OPTION_CLIENTID, r, len);
	if (o && ntohs(o->len) != duid_len &&
	    memcmp(D6_COPTION_DATA(o), duid, duid_len) != 0)
	{
		syslog(LOG_ERR, "%s: incorrect client ID from %s",
		    ifp->name, sfrom);
		return;
	}

	ifo = ifp->state->options;
	for (opt = dhcp6_opts; opt->option; opt++) {
		if (has_option_mask(ifo->requiremask6, opt->option) &&
		    dhcp6_getoption(opt->option, r, len) == NULL)
		{
			syslog(LOG_WARNING,
			    "%s: reject DHCPv6 (no option %s) from %s",
			    ifp->name, opt->var, sfrom);
			return;
		}
	}

	m = malloc(len);
	if (m == NULL) {
		syslog(LOG_ERR, "%s: malloc DHCPv6 reply: %m", ifp->name);
		return;
	}

	free(state->old);
	state->old = state->new;
	state->old_len = state->new_len;
	state->new = m;
	memcpy(m, r, len);
	state->new_len = len;

	op = dhcp6_get_op(r->type);
	if (r->type != DHCP6_REPLY) {
		syslog(LOG_ERR, "%s: invalid DHCP6 type %s (%d)",
		    ifp->name, op, r->type);
		return;
	}

	syslog(LOG_INFO, "%s: %s received from %s", ifp->name, op, sfrom);
	switch(state->state) {
	case DH6S_INFORM:
		reason = "INFORM6";
		break;
	default:
		reason = "UNKNOWN6";
		break;
	}
	run_script_reason(ifp, options & DHCPCD_TEST ? "TEST" : reason);
	if (options & DHCPCD_TEST ||
	    (ifp->state->options->options & DHCPCD_INFORM &&
	    !(options & DHCPCD_MASTER)))
	{
#ifdef DEBUG_MEMORY
		dhcp6_free(ifp);
#endif
		exit(EXIT_SUCCESS);
	}
	delete_timeout(NULL, ifp);
}


static int
dhcp6_open(void)
{
	struct sockaddr_in6 sa;
	int n;

	if (sndbuf == NULL && dhcp6_init() == -1)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(DHCP6_CLIENT_PORT);
#ifdef BSD
	sa.sin6_len = sizeof(sa);
#endif

	sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		return -1;

	n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
	    &n, sizeof(n)) == -1)
		goto errexit;

	n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
	    &n, sizeof(n)) == -1)
		goto errexit;

#ifdef SO_REUSEPORT
	n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
	    &n, sizeof(n)) == -1)
		goto errexit;
#endif

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		goto errexit;

	n = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
	    &n, sizeof(n)) == -1)
		goto errexit;

	if (set_cloexec(sock) == -1 || set_nonblock(sock) == -1)
		goto errexit;

	add_event(sock, dhcp6_handledata, NULL);

	return 0;

errexit:
	close(sock);
	return -1;
}

int
dhcp6_start(struct interface *ifp, int manage)
{
	struct dhcp6_state *state;

	state = D6_STATE(ifp);
	if (state) {
		/* We're already running DHCP6 */
		/* XXX: What if the managed flag changes? */
		return 0;
	}

	syslog(LOG_INFO, "%s: %s", ifp->name,
	    manage ? "soliciting DHCPv6 address" :
	    "requesting DHCPv6 information");

	if (sock == -1 && dhcp6_open() == -1)
		return -1;

	if (duid == NULL) {
		duid = malloc(DUID_LEN);
		if (duid == NULL)
			return -1;
		duid_len = get_duid(duid, ifp);
	}

	ifp->if_data[IF_DATA_DHCP6] = calloc(1, sizeof(*state));
	state = D6_STATE(ifp);
	if (state == NULL)
		return -1;

	state->state = manage ? DH6S_INIT : DH6S_INFORM;
	state->start_uptime = uptime();

	if (dhcp6_makemessage(ifp) == -1)
		return -1;

	if (state->state == DH6S_INFORM)
		dhcp6_sendinform(ifp);

	return 1;
}

static void
dhcp6_freedrop(struct interface *ifp, int drop)
{
	struct dhcp6_state *state;

	delete_timeout(NULL, ifp);
	state = D6_STATE(ifp);
	if (state) {
		if (drop && state->new)
			run_script_reason(ifp, "STOP6");
		free(state->send);
		free(state->new);
		free(state->old);
		free(state);
		ifp->if_data[IF_DATA_DHCP6] = NULL;
	}

	/* If we don't have any more DHCP6 enabled interfaces,
	 * close the global socket */
	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (D6_STATE(ifp))
			break;
	if (ifp == NULL && sock != -1) {
		close(sock);
		delete_event(sock);
		sock = -1;
	}
}

void
dhcp6_drop(struct interface *ifp)
{

	dhcp6_freedrop(ifp, 1);
}

void
dhcp6_free(struct interface *ifp)
{

	dhcp6_freedrop(ifp, 0);
}

ssize_t
dhcp6_env(char **env, const char *prefix, const struct interface *ifp,
    const struct dhcp6_message *m, ssize_t mlen)
{
	const struct if_options *ifo;
	const struct dhcp_opt *opt;
	const struct dhcp6_option *o;
	ssize_t len, e;
	uint16_t ol;
	const uint8_t *od;
	char **ep, *v, *val;

	e = 0;
	ep = env;
	ifo = ifp->state->options;
	for (opt = dhcp6_opts; opt->option; opt++) {
		if (!opt->var)
			continue;
		if (has_option_mask(ifo->nomask6, opt->option))
			continue;
 		o = dhcp6_getoption(opt->option, m, mlen);
		if (o == NULL)
			continue;
		if (env == NULL) {
			e++;
			continue;
		}
		ol = ntohs(o->len);
		od = D6_COPTION_DATA(o);
		len = print_option(NULL, 0, opt->type, ol, od);
		if (len < 0)
			return -1;
		e = strlen(prefix) + 6 + strlen(opt->var) + len + 4;
		v = val = *ep++ = xmalloc(e);
		v += snprintf(val, e, "%s_dhcp6_%s=", prefix, opt->var);
		if (len != 0)
			print_option(v, len, opt->type, ol, od);

	}

	if (env == NULL)
		return e;
	return ep - env;
}
