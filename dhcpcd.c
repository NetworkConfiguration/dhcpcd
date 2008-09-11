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

const char copyright[] = "Copyright (c) 2006-2008 Roy Marples";

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include "arp.h"
#include "bind.h"
#include "config.h"
#include "common.h"
#include "configure.h"
#include "control.h"
#include "dhcpcd.h"
#include "dhcpf.h"
#include "duid.h"
#include "eloop.h"
#include "if-options.h"
#include "if-pref.h"
#include "ipv4ll.h"
#include "net.h"
#include "signals.h"

/* We should define a maximum for the NAK exponential backoff */ 
#define NAKOFF_MAX              60

int options = 0;
int pidfd = -1;
struct interface *ifaces = NULL;
int ifac = 0;
char **ifav = NULL;
int ifdc = 0;
char **ifdv = NULL;

static char **ifv = NULL;
static int ifc = 0;
static int linkfd = -1;
static char *cffile = NULL;
static char *pidfile;

struct dhcp_op {
	uint8_t value;
	const char *name;
};

static const struct dhcp_op const dhcp_ops[] = {
	{ DHCP_DISCOVER, "DHCP_DISCOVER" },
	{ DHCP_OFFER,    "DHCP_OFFER" },
	{ DHCP_REQUEST,  "DHCP_REQUEST" },
	{ DHCP_DECLINE,  "DHCP_DECLINE" },
	{ DHCP_ACK,      "DHCP_ACK" },
	{ DHCP_NAK,      "DHCP_NAK" },
	{ DHCP_RELEASE,  "DHCP_RELEASE" },
	{ DHCP_INFORM,   "DHCP_INFORM" },
	{ 0, NULL }
};

static const char *
get_dhcp_op(uint8_t type)
{
	const struct dhcp_op *d;

	for (d = dhcp_ops; d->name; d++)
		if (d->value == type)
			return d->name;
	return NULL;
}

static pid_t
read_pid(void)
{
	FILE *fp;
	pid_t pid = 0;

	if ((fp = fopen(pidfile, "r")) == NULL) {
		errno = ENOENT;
		return 0;
	}

	fscanf(fp, "%d", &pid);
	fclose(fp);

	return pid;
}

static void
usage(void)
{
	printf("usage: "PACKAGE" [-dknpqxADEGHKLOTV] [-c script] [-f file ] [-h hostname]\n"
	       "              [-i classID ] [-l leasetime] [-m metric] [-o option] [-r ipaddr]\n"
	       "              [-s ipaddr] [-t timeout] [-u userclass] [-F none|ptr|both]\n"
	       "              [-I clientID] [-C hookscript] [-Q option] [-X ipaddr] <interface>\n");
}

static void
cleanup(void)
{
#ifdef DEBUG_MEMORY
	struct interface *iface;
	int i;

	while (ifaces) {
		iface = ifaces;
		ifaces = iface->next;
		free_interface(iface);
	}

	for (i = 0; i < ifac; i++)
		free(ifav[i]);
	free(ifav);
	for (i = 0; i < ifdc; i++)
		free(ifdv[i]);
	free(ifdv);
#endif

	if (linkfd != -1)
		close(linkfd);
	if (pidfd > -1) {
		if (options & DHCPCD_MASTER) {
			if (stop_control() == -1)
				syslog(LOG_ERR, "stop_control: %m");
		}
		close(pidfd);
		unlink(pidfile);
	}
#ifdef DEBUG_MEMORY
	free(pidfile);
#endif
}

_noreturn void
handle_exit_timeout(_unused void *arg)
{
	syslog(LOG_ERR, "timed out");
	exit(EXIT_FAILURE);
}

void
drop_config(struct interface *iface, const char *reason)
{
	if (iface->state->new || strcmp(reason, "FAIL") == 0) {
		free(iface->state->old);
		iface->state->old = iface->state->new;
		iface->state->new = NULL;
		configure(iface, reason);
	}
	iface->state->lease.addr.s_addr = 0;
}

void
close_sockets(struct interface *iface)
{
	if (iface->arp_fd != -1) {
		delete_event(iface->arp_fd);
		close(iface->arp_fd);
		iface->arp_fd = -1;
	}
	if (iface->raw_fd != -1) {
		delete_event(iface->raw_fd);
		close(iface->raw_fd);
		iface->raw_fd = -1;
	}
	if (iface->udp_fd != -1) {
		close(iface->udp_fd);
		iface->udp_fd = -1;
	}
}

static void
stop_interface(struct interface *iface, const char *reason)
{
	struct interface *ifp, *ifl = NULL;

	syslog(LOG_INFO, "%s: removing interface", iface->name);
	drop_config(iface, reason ? reason : "STOP");
	close_sockets(iface);
	delete_timeout(NULL, iface);
	for (ifp = ifaces; ifp; ifp = ifp->next) {
		if (ifp == iface)
			break;
		ifl = ifp;
	}
	if (ifl)
		ifl->next = ifp->next;
	else
		ifaces = ifp->next;
	free_interface(ifp);
	if (!(options & DHCPCD_MASTER))
		exit(EXIT_FAILURE);
}

static void
send_message(struct interface *iface, int type,
	     void (*callback)(void *))
{
	struct if_state *state = iface->state;
	struct dhcp_message *dhcp;
	uint8_t *udp;
	ssize_t len, r;
	struct in_addr from, to;
	in_addr_t a = 0;
	struct timeval tv;

	if (!callback)
		syslog(LOG_DEBUG, "%s: sending %s with xid 0x%x",
		       iface->name, get_dhcp_op(type), state->xid);
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
		       "%s: sending %s with xid 0x%x, next in %0.2f seconds",
		       iface->name, get_dhcp_op(type), state->xid,
		       timeval_to_double(&tv));
	}
	/* If we couldn't open a UDP port for our IP address
	 * then we cannot renew.
	 * This could happen if our IP was pulled out from underneath us. */
	if (iface->udp_fd == -1) {
		a = iface->addr.s_addr;
		iface->addr.s_addr = 0;
	}
	len = make_message(&dhcp, iface, type);
	if (iface->udp_fd == -1)
		iface->addr.s_addr = a;
	from.s_addr = dhcp->ciaddr;
	if (from.s_addr)
		to.s_addr = state->lease.server.s_addr;
	else
		to.s_addr = 0;
	if (to.s_addr && to.s_addr != INADDR_BROADCAST) {
		r = send_packet(iface, to, (uint8_t *)dhcp, len);
		if (r == -1)
			syslog(LOG_ERR, "%s: send_packet: %m", iface->name);
	} else {
		len = make_udp_packet(&udp, (uint8_t *)dhcp, len, from, to);
		r = send_raw_packet(iface, ETHERTYPE_IP, udp, len);
		free(udp);
		if (r == -1)
			syslog(LOG_ERR, "%s: send_raw_packet: %m", iface->name);
	}
	free(dhcp);
	if (r == -1) {
		stop_interface(iface, "STOP");
	} else {
		if (callback)
			add_timeout_tv(&tv, callback, iface);
	}
}

static void
send_discover(void *arg)
{
	send_message((struct interface *)arg, DHCP_DISCOVER, send_discover);
}

void
send_request(void *arg)
{
	send_message((struct interface *)arg, DHCP_REQUEST, send_request);
}

static void
send_renew(void *arg)
{
	send_message((struct interface *)arg, DHCP_REQUEST, send_renew);
}

static void
send_rebind(void *arg)
{
	send_message((struct interface *)arg, DHCP_REQUEST, send_rebind);
}

void
start_rebind(void *arg)
{
	struct interface *iface = arg;

	syslog(LOG_ERR, "%s: failed to renew, attmepting to rebind",
	       iface->name);
	iface->state->state = DHS_REBINDING;
	delete_timeout(send_renew, iface);
	iface->state->lease.server.s_addr = 0;
	send_rebind(iface);
}

void
start_expire(void *arg)
{
	struct interface *iface = arg;
	int ll = IN_LINKLOCAL(htonl(iface->state->lease.addr.s_addr));

	syslog(LOG_ERR, "%s: lease expired", iface->name);
	delete_timeout(NULL, iface);
	drop_config(iface, "EXPIRE");
	iface->state->interval = 0;
	if (iface->carrier != LINK_DOWN) {
		if (ll)
			start_interface(iface);
		else
			start_ipv4ll(iface);
	}
}

void
send_decline(struct interface *iface)
{
	send_message(iface, DHCP_DECLINE, NULL);
}

static void
log_dhcp(int lvl, const char *msg,
	 const struct interface *iface, const struct dhcp_message *dhcp)
{
	char *a;
	struct in_addr addr;
	int r;

	if (strcmp(msg, "NAK:") == 0)
		a = get_option_string(dhcp, DHO_MESSAGE);
	else {
		addr.s_addr = dhcp->yiaddr;
		a = xstrdup(inet_ntoa(addr));
	}
	r = get_option_addr(&addr.s_addr, dhcp, DHO_SERVERID);
	if (dhcp->servername[0] && r == 0)
		syslog(lvl, "%s: %s %s from %s `%s'", iface->name, msg, a,
		       inet_ntoa(addr), dhcp->servername);
	else if (r == 0)
		syslog(lvl, "%s: %s %s from %s",
		       iface->name, msg, a, inet_ntoa(addr));
	else
		syslog(lvl, "%s: %s %s", iface->name, msg, a);
	free(a);
}

static void
handle_dhcp(struct interface *iface, struct dhcp_message **dhcpp)
{
	struct if_state *state = iface->state;
	struct if_options *ifo = state->options;
	struct dhcp_message *dhcp = *dhcpp;
	struct dhcp_lease *lease = &state->lease;
	uint8_t type, tmp;
	struct in_addr addr;
	size_t i;

	/* reset the message counter */
	state->interval = 0;

	/* We have to have DHCP type to work */
	if (get_option_uint8(&type, dhcp, DHO_MESSAGETYPE) == -1) {
		log_dhcp(LOG_ERR, "no DHCP type in", iface, dhcp);
		return;
	}

	/* Ensure that it's not from a blacklisted server.
	 * We should expand this to check IP and/or hardware address
	 * at the packet level. */
	if (ifo->blacklist_len != 0 &&
	    get_option_addr(&addr.s_addr, dhcp, DHO_SERVERID) == 0)
	{
		for (i = 0; i < ifo->blacklist_len; i++) {
			if (ifo->blacklist[i] != addr.s_addr)
				continue;
			if (dhcp->servername[0])
				syslog(LOG_WARNING,
				       "%s: ignoring blacklisted server %s `%s'",
				       iface->name,
				       inet_ntoa(addr), dhcp->servername);
			else
				syslog(LOG_WARNING,
				       "%s: ignoring blacklisted server %s",
				       iface->name, inet_ntoa(addr));
			return;
		}
	}

	/* We should restart on a NAK */
	if (type == DHCP_NAK) {
		log_dhcp(LOG_WARNING, "NAK:", iface, dhcp);
		drop_config(iface, "EXPIRE");
		delete_event(iface->raw_fd);
		close(iface->raw_fd);
		iface->raw_fd = -1;
		close(iface->udp_fd);
		iface->udp_fd = -1;
		/* If we constantly get NAKS then we should slowly back off */
		add_timeout_sec(state->nakoff, start_interface, iface);
		state->nakoff *= 2;
		if (state->nakoff > NAKOFF_MAX)
			state->nakoff = NAKOFF_MAX;
		return;
	}

	/* No NAK, so reset the backoff */
	state->nakoff = 1;

	/* Ensure that all required options are present */
	for (i = 1; i < 255; i++) {
		if (has_option_mask(ifo->requiremask, i) &&
		    get_option_uint8(&tmp, dhcp, i) != 0)
		{
			log_dhcp(LOG_WARNING, "reject", iface, dhcp);
			return;
		}
	}

	if (type == DHCP_OFFER && state->state == DHS_DISCOVERING) {
		lease->addr.s_addr = dhcp->yiaddr;
		get_option_addr(&lease->server.s_addr, dhcp, DHO_SERVERID);
		log_dhcp(LOG_INFO, "offered", iface, dhcp);
		free(state->offer);
		state->offer = dhcp;
		*dhcpp = NULL;
		if (options & DHCPCD_TEST) {
			free(state->old);
			state->old = state->new;
			state->new = state->offer;
			state->offer = NULL;
			run_script(iface, "TEST");
			exit(EXIT_SUCCESS);
		}
		delete_timeout(send_discover, iface);
		if (ifo->options & DHCPCD_ARP &&
		    iface->addr.s_addr != state->offer->yiaddr)
		{
			/* If the interface already has the address configured
			 * then we can't ARP for duplicate detection. */
			addr.s_addr = state->offer->yiaddr;
			if (!has_address(iface->name, &addr, NULL)) {
				state->state = DHS_PROBING;
				state->claims = 0;
				state->probes = 0;
				state->conflicts = 0;
				send_arp_probe(iface);
				return;
			}
		}
		state->state = DHS_REQUESTING;
		send_request(iface);
		return;
	}

	if (type == DHCP_OFFER) {
		log_dhcp(LOG_INFO, "ignoring offer of", iface, dhcp);
		return;
	}

	/* We should only be dealing with acks */
	if (type != DHCP_ACK) {
		log_dhcp(LOG_ERR, "not ACK or OFFER", iface, dhcp);
		return;
	}

	if (!(ifo->options & DHCPCD_INFORM))
		log_dhcp(LOG_INFO, "acknowledged", iface, dhcp);
	close_sockets(iface);
	free(state->offer);
	state->offer = dhcp;
	*dhcpp = NULL;
	/* Delete all timeouts for this interface. */
	delete_timeout(NULL, iface);
	bind_interface(iface);
}

static void
handle_dhcp_packet(void *arg)
{
	struct interface *iface = arg;
	uint8_t *packet;
	struct dhcp_message *dhcp = NULL;
	const uint8_t *pp;
	uint8_t *p;
	ssize_t bytes;

	/* We loop through until our buffer is empty.
	 * The benefit is that if we get >1 DHCP packet in our buffer and
	 * the first one fails for any reason, we can use the next. */
	packet = xmalloc(udp_dhcp_len);
	for(;;) {
		bytes = get_raw_packet(iface, ETHERTYPE_IP,
				       packet, udp_dhcp_len);
		if (bytes == 0 || bytes == -1)
			break;
		if (valid_udp_packet(packet) == -1)
			continue;
		bytes = get_udp_data(&pp, packet);
		if ((size_t)bytes > sizeof(*dhcp)) {
			syslog(LOG_ERR, "%s: packet greater than DHCP size",
			       iface->name);
			continue;
		}
		if (!dhcp)
			dhcp = xmalloc(sizeof(*dhcp));
		memcpy(dhcp, pp, bytes);
		if (dhcp->cookie != htonl(MAGIC_COOKIE)) {
			syslog(LOG_DEBUG, "%s: bogus cookie, ignoring",
			       iface->name);
			continue;
		}
		/* Ensure it's the right transaction */
		if (iface->state->xid != dhcp->xid) {
			syslog(LOG_DEBUG,
			       "%s: ignoring packet with xid 0x%x as"
			       " it's not ours (0x%x)",
			       iface->name, dhcp->xid, iface->state->xid);
			continue;
		}
		/* Ensure packet is for us */
		if (iface->hwlen <= sizeof(dhcp->chaddr) &&
		    memcmp(dhcp->chaddr, iface->hwaddr, iface->hwlen))
		{
			syslog(LOG_DEBUG, "%s: xid 0x%x is not for our hwaddr %s",
			       iface->name, dhcp->xid,
			       hwaddr_ntoa(dhcp->chaddr, sizeof(dhcp->chaddr)));
			continue;
		}
		/* We should ensure that the packet is terminated correctly
		 * if we have space for the terminator */
		if ((size_t)bytes < sizeof(struct dhcp_message)) {
			p = (uint8_t *)dhcp + bytes - 1;
			while (p > dhcp->options && *p == DHO_PAD)
				p--;
			if (*p != DHO_END)
				*++p = DHO_END;
		}
		handle_dhcp(iface, &dhcp);
		if (iface->raw_fd == -1)
			break;
	}
	free(packet);
	free(dhcp);
}

static void
open_sockets(struct interface *iface)
{
	if (iface->udp_fd != -1)
		close(iface->udp_fd);
	if (open_udp_socket(iface) == -1 &&
	    (errno != EADDRINUSE || iface->addr.s_addr != 0))
		syslog(LOG_ERR, "%s: open_udp_socket: %m", iface->name);
	if (iface->raw_fd != -1)
		delete_event(iface->raw_fd);
	if (open_socket(iface, ETHERTYPE_IP) == -1)
		syslog(LOG_ERR, "%s: open_socket: %m", iface->name);
	if (iface->raw_fd != -1)
		add_event(iface->raw_fd, handle_dhcp_packet, iface);
}

static void
handle_carrier(const char *ifname)
{
	struct interface *iface;

	for (iface = ifaces; iface; iface = iface->next)
		if (strcmp(iface->name, ifname) == 0)
			break;
	if (!iface || !(iface->state->options->options & DHCPCD_LINK))
		return;
	switch (carrier_status(iface->name)) {
	case -1:
		syslog(LOG_ERR, "carrier_status: %m");
		break;
	case 0:
		if (iface->carrier != LINK_DOWN) {
			iface->carrier = LINK_DOWN;
			syslog(LOG_INFO, "%s: carrier lost", iface->name);
			close_sockets(iface);
			delete_timeouts(iface, start_expire, NULL);
		}
		break;
	default:
		if (iface->carrier != LINK_UP) {
			iface->carrier = LINK_UP;
			syslog(LOG_INFO, "%s: carrier acquired", iface->name);
			start_interface(iface);
		}
		break;
	}
}

void
start_discover(void *arg)
{
	struct interface *iface = arg;
	struct if_options *ifo = iface->state->options;

	iface->state->state = DHS_DISCOVERING;
	iface->state->xid = arc4random();
	open_sockets(iface);
	delete_timeout(NULL, iface);
	if (ifo->options & DHCPCD_IPV4LL &&
	    !IN_LINKLOCAL(htonl(iface->addr.s_addr)))
	{
		if (IN_LINKLOCAL(htonl(iface->state->fail.s_addr)))
			add_timeout_sec(RATE_LIMIT_INTERVAL, start_ipv4ll, iface);
		else
			add_timeout_sec(ifo->timeout, start_ipv4ll, iface);
	}
	syslog(LOG_INFO, "%s: broadcasting for a lease", iface->name);
	send_discover(iface);
}


void
start_renew(void *arg)
{
	struct interface *iface = arg;

	syslog(LOG_INFO, "%s: renewing lease of %s",
	       iface->name, inet_ntoa(iface->state->lease.addr));
	iface->state->state = DHS_RENEWING;
	iface->state->xid = arc4random();
	open_sockets(iface);
	send_renew(iface);
}

void
start_reboot(struct interface *iface)
{
	struct if_options *ifo = iface->state->options;

	if (ifo->options & DHCPCD_LINK && iface->carrier == LINK_DOWN) {
		syslog(LOG_INFO, "%s: waiting for carrier", iface->name);
		return;
	}
	syslog(LOG_INFO, "%s: rebinding lease of %s",
	       iface->name, inet_ntoa(iface->state->lease.addr));
	iface->state->state = DHS_REBINDING;
	iface->state->xid = arc4random();
	iface->state->lease.server.s_addr = 0;
	delete_timeout(NULL, iface);
	add_timeout_sec(ifo->timeout, start_expire, iface);
	open_sockets(iface);
	send_rebind(iface);
}

static void
send_release(struct interface *iface)
{
	if (iface->state->lease.addr.s_addr &&
	    !IN_LINKLOCAL(htonl(iface->state->lease.addr.s_addr)))
	{
		syslog(LOG_INFO, "%s: releasing lease of %s",
		       iface->name, inet_ntoa(iface->state->lease.addr));
		open_sockets(iface);
		send_message(iface, DHCP_RELEASE, NULL);
	}
}

void
start_interface(void *arg)
{
	struct interface *iface = arg;

	if (iface->carrier == LINK_DOWN) {
		syslog(LOG_INFO, "%s: waiting for carrier", iface->name);
		return;
	}

	iface->start_uptime = uptime();
	if (!iface->state->lease.addr.s_addr)
		start_discover(iface);
	else if (IN_LINKLOCAL(htonl(iface->state->lease.addr.s_addr)))
		start_ipv4ll(iface);
	else
		start_reboot(iface);
}

static void
configure_interface(struct interface *iface, int argc, char **argv)
{
	struct if_state *ifs = iface->state;
	struct if_options *ifo;
	uint8_t *duid;
	size_t len = 0, ifl;

	free_options(ifs->options);
	ifo = ifs->options = read_config(cffile, iface->name);
	add_options(ifo, argc, argv);

	if (ifo->metric != -1)
		iface->metric = ifo->metric;

	free(iface->clientid);
	if (*ifo->clientid) {
		iface->clientid = xmalloc(ifo->clientid[0] + 1);
		memcpy(iface->clientid, ifo->clientid, ifo->clientid[0] + 1);
	} else if (ifo->options & DHCPCD_CLIENTID) {
		if (ifo->options & DHCPCD_DUID) {
			duid = xmalloc(DUID_LEN);
			if ((len = get_duid(duid, iface)) == 0)
				syslog(LOG_ERR, "get_duid: %m");
		}
		if (len > 0) {
			iface->clientid = xmalloc(len + 6);
			iface->clientid[0] = len + 5;
			iface->clientid[1] = 255; /* RFC 4361 */
			ifl = strlen(iface->name);
			if (ifl < 5) {
				memcpy(iface->clientid + 2, iface->name, ifl);
				if (ifl < 4)
					memset(iface->clientid + 2 + ifl,
							0, 4 - ifl);
			} else {
				ifl = htonl(if_nametoindex(iface->name));
				memcpy(iface->clientid + 2, &ifl, 4);
			}
		} else if (len == 0) {
			len = iface->hwlen + 1;
			iface->clientid = xmalloc(len + 1);
			iface->clientid[0] = len;
			iface->clientid[1] = iface->family;
			memcpy(iface->clientid + 2, iface->hwaddr, iface->hwlen);
		}
	}

}

static void
init_state(struct interface *iface, int argc, char **argv)
{
	struct if_state *ifs;

	if (iface->state) {
		ifs = iface->state;
	} else
		ifs = iface->state = xzalloc(sizeof(*ifs));

	ifs->state = DHS_INIT;
	ifs->nakoff = 1;
	configure_interface(iface, argc, argv);

	if (ifs->options->options & DHCPCD_LINK) {
		switch (carrier_status(iface->name)) {
		case 0:
			iface->carrier = LINK_DOWN;
			break;
		case 1:
			iface->carrier = LINK_UP;
			break;
		default:
			iface->carrier = LINK_UNKNOWN;
		}
	} else
		iface->carrier = LINK_UNKNOWN;
}

static void
handle_new_interface(const char *ifname)
{
	struct interface *ifs, *ifp, *ifn, *ifl = NULL;
	const char * const argv[] = { "dhcpcd", ifname };
	int i;

	/* If running off an interface list, check it's in it. */
	if (ifc) {
		for (i = 0; i < ifc; i++)
			if (strcmp(ifv[i], ifname) == 0)
				break;
		if (i >= ifc)
			return;
	}

	if ((ifs = discover_interfaces(2, UNCONST(argv)))) {
		for (ifp = ifs; ifp; ifp = ifp->next) {
			/* Check if we already have the interface */
			for (ifn = ifaces; ifn; ifn = ifn->next) {
				if (strcmp(ifn->name, ifp->name) == 0)
					break;
				ifl = ifn;
			}
			if (ifn)
				continue;
			init_state(ifp, 2, UNCONST(argv));
			run_script(ifp, "PREINIT");
			start_interface(ifp);
			if (ifl)
				ifl->next = ifp;
			else
				ifaces = ifp;
		}
	}
}

static void
handle_remove_interface(const char *ifname)
{
	struct interface *iface;

	for (iface = ifaces; iface; iface = iface->next)
		if (strcmp(iface->name, ifname) == 0)
			break;
	if (iface && iface->state->options->options & DHCPCD_LINK)
		stop_interface(iface, "STOP");
}

static void
handle_link(_unused void *arg)
{
	if (manage_link(linkfd,
			handle_carrier,
			handle_new_interface,
			handle_remove_interface) == -1)
		syslog(LOG_ERR, "manage_link: %m");
}

static void
handle_signal(_unused void *arg)
{
	struct interface *iface, *ifl;
	int sig = signal_read();
	int do_reboot = 0, do_release = 0;

	switch (sig) {
	case SIGINT:
		syslog(LOG_INFO, "received SIGINT, stopping");
		break;
	case SIGTERM:
		syslog(LOG_INFO, "received SIGTERM, stopping");
		break;
	case SIGALRM:
		syslog(LOG_INFO, "received SIGALRM, rebinding lease");
		do_reboot = 1;
	case SIGHUP:
		syslog(LOG_INFO, "received SIGHUP, releasing lease");
		do_release = 1;
		break;
	default:
		syslog (LOG_ERR,
			"received signal %d, but don't know what to do with it",
			sig);
		return;
	}

	/* As drop_config could re-arrange the order, we do it like this. */
	for (;;) {
		/* Be sane and drop the last config first */
		ifl = NULL;
		for (iface = ifaces; iface; iface = iface->next)
			if (iface->state && iface->state->new)
				ifl = iface;
		if (!ifl)
			break;
		if (do_reboot)
			start_reboot(ifl);
		else {
			if (do_release)
				send_release(ifl);
			if (!(ifl->state->options->options & DHCPCD_PERSISTENT))
				drop_config(ifl, do_release ? "RELEASE" : "STOP");
		}
	}
	exit(EXIT_FAILURE);
}

int
handle_args(int argc, char **argv)
{
	struct interface *ifs, *ifp, *ifl, *ifn;
	int do_exit = 0, do_release = 0, do_reboot = 0, opt, oi = 0;

	optind = 0;
	while ((opt = getopt_long(argc, argv, IF_OPTS, cf_options, &oi)) != -1)
	{
		switch (opt) {
		case 'k':
			do_release = 1;
			break;
		case 'n':
			do_reboot = 1;
			break;
		case 'x':
			do_exit = 1;
			break;
		}
	}

	/* We only deal with one interface here */
	if (optind == argc) {
		syslog(LOG_ERR, "handle_args: no interface");
		return -1;
	}

	if (do_release || do_reboot || do_exit) {
		for (oi = optind; oi < argc; oi++) {
			for (ifp = ifaces; ifp; ifp = ifp->next)
				if (strcmp(ifp->name, argv[oi]) == 0)
					break;
			if (!ifp)
				continue;
			if (do_release)
				send_release(ifp);
			if (do_exit || do_release) {
				stop_interface(ifp, do_release ? "RELEASE" : "STOP");
			} else if (do_reboot) {
				configure_interface(ifp, argc, argv);
				start_reboot(ifp);
			}
		}
		sort_interfaces();
		return 0;
	}

	if ((ifs = discover_interfaces(argc, argv))) {
		argc += optind;
		argv -= optind;
		for (ifp = ifs; ifp; ifp = ifp->next) {
			ifl = NULL;
			for (ifn = ifaces; ifn; ifn = ifn->next) {
				if (strcmp(ifn->name, ifp->name) == 0)
					break;
				ifl = ifn;
			}
			if (!ifn) {
				init_state(ifp, argc, argv);
				run_script(ifp, "PREINIT");
				start_interface(ifp);
				if (ifl)
					ifl->next = ifp;
				else
					ifaces = ifp;
			}
		}
		sort_interfaces();
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct if_options *ifo;
	struct interface *iface;
	int opt, oi = 0, signal_fd, sig = 0, i, control_fd;
	size_t len;
	pid_t pid;
	struct timespec ts;

	closefrom(3);
	openlog(PACKAGE, LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_INFO));

	/* Test for --help and --version */
	if (argc > 1) {
		if (strcmp(argv[1], "--help") == 0) {
			usage();
			exit(EXIT_SUCCESS);
		} else if (strcmp(argv[1], "--version") == 0) {
			printf(""PACKAGE" "VERSION"\n%s\n", copyright);
			exit(EXIT_SUCCESS);
		}
	}

	i = 0;
	while ((opt = getopt_long(argc, argv, IF_OPTS, cf_options, &oi)) != -1)
	{
		switch (opt) {
		case 'd':
			setlogmask(LOG_UPTO(LOG_DEBUG));
			break;
		case 'f':
			cffile = optarg;
			break;
		case 'k':
			sig = SIGHUP;
			break;
		case 'n':
			sig = SIGALRM;
			break;
		case 'x':
			sig = SIGTERM;
			break;
		case 'T':
			i = 1;
			break;
		case 'V':
			print_options();
			exit(EXIT_SUCCESS);
		case '?':
			usage();
			exit(EXIT_FAILURE);
		}
	}

	ifo = read_config(cffile, NULL);
	opt = add_options(ifo, argc, argv);
	if (opt != 1) {
		if (opt == 0)
			usage();
		exit(EXIT_FAILURE);
	}
	options = ifo->options;
	if (i)
		options |= DHCPCD_TEST | DHCPCD_PERSISTENT;

#ifdef THERE_IS_NO_FORK
	options &= ~DHCPCD_DAEMONISE;
#endif

	if (options & DHCPCD_QUIET)
		setlogmask(LOG_UPTO(LOG_WARNING));

	/* If we have any other args, we should run as a single dhcpcd instance
	 * for that interface. */
	len = strlen(PIDFILE) + IF_NAMESIZE + 2;
	pidfile = xmalloc(len);
	if (optind == argc - 1 && !(options & DHCPCD_TEST)) {
		snprintf(pidfile, len, PIDFILE, "-", argv[optind]);
	} else {
		snprintf(pidfile, len, PIDFILE, "", "");
		options |= DHCPCD_MASTER;
	}

	chdir("/");
	umask(022);
	atexit(cleanup);

	if (!(options & DHCPCD_MASTER)) {
		control_fd = open_control();
		if (control_fd != -1) {
			syslog(LOG_INFO, "sending commands to master dhcpcd process");
			i = send_control(argc, argv);
			if (i > 0) {
				syslog(LOG_DEBUG, "send OK");
				exit(EXIT_SUCCESS);
			} else {
				syslog(LOG_ERR, "failed to send commands");
				exit(EXIT_FAILURE);
			}
		} else {
			if (errno != ENOENT)
				syslog(LOG_ERR, "open_control: %m");
		}
	}

	if (geteuid())
		syslog(LOG_WARNING, PACKAGE " will not work correctly unless"
		       " run as root");

	if (sig != 0) {
		i = -1;
		pid = read_pid();
		if (pid != 0)
			syslog(LOG_INFO, "sending signal %d to pid %d",
			       sig, pid);

		if (!pid || (i = kill(pid, sig))) {
			if (sig != SIGALRM)
				syslog(LOG_ERR, ""PACKAGE" not running");
			unlink(pidfile);
			exit(EXIT_FAILURE);
		}
		/* Spin until it exits */
		syslog(LOG_INFO, "waiting for pid %d to exit", pid);
		ts.tv_sec = 0;
		ts.tv_nsec = 100000000; /* 10th of a second */
		for(i = 0; i < 100; i++) {
			nanosleep(&ts, NULL);
			if (read_pid() == 0)
				exit(EXIT_SUCCESS);
		}
		syslog(LOG_ERR, "pid %d failed to exit", pid);
		exit(EXIT_FAILURE);
	}

	if (!(options & DHCPCD_TEST)) {
		if ((pid = read_pid()) > 0 &&
		    kill(pid, 0) == 0)
		{
			syslog(LOG_ERR, ""PACKAGE
			       " already running on pid %d (%s)",
			       pid, pidfile);
			exit(EXIT_FAILURE);
		}

		pidfd = open(pidfile, O_WRONLY | O_CREAT | O_NONBLOCK, 0664);
		if (pidfd == -1) {
			syslog(LOG_ERR, "open `%s': %m", pidfile);
			exit(EXIT_FAILURE);
		}
		/* Lock the file so that only one instance of dhcpcd runs
		 * on an interface */
		if (flock(pidfd, LOCK_EX | LOCK_NB) == -1) {
			syslog(LOG_ERR, "flock `%s': %m", pidfile);
			exit(EXIT_FAILURE);
		}
		if (set_cloexec(pidfd) == -1)
			exit(EXIT_FAILURE);
		writepid(pidfd, getpid());
	}

	syslog(LOG_INFO, "version " VERSION " starting");

	if ((signal_fd =signal_init()) == -1)
		exit(EXIT_FAILURE);
	if (signal_setup() == -1)
		exit(EXIT_FAILURE);
	add_event(signal_fd, handle_signal, NULL);

	if (options & DHCPCD_MASTER) {
		if (start_control() == -1) {
			syslog(LOG_ERR, "start_control: %m");
			exit(EXIT_FAILURE);
		}
	}

	if (ifo->options & DHCPCD_LINK) {
		linkfd = open_link_socket();
		if (linkfd == -1)
			syslog(LOG_ERR, "open_link_socket: %m");
		else
			add_event(linkfd, handle_link, NULL);
	}

	if (options & DHCPCD_DAEMONISE && !(options & DHCPCD_BACKGROUND)) {
		oi = ifo->timeout;
		if (ifo->options & DHCPCD_IPV4LL)
			oi += 10;
		add_timeout_sec(oi, handle_exit_timeout, NULL);
	}
	free_options(ifo);

	ifc = argc - optind;
	ifv = argv + optind;
	ifaces = discover_interfaces(ifc, ifv);
	if (!ifaces && ifc == 1) {
		syslog(LOG_ERR, "interface `%s' does not exist", ifv[0]);
		exit(EXIT_FAILURE);
	}
	if (options & DHCPCD_BACKGROUND)
		daemonise();
	for (iface = ifaces; iface; iface = iface->next)
		init_state(iface, argc, argv);
	sort_interfaces();
	if (!(options & DHCPCD_TEST)) {
		for (iface = ifaces; iface; iface = iface->next) {
			run_script(iface, "PREINIT");
			start_interface(iface);
		}
	}
	start_eloop();
	/* NOTREACHED */
}
