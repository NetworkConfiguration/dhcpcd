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

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#  include <asm/types.h> /* for systems with broken headers */
#  include <linux/rtnetlink.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "if-options.h"
#include "if-pref.h"
#include "ipv4.h"
#include "net.h"
#include "script.h"

static struct rt *routes;

static struct rt *
find_route(struct rt *rts, const struct rt *r, struct rt **lrt,
    const struct rt *srt)
{
	struct rt *rt;

	if (lrt)
		*lrt = NULL;
	for (rt = rts; rt; rt = rt->next) {
		if (rt->dest.s_addr == r->dest.s_addr &&
#if HAVE_ROUTE_METRIC
		    (srt || (!rt->iface ||
			rt->iface->metric == r->iface->metric)) &&
#endif
                    (!srt || srt != rt) &&
		    rt->net.s_addr == r->net.s_addr)
			return rt;
		if (lrt)
			*lrt = rt;
	}
	return NULL;
}

static void
desc_route(const char *cmd, const struct rt *rt)
{
	char addr[sizeof("000.000.000.000") + 1];
	const char *ifname = rt->iface->name;

	strlcpy(addr, inet_ntoa(rt->dest), sizeof(addr));
	if (rt->gate.s_addr == INADDR_ANY)
		syslog(LOG_DEBUG, "%s: %s route to %s/%d", ifname, cmd,
		    addr, inet_ntocidr(rt->net));
	else if (rt->gate.s_addr == rt->dest.s_addr &&
	    rt->net.s_addr == INADDR_BROADCAST)
		syslog(LOG_DEBUG, "%s: %s host route to %s", ifname, cmd,
		    addr);
	else if (rt->dest.s_addr == INADDR_ANY && rt->net.s_addr == INADDR_ANY)
		syslog(LOG_DEBUG, "%s: %s default route via %s", ifname, cmd,
		    inet_ntoa(rt->gate));
	else
		syslog(LOG_DEBUG, "%s: %s route to %s/%d via %s", ifname, cmd,
		    addr, inet_ntocidr(rt->net), inet_ntoa(rt->gate));
}

/* If something other than dhcpcd removes a route,
 * we need to remove it from our internal table. */
int
ipv4_routedeleted(const struct rt *rt)
{
	struct rt *f, *l;

	f = find_route(routes, rt, &l, NULL);
	if (f == NULL)
		return 0;
	desc_route("removing", f);
	if (l)
		l->next = f->next;
	else
		routes = f->next;
	free(f);
	return 1;
}

static int
n_route(struct rt *rt)
{
	struct if_state *s;

	/* Don't set default routes if not asked to */
	if (rt->dest.s_addr == 0 &&
	    rt->net.s_addr == 0 &&
	    !(rt->iface->options->options & DHCPCD_GATEWAY))
		return -1;

	desc_route("adding", rt);
	if (!add_route(rt))
		return 0;
	if (errno == EEXIST) {
		s = rt->iface->state;
		/* Pretend we added the subnet route */
		if (rt->dest.s_addr == (s->addr.s_addr & s->net.s_addr) &&
		    rt->net.s_addr == s->net.s_addr &&
		    rt->gate.s_addr == 0)
			return 0;
		else
			return -1;
	}
	syslog(LOG_ERR, "%s: add_route: %m", rt->iface->name);
	return -1;
}

static int
c_route(struct rt *ort, struct rt *nrt)
{
	/* Don't set default routes if not asked to */
	if (nrt->dest.s_addr == 0 &&
	    nrt->net.s_addr == 0 &&
	    !(nrt->iface->options->options & DHCPCD_GATEWAY))
		return -1;

	desc_route("changing", nrt);
	/* We delete and add the route so that we can change metric.
	 * This also has the nice side effect of flushing ARP entries so
	 * we don't have to do that manually. */
	del_route(ort);
	if (!add_route(nrt))
		return 0;
	syslog(LOG_ERR, "%s: add_route: %m", nrt->iface->name);
	return -1;
}

static int
d_route(struct rt *rt)
{
	int retval;

	desc_route("deleting", rt);
	retval = del_route(rt);
	if (retval != 0 && errno != ENOENT && errno != ESRCH)
		syslog(LOG_ERR,"%s: del_route: %m", rt->iface->name);
	return retval;
}

static struct rt *
get_subnet_route(struct dhcp_message *dhcp)
{
	in_addr_t addr;
	struct in_addr net;
	struct rt *rt;

	addr = dhcp->yiaddr;
	if (addr == 0)
		addr = dhcp->ciaddr;
	/* Ensure we have all the needed values */
	if (get_option_addr(&net, dhcp, DHO_SUBNETMASK) == -1)
		net.s_addr = get_netmask(addr);
	if (net.s_addr == INADDR_BROADCAST || net.s_addr == INADDR_ANY)
		return NULL;
	rt = malloc(sizeof(*rt));
	rt->dest.s_addr = addr & net.s_addr;
	rt->net.s_addr = net.s_addr;
	rt->gate.s_addr = 0;
	return rt;
}

static struct rt *
add_subnet_route(struct rt *rt, const struct interface *iface)
{
	struct rt *r;
	struct if_state *s;

	s = iface->state;
	if (s->net.s_addr == INADDR_BROADCAST ||
	    s->net.s_addr == INADDR_ANY ||
	    (iface->options->options &
	     (DHCPCD_INFORM | DHCPCD_STATIC) &&
	     iface->options->req_addr.s_addr == INADDR_ANY))
		return rt;

	r = xmalloc(sizeof(*r));
	r->dest.s_addr = s->addr.s_addr & s->net.s_addr;
	r->net.s_addr = s->net.s_addr;
	r->gate.s_addr = 0;
	r->next = rt;
	return r;
}

static struct rt *
get_routes(struct interface *ifp)
{
	struct rt *rt, *nrt = NULL, *r = NULL;

	if (ifp->options->routes != NULL) {
		for (rt = ifp->options->routes;
		     rt != NULL;
		     rt = rt->next)
		{
			if (rt->gate.s_addr == 0)
				break;
			if (r == NULL)
				r = nrt = xmalloc(sizeof(*r));
			else {
				r->next = xmalloc(sizeof(*r));
				r = r->next;
			}
			memcpy(r, rt, sizeof(*r));
			r->next = NULL;
		}
		return nrt;
	}

	return get_option_routes(ifp, ifp->state->new);
}

/* Some DHCP servers add set host routes by setting the gateway
 * to the assinged IP address. This differs from our notion of a host route
 * where the gateway is the destination address, so we fix it. */
static struct rt *
massage_host_routes(struct rt *rt, const struct interface *ifp)
{
	struct rt *r;

	for (r = rt; r; r = r->next) {
		if (r->gate.s_addr == ifp->state->addr.s_addr &&
		    r->net.s_addr == INADDR_BROADCAST)
			r->gate.s_addr = r->dest.s_addr;
	}
	return rt;
}

static struct rt *
add_destination_route(struct rt *rt, const struct interface *iface)
{
	struct rt *r;

	if (!(iface->flags & IFF_POINTOPOINT) ||
	    !has_option_mask(iface->options->dstmask, DHO_ROUTER))
		return rt;
	r = xmalloc(sizeof(*r));
	r->dest.s_addr = INADDR_ANY;
	r->net.s_addr = INADDR_ANY;
	r->gate.s_addr = iface->state->dst.s_addr;
	r->next = rt;
	return r;
}

/* We should check to ensure the routers are on the same subnet
 * OR supply a host route. If not, warn and add a host route. */
static struct rt *
add_router_host_route(struct rt *rt, const struct interface *ifp)
{
	struct rt *rtp, *rtl, *rtn;
	const char *cp, *cp2, *cp3, *cplim;

	for (rtp = rt, rtl = NULL; rtp; rtl = rtp, rtp = rtp->next) {
		if (rtp->dest.s_addr != INADDR_ANY)
			continue;
		/* Scan for a route to match */
		for (rtn = rt; rtn != rtp; rtn = rtn->next) {
			/* match host */
			if (rtn->dest.s_addr == rtp->gate.s_addr)
				break;
			/* match subnet */
			cp = (const char *)&rtp->gate.s_addr;
			cp2 = (const char *)&rtn->dest.s_addr;
			cp3 = (const char *)&rtn->net.s_addr;
			cplim = cp3 + sizeof(rtn->net.s_addr);
			while (cp3 < cplim) {
				if ((*cp++ ^ *cp2++) & *cp3++)
					break;
			}
			if (cp3 == cplim)
				break;
		}
		if (rtn != rtp)
			continue;
		if (ifp->flags & IFF_NOARP) {
			syslog(LOG_WARNING,
			    "%s: forcing router %s through interface",
			    ifp->name, inet_ntoa(rtp->gate));
			rtp->gate.s_addr = 0;
			continue;
		}
		syslog(LOG_WARNING, "%s: router %s requires a host route",
		    ifp->name, inet_ntoa(rtp->gate));
		rtn = xmalloc(sizeof(*rtn));
		rtn->dest.s_addr = rtp->gate.s_addr;
		rtn->net.s_addr = INADDR_BROADCAST;
		rtn->gate.s_addr = rtp->gate.s_addr;
		rtn->next = rtp;
		if (rtl == NULL)
			rt = rtn;
		else
			rtl->next = rtn;
	}
	return rt;
}

void
ipv4_buildroutes(void)
{
	struct rt *nrs = NULL, *dnr, *or, *rt, *rtn, *rtl, *lrt = NULL;
	struct interface *ifp;

	for (ifp = ifaces; ifp; ifp = ifp->next) {
		if (ifp->state->new == NULL)
			continue;
		dnr = get_routes(ifp);
		dnr = massage_host_routes(dnr, ifp);
		dnr = add_subnet_route(dnr, ifp);
		if (ifp->options->options & DHCPCD_GATEWAY) {
			dnr = add_router_host_route(dnr, ifp);
			dnr = add_destination_route(dnr, ifp);
		}
		for (rt = dnr; rt && (rtn = rt->next, 1); lrt = rt, rt = rtn) {
			rt->iface = ifp;
			rt->metric = ifp->metric;
			/* Is this route already in our table? */
			if ((find_route(nrs, rt, NULL, NULL)) != NULL)
				continue;
			rt->src.s_addr = ifp->state->addr.s_addr;
			/* Do we already manage it? */
			if ((or = find_route(routes, rt, &rtl, NULL))) {
				if (or->iface != ifp ||
				    or->src.s_addr != ifp->state->addr.s_addr ||
				    rt->gate.s_addr != or->gate.s_addr ||
				    rt->metric != or->metric)
				{
					if (c_route(or, rt) != 0)
						continue;
				}
				if (rtl != NULL)
					rtl->next = or->next;
				else
					routes = or->next;
				free(or);
			} else {
				if (n_route(rt) != 0)
					continue;
			}
			if (dnr == rt)
				dnr = rtn;
			else if (lrt)
				lrt->next = rtn;
			rt->next = nrs;
			nrs = rt;
			rt = lrt; /* When we loop this makes lrt correct */
		}
		free_routes(dnr);
	}

	/* Remove old routes we used to manage */
	for (rt = routes; rt; rt = rt->next) {
		if (find_route(nrs, rt, NULL, NULL) == NULL)
			d_route(rt);
	}

	free_routes(routes);
	routes = nrs;
}

static int
delete_address(struct interface *iface)
{
	int retval;
	struct if_options *ifo;

	ifo = iface->options;
	if (ifo->options & DHCPCD_INFORM ||
	    (ifo->options & DHCPCD_STATIC && ifo->req_addr.s_addr == 0))
		return 0;
	syslog(LOG_DEBUG, "%s: deleting IP address %s/%d",
	    iface->name,
	    inet_ntoa(iface->state->addr),
	    inet_ntocidr(iface->state->net));
	retval = del_address(iface, &iface->state->addr, &iface->state->net);
	if (retval == -1 && errno != EADDRNOTAVAIL) 
		syslog(LOG_ERR, "del_address: %m");
	iface->state->addr.s_addr = 0;
	iface->state->net.s_addr = 0;
	return retval;
}

void
ipv4_applyaddr(void *arg)
{
	struct interface *iface = arg;
	struct dhcp_message *dhcp = iface->state->new;
	struct dhcp_lease *lease = &iface->state->lease;
	struct if_options *ifo = iface->options;
	struct rt *rt;

	/* As we are now adjusting an interface, we need to ensure
	 * we have them in the right order for routing and configuration. */
	sort_interfaces();

	if (dhcp == NULL) {
		if (!(ifo->options & DHCPCD_PERSISTENT)) {
			ipv4_buildroutes();
			if (iface->state->addr.s_addr != 0)
				delete_address(iface);
			script_run(iface);
		}
		return;
	}

	/* This also changes netmask */
	if (!(ifo->options & DHCPCD_INFORM) ||
	    !has_address(iface->name, &lease->addr, &lease->net))
	{
		syslog(LOG_DEBUG, "%s: adding IP address %s/%d",
		    iface->name, inet_ntoa(lease->addr),
		    inet_ntocidr(lease->net));
		if (add_address(iface,
			&lease->addr, &lease->net, &lease->brd) == -1 &&
		    errno != EEXIST)
		{
			syslog(LOG_ERR, "%s: add_address: %m", __func__);
			return;
		}
	}

	/* Now delete the old address if different */
	if (iface->state->addr.s_addr != lease->addr.s_addr &&
	    iface->state->addr.s_addr != 0)
		delete_address(iface);

	iface->state->addr.s_addr = lease->addr.s_addr;
	iface->state->net.s_addr = lease->net.s_addr;

	/* We need to delete the subnet route to have our metric or
	 * prefer the interface. */
	rt = get_subnet_route(dhcp);
	if (rt != NULL) {
		rt->iface = iface;
		rt->metric = 0;
		if (!find_route(routes, rt, NULL, NULL))
			del_route(rt);
		free(rt);
	}

	ipv4_buildroutes();
	if (!iface->state->lease.frominfo &&
	    !(ifo->options & (DHCPCD_INFORM | DHCPCD_STATIC)))
		if (write_lease(iface, dhcp) == -1)
			syslog(LOG_ERR, "%s: write_lease: %m", __func__);
	script_run(iface);
}

void
ipv4_handleifa(int type, const char *ifname,
    struct in_addr *addr, struct in_addr *net, struct in_addr *dst)
{
	struct interface *ifp;
	struct if_options *ifo;
	int i;

	if (addr->s_addr == INADDR_ANY)
		return;
	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (strcmp(ifp->name, ifname) == 0)
			break;
	if (ifp == NULL)
		return;

	if (type == RTM_DELADDR) {
		if (ifp->state->new &&
		    ifp->state->new->yiaddr == addr->s_addr)
			syslog(LOG_INFO, "%s: removing IP address %s/%d",
			    ifp->name, inet_ntoa(ifp->state->lease.addr),
			    inet_ntocidr(ifp->state->lease.net));
		return;
	}

	if (type != RTM_NEWADDR)
		return;

	ifo = ifp->options;
	if ((ifo->options & (DHCPCD_INFORM | DHCPCD_STATIC)) == 0 ||
	    ifo->req_addr.s_addr != INADDR_ANY)
		return;

	free(ifp->state->old);
	ifp->state->old = ifp->state->new;
	ifp->state->new = dhcp_message_new(addr, net);
	ifp->state->dst.s_addr = dst ? dst->s_addr : INADDR_ANY;
	if (dst) {
		for (i = 1; i < 255; i++)
			if (i != DHO_ROUTER && has_option_mask(ifo->dstmask,i))
				dhcp_message_add_addr(ifp->state->new, i, *dst);
	}
	ifp->state->reason = "STATIC";
	ipv4_buildroutes();
	script_run(ifp);
	if (ifo->options & DHCPCD_INFORM) {
		ifp->state->state = DHS_INFORM;
		ifp->state->xid = dhcp_xid(ifp);
		ifp->state->lease.server.s_addr =
		    dst ? dst->s_addr : INADDR_ANY;
		ifp->state->addr = *addr;
		ifp->state->net = *net;
		dhcp_inform(ifp);
	}
}
