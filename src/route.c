/*
 * dhcpcd - route management
 * Copyright (c) 2006-2019 Roy Marples <roy@marples.name>
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcpcd.h"
#include "if.h"
#include "ipv4.h"
#include "ipv4ll.h"
#include "ipv6.h"
#include "logerr.h"
#include "route.h"
#include "sa.h"

static int
rt_compare(__unused void *context, const void *node1, const void *node2)
{
	const struct rt *rt1 = node1, *rt2 = node2;
	bool rt1u, rt2u;
	int c;

	/* Default routes come last. */
	rt1u = !(rt1->rt_flags & RTF_HOST) &&
	    sa_is_unspecified(&rt1->rt_dest) &&
	    sa_is_unspecified(&rt1->rt_netmask);
	rt2u = !(rt2->rt_flags & RTF_HOST) &&
	    sa_is_unspecified(&rt2->rt_dest) &&
	    sa_is_unspecified(&rt2->rt_netmask);
	if (rt1u != rt2u)
		return rt1u ? 1 : -1;

	/* Sort by destination and netmask. */
	c = sa_cmp(&rt1->rt_dest, &rt2->rt_dest);
	if (c != 0)
		return c;
	c = sa_cmp(&rt1->rt_netmask, &rt2->rt_netmask);
	if (c != 0)
		return c;

	/* Finally by interface metric. */
	if (rt1->rt_ifp == NULL || rt2->rt_ifp == NULL)
		/* option or freed route */
		c = rt1 == rt2 ? 0 : rt1 < rt2 ? -1 : 1;
	else
		c = (int)(rt1->rt_ifp->metric - rt2->rt_ifp->metric);

	return c;
}

const rb_tree_ops_t rt_rb_tree_ops = {
	.rbto_compare_nodes = rt_compare,
	.rbto_compare_key = rt_compare,
	.rbto_node_offset = offsetof(struct rt, rt_tree),
	.rbto_context = NULL
};

void
rt_init(struct dhcpcd_ctx *ctx)
{

	rb_tree_init(&ctx->routes, &rt_rb_tree_ops);
	rb_tree_init(&ctx->kroutes, &rt_rb_tree_ops);
	rb_tree_init(&ctx->froutes, &rt_rb_tree_ops);
}

/*
 * On some systems, host routes have no need for a netmask.
 * However DHCP specifies host routes using an all-ones netmask.
 * This handy function allows easy comparison when the two
 * differ.
 */
static int
rt_cmp_netmask(const struct rt *rt1, const struct rt *rt2)
{

	if (rt1->rt_flags & RTF_HOST && rt2->rt_flags & RTF_HOST)
		return 0;
	return sa_cmp(&rt1->rt_netmask, &rt2->rt_netmask);
}

static void
rt_desc(const char *cmd, const struct rt *rt)
{
	char dest[INET_MAX_ADDRSTRLEN], gateway[INET_MAX_ADDRSTRLEN];
	int prefix;
	const char *ifname;
	bool gateway_unspec;

	assert(cmd != NULL);
	assert(rt != NULL);

	sa_addrtop(&rt->rt_dest, dest, sizeof(dest));
	prefix = sa_toprefix(&rt->rt_netmask);
	sa_addrtop(&rt->rt_gateway, gateway, sizeof(gateway));
	gateway_unspec = sa_is_unspecified(&rt->rt_gateway);
	ifname = rt->rt_ifp == NULL ? "(null)" : rt->rt_ifp->name;

	if (rt->rt_flags & RTF_HOST) {
		if (gateway_unspec)
			loginfox("%s: %s host route to %s",
			    ifname, cmd, dest);
		else
			loginfox("%s: %s host route to %s via %s",
			    ifname, cmd, dest, gateway);
	} else if (sa_is_unspecified(&rt->rt_dest) &&
		   sa_is_unspecified(&rt->rt_netmask))
	{
		if (gateway_unspec)
			loginfox("%s: %s default route",
			    ifname, cmd);
		else
			loginfox("%s: %s default route via %s",
			    ifname, cmd, gateway);
	} else if (gateway_unspec)
		loginfox("%s: %s%s route to %s/%d",
		    ifname, cmd,
		    rt->rt_flags & RTF_REJECT ? " reject" : "",
		    dest, prefix);
	else
		loginfox("%s: %s%s route to %s/%d via %s",
		    ifname, cmd,
		    rt->rt_flags & RTF_REJECT ? " reject" : "",
		    dest, prefix, gateway);
}

void
rt_headclear0(struct dhcpcd_ctx *ctx, rb_tree_t *rts, int af)
{
	struct rt *rt, *rtn;

	if (rts == NULL)
		return;
	assert(ctx != NULL);
	assert(&ctx->froutes != rts);

	RB_TREE_FOREACH_SAFE(rt, rts, rtn) {
		if (af != AF_UNSPEC &&
		    rt->rt_dest.sa_family != af &&
		    rt->rt_gateway.sa_family != af)
			continue;
		rb_tree_remove_node(rts, rt);
		rt_free(rt);
	}
}

void
rt_headclear(rb_tree_t *rts, int af)
{
	struct rt *rt;

	if (rts == NULL || (rt = RB_TREE_MIN(rts)) == NULL)
		return;
	rt_headclear0(rt->rt_ifp->ctx, rts, af);
}

static void
rt_headfree(rb_tree_t *rts)
{
	struct rt *rt;

	while ((rt = RB_TREE_MIN(rts)) != NULL) {
		rb_tree_remove_node(rts, rt);
		free(rt);
	}
}

void
rt_dispose(struct dhcpcd_ctx *ctx)
{

	assert(ctx != NULL);
	rt_headfree(&ctx->routes);
	rt_headfree(&ctx->kroutes);
	rt_headfree(&ctx->froutes);
}

struct rt *
rt_new0(struct dhcpcd_ctx *ctx)
{
	struct rt *rt;

	assert(ctx != NULL);
	if ((rt = RB_TREE_MIN(&ctx->froutes)) != NULL)
		rb_tree_remove_node(&ctx->froutes, rt);
	else if ((rt = malloc(sizeof(*rt))) == NULL) {
		logerr(__func__);
		return NULL;
	}
	memset(rt, 0, sizeof(*rt));
	return rt;
}

void
rt_setif(struct rt *rt, struct interface *ifp)
{

	assert(rt != NULL);
	assert(ifp != NULL);
	rt->rt_ifp = ifp;
#ifdef HAVE_ROUTE_METRIC
	rt->rt_metric = ifp->metric;
#endif
}

struct rt *
rt_new(struct interface *ifp)
{
	struct rt *rt;

	assert(ifp != NULL);
	if ((rt = rt_new0(ifp->ctx)) == NULL)
		return NULL;
	rt_setif(rt, ifp);
	return rt;
}

void
rt_free(struct rt *rt)
{
	struct dhcpcd_ctx *ctx;

	assert(rt != NULL);
	assert(rt->rt_ifp != NULL);
	assert(rt->rt_ifp->ctx != NULL);

	ctx = rt->rt_ifp->ctx;
	rt->rt_ifp = NULL;
	rb_tree_insert_node(&ctx->froutes, rt);
}

void
rt_freeif(struct interface *ifp)
{
	struct dhcpcd_ctx *ctx;
	struct rt *rt, *rtn;

	if (ifp == NULL)
		return;
	ctx = ifp->ctx;
	RB_TREE_FOREACH_SAFE(rt, &ctx->routes, rtn) {
		if (rt->rt_ifp == ifp) {
			rb_tree_remove_node(&ctx->routes, rt);
			rt_free(rt);
		}
	}
	RB_TREE_FOREACH_SAFE(rt, &ctx->kroutes, rtn) {
		if (rt->rt_ifp == ifp) {
			rb_tree_remove_node(&ctx->kroutes, rt);
			rt_free(rt);
		}
	}
}

struct rt *
rt_find(rb_tree_t *rts, const struct rt *f)
{
	struct rt *rt;

	assert(rts != NULL);
	assert(f != NULL);
	RB_TREE_FOREACH(rt, rts) {
		if (sa_cmp(&rt->rt_dest, &f->rt_dest) == 0 &&
#ifdef HAVE_ROUTE_METRIC
		    (f->rt_ifp == NULL ||
		    rt->rt_ifp->metric == f->rt_ifp->metric) &&
#endif
		    rt_cmp_netmask(f, rt) == 0)
			return rt;
	}
	return NULL;
}

static void
rt_kfree(struct rt *rt)
{
	struct dhcpcd_ctx *ctx;
	struct rt *f;

	assert(rt != NULL);
	ctx = rt->rt_ifp->ctx;
	if ((f = rt_find(&ctx->kroutes, rt)) != NULL) {
		rb_tree_remove_node(&ctx->kroutes, f);
		rt_free(f);
	}
}

/* If something other than dhcpcd removes a route,
 * we need to remove it from our internal table. */
void
rt_recvrt(int cmd, const struct rt *rt)
{
	struct dhcpcd_ctx *ctx;
	struct rt *f;

	assert(rt != NULL);
	ctx = rt->rt_ifp->ctx;
	f = rt_find(&ctx->kroutes, rt);

	switch(cmd) {
	case RTM_DELETE:
		if (f != NULL) {
			rb_tree_remove_node(&ctx->kroutes, f);
			rt_free(f);
		}
		if ((f = rt_find(&ctx->routes, rt)) != NULL) {
			rb_tree_remove_node(&ctx->routes, f);
			rt_desc("deleted", f);
			rt_free(f);
		}
		break;
	case RTM_ADD:
		if (f != NULL)
			break;
		if ((f = rt_new(rt->rt_ifp)) == NULL)
			break;
		memcpy(f, rt, sizeof(*f));
		rb_tree_insert_node(&ctx->kroutes, f);
		break;
	}

#if defined(IPV4LL) && defined(HAVE_ROUTE_METRIC)
	if (rt->rt_dest.sa_family == AF_INET)
		ipv4ll_recvrt(cmd, rt);
#endif
}

static bool
rt_add(struct rt *nrt, struct rt *ort)
{
	struct dhcpcd_ctx *ctx;
	bool change;

	assert(nrt != NULL);
	ctx = nrt->rt_ifp->ctx;

	/*
	 * Don't install a gateway if not asked to.
	 * This option is mainly for VPN users who want their VPN to be the
	 * default route.
	 * Because VPN's generally don't care about route management
	 * beyond their own, a longer term solution would be to remove this
	 * and get the VPN to inject the default route into dhcpcd somehow.
	 */
	if (((nrt->rt_ifp->active &&
	    !(nrt->rt_ifp->options->options & DHCPCD_GATEWAY)) ||
	    (!nrt->rt_ifp->active && !(ctx->options & DHCPCD_GATEWAY))) &&
	    sa_is_unspecified(&nrt->rt_dest) &&
	    sa_is_unspecified(&nrt->rt_netmask))
		return false;

	rt_desc(ort == NULL ? "adding" : "changing", nrt);

	change = false;
	if (ort == NULL) {
		ort = rt_find(&ctx->kroutes, nrt);
		if (ort != NULL &&
		    ((ort->rt_flags & RTF_REJECT &&
		      nrt->rt_flags & RTF_REJECT) ||
		     (ort->rt_ifp == nrt->rt_ifp &&
#ifdef HAVE_ROUTE_METRIC
		    ort->rt_metric == nrt->rt_metric &&
#endif
		    sa_cmp(&ort->rt_gateway, &nrt->rt_gateway) == 0)))
		{
			if (ort->rt_mtu == nrt->rt_mtu)
				return true;
			change = true;
		}
	} else if (ort->rt_dflags & RTDF_FAKE &&
	    !(nrt->rt_dflags & RTDF_FAKE) &&
	    ort->rt_ifp == nrt->rt_ifp &&
#ifdef HAVE_ROUTE_METRIC
	    ort->rt_metric == nrt->rt_metric &&
#endif
	    sa_cmp(&ort->rt_dest, &nrt->rt_dest) == 0 &&
	    rt_cmp_netmask(ort, nrt) == 0 &&
	    sa_cmp(&ort->rt_gateway, &nrt->rt_gateway) == 0)
	{
		if (ort->rt_mtu == nrt->rt_mtu)
			return true;
		change = true;
	}

#ifdef RTF_CLONING
	/* BSD can set routes to be cloning routes.
	 * Cloned routes inherit the parent flags.
	 * As such, we need to delete and re-add the route to flush children
	 * to correct the flags. */
	if (change && ort != NULL && ort->rt_flags & RTF_CLONING)
		change = false;
#endif

	if (change) {
		if (if_route(RTM_CHANGE, nrt) != -1)
			return true;
		if (errno != ESRCH)
			logerr("if_route (CHG)");
	}

#ifdef HAVE_ROUTE_METRIC
	/* With route metrics, we can safely add the new route before
	 * deleting the old route. */
	if (if_route(RTM_ADD, nrt) != -1) {
		if (ort != NULL) {
			if (if_route(RTM_DELETE, ort) == -1 && errno != ESRCH)
				logerr("if_route (DEL)");
			rt_kfree(ort);
		}
		return true;
	}

	/* If the kernel claims the route exists we need to rip out the
	 * old one first. */
	if (errno != EEXIST || ort == NULL)
		goto logerr;
#endif

	/* No route metrics, we need to delete the old route before
	 * adding the new one. */
#ifdef ROUTE_PER_GATEWAY
	errno = 0;
#endif
	if (ort != NULL) {
		if (if_route(RTM_DELETE, ort) == -1 && errno != ESRCH)
			logerr("if_route (DEL)");
		else
			rt_kfree(ort);
	}
#ifdef ROUTE_PER_GATEWAY
	/* The OS allows many routes to the same dest with different gateways.
	 * dhcpcd does not support this yet, so for the time being just keep on
	 * deleting the route until there is an error. */
	if (ort != NULL && errno == 0) {
		for (;;) {
			if (if_route(RTM_DELETE, ort) == -1)
				break;
		}
	}
#endif
	if (if_route(RTM_ADD, nrt) != -1)
		return true;
#ifdef HAVE_ROUTE_METRIC
logerr:
#endif
	logerr("if_route (ADD)");
	return false;
}

static bool
rt_delete(struct rt *rt)
{
	int retval;

	rt_desc("deleting", rt);
	retval = if_route(RTM_DELETE, rt) == -1 ? false : true;
	if (!retval && errno != ENOENT && errno != ESRCH)
		logerr(__func__);
	/* Remove the route from our kernel table so we can add a
	 * IPv4LL default route if possible. */
	else
		rt_kfree(rt);
	return retval;
}

static bool
rt_cmp(const struct rt *r1, const struct rt *r2)
{

	return (r1->rt_ifp == r2->rt_ifp &&
#ifdef HAVE_ROUTE_METRIC
	    r1->rt_metric == r2->rt_metric &&
#endif
	    sa_cmp(&r1->rt_gateway, &r2->rt_gateway) == 0);
}

static bool
rt_doroute(struct rt *rt)
{
	struct dhcpcd_ctx *ctx;
	struct rt *or;

	ctx = rt->rt_ifp->ctx;
	/* Do we already manage it? */
	if ((or = rt_find(&ctx->routes, rt))) {
		if (rt->rt_dflags & RTDF_FAKE)
			return true;
		if (or->rt_dflags & RTDF_FAKE ||
		    !rt_cmp(rt, or) ||
		    (rt->rt_ifa.sa_family != AF_UNSPEC &&
		    sa_cmp(&or->rt_ifa, &rt->rt_ifa) != 0) ||
		    or->rt_mtu != rt->rt_mtu)
		{
			if (!rt_add(rt, or))
				return false;
		}
		rb_tree_remove_node(&ctx->routes, or);
		rt_free(or);
	} else {
		if (rt->rt_dflags & RTDF_FAKE) {
			if ((or = rt_find(&ctx->kroutes, rt)) == NULL)
				return false;
			if (!rt_cmp(rt, or))
				return false;
		} else {
			if (!rt_add(rt, NULL))
				return false;
		}
	}

	return true;
}

void
rt_build(struct dhcpcd_ctx *ctx, int af)
{
	rb_tree_t routes, added;
	struct rt *rt, *rtn;
	unsigned long long o;

	/* We need to have the interfaces in the correct order to ensure
	 * our routes are managed correctly. */
	if_sortinterfaces(ctx);

	rb_tree_init(&routes, &rt_rb_tree_ops);
	rb_tree_init(&added, &rt_rb_tree_ops);

	switch (af) {
#ifdef INET
	case AF_INET:
		if (!inet_getroutes(ctx, &routes))
			goto getfail;
		break;
#endif
#ifdef INET6
	case AF_INET6:
		if (!inet6_getroutes(ctx, &routes))
			goto getfail;
		break;
#endif
	}

	RB_TREE_FOREACH_SAFE(rt, &routes, rtn) {
		if (rt->rt_dest.sa_family != af &&
		    rt->rt_gateway.sa_family != af)
			continue;
		/* Is this route already in our table? */
		if ((rt_find(&added, rt)) != NULL)
			continue;
		if (rt_doroute(rt)) {
			rb_tree_remove_node(&routes, rt);
			rb_tree_insert_node(&added, rt);
		}
	}

	/* Remove old routes we used to manage. */
	while ((rt = RB_TREE_MAX(&ctx->routes)) != NULL) {
		rb_tree_remove_node(&ctx->routes, rt);
		if (rt->rt_dest.sa_family == af &&
		    rt->rt_gateway.sa_family == af &&
		    rt_find(&added, rt) == NULL)
		{
			o = rt->rt_ifp->options ?
			    rt->rt_ifp->options->options :
			    ctx->options;
			if ((o &
				(DHCPCD_EXITING | DHCPCD_PERSISTENT)) !=
				(DHCPCD_EXITING | DHCPCD_PERSISTENT))
				rt_delete(rt);
		}
		rt_free(rt);
	}

	/* XXX This can be optimised if */
	while ((rt = RB_TREE_MIN(&added)) != NULL) {
		rb_tree_remove_node(&added, rt);
		rb_tree_insert_node(&ctx->routes, rt);
	}

getfail:
	rt_headclear(&routes, AF_UNSPEC);
}
