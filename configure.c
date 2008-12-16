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

#include <sys/stat.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcpf.h"
#include "if-options.h"
#include "if-pref.h"
#include "net.h"
#include "signals.h"

#define DEFAULT_PATH	"PATH=/usr/bin:/usr/sbin:/bin:/sbin"

/* Some systems have route metrics */
#ifndef HAVE_ROUTE_METRIC
# ifdef __linux__
#  define HAVE_ROUTE_METRIC 1
# endif
# ifndef HAVE_ROUTE_METRIC
#  define HAVE_ROUTE_METRIC 0
# endif
#endif

static struct rt *routes;

static int
exec_script(char *const *argv, char *const *env)
{
	pid_t pid;
	sigset_t full;
	sigset_t old;

	/* OK, we need to block signals */
	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);
	signal_reset();

	switch (pid = vfork()) {
	case -1:
		syslog(LOG_ERR, "vfork: %m");
		break;
	case 0:
		sigprocmask(SIG_SETMASK, &old, NULL);
		execve(argv[0], argv, env);
		syslog(LOG_ERR, "%s: %m", argv[0]);
		_exit(127);
		/* NOTREACHED */
	}

	/* Restore our signals */
	signal_setup();
	sigprocmask(SIG_SETMASK, &old, NULL);
	return pid;
}

int
run_script(const struct interface *iface, const char *reason)
{
	char *const argv[2] = { UNCONST(iface->state->options->script), NULL };
	char **env = NULL, **ep;
	char *path, *p;
	ssize_t e, elen, l;
	pid_t pid;
	int status = 0;
	const struct if_options *ifo = iface->state->options;
	const struct interface *ifp;

	syslog(LOG_DEBUG, "%s: executing `%s', reason %s",
	       iface->name, argv[0], reason);

	/* Make our env */
	elen = 6;
	env = xmalloc(sizeof(char *) * (elen + 1));
	path = getenv("PATH");
	if (path) {
		e = strlen("PATH") + strlen(path) + 2;
		env[0] = xmalloc(e);
		snprintf(env[0], e, "PATH=%s", path);
	} else
		env[0] = xstrdup(DEFAULT_PATH);
	e = strlen("interface") + strlen(iface->name) + 2;
	env[1] = xmalloc(e);
	snprintf(env[1], e, "interface=%s", iface->name);
	e = strlen("reason") + strlen(reason) + 2;
	env[2] = xmalloc(e);
	snprintf(env[2], e, "reason=%s", reason);
	e = 20;
	env[3] = xmalloc(e);
	snprintf(env[3], e, "pid=%d", getpid());
	env[4] = xmalloc(e);
	snprintf(env[4], e, "metric=%d", iface->metric);
	l = e = strlen("interface_order=");
	for (ifp = ifaces; ifp; ifp = ifp->next)
		e += strlen(ifp->name) + 1;
	p = env[5] = xmalloc(e);
	strlcpy(p, "interface_order=", e);
	e -= l;
	p += l;
	for (ifp = ifaces; ifp; ifp = ifp->next) {
		l = strlcpy(p, ifp->name, e);
		p += l;
		e -= l;
		*p++ = ' ';
		e--;
	}
	*--p = '\0';
	if (iface->state->old) {
		e = configure_env(NULL, NULL, iface->state->old, ifo);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += configure_env(env + elen, "old",
					iface->state->old, ifo);
		}
	}
	if (iface->state->new) {
		e = configure_env(NULL, NULL, iface->state->new, ifo);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += configure_env(env + elen, "new",
					iface->state->new, ifo);
		}
	}
	/* Add our base environment */
	if (ifo->environ) {
		e = 0;
		while (ifo->environ[e++])
			;
		env = xrealloc(env, sizeof(char *) * (elen + e + 1));
		e = 0;
		while (ifo->environ[e]) {
			env[elen + e] = xstrdup(ifo->environ[e]);
			e++;
		}
		elen += e;
	}
	env[elen] = '\0';

	pid = exec_script(argv, env);
	if (pid == -1)
		status = -1;
	else if (pid != 0) {
		/* Wait for the script to finish */
		while (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR) {
				syslog(LOG_ERR, "waitpid: %m");
				status = -1;
				break;
			}
		}
	}

	/* Cleanup */
	ep = env;
	while (*ep)
		free(*ep++);
	free(env);
	return status;
}

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
		    (srt || (!rt->iface || rt->iface->metric == r->iface->metric)) &&
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
desc_route(const char *cmd, const struct rt *rt, const char *ifname)
{
	char addr[sizeof("000.000.000.000") + 1];

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

static int
n_route(struct rt *rt, const struct interface *iface)
{
	/* Don't set default routes if not asked to */
	if (rt->dest.s_addr == 0 &&
	    rt->net.s_addr == 0 &&
	    !(iface->state->options->options & DHCPCD_GATEWAY))
		return -1;

	desc_route("adding", rt, iface->name);
	if (!add_route(iface, &rt->dest, &rt->net, &rt->gate, iface->metric))
		return 0;
	if (errno == EEXIST) {
		/* Pretend we added the subnet route */
		if (rt->dest.s_addr == (iface->addr.s_addr & iface->net.s_addr) &&
		    rt->net.s_addr == iface->net.s_addr &&
		    rt->gate.s_addr == 0)
			return 0;
		else
			return -1;
	}
	syslog(LOG_ERR, "%s: add_route: %m", iface->name);
	return -1;
}

static int
c_route(struct rt *ort, struct rt *nrt, const struct interface *iface)
{
	/* Don't set default routes if not asked to */
	if (nrt->dest.s_addr == 0 &&
	    nrt->net.s_addr == 0 &&
	    !(iface->state->options->options & DHCPCD_GATEWAY))
		return -1;

	desc_route("changing", nrt, iface->name);
	/* We don't call change_route because it doesn't work when something
	 * has already used it. */
	del_route(ort->iface, &ort->dest, &ort->net, &ort->gate, ort->iface->metric);
	if (!add_route(iface, &nrt->dest, &nrt->net, &nrt->gate, iface->metric))
		return 0;
	syslog(LOG_ERR, "%s: add_route: %m", iface->name);
	return -1;
}

static int
d_route(struct rt *rt, const struct interface *iface, int metric)
{
	int retval;

	desc_route("deleting", rt, iface->name);
	retval = del_route(iface, &rt->dest, &rt->net, &rt->gate, metric);
	if (retval != 0 && errno != ENOENT && errno != ESRCH)
		syslog(LOG_ERR,"%s: del_route: %m", iface->name);
	return retval;
}

static struct rt *
get_subnet_route(struct dhcp_message *dhcp)
{
	in_addr_t addr, net;
	struct rt *rt;

	addr = dhcp->yiaddr;
	if (addr == 0)
		addr = dhcp->ciaddr;
	/* Ensure we have all the needed values */
	if (get_option_addr(&net, dhcp, DHO_SUBNETMASK) == -1)
		net = get_netmask(addr);
	if (net == INADDR_BROADCAST)
		return NULL;
	rt = malloc(sizeof(*rt));
	rt->dest.s_addr = addr & net;
	rt->net.s_addr = net;
	rt->gate.s_addr = 0;
	return rt;
}

static struct rt *
add_subnet_route(struct rt *rt, const struct interface *iface)
{
	struct rt *r;

	/* We don't have subnet routes with host masks */
	if (iface->net.s_addr == INADDR_BROADCAST)
		return rt;
	
	r = xmalloc(sizeof(*r));
	r->dest.s_addr = iface->addr.s_addr & iface->net.s_addr;
	r->net.s_addr = iface->net.s_addr;
	r->gate.s_addr = 0;
	r->next = rt;
	return r;
}

static void
build_routes()
{
	struct rt *nrs = NULL, *dnr, *or, *rt, *rtn, *rtl, *lrt = NULL;
	const struct interface *ifp;

	for (ifp = ifaces; ifp; ifp = ifp->next) {
		if (ifp->state->new == NULL)
			continue;
		dnr = get_option_routes(ifp->state->new);
		dnr = add_subnet_route(dnr, ifp);
		for (rt = dnr; rt && (rtn = rt->next, 1); lrt = rt, rt = rtn) {
			rt->iface = ifp;
			/* Is this route already in our table? */
			if ((find_route(nrs, rt, NULL, NULL)) != NULL)
				continue;
			/* Do we already manage it? */
			if ((or = find_route(routes, rt, &rtl, NULL))) {
				if (or->iface != ifp ||
				    rt->gate.s_addr != or->gate.s_addr)
				{
					if (c_route(or, rt, ifp) != 0)
						continue;
				}
				if (rtl != NULL)
					rtl->next = or->next;
				else
					routes = or->next;
				free(or);
			} else {
				if (n_route(rt, ifp) != 0)
					continue;
			}
			if (dnr == rt)
				dnr = rtn;
			else if (lrt)
				lrt->next = rtn;
			rt->next = nrs;
			nrs = rt;
		}
		free_routes(dnr);
	}

	/* Remove old routes we used to manage */
	for (rt = routes; rt; rt = rt->next) {
		if (find_route(nrs, rt, NULL, NULL) == NULL)
			d_route(rt, rt->iface, rt->iface->metric);
	}

	free_routes(routes);
	routes = nrs;
}

static int
delete_address(struct interface *iface)
{
	int retval;

	syslog(LOG_DEBUG, "%s: deleting IP address %s/%d",
	       iface->name,
	       inet_ntoa(iface->addr),
	       inet_ntocidr(iface->net));
	retval = del_address(iface, &iface->addr, &iface->net);
	if (retval == -1 && errno != EADDRNOTAVAIL) 
		syslog(LOG_ERR, "del_address: %m");
	iface->addr.s_addr = 0;
	iface->net.s_addr = 0;
	return retval;
}

int
configure(struct interface *iface, const char *reason)
{
	struct dhcp_message *dhcp = iface->state->new;
	struct dhcp_lease *lease = &iface->state->lease;
	struct rt *rt;

	/* As we are now adjusting an interface, we need to ensure
	 * we have them in the right order for routing and configuration. */
	sort_interfaces();

	if (dhcp == NULL) {
		if (iface->addr.s_addr != 0) {
			build_routes();
			delete_address(iface);
		}
		run_script(iface, reason);
		return 0;
	}

	/* This also changes netmask */
	if (!(iface->state->options->options & DHCPCD_INFORM) ||
	    !has_address(iface->name, &lease->addr, &lease->net))
	{
		syslog(LOG_DEBUG, "%s: adding IP address %s/%d",
		       iface->name, inet_ntoa(lease->addr),
		       inet_ntocidr(lease->net));
		if (add_address(iface,
				&lease->addr, &lease->net, &lease->brd) == -1 &&
		    errno != EEXIST)
		{
			syslog(LOG_ERR, "add_address: %m");
			return -1;
		}
	}

	/* Now delete the old address if different */
	if (iface->addr.s_addr != lease->addr.s_addr &&
	    iface->addr.s_addr != 0)
		delete_address(iface);

	iface->addr.s_addr = lease->addr.s_addr;
	iface->net.s_addr = lease->net.s_addr;

	/* We need to delete the subnet route to have our metric or
	 * prefer the interface. */
	rt = get_subnet_route(dhcp);
	if (rt != NULL) {
		rt->iface = iface;
		if (!find_route(routes, rt, NULL, NULL))
			del_route(iface, &rt->dest, &rt->net, &rt->gate, 0);
		free(rt);
	}

	build_routes();
	if (arp_flush() == -1)
		syslog(LOG_ERR, "arp_flush: %m");
	if (!iface->state->lease.frominfo &&
	    !(iface->state->options->options & DHCPCD_INFORM))
		if (write_lease(iface, dhcp) == -1)
			syslog(LOG_ERR, "write_lease: %m");
	run_script(iface, reason);
	return 0;
}
