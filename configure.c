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
#include "net.h"
#include "signals.h"

#define DEFAULT_PATH	"PATH=/usr/bin:/usr/sbin:/bin:/sbin"

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
	char *path;
	ssize_t e, elen;
	pid_t pid;
	int status = 0;
	const struct if_options *ifo = iface->state->options;

	syslog(LOG_DEBUG, "%s: executing `%s', reason %s",
	       iface->name, argv[0], reason);

	/* Make our env */
	elen = 5;
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

static int
delete_route(const struct interface *iface, struct rt *rt, int metric)
{
	char *addr;
	int retval;

	addr = xstrdup(inet_ntoa(rt->dest));
	syslog(LOG_DEBUG, "%s: deleting route %s/%d via %s", iface->name,
	       addr, inet_ntocidr(rt->net), inet_ntoa(rt->gate));
	free(addr);
	retval = del_route(iface, &rt->dest, &rt->net, &rt->gate, metric);
	if (retval != 0 && errno != ENOENT && errno != ESRCH)
		syslog(LOG_ERR," del_route: %m");
	return retval;
}

static int
delete_routes(struct interface *iface)
{
	struct rt *rt;
	struct rt *rtn;
	int retval = 0;

	rt = iface->routes;
	while (rt) {
		rtn = rt->next;
		retval += delete_route(iface, rt, iface->metric);
		free(rt);
		rt = rtn;
	}
	iface->routes = NULL;

	return retval;
}

static int
in_routes(const struct rt *routes, const struct rt *rt)
{
	while (routes) {
		if (routes->dest.s_addr == rt->dest.s_addr &&
				routes->net.s_addr == rt->net.s_addr &&
				routes->gate.s_addr == rt->gate.s_addr)
			return 0;
		routes = routes->next;
	}
	return -1;
}

static int
configure_routes(struct interface *iface, const struct dhcp_message *dhcp)
{
	const struct if_options *ifo = iface->state->options;
	struct rt *rt, *ort;
	struct rt *rtn = NULL, *nr = NULL;
	int remember;
	int retval = 0;
	char *addr;

	ort = get_option_routes(dhcp);

#ifdef IPV4LL_ALWAYSROUTE
	if (ifo->options & DHCPCD_IPV4LL &&
	    IN_PRIVATE(ntohl(dhcp->yiaddr)))
	{
		for (rt = ort; rt; rt = rt->next) {
			/* Check if we have already got a link locale route
			 * dished out by the DHCP server */
			if (rt->dest.s_addr == htonl(LINKLOCAL_ADDR) &&
			    rt->net.s_addr == htonl(LINKLOCAL_MASK))
				break;
			rtn = rt;
		}

		if (!rt) {
			rt = xmalloc(sizeof(*rt));
			rt->dest.s_addr = htonl(LINKLOCAL_ADDR);
			rt->net.s_addr = htonl(LINKLOCAL_MASK);
			rt->gate.s_addr = 0;
			rt->next = NULL;
			if (rtn)
				rtn->next = rt;
			else
				ort = rt;
		}
	}
#endif

	/* Now remove old routes we no longer use. */
	for (rt = iface->routes; rt; rt = rt->next)
		if (in_routes(ort, rt) != 0)
			delete_route(iface, rt, iface->metric);

	for (rt = ort; rt; rt = rt->next) {
		/* Don't set default routes if not asked to */
		if (rt->dest.s_addr == 0 &&
		    rt->net.s_addr == 0 &&
		    !(ifo->options & DHCPCD_GATEWAY))
			continue;

		addr = xstrdup(inet_ntoa(rt->dest));
		syslog(LOG_DEBUG, "%s: adding route to %s/%d via %s",
		       iface->name, addr,
		       inet_ntocidr(rt->net), inet_ntoa(rt->gate));
		free(addr);
		remember = add_route(iface, &rt->dest,
				     &rt->net, &rt->gate, iface->metric);
		retval += remember;

		/* If we failed to add the route, we may have already added it
		   ourselves. If so, remember it again. */
		if (remember < 0) {
			if (errno != EEXIST)
				syslog(LOG_ERR, "add_route: %m");
			if (in_routes(iface->routes, rt) == 0)
				remember = 1;
		}
		if (remember >= 0) {
			rtn = xmalloc(sizeof(*rtn));
			rtn->dest.s_addr = rt->dest.s_addr;
			rtn->net.s_addr = rt->net.s_addr;
			rtn->gate.s_addr = rt->gate.s_addr;
			rtn->next = nr;
			nr = rtn;
		}
	}
	free_routes(ort);
	free_routes(iface->routes);
	iface->routes = nr;
	return retval;
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
	struct in_addr addr;
	struct in_addr net;
	struct in_addr brd;
#ifdef __linux__
	struct in_addr dest;
	struct in_addr gate;
#endif

	/* Grab our IP config */
	if (dhcp) {
		addr.s_addr = dhcp->yiaddr;
		if (addr.s_addr == 0)
			addr.s_addr = iface->state->lease.addr.s_addr;
		/* Ensure we have all the needed values */
		if (get_option_addr(&net.s_addr, dhcp, DHO_SUBNETMASK) == -1)
			net.s_addr = get_netmask(addr.s_addr);
		if (get_option_addr(&brd.s_addr, dhcp, DHO_BROADCAST) == -1)
			brd.s_addr = addr.s_addr | ~net.s_addr;
#ifdef __linux__
		dest.s_addr = addr.s_addr & net.s_addr;
		gate.s_addr = 0;
#endif
	} else {
		/* Only reset things if we had set them before */
		if (iface->addr.s_addr != 0) {
			delete_routes(iface);
			delete_address(iface);
		}

		run_script(iface, reason);
		return 0;
	}

	/* This also changes netmask */
	if (!(iface->state->options->options & DHCPCD_INFORM) ||
	    !has_address(iface->name, &addr, &net)) {
		syslog(LOG_DEBUG, "%s: adding IP address %s/%d",
		       iface->name, inet_ntoa(addr), inet_ntocidr(net));
		if (add_address(iface, &addr, &net, &brd) == -1 &&
		    errno != EEXIST)
		{
			syslog(LOG_ERR, "add_address: %m");
			return -1;
		}
	}

	/* Now delete the old address if different */
	if (iface->addr.s_addr != addr.s_addr &&
	    iface->addr.s_addr != 0)
		delete_address(iface);

#ifdef __linux__
	/* On linux, we need to change the subnet route to have our metric. */
	if (iface->metric > 0 && 
	    (net.s_addr != iface->net.s_addr ||
	     dest.s_addr != (iface->addr.s_addr & iface->net.s_addr)))
	{
		iface->addr.s_addr = addr.s_addr;
		iface->net.s_addr = net.s_addr;
		change_route(iface, &dest, &net, &gate, iface->metric);
		del_route(iface, &dest, &net, &gate, 0);
	}
#endif

	iface->addr.s_addr = addr.s_addr;
	iface->net.s_addr = net.s_addr;
	configure_routes(iface, dhcp);

	if (!iface->state->lease.frominfo)
		if (write_lease(iface, dhcp) == -1)
			syslog(LOG_ERR, "write_lease: %m");

	run_script(iface, reason);
	return 0;
}
