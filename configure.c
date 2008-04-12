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

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcpcd.h"
#include "logger.h"
#include "net.h"
#include "signal.h"

int
exec_cmd(const char *cmd, const char *args, ...)
{
	va_list va;
	char **argv;
	int n = 1;
	int ret = 0;
	pid_t pid;
	pid_t wpid;
	int status = 0;
	sigset_t full;
	sigset_t old;

	va_start(va, args);
	while (va_arg(va, char *) != NULL)
		n++;
	va_end(va);
	argv = xmalloc(sizeof(char *) * (n + 2));

	va_start(va, args);
	n = 2;
	argv[0] = (char *)cmd;
	argv[1] = (char *)args;
	while ((argv[n] = va_arg(va, char *)) != NULL)
		n++;
	va_end(va);

	/* OK, we need to block signals */
	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);

#ifdef THERE_IS_NO_FORK
	signal_reset();
	pid = vfork();
#else
	pid = fork();
#endif

	switch (pid) {
	case -1:
		logger(LOG_ERR, "vfork: %s", strerror(errno));
		ret = -1;
		break;
	case 0:
#ifndef THERE_IS_NO_FORK
		signal_reset();
#endif
		sigprocmask (SIG_SETMASK, &old, NULL);
		if (execvp(cmd, argv) && errno != ENOENT)
			logger (LOG_ERR, "error executing \"%s\": %s",
				cmd, strerror(errno));
		_exit(111);
		/* NOTREACHED */
	}

#ifdef THERE_IS_NO_FORK
	signal_setup();
#endif

	/* Restore our signals */
	sigprocmask(SIG_SETMASK, &old, NULL);
	free(argv);

	/* Wait for the script to finish */
	do {
		wpid = waitpid(pid, &status, 0);
		if (wpid < 1)
			logger(LOG_ERR, "waitpid: %s", strerror(errno));
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));

	if (WIFEXITED(status))
		ret = WEXITSTATUS(status);
	else
		ret = -1;
	if (ret != 0)
		logger(LOG_ERR, "%s exited non zero", cmd);
	return ret;
}

/* IMPORTANT: Ensure that the last parameter is NULL when calling */
static void
exec_script(const char *script, _unused const char *infofile, const char *arg)
{
	struct stat buf;

	if (stat(script, &buf) == -1) {
		if (strcmp(script, DEFAULT_SCRIPT) != 0)
			logger(LOG_ERR, "`%s': %s", script, strerror(ENOENT));
		return;
	}

	logger(LOG_DEBUG, "exec \"%s\" \"%s\" \"%s\"", script, infofile, arg);
	exec_cmd(script, infofile, arg, (char *)NULL);
}

static struct rt *
reverse_routes(struct rt *routes)
{
	struct rt *rt;
	struct rt *rtn = NULL;
	
	while (routes) {
		rt = routes->next;
		routes->next = rtn;
		rtn = routes;
		routes = rt;
	}
	return rtn;
}

static int
delete_route(const char *iface, struct rt *rt, int metric)
{
	char *addr;
	int retval;

	addr = xstrdup(inet_ntoa(rt->dest));
	logger(LOG_DEBUG, "removing route %s/%d via %s",
			addr, inet_ntocidr(rt->net), inet_ntoa(rt->gate));
	free(addr);
	retval = del_route(iface, &rt->dest, &rt->net, &rt->gate, metric);
	if (retval != 0)
		logger(LOG_ERR," del_route: %s", strerror(errno));
	return retval;

}

static int
delete_routes(struct interface *iface, int metric)
{
	struct rt *rt;
	struct rt *rtn;
	int retval = 0;

	rt = reverse_routes(iface->routes);
	while (rt) {
		rtn = rt->next;
		retval += delete_route(iface->name, rt, metric);
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
configure_routes(struct interface *iface, const struct dhcp_message *dhcp,
		const struct options *options)
{
	struct rt *rt, *ort;
	struct rt *rtn = NULL, *nr = NULL;
	int remember;
	int retval = 0;
	char *addr;

#ifdef THERE_IS_NO_FORK
	char *skipp;
	size_t skiplen;
	int skip = 0;

	free(dhcpcd_skiproutes);
	/* We can never have more than 255 routes. So we need space
	 * for 255 3 digit numbers and commas */
	skiplen = 255 * 4 + 1;
	skipp = dhcpcd_skiproutes = xmalloc(sizeof(char) * skiplen);
	*skipp = '\0';
#endif

	ort = get_option_routes(dhcp);

#ifdef ENABLE_IPV4LL
	if (options->options & DHCPCD_IPV4LL &&
	    IN_PRIVATE(ntohl(dhcp->yiaddr)))
	{
		for (rt = ort; rt; rt = rt->next) {
			/* Check if we have already got a link locale route dished
			 * out by the DHCP server */
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

#ifdef THERE_IS_NO_FORK
	if (dhcpcd_skiproutes) {
		int i = -1;
		char *sk, *skp, *token;
		free_routes(iface->routes);
		for (rt = ort; rt; rt = rt->next) {
			i++;
			/* Check that we did add this route or not */
			sk = skp = xstrdup(dhcpcd_skiproutes);
			while ((token = strsep(&skp, ","))) {
				if (isdigit(*token) && atoi(token) == i)
					break;
			}
			free(sk);
			if (token)
				continue;
			if (nr) {
				rtn->next = xmalloc(sizeof(*rtn));
				rtn = rtn->next;
			} else {
				nr = rtn = xmalloc(sizeof(*rtn));
			}
			rtn->dest.s_addr = rt->dest.s_addr;
			rtn->net.s_addr = rt->net.s_addr;
			rtn->gate.s_addr = rt->gate.s_addr;
			rtn->next = NULL;
		}
		iface->routes = nr;
		nr = NULL;

		/* We no longer need this */
		free(dhcpcd_skiproutes);
		dhcpcd_skiproutes = NULL;
	}
#endif

	/* Now remove old routes we no longer use.
 	 * We should do this in reverse order. */
	iface->routes = reverse_routes(iface->routes);
	for (rt = iface->routes; rt; rt = rt->next)
		if (in_routes(ort, rt) != 0)
			delete_route(iface->name, rt, options->metric);

	for (rt = ort; rt; rt = rt->next) {
		/* Don't set default routes if not asked to */
		if (rt->dest.s_addr == 0 &&
		    rt->net.s_addr == 0 &&
		    !(options->options & DHCPCD_GATEWAY))
			continue;

		addr = xstrdup(inet_ntoa(rt->dest));
		logger(LOG_DEBUG, "adding route to %s/%d via %s",
			addr, inet_ntocidr(rt->net), inet_ntoa(rt->gate));
		free(addr);
		remember = add_route(iface->name, &rt->dest,
				     &rt->net, &rt->gate,
				     options->metric);
		retval += remember;

		/* If we failed to add the route, we may have already added it
		   ourselves. If so, remember it again. */
		if (remember < 0) {
			if (errno != EEXIST)
				logger(LOG_ERR, "add_route: %s",
				       strerror(errno));
			if (in_routes(iface->routes, rt) == 0)
				remember = 1;
		}

		/* This login is split from above due to the #ifdef below */
		if (remember >= 0) {
			if (nr) {
				rtn->next = xmalloc(sizeof(*rtn));
				rtn = rtn->next;
			} else {
				nr = rtn = xmalloc(sizeof(*rtn));
			}
			rtn->dest.s_addr = rt->dest.s_addr;
			rtn->net.s_addr = rt->net.s_addr;
			rtn->gate.s_addr = rt->gate.s_addr;
			rtn->next = NULL;
		}
#ifdef THERE_IS_NO_FORK
		/* If we have daemonised yet we need to record which routes
		 * we failed to add so we can skip them */
		else if (!(options->options & DHCPCD_DAEMONISED)) {
			/* We can never have more than 255 / 4 routes,
			 * so 3 chars is plently */
			if (*skipp)
				*skipp++ = ',';
			skipp += snprintf(skipp,
					  dhcpcd_skiproutes + skiplen - skipp,
					  "%d", skip);
		}
		skip++;
#endif
	}
	free_routes(ort);
	free_routes(iface->routes);
	iface->routes = nr;

#ifdef THERE_IS_NO_FORK
	if (*dhcpcd_skiproutes)
		*skipp = '\0';
	else {
		free(dhcpcd_skiproutes);
		dhcpcd_skiproutes = NULL;
	}
#endif


	return retval;
}

static void
print_clean(FILE *f, const char *name, const char *value)
{
        char *clean;

        if (! value)
                return;

        clean = clean_metas(value);
        fprintf(f, "%s='%s'\n", name, clean);
        free(clean);
}

int
write_info(const struct interface *iface, const struct dhcp_message *dhcp,
	   const struct dhcp_lease *lease, const struct options *options,
	int overwrite)
{
	FILE *f;
	struct rt *rt, *ort;
	struct stat sb;
	struct in_addr addr;
	int doneone;

	if (options->options & DHCPCD_TEST)
		f = stdout;
	else {
		if (!overwrite && stat(iface->infofile, &sb) == 0)
			return 0;

		if ((f = fopen(iface->infofile, "w")) == NULL)
			return -1;
	}

	if (dhcp->yiaddr) {
		fprintf(f, "IPADDR=%s\n", inet_ntoa(iface->addr));
		fprintf(f, "NETMASK=%s\n", inet_ntoa(iface->net));
		addr.s_addr = dhcp->yiaddr & iface->net.s_addr;
		fprintf(f, "NETWORK=%s\n", inet_ntoa(addr));
		if (get_option_addr(&addr.s_addr, dhcp, DHCP_BROADCAST) == -1)
			addr.s_addr = dhcp->yiaddr | ~iface->net.s_addr;
		fprintf(f, "BROADCAST=%s\n", inet_ntoa(addr));

		ort = get_option_routes(dhcp);
		doneone = 0;
		fprintf(f, "ROUTES=");
		for (rt = ort; rt; rt = rt->next) {
			if (rt->dest.s_addr == 0)
				continue;
			if (doneone)
				fputc(' ', f);
			else {
				fputc('\'', f);
				doneone = 1;
			}
			fprintf(f, "%s", inet_ntoa(rt->dest));
			fprintf(f, ",%s", inet_ntoa(rt->net));
			fprintf(f, ",%s", inet_ntoa(rt->gate));
		}
		if (doneone)
			fputc('\'', f);
		fputc('\n', f);

		doneone = 0;
		fprintf(f, "GATEWAYS=");
		for (rt = ort; rt; rt = rt->next) {
			if (rt->dest.s_addr != 0)
				continue;
			if (doneone)
				fputc(' ', f);
			else {
				fputc('\'', f);
				doneone = 1;
			}
			fprintf(f, "%s", inet_ntoa(rt->gate));
		}
		if (doneone)
			fputc('\'', f);
		fputc('\n', f);
		free_routes(ort);
	}

	write_options(f, dhcp);

/*  FIXME
	if (dhcp->fqdn) {
		fprintf(f, "FQDNFLAGS='%u'\n", dhcp->fqdn->flags);
		fprintf(f, "FQDNRCODE1='%u'\n", dhcp->fqdn->r1);
		fprintf(f, "FQDNRCODE2='%u'\n", dhcp->fqdn->r2);
		print_clean(f, "FQDNHOSTNAME", dhcp->fqdn->name);
	}
*/
	if (dhcp->siaddr) {
		addr.s_addr = dhcp->siaddr;
		fprintf(f, "DHCPSID='%s'\n", inet_ntoa(addr));
	}
	if (dhcp->servername[0])
		print_clean(f, "DHCPSNAME", (const char *)dhcp->servername);

	if (!(options->options & DHCPCD_INFORM) && dhcp->yiaddr) {
		if (!(options->options & DHCPCD_TEST))
			fprintf(f, "LEASEDFROM=%u\n", lease->leasedfrom);
		fprintf(f, "LEASETIME=%u\n", lease->leasetime);
		fprintf(f, "RENEWALTIME=%u\n", lease->renewaltime);
		fprintf(f, "REBINDTIME=%u\n", lease->rebindtime);
	}
	print_clean(f, "INTERFACE", iface->name);
	print_clean(f, "CLASSID", options->classid);
	if (iface->clientid_len > 0) {
		fprintf(f, "CLIENTID=%s\n",
			hwaddr_ntoa(iface->clientid, iface->clientid_len));
	}
	fprintf(f, "DHCPCHADDR=%s\n",
		hwaddr_ntoa(iface->hwaddr, iface->hwlen));

	if (!(options->options & DHCPCD_TEST))
		fclose(f);
	return 0;
}

int
configure(struct interface *iface, const struct dhcp_message *dhcp,
	  const struct dhcp_lease *lease, const struct options *options,
	int up)
{
	unsigned short mtu;
	struct in_addr addr;
	struct in_addr net;
	struct in_addr brd;
#ifdef __linux__
	struct in_addr dest;
	struct in_addr gate;
#endif

	/* Grab our IP config */
	if (dhcp == NULL || dhcp->yiaddr == 0)
		up = 0;
	else {
		addr.s_addr = dhcp->yiaddr;
		/* Ensure we have all the needed values */
		if (get_option_addr(&net.s_addr, dhcp, DHCP_NETMASK) == -1)
			net.s_addr = get_netmask(addr.s_addr);
		if (get_option_addr(&brd.s_addr, dhcp, DHCP_BROADCAST) == -1)
			brd.s_addr = addr.s_addr | ~net.s_addr;
	}

	/* If we aren't up, then reset the interface as much as we can */
	if (!up) {
		/* Restore the original MTU value */
		if (iface->initial_mtu != iface->mtu) {
			set_mtu(iface->name, iface->initial_mtu);
			iface->mtu = iface->initial_mtu;
		}

		/* If we haven't created an info file, do so now */
		if (!lease->frominfo) {
			if (write_info(iface, dhcp, lease, options, 0) == -1)
				logger(LOG_ERR, "write_info: %s",
					strerror(errno));
		}

		/* Only reset things if we had set them before */
		if (iface->addr.s_addr != 0) {
			if (!(options->options & DHCPCD_KEEPADDRESS)) {
				delete_routes(iface, options->metric);
				logger(LOG_DEBUG, "deleting IP address %s/%d",
					inet_ntoa(iface->addr),
					inet_ntocidr(iface->net));
				if (del_address(iface->name, &iface->addr,
						&iface->net) == -1 &&
				   errno != ENOENT) 
					logger(LOG_ERR, "del_address: %s",
							strerror(errno));
				iface->addr.s_addr = 0;
				iface->net.s_addr = 0;
			}
		}

		exec_script(options->script, iface->infofile, "down");

		return 0;
	}

	if (options->options & DHCPCD_MTU)
		if (get_option_uint16(&mtu, dhcp, DHCP_MTU) == 0)
			if (mtu != iface->mtu && mtu >= MTU_MIN) {
				if (set_mtu(iface->name, mtu) == 0)
					iface->mtu = mtu;
				else
					logger(LOG_ERR, "set_mtu: %s",
							strerror(errno));
			}

	/* This also changes netmask */
	if (!(options->options & DHCPCD_INFORM) ||
	    !has_address(iface->name, &addr, &net)) {
		logger(LOG_DEBUG, "adding IP address %s/%d",
			inet_ntoa(addr), inet_ntocidr(net));
		if (add_address(iface->name, &addr, &net, &brd) == -1 &&
		    errno != EEXIST)
		{
			logger(LOG_ERR, "add_address: %s", strerror(errno));
			return -1;
		}
	}

	/* Now delete the old address if different */
	if (iface->addr.s_addr != addr.s_addr &&
	    iface->addr.s_addr != 0 &&
	    !(options->options & DHCPCD_KEEPADDRESS))
		del_address(iface->name, &iface->addr, &iface->net);

#ifdef __linux__
	/* On linux, we need to change the subnet route to have our metric. */
	if (iface->addr.s_addr != lease->addr.s_addr &&
	    options->metric > 0 && net.s_addr != INADDR_BROADCAST)
	{
		dest.s_addr = addr.s_addr & net.s_addr;
		gate.s_addr = 0;
		add_route(iface->name, &dest, &net, &gate, options->metric);
		del_route(iface->name, &dest, &net, &gate, 0);
	}
#endif

	configure_routes(iface, dhcp, options);
	up = (iface->addr.s_addr != addr.s_addr ||
			iface->net.s_addr != net.s_addr);
	iface->addr.s_addr = addr.s_addr;
	iface->net.s_addr = net.s_addr;

	if (!lease->frominfo)
		write_info(iface, dhcp, lease, options, 1);
		if (write_lease(iface, dhcp) == -1)
			logger(LOG_ERR, "write_lease: %s", strerror(errno));

	exec_script(options->script, iface->infofile, up ? "new" : "up");

	return 0;
}
