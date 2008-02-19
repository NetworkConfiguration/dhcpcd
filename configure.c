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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#ifdef __linux__
# include <netinet/ether.h>
#endif
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "configure.h"
#include "dhcp.h"
#ifdef ENABLE_INFO
# include "info.h"
#endif
#include "interface.h"
#include "dhcpcd.h"
#include "logger.h"
#include "signal.h"
#include "socket.h"

static int file_in_path (const char *file)
{
	char *p = getenv ("PATH");
	char *path;
	char *token;
	struct stat s;
	char mypath[PATH_MAX];
	int retval = -1;

	if (! p) {
		errno = ENOENT;
		return (-1);
	}

	path = strdup (p);
	p = path;
	while ((token = strsep (&p, ":"))) {
		snprintf (mypath, PATH_MAX, "%s/%s", token, file);
		if (stat (mypath, &s) == 0) {
			retval = 0;
			break;
		}
	}
	free (path);
	return (retval);
}

/* IMPORTANT: Ensure that the last parameter is NULL when calling */
static int exec_cmd (const char *cmd, const char *args, ...)
{
	va_list va;
	char **argv;
	int n = 1;
	int ret = 0;
	pid_t pid;
	sigset_t full;
	sigset_t old;

	va_start (va, args);
	while (va_arg (va, char *) != NULL)
		n++;
	va_end (va);
	argv = xmalloc (sizeof (char *) * (n + 2));

	va_start (va, args);
	n = 2;
	argv[0] = (char *) cmd;
	argv[1] = (char *) args;
	while ((argv[n] = va_arg (va, char *)) != NULL)
		n++;
	va_end (va);

	/* OK, we need to block signals */
	sigfillset (&full);
	sigprocmask (SIG_SETMASK, &full, &old);

#ifdef THERE_IS_NO_FORK
	signal_reset ();
	pid = vfork ();
#else
	pid = fork();
#endif

	switch (pid) {
		case -1:
			logger (LOG_ERR, "vfork: %s", strerror (errno));
			ret = -1;
			break;
		case 0:
#ifndef THERE_IS_NO_FORK
			signal_reset ();
#endif
			sigprocmask (SIG_SETMASK, &old, NULL);
			if (execvp (cmd, argv) && errno != ENOENT)
				logger (LOG_ERR, "error executing \"%s\": %s",
					cmd, strerror (errno));
			_exit (111);
			/* NOTREACHED */
	}

#ifdef THERE_IS_NO_FORK
	signal_setup ();
#endif

	/* Restore our signals */
	sigprocmask (SIG_SETMASK, &old, NULL);

	free (argv);
	return (ret);
}

static void exec_script (const char *script, const char *infofile,
			 const char *arg)
{
	struct stat buf;

	if (! script || ! infofile || ! arg)
		return;

	if (stat (script, &buf) == -1) {
		if (strcmp (script, DEFAULT_SCRIPT) != 0)
			logger (LOG_ERR, "`%s': %s", script, strerror (ENOENT));
		return;
	}

#ifdef ENABLE_INFO
	logger (LOG_DEBUG, "exec \"%s\" \"%s\" \"%s\"", script, infofile, arg);
	exec_cmd (script, infofile, arg, (char *) NULL);
#else
	logger (LOG_DEBUG, "exec \"%s\" \"\" \"%s\"", script, arg);
	exec_cmd (script, "", arg, (char *) NULL);
#endif
}

static int make_resolv (const char *ifname, const dhcp_t *dhcp)
{
	FILE *f = NULL;
	address_t *address;

#ifdef ENABLE_RESOLVCONF
	char *resolvconf = NULL;

	if (file_in_path ("resolvconf") == 0) {
		size_t len = strlen ("resolvconf -a ") + strlen (ifname) + 1;
		resolvconf = xmalloc (sizeof (char) * len);
		snprintf (resolvconf, len, "resolvconf -a %s", ifname);
		if ((f = popen (resolvconf , "w")))
			logger (LOG_DEBUG,
				"sending DNS information to resolvconf");
		else if (errno == EEXIST)
			logger (LOG_ERR, "popen: %s", strerror (errno));

		if (ferror (f))
			logger (LOG_ERR, "ferror");
		free (resolvconf);
	}
#endif
	if (! f) {
		logger (LOG_DEBUG, "writing "RESOLVFILE);
		if (! (f = fopen(RESOLVFILE, "w")))
			logger (LOG_ERR, "fopen `%s': %s", RESOLVFILE, strerror (errno));
	}

	if (! f)
		return (-1);

	fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
	if (dhcp->dnssearch)
		fprintf (f, "search %s\n", dhcp->dnssearch);
	else if (dhcp->dnsdomain) {
		fprintf (f, "search %s\n", dhcp->dnsdomain);
	}

	for (address = dhcp->dnsservers; address; address = address->next)
		fprintf (f, "nameserver %s\n", inet_ntoa (address->address));

#ifdef ENABLE_RESOLVCONF
	if (resolvconf)
		pclose (f);
	else
#endif
		fclose (f);

	/* Refresh the local resolver */
	res_init ();
	return (0);
}

static void restore_resolv (const char *ifname)
{
#ifdef ENABLE_RESOLVCONF
	if (file_in_path ("resolvconf") == 0) {
		logger (LOG_DEBUG, "removing information from resolvconf");
		exec_cmd("resolvconf", "-d", ifname, (char *) NULL);
	}
#endif
}

static bool in_addresses (const address_t *addresses, struct in_addr addr)
{
	const address_t *address;

	for (address = addresses; address; address = address->next)
		if (address->address.s_addr == addr.s_addr)
			return (true);

	return (false);
}

static bool in_routes (const route_t *routes, route_t *route)
{
	const route_t *r;
	
	for (r = routes; r; r=r->next)
		if (r->destination.s_addr == route->destination.s_addr &&
		    r->netmask.s_addr == route->netmask.s_addr &&
		    r->gateway.s_addr == route->gateway.s_addr)
			return (true);

	return (false);
}

#ifdef ENABLE_NTP
static int _make_ntp (const char *file, const char *ifname, const dhcp_t *dhcp)
{
	FILE *f;
	address_t *address;
	char *a;
	char *line;
	int tomatch = 0;
	char *token;
	bool ntp = false;

	for (address = dhcp->ntpservers; address; address = address->next)
		tomatch++;

	/* Check that we really need to update the servers.
	 * We do this because ntp has to be restarted to
	 * work with a changed config. */
	if (! (f = fopen (file, "r"))) {
		if (errno != ENOENT) {
			logger (LOG_ERR, "fopen `%s': %s",
				file, strerror (errno));
			return (-1);
		}
	} else {
		while (tomatch != 0 && (line = get_line (f))) {
			struct in_addr addr;

			a = line;
			token = strsep (&a, " ");
			if (! token || strcmp (token, "server") != 0)
				goto next;

			if ((token = strsep (&a, " \n")) == NULL)
				goto next;

			if (inet_aton (token, &addr) == 1 &&
			    in_addresses (dhcp->ntpservers, addr))
				tomatch--;

next:
			free (line);
		}
		fclose (f);

		/* File has the same name servers that we do,
		 * so no need to restart ntp */
		if (tomatch == 0) {
			logger (LOG_DEBUG, "%s already configured, skipping",
				file);
			return (0);
		}
	}

	logger (LOG_DEBUG, "writing %s", file);
	if (! (f = fopen (file, "w"))) {
		logger (LOG_ERR, "fopen `%s': %s", file, strerror (errno));
		return (-1);
	}

	fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);
#ifdef NTPFILE
	if (strcmp (file, NTPFILE) == 0) {
		ntp = true;
		fprintf (f, "restrict default noquery notrust nomodify\n");
		fprintf (f, "restrict 127.0.0.1\n");
	}
#endif

	for (address = dhcp->ntpservers; address; address = address->next) {
		a = inet_ntoa (address->address);
		if (ntp)
			fprintf (f, "restrict %s nomodify notrap noquery\n", a);
		fprintf (f, "server %s\n", a);
	}
	fclose (f);

	return (1);
}

static int make_ntp (const char *ifname, const dhcp_t *dhcp)
{
	/* On some systems we have only have one ntp service, but we don't
	 * know which configuration file we're using. So we need to write
	 * to both and restart accordingly. */

	bool restart_ntp = false;
	bool restart_openntp = false;
	int retval = 0;

#ifdef NTPFILE
	if (_make_ntp (NTPFILE, ifname, dhcp) > 0)
		restart_ntp = true;
#endif

#ifdef OPENNTPFILE
	if (_make_ntp (OPENNTPFILE, ifname, dhcp) > 0)
		restart_openntp = true;
#endif

#ifdef NTPSERVICE
	if (restart_ntp) {
#ifdef NTPCHECK
		if (system (NTPCHECK) == 0)
#endif
			retval += exec_cmd (NTPSERVICE, NTPRESTARTARGS,
					    (char *) NULL);
	}
#endif

#if defined (NTPSERVICE) && defined (OPENNTPSERVICE)
	if (restart_openntp &&
	    (strcmp (NTPSERVICE, OPENNTPSERVICE) != 0 || ! restart_ntp))
	{
#ifdef OPENNTPCHECK
		if (system (OPENNTPCHECK) == 0)
#endif
			retval += exec_cmd (OPENNTPSERVICE,
					    OPENNTPRESTARTARGS, (char *) NULL);
	}
#elif defined (OPENNTPSERVICE) && ! defined (NTPSERVICE)
	if (restart_openntp) {
#ifdef OPENNTPCHECK
		if (system (OPENNTPCHECK) == 0)
#endif
			retval += exec_cmd (OPENNTPSERVICE,
					    OPENNTPRESTARTARGS, (char *) NULL);
	}
#endif

	return (retval);
}
#endif

#ifdef ENABLE_NIS
#define PREFIXSIZE 256
static int make_nis (const char *ifname, const dhcp_t *dhcp)
{
	FILE *f;
	address_t *address;
	char *prefix;

	logger (LOG_DEBUG, "writing "NISFILE);
	if (! (f = fopen(NISFILE, "w"))) {
		logger (LOG_ERR, "fopen `%s': %s", NISFILE, strerror (errno));
		return (-1);
	}

	prefix = xmalloc (sizeof (char) * PREFIXSIZE);
	*prefix = '\0';
	fprintf (f, "# Generated by dhcpcd for interface %s\n", ifname);

	if (dhcp->nisdomain) {
		setdomainname (dhcp->nisdomain, (int) strlen (dhcp->nisdomain));

		if (dhcp->nisservers)
			snprintf (prefix, PREFIXSIZE, "domain %s server",
				  dhcp->nisdomain);
		else
			fprintf (f, "domain %s broadcast\n", dhcp->nisdomain);
	}
	else
		snprintf (prefix, PREFIXSIZE, "%s", "ypserver");

	for (address = dhcp->nisservers; address; address = address->next)
		fprintf (f, "%s %s\n", prefix, inet_ntoa (address->address));

	free (prefix);
	fclose (f);

#ifdef NISCHECK
	if (system (NISCHECK) == 0)
#endif
		exec_cmd (NISSERVICE, NISRESTARTARGS, (char *) NULL);
	return (0);
}
#endif

static char *lookuphostname (char *hostname, const dhcp_t *dhcp,
			     const options_t *options)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
	} su;
	socklen_t salen;
	char *addr;
	struct addrinfo hints;
	struct addrinfo *res;
	int result;
	char *p;

	logger (LOG_DEBUG, "Looking up hostname via DNS");
	addr = xmalloc (sizeof (char) * NI_MAXHOST);
	salen = sizeof (su.sa);
	memset (&su.sa, 0, salen);
	su.sin.sin_family = AF_INET;
	memcpy (&su.sin.sin_addr, &dhcp->address, sizeof (su.sin.sin_addr));

	if ((result = getnameinfo (&su.sa, salen, addr, NI_MAXHOST,
				   NULL, 0, NI_NAMEREQD)) != 0) {
		logger (LOG_ERR,
			"Failed to lookup hostname via DNS: %s",
			gai_strerror (result));
		free (addr);
		return (NULL);
	}
	
	/* Check for a malicious PTR record */
	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	result = getaddrinfo (addr, "0", &hints, &res);
	freeaddrinfo (res);
	if (result == 0)
		logger (LOG_ERR, "malicious PTR record detected");
	if (result == 0 || ! *addr) {
		free (addr);
		return (NULL);
	}

	p = strchr (addr, '.');
	if (p) {
		switch (options->dohostname) {
			case 1: /* -H */
			case 4: /* -HHHH */
				break;
			case 2: /* -HH */
			case 5: /* -HHHHH */
				/* Strip out the domain if it matches */
				p++;
				if (*p && dhcp->dnssearch) {
					char *s = xstrdup (dhcp->dnssearch);
					char *sp = s;
					char *t;

					while ((t = strsep (&sp, " ")))
						if (strcmp (t, p) == 0) {
							*--p = '\0';
							break;
						}
					free (s);
				} else if (dhcp->dnsdomain) {
					if (strcmp (dhcp->dnsdomain, p) == 0)
						*--p = '\0';
				}
				break;
			case 3: /* -HHH */
			case 6: /* -HHHHHH */
				/* Just strip the domain */
				*p = '\0';
				break;
			default: /* Too many H! */
				break;
		}
	}

	strlcpy (hostname, addr, MAXHOSTNAMELEN);
	free (addr);
	return (hostname);
}

int configure (const options_t *options, interface_t *iface,
	       const dhcp_t *dhcp, bool up)
{
	route_t *route = NULL;
	route_t *new_routes = NULL;
	route_t *new_route = NULL;
	char *newhostname = NULL;
	char *curhostname = NULL;
	int remember;
#ifdef ENABLE_IPV4LL
	bool haslinklocal = false;
#endif
#ifdef THERE_IS_NO_FORK
	int skip = 0;
	size_t skiplen;
	char *skipp;
#endif

	if (! options || ! iface || ! dhcp)
		return (-1);

	if (dhcp->address.s_addr == 0)
		up = 0;

	/* Remove old routes.
	 * Always do this as the interface may have >1 address not added by us
	 * so the routes we added may still exist. */
	for (route = iface->previous_routes; route; route = route->next)
		if ((route->destination.s_addr || options->dogateway) &&
		    (! up || ! in_routes (dhcp->routes, route)))
			del_route (iface->name, route->destination,
				   route->netmask, route->gateway,
				   options->metric);

	/* If we aren't up, then reset the interface as much as we can */
	if (! up) {
		if (iface->previous_routes) {
			free_route (iface->previous_routes);
			iface->previous_routes = NULL;
		}

		/* Restore the original MTU value */
		if (iface->mtu && iface->previous_mtu != iface->mtu) {
			set_mtu (iface->name, iface->mtu);
			iface->previous_mtu = iface->mtu;
		}

#ifdef ENABLE_INFO
		/* If we haven't created an info file, do so now */
		if (! dhcp->frominfo)
			write_info (iface, dhcp, options, false);
#endif

		/* Only reset things if we had set them before */
		if (iface->previous_address.s_addr != 0) {
			if (! options->keep_address) {
				del_address (iface->name,
					     iface->previous_address,
					     iface->previous_netmask);
				memset (&iface->previous_address,
					0, sizeof (iface->previous_address));
				memset (&iface->previous_netmask,
					0, sizeof (iface->previous_netmask));
			}
		}

		restore_resolv (iface->name);
		exec_script (options->script, iface->infofile, "down");

		return (0);
	}

	/* Set the MTU requested.
	 * If the DHCP server no longer sends one OR it's invalid then
	 * we restore the original MTU */
	if (options->domtu) {
		unsigned short mtu = iface->mtu;
		if (dhcp->mtu)
			mtu = dhcp->mtu;

		if (mtu != iface->previous_mtu) {
			if (set_mtu (iface->name, mtu) == 0)
				iface->previous_mtu = mtu;
		}
	}

	/* This also changes netmask */
	if (! options->doinform || ! has_address (iface->name, dhcp->address))
		if (add_address (iface->name, dhcp->address, dhcp->netmask,
				 dhcp->broadcast) == -1 && errno != EEXIST)
			return (false);

	/* Now delete the old address if different */
	if (iface->previous_address.s_addr != dhcp->address.s_addr &&
	    iface->previous_address.s_addr != 0 &&
	    ! options->keep_address)
		del_address (iface->name,
			     iface->previous_address, iface->previous_netmask);

#ifdef __linux__
	/* On linux, we need to change the subnet route to have our metric. */
	if (iface->previous_address.s_addr != dhcp->address.s_addr &&
	    options->metric > 0 &&
	    dhcp->netmask.s_addr != INADDR_BROADCAST)
	{
		struct in_addr td;
		struct in_addr tg;
		memset (&td, 0, sizeof (td));
		memset (&tg, 0, sizeof (tg));
		td.s_addr = dhcp->address.s_addr & dhcp->netmask.s_addr;
		add_route (iface->name, td, dhcp->netmask, tg, options->metric);
		del_route (iface->name, td, dhcp->netmask, tg, 0);
	}
#endif

#ifdef THERE_IS_NO_FORK
	free (dhcpcd_skiproutes);
	/* We can never have more than 255 routes. So we need space
	 * for 255 3 digit numbers and commas */
	skiplen = 255 * 4 + 1;
	skipp = dhcpcd_skiproutes = xmalloc (sizeof (char) * skiplen);
	*skipp = '\0';
#endif

	/* Remember added routes */
	for (route = dhcp->routes; route; route = route->next) {
#ifdef ENABLE_IPV4LL
		/* Check if we have already got a link locale route dished
		 * out by the DHCP server */
		if (route->destination.s_addr == htonl (LINKLOCAL_ADDR) &&
		    route->netmask.s_addr == htonl (LINKLOCAL_MASK))
			haslinklocal = true;
#endif
		/* Don't set default routes if not asked to */
		if (route->destination.s_addr == 0 &&
		    route->netmask.s_addr == 0 &&
		    ! options->dogateway)
			continue;

		remember = add_route (iface->name, route->destination,
				      route->netmask,  route->gateway,
				      options->metric);
		/* If we failed to add the route, we may have already added it
		   ourselves. If so, remember it again. */
		if (remember < 0 && in_routes (iface->previous_routes, route))
			remember = 1;

		if (remember >= 0) {
			if (! new_routes) {
				new_routes = xmalloc (sizeof (*new_routes));
				new_route = new_routes;
			} else {
				new_route->next = xmalloc (sizeof (*new_route));
				new_route = new_route->next;
			}
			memcpy (new_route, route, sizeof (*new_route));
			new_route -> next = NULL;
		}
#ifdef THERE_IS_NO_FORK
		/* If we have daemonised yet we need to record which routes
		 * we failed to add so we can skip them */
		else if (! options->daemonised) {
			/* We can never have more than 255 / 4 routes,
			 * so 3 chars is plently */
			if (*skipp)
				*skipp++ = ',';
			skipp += snprintf (skipp,
					   dhcpcd_skiproutes + skiplen - skipp,
					   "%d", skip);
		}
		skip++;
#endif
	}

#ifdef THERE_IS_NO_FORK
	if (*dhcpcd_skiproutes)
		*skipp = '\0';
	else {
		free (dhcpcd_skiproutes);
		dhcpcd_skiproutes = NULL;
	}
#endif

#ifdef ENABLE_IPV4LL
	/* Ensure we always add the link local route if we got a private
	 * address and isn't link local itself */
	if (options->doipv4ll &&
	    ! haslinklocal &&
	    IN_PRIVATE (ntohl (dhcp->address.s_addr)))
	{
		struct in_addr dest;
		struct in_addr mask;
		struct in_addr gate;

		dest.s_addr = htonl (LINKLOCAL_ADDR);
		mask.s_addr = htonl (LINKLOCAL_MASK);
		gate.s_addr = 0;
		remember = add_route (iface->name, dest, mask, gate,
				      options->metric);

		if (remember >= 0) {
			if (! new_routes) {
				new_routes = xmalloc (sizeof (*new_routes));
				new_route = new_routes;
			} else {
				new_route->next = xmalloc (sizeof (*new_route));
				new_route = new_route->next;
			}
			new_route->destination.s_addr = dest.s_addr;
			new_route->netmask.s_addr = mask.s_addr;
			new_route->gateway.s_addr = gate.s_addr;
			new_route->next = NULL;
		}
	}
#endif

	if (iface->previous_routes)
		free_route (iface->previous_routes);
	iface->previous_routes = new_routes;

	if (options->dodns && dhcp->dnsservers)
		make_resolv(iface->name, dhcp);
	else
		logger (LOG_DEBUG, "no dns information to write");

#ifdef ENABLE_NTP
	if (options->dontp && dhcp->ntpservers)
		make_ntp(iface->name, dhcp);
#endif

#ifdef ENABLE_NIS
	if (options->donis && (dhcp->nisservers || dhcp->nisdomain))
		make_nis(iface->name, dhcp);
#endif

	curhostname = xmalloc (sizeof (char) * MAXHOSTNAMELEN);
	*curhostname = '\0';

	gethostname (curhostname, MAXHOSTNAMELEN);
	if (options->dohostname ||
	    strlen (curhostname) == 0 ||
	    strcmp (curhostname, "(none)") == 0 ||
	    strcmp (curhostname, "localhost") == 0)
	{
		newhostname = xmalloc (sizeof (char) * MAXHOSTNAMELEN);

		if (dhcp->hostname)
			strlcpy (newhostname, dhcp->hostname, MAXHOSTNAMELEN);
		else
			*newhostname = '\0';

		/* Now we have made a resolv.conf we can obtain a hostname
		 * if we need it */
		if (! *newhostname && options->dohostname > 3)
			lookuphostname (newhostname, dhcp, options);

		if (*newhostname) {
			logger (LOG_INFO, "setting hostname to `%s'",
				newhostname);
			sethostname (newhostname, (int) strlen (newhostname));
		}

		free (newhostname);
	}

	free (curhostname);

#ifdef ENABLE_INFO
	if (! dhcp->frominfo)
		write_info (iface, dhcp, options, true);
#endif

	if (iface->previous_address.s_addr != dhcp->address.s_addr ||
	    iface->previous_netmask.s_addr != dhcp->netmask.s_addr)
	{
		memcpy (&iface->previous_address,
			&dhcp->address, sizeof (iface->previous_address));
		memcpy (&iface->previous_netmask,
			&dhcp->netmask, sizeof (iface->previous_netmask));
		exec_script (options->script, iface->infofile, "new");
	} else
		exec_script (options->script, iface->infofile, "up");

	return (0);
}
