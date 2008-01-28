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

#include <arpa/inet.h>

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"
#include "info.h"

#ifdef ENABLE_INFO

/* Create a malloced string of cstr, changing ' to '\''
 * so the contents work in a shell */
static char *cleanmetas (const char *cstr)
{
	const char *p = cstr;
	char *new;
	char *n;
	size_t len;

	if (cstr == NULL || (len = strlen (cstr)) == 0)
		return (xstrdup (""));

	n = new = xmalloc (sizeof (char) * len + 2);
	do
		if (*p == '\'') {
			size_t pos = n - new;
			len += 4;
			new = xrealloc (new, sizeof (char) * len + 1);
			n = new + pos;
			*n++ = '\'';
			*n++ = '\\';
			*n++ = '\'';
			*n++ = '\'';
		} else
			*n++ = *p;
	while (*p++);

	/* Terminate the sucker */
	*n = '\0';

	return (new);
}


static void print_addresses (FILE *f, const address_t *addresses)
{
	const address_t *addr;

	for (addr = addresses; addr; addr = addr->next) {
		fprintf (f, "%s", inet_ntoa (addr->address));
		if (addr->next)
			fprintf (f, " ");
	}
}

static void print_clean (FILE *f, const char *name, const char *value)
{
	char *clean;

	if (! value)
		return;

	clean = cleanmetas (value);
	fprintf (f, "%s='%s'\n", name, clean);
	free (clean);
}

bool write_info(const interface_t *iface, const dhcp_t *dhcp,
		const options_t *options, bool overwrite)
{
	FILE *f;
	route_t *route;
	struct stat sb;

	if (options->test)
		f = stdout;
	else {
		if (! overwrite && stat (iface->infofile, &sb) == 0)
			return (true);

		logger (LOG_DEBUG, "writing %s", iface->infofile);
		if ((f = fopen (iface->infofile, "w")) == NULL) {
			logger (LOG_ERR, "fopen `%s': %s",
				iface->infofile, strerror (errno));
			return (false);
		}
	}

	if (dhcp->address.s_addr) {
		struct in_addr n;
		n.s_addr = dhcp->address.s_addr & dhcp->netmask.s_addr;
		fprintf (f, "IPADDR='%s'\n", inet_ntoa (dhcp->address));
		fprintf (f, "NETMASK='%s'\n", inet_ntoa (dhcp->netmask));
		fprintf (f, "NETWORK='%s'\n", inet_ntoa (n));
		fprintf (f, "BROADCAST='%s'\n", inet_ntoa (dhcp->broadcast));
	}
	if (dhcp->mtu > 0)
		fprintf (f, "MTU='%d'\n", dhcp->mtu);

	if (dhcp->routes) {
		bool doneone = false;
		fprintf (f, "ROUTES='");
		for (route = dhcp->routes; route; route = route->next) {
			if (route->destination.s_addr != 0) {
				if (doneone)
					fprintf (f, " ");
				fprintf (f, "%s", inet_ntoa (route->destination));
				fprintf (f, ",%s", inet_ntoa (route->netmask));
				fprintf (f, ",%s", inet_ntoa (route->gateway));
				doneone = true;
			}
		}
		fprintf (f, "'\n");

		doneone = false;
		fprintf (f, "GATEWAYS='");
		for (route = dhcp->routes; route; route = route->next) {
			if (route->destination.s_addr == 0) {
				if (doneone)
					fprintf (f, " ");
				fprintf (f, "%s", inet_ntoa (route->gateway));
				doneone = true;
			}
		}
		fprintf (f, "'\n");
	}

	print_clean (f, "HOSTNAME", dhcp->hostname);
	print_clean (f, "DNSDOMAIN", dhcp->dnsdomain);
	print_clean (f, "DNSSEARCH", dhcp->dnssearch);

	if (dhcp->dnsservers) {
		fprintf (f, "DNSSERVERS='");
		print_addresses (f, dhcp->dnsservers);
		fprintf (f, "'\n");
	}

	if (dhcp->fqdn) {
		fprintf (f, "FQDNFLAGS='%u'\n", dhcp->fqdn->flags);
		fprintf (f, "FQDNRCODE1='%u'\n", dhcp->fqdn->r1);
		fprintf (f, "FQDNRCODE2='%u'\n", dhcp->fqdn->r2);
		print_clean (f, "FQDNHOSTNAME", dhcp->fqdn->name);
	}

	if (dhcp->ntpservers) {
		fprintf (f, "NTPSERVERS='");
		print_addresses (f, dhcp->ntpservers);
		fprintf (f, "'\n");
	}

	print_clean (f, "NISDOMAIN", dhcp->nisdomain);
	if (dhcp->nisservers) {
		fprintf (f, "NISSERVERS='");
		print_addresses (f, dhcp->nisservers);
		fprintf (f, "'\n");
	}

	print_clean (f, "ROOTPATH", dhcp->rootpath);
	print_clean (f, "SIPSERVERS", dhcp->sipservers);

	if (dhcp->serveraddress.s_addr)
		fprintf (f, "DHCPSID='%s'\n", inet_ntoa (dhcp->serveraddress));
	if (dhcp->servername[0])
		print_clean (f, "DHCPSNAME", dhcp->servername);

	if (! options->doinform && dhcp->address.s_addr) {
		if (! options->test)
			fprintf (f, "LEASEDFROM='%u'\n", dhcp->leasedfrom);
		fprintf (f, "LEASETIME='%u'\n", dhcp->leasetime);
		fprintf (f, "RENEWALTIME='%u'\n", dhcp->renewaltime);
		fprintf (f, "REBINDTIME='%u'\n", dhcp->rebindtime);
	}
	print_clean (f, "INTERFACE", iface->name);
	print_clean (f, "CLASSID", options->classid);
	if (options->clientid_len > 0) {
		char *clean = cleanmetas (options->clientid);
		fprintf (f, "CLIENTID='00:%s'\n", clean);
		free (clean);
	}
#ifdef ENABLE_DUID
	else if (iface->duid_length > 0 && options->doduid) {
		unsigned char *duid;
		unsigned char *p;
		uint32_t ul;

		p = duid = xmalloc (iface->duid_length + 6);
		*p++ = 255;

		/* IAID is 4 bytes, so if the interface name is 4 bytes
		 * then use it */
		if (strlen (iface->name) == 4) {
			memcpy (p, iface->name, 4);
		} else {
			/* Name isn't 4 bytes, so use the index */
			ul = htonl (if_nametoindex (iface->name));
			memcpy (p, &ul, 4);
		}
		p += 4;

		memcpy (p, iface->duid, iface->duid_length);
		p += iface->duid_length;

		fprintf (f, "CLIENTID='%s'\n", hwaddr_ntoa (duid,
							    (size_t) (p - duid)));
		free (duid);
	}
#endif
	else
		fprintf (f, "CLIENTID='%.2X:%s'\n", iface->family,
			 hwaddr_ntoa (iface->hwaddr, iface->hwlen));
	fprintf (f, "DHCPCHADDR='%s'\n", hwaddr_ntoa (iface->hwaddr,
						      iface->hwlen));

#ifdef ENABLE_INFO_COMPAT
	/* Support the old .info settings if we need to */
	fprintf (f, "\n# dhcpcd-1.x and 2.x compatible variables\n");
	if (dhcp->dnsservers) {
		address_t *addr;

		fprintf (f, "DNS='");
		for (addr = dhcp->dnsservers; addr; addr = addr->next) {
			fprintf (f, "%s", inet_ntoa (addr->address));
			if (addr->next)
				fprintf (f, ",");
		}
		fprintf (f, "'\n");
	}

	if (dhcp->routes) {
		bool doneone = false;
		fprintf (f, "GATEWAY='");
		for (route = dhcp->routes; route; route = route->next) {
			if (route->destination.s_addr == 0) {
				if (doneone)
					fprintf (f, ",");
				fprintf (f, "%s", inet_ntoa (route->gateway));
				doneone = true;
			}
		}
		fprintf (f, "'\n");
	}
#endif

	if (! options->test)
		fclose (f);
	return (true);
}

static bool parse_address (struct in_addr *addr,
			   const char *value, const char *var)
{
	if (inet_aton (value, addr) == 0) {
		logger (LOG_ERR, "%s `%s': %s", var, value,
			strerror (errno));
		return (false);
	}
	return (true);
}

static bool parse_uint (unsigned int *i,
			const char *value, const char *var)
{
	if (sscanf (value, "%u", i) != 1) {
		logger (LOG_ERR, "%s `%s': not a valid number",
			var, value);
		return (false);
	}
	return (true);
}

static bool parse_ushort (unsigned short *s,
			  const char *value, const char *var)
{
	if (sscanf (value, "%hu", s) != 1) {
		logger (LOG_ERR, "%s `%s': not a valid number",
			var, value);
		return (false);
	}
	return (true);
}

static bool parse_addresses (address_t **address, char *value, const char *var)
{
	char *token;
	char *p = value;
	bool retval = true;

	while ((token = strsep (&p, " "))) {
		address_t *a = xzalloc (sizeof (address_t));

		if (inet_aton (token, &a->address) == 0) {
			logger (LOG_ERR, "%s: invalid address `%s'", var, token);
			free (a);
			retval = false;
		} else {
			if (*address) {
				address_t *aa = *address;
				while (aa->next)
					aa = aa->next;
				aa->next = a;
			} else
				*address = a;
		}
	}

	return (retval);
}

bool read_info (const interface_t *iface, dhcp_t *dhcp)
{
	FILE *fp;
	char *line;
	char *var;
	char *value;
	char *p;
	struct stat sb;

	if (stat (iface->infofile, &sb) != 0) {
		logger (LOG_ERR, "lease information file `%s' does not exist",
			iface->infofile);
		return (false);
	}

	if (! (fp = fopen (iface->infofile, "r"))) {
		logger (LOG_ERR, "fopen `%s': %s",
			iface->infofile, strerror (errno));
		return (false);
	}

	dhcp->frominfo = true;

	while ((line = getline (fp))) {
		var = line;

		/* Strip leading spaces/tabs */
		while ((*var == ' ') || (*var == '\t'))
			var++;

		/* Trim trailing \n */
		p = var + strlen (var) - 1;
		if (*p == '\n')
			*p = 0;

		/* Skip comments */
		if (*var == '#')
			goto next;

		/* If we don't have an equals sign then skip it */
		if (! (p = strchr (var, '=')))
			goto next;	

		/* Terminate the = so we have two strings */
		*p = 0;

		value = p + 1;
		/* Strip leading and trailing quotes if present */
		if (*value == '\'' || *value == '"')
			value++;
		p = value + strlen (value) - 1;
		if (*p == '\'' || *p == '"')
			*p = 0;

		/* Don't process null vars or values */
		if (! *var || ! *value)
			goto next;

		if (strcmp (var, "IPADDR") == 0)
			parse_address (&dhcp->address, value, "IPADDR");
		else if (strcmp (var, "NETMASK") == 0)
			parse_address (&dhcp->netmask, value, "NETMASK");
		else if (strcmp (var, "BROADCAST") == 0)
			parse_address (&dhcp->broadcast, value, "BROADCAST");
		else if (strcmp (var, "MTU") == 0)
			parse_ushort (&dhcp->mtu, value, "MTU");
		else if (strcmp (var, "ROUTES") == 0) {
			p = value;
			while ((value = strsep (&p, " "))) {
				char *pp = value;
				char *dest = strsep (&pp, ",");
				char *net = strsep (&pp, ",");
				char *gate = strsep (&pp, ",");
				route_t *route;

				if (! dest || ! net || ! gate) {
					logger (LOG_ERR, "read_info ROUTES `%s,%s,%s': invalid route",
						dest, net, gate);
					goto next;
				}

				/* See if we can create a route */
				route = xzalloc (sizeof (*route));
				if (inet_aton (dest, &route->destination) == 0) {
					logger (LOG_ERR, "read_info ROUTES `%s': not a valid destination address",
						dest);
					free (route);
					goto next;
				}
				if (inet_aton (dest, &route->netmask) == 0) {
					logger (LOG_ERR, "read_info ROUTES `%s': not a valid netmask address",
						net);
					free (route);
					goto next;
				}
				if (inet_aton (dest, &route->gateway) == 0) {
					logger (LOG_ERR, "read_info ROUTES `%s': not a valid gateway address",
						gate);
					free (route);
					goto next;
				}

				/* OK, now add our route */
				if (dhcp->routes) {
					route_t *r = dhcp->routes;
					while (r->next)
						r = r->next;
					r->next = route;
				} else
					dhcp->routes = route;
			}
		} else if (strcmp (var, "GATEWAYS") == 0) {
			p = value;
			while ((value = strsep (&p, " "))) {
				route_t *route = xzalloc (sizeof (*route));
				if (parse_address (&route->gateway, value, "GATEWAYS")) {
					if (dhcp->routes) {
						route_t *r = dhcp->routes;
						while (r->next)
							r = r->next;
						r->next = route;
					} else
						dhcp->routes = route;
				} else
					free (route);
			}
		} else if (strcmp (var, "HOSTNAME") == 0)
			dhcp->hostname = xstrdup (value);
		else if (strcmp (var, "DNSDOMAIN") == 0)
			dhcp->dnsdomain = xstrdup (value);
		else if (strcmp (var, "DNSSEARCH") == 0)
			dhcp->dnssearch = xstrdup (value);
		else if (strcmp (var, "DNSSERVERS") == 0)
			parse_addresses (&dhcp->dnsservers, value, "DNSSERVERS");
		else if (strcmp (var, "NTPSERVERS") == 0)
			parse_addresses (&dhcp->ntpservers, value, "NTPSERVERS");
		else if (strcmp (var, "NISDOMAIN") == 0)
			dhcp->nisdomain = xstrdup (value);
		else if (strcmp (var, "NISSERVERS") == 0)
			parse_addresses (&dhcp->nisservers, value, "NISSERVERS");
		else if (strcmp (var, "ROOTPATH") == 0)
			dhcp->rootpath = xstrdup (value);
		else if (strcmp (var, "DHCPSID") == 0)
			parse_address (&dhcp->serveraddress, value, "DHCPSID");
		else if (strcmp (var, "DHCPSNAME") == 0)
			strlcpy (dhcp->servername, value, sizeof (dhcp->servername));
		else if (strcmp (var, "LEASEDFROM") == 0)
			parse_uint (&dhcp->leasedfrom, value, "LEASEDFROM");
		else if (strcmp (var, "LEASETIME") == 0)
			parse_uint (&dhcp->leasetime, value, "LEASETIME");
		else if (strcmp (var, "RENEWALTIME") == 0)
			parse_uint (&dhcp->renewaltime, value, "RENEWALTIME");
		else if (strcmp (var, "REBINDTIME") == 0)
			parse_uint (&dhcp->rebindtime, value, "REBINDTIME");

next:
		free (line);
	}

	fclose (fp);
	return (true);
}

#endif

