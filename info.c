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
#include "if.h"
#include "logger.h"
#include "info.h"

#ifdef ENABLE_INFO

/* Create a malloced string of cstr, changing ' to '\''
 * so the contents work in a shell */
static char *
cleanmetas(const char *cstr)
{
	const char *p = cstr;
	char *new;
	char *n;
	size_t len;
	size_t pos;

	if (cstr == NULL || (len = strlen(cstr)) == 0)
		return (xstrdup(""));

	n = new = xmalloc(sizeof(char) * len + 2);
	do
		if (*p == '\'') {
			pos = n - new;
			len += 4;
			new = xrealloc(new, sizeof(char) * len + 1);
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

	return new;
}


static void
print_addresses(FILE *f, const struct address_head *addresses)
{
	const struct address *addr;

	STAILQ_FOREACH(addr, addresses, entries) {
		fprintf(f, "%s", inet_ntoa(addr->address));
		if (STAILQ_NEXT(addr, entries))
			fprintf(f, " ");
	}
}

static void
print_clean(FILE *f, const char *name, const char *value)
{
	char *clean;

	if (! value)
		return;

	clean = cleanmetas(value);
	fprintf(f, "%s='%s'\n", name, clean);
	free(clean);
}

bool
write_info(const struct interface *iface, const struct dhcp *dhcp,
	   const struct options *options, bool overwrite)
{
	FILE *f;
	struct rt *route;
	struct stat sb;
	struct in_addr addr;
	bool doneone;

	if (options->options & DHCPCD_TEST)
		f = stdout;
	else {
		if (!overwrite && stat(iface->infofile, &sb) == 0)
			return true;

		logger(LOG_DEBUG, "writing %s", iface->infofile);
		if ((f = fopen(iface->infofile, "w")) == NULL) {
			logger(LOG_ERR, "fopen `%s': %s",
			       iface->infofile, strerror(errno));
			return false;
		}
	}

	if (dhcp->address.s_addr) {
		addr.s_addr = dhcp->address.s_addr & dhcp->netmask.s_addr;
		fprintf(f, "IPADDR='%s'\n", inet_ntoa(dhcp->address));
		fprintf(f, "NETMASK='%s'\n", inet_ntoa(dhcp->netmask));
		fprintf(f, "NETWORK='%s'\n", inet_ntoa(addr));
		fprintf(f, "BROADCAST='%s'\n", inet_ntoa(dhcp->broadcast));
	}
	if (dhcp->mtu > 0)
		fprintf(f, "MTU='%d'\n", dhcp->mtu);

	if (dhcp->routes) {
		doneone = false;
		fprintf(f, "ROUTES='");
		STAILQ_FOREACH(route, dhcp->routes, entries) {
			if (route->destination.s_addr != 0) {
				if (doneone)
					fprintf(f, " ");
				fprintf(f, "%s", inet_ntoa(route->destination));
				fprintf(f, ",%s", inet_ntoa(route->netmask));
				fprintf(f, ",%s", inet_ntoa(route->gateway));
				doneone = true;
			}
		}
		fprintf(f, "'\n");

		doneone = false;
		fprintf(f, "GATEWAYS='");
		STAILQ_FOREACH(route, dhcp->routes, entries) {
			if (route->destination.s_addr == 0) {
				if (doneone)
					fprintf(f, " ");
				fprintf(f, "%s", inet_ntoa(route->gateway));
				doneone = true;
			}
		}
		fprintf(f, "'\n");
	}

	print_clean(f, "HOSTNAME", dhcp->hostname);
	print_clean(f, "DNSDOMAIN", dhcp->dnsdomain);
	print_clean(f, "DNSSEARCH", dhcp->dnssearch);

	if (dhcp->dnsservers) {
		fprintf(f, "DNSSERVERS='");
		print_addresses(f, dhcp->dnsservers);
		fprintf(f, "'\n");
	}

	if (dhcp->fqdn) {
		fprintf(f, "FQDNFLAGS='%u'\n", dhcp->fqdn->flags);
		fprintf(f, "FQDNRCODE1='%u'\n", dhcp->fqdn->r1);
		fprintf(f, "FQDNRCODE2='%u'\n", dhcp->fqdn->r2);
		print_clean(f, "FQDNHOSTNAME", dhcp->fqdn->name);
	}

	if (dhcp->ntpservers) {
		fprintf(f, "NTPSERVERS='");
		print_addresses(f, dhcp->ntpservers);
		fprintf(f, "'\n");
	}

	print_clean(f, "NISDOMAIN", dhcp->nisdomain);
	if (dhcp->nisservers) {
		fprintf(f, "NISSERVERS='");
		print_addresses(f, dhcp->nisservers);
		fprintf(f, "'\n");
	}

	print_clean(f, "ROOTPATH", dhcp->rootpath);
	print_clean(f, "SIPSERVERS", dhcp->sipservers);

	if (dhcp->serveraddress.s_addr)
		fprintf(f, "DHCPSID='%s'\n", inet_ntoa(dhcp->serveraddress));
	if (dhcp->servername[0])
		print_clean(f, "DHCPSNAME", dhcp->servername);

	if (!(options->options & DHCPCD_INFORM) && dhcp->address.s_addr) {
		if (!(options->options & DHCPCD_TEST))
			fprintf(f, "LEASEDFROM='%u'\n", dhcp->leasedfrom);
		fprintf(f, "LEASETIME='%u'\n", dhcp->leasetime);
		fprintf(f, "RENEWALTIME='%u'\n", dhcp->renewaltime);
		fprintf(f, "REBINDTIME='%u'\n", dhcp->rebindtime);
	}
	print_clean(f, "INTERFACE", iface->name);
	print_clean(f, "CLASSID", options->classid);
	if (iface->clientid_len > 0) {
		fprintf(f, "CLIENTID='%s'\n",
			hwaddr_ntoa(iface->clientid, iface->clientid_len));
	}
	fprintf(f, "DHCPCHADDR='%s'\n",
		hwaddr_ntoa(iface->hwaddr, iface->hwlen));

#ifdef ENABLE_INFO_COMPAT
	/* Support the old .info settings if we need to */
	fprintf(f, "\n# dhcpcd-1.x and 2.x compatible variables\n");
	if (dhcp->dnsservers) {
		struct address *a;

		fprintf(f, "DNS='");
		STAILQ_FOREACH(a, dhcp->dnsservers, entries) {
			fprintf(f, "%s", inet_ntoa(a->address));
			if (STAILQ_NEXT(a, entries))
				fprintf(f, ",");
		}
		fprintf(f, "'\n");
	}

	if (dhcp->routes) {
		doneone = false;
		fprintf(f, "GATEWAY='");
		STAILQ_FOREACH(route, dhcp->routes, entries) {
			if (route->destination.s_addr == 0) {
				if (doneone)
					fprintf(f, ",");
				fprintf(f, "%s", inet_ntoa(route->gateway));
				doneone = true;
			}
		}
		fprintf(f, "'\n");
	}
#endif

	if (!(options->options & DHCPCD_TEST))
		fclose(f);
	return true;
}

static bool
parse_address(struct in_addr *addr, const char *value, const char *var)
{
	if (inet_aton(value, addr) == 0) {
		logger(LOG_ERR, "%s `%s': %s", var, value, strerror(errno));
		return false;
	}
	return true;
}

static bool
parse_uint(unsigned int *i, const char *value, const char *var)
{
	if (sscanf(value, "%u", i) != 1) {
		logger(LOG_ERR, "%s `%s': not a valid number", var, value);
		return false;
	}
	return true;
}

static bool
parse_ushort(unsigned short *s, const char *value, const char *var)
{
	if (sscanf(value, "%hu", s) != 1) {
		logger(LOG_ERR, "%s `%s': not a valid number", var, value);
		return false;
	}
	return true;
}

static struct address_head *
parse_addresses(char *value, const char *var)
{
	char *token;
	char *p = value;
	struct address_head *head = NULL;
	struct address *a;

	while ((token = strsep (&p, " "))) {
		a = xzalloc (sizeof(*a));
		if (inet_aton(token, &a->address) == 0) {
			logger(LOG_ERR, "%s: invalid address `%s'", var, token);
			free_address(head);
			free(a);
			return NULL;
		}

		if (!head) {
			head = xmalloc(sizeof(*head));
			STAILQ_INIT(head);
		}
		STAILQ_INSERT_TAIL(head, a, entries);
	}

	return head;
}

bool
read_info(const struct interface *iface, struct dhcp *dhcp)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	char *var;
	char *value;
	char *p;
	struct stat sb;
	char *pp, *dest, *net, *gate;
	struct rt *route;

	if (stat(iface->infofile, &sb) != 0) {
		logger(LOG_ERR, "lease information file `%s' does not exist",
		       iface->infofile);
		return false;
	}

	if (!(fp = fopen(iface->infofile, "r"))) {
		logger(LOG_ERR, "fopen `%s': %s",
		       iface->infofile, strerror(errno));
		return false;
	}

	dhcp->frominfo = true;

	while ((get_line(&line, &len, fp))) {
		var = line;

		/* Strip leading spaces/tabs */
		while ((*var == ' ') || (*var == '\t'))
			var++;

		/* Trim trailing \n */
		p = var + strlen(var) - 1;
		if (*p == '\n')
			*p = 0;

		/* Skip comments */
		if (*var == '#')
			continue;

		/* If we don't have an equals sign then skip it */
		if (!(p = strchr(var, '=')))
			continue;	

		/* Terminate the = so we have two strings */
		*p = 0;

		value = p + 1;
		/* Strip leading and trailing quotes if present */
		if (*value == '\'' || *value == '"')
			value++;
		p = value + strlen(value) - 1;
		if (*p == '\'' || *p == '"')
			*p = 0;

		/* Don't process null vars or values */
		if (!*var || !*value)
			continue;

		if (strcmp(var, "IPADDR") == 0)
			parse_address(&dhcp->address, value, "IPADDR");
		else if (strcmp(var, "NETMASK") == 0)
			parse_address (&dhcp->netmask, value, "NETMASK");
		else if (strcmp(var, "BROADCAST") == 0)
			parse_address (&dhcp->broadcast, value, "BROADCAST");
		else if (strcmp(var, "MTU") == 0)
			parse_ushort (&dhcp->mtu, value, "MTU");
		else if (strcmp(var, "ROUTES") == 0) {
			p = value;
			while ((value = strsep (&p, " "))) {
				pp = value;
				dest = strsep (&pp, ",");
				net = strsep (&pp, ",");
				gate = strsep (&pp, ",");

				if (!dest || !net || !gate) {
					logger(LOG_ERR,
					       "read_info ROUTES `%s,%s,%s': "
					       "invalid route",
						dest, net, gate);
					continue;
				}

				/* See if we can create a route */
				route = xzalloc(sizeof(*route));
				if (inet_aton(dest, &route->destination) == 0) {
					logger(LOG_ERR,
					       "read_info ROUTES `%s': "
					       "not a valid destination address",
					       dest);
					free(route);
					continue;
				}
				if (inet_aton(dest, &route->netmask) == 0) {
					logger(LOG_ERR,
					       "read_info ROUTES `%s': "
					       "not a valid netmask address",
					       net);
					free(route);
					continue;
				}
				if (inet_aton(dest, &route->gateway) == 0) {
					logger(LOG_ERR,
					       "read_info ROUTES `%s': "
					       "not a valid gateway address",
					       gate);
					free(route);
					continue;
				}

				/* OK, now add our route */
				if (!dhcp->routes) {
					dhcp->routes = xmalloc(sizeof(*dhcp->routes));
					STAILQ_INIT(dhcp->routes);
				}
				STAILQ_INSERT_TAIL(dhcp->routes, route, entries);
			}
		} else if (strcmp(var, "GATEWAYS") == 0) {
			p = value;
			while ((value = strsep(&p, " "))) {
				route = xzalloc(sizeof(*route));
				if (parse_address(&route->gateway, value,
						  "GATEWAYS"))
				{
					if (!dhcp->routes) {
						dhcp->routes = xmalloc(sizeof(*dhcp->routes));
						STAILQ_INIT(dhcp->routes);
					}
					STAILQ_INSERT_TAIL(dhcp->routes, route, entries);
				} else
					free(route);
			}
		} else if (strcmp(var, "HOSTNAME") == 0)
			dhcp->hostname = xstrdup(value);
		else if (strcmp (var, "DNSDOMAIN") == 0)
			dhcp->dnsdomain = xstrdup(value);
		else if (strcmp(var, "DNSSEARCH") == 0)
			dhcp->dnssearch = xstrdup(value);
		else if (strcmp(var, "DNSSERVERS") == 0)
			dhcp->dnsservers = parse_addresses(value, "DNSSERVERS");
		else if (strcmp(var, "NTPSERVERS") == 0)
			dhcp->ntpservers = parse_addresses(value, "NTPSERVERS");
		else if (strcmp(var, "NISDOMAIN") == 0)
			dhcp->nisdomain = xstrdup (value);
		else if (strcmp(var, "NISSERVERS") == 0)
			dhcp->nisservers = parse_addresses(value, "NISSERVERS");
		else if (strcmp(var, "ROOTPATH") == 0)
			dhcp->rootpath = xstrdup(value);
		else if (strcmp(var, "DHCPSID") == 0)
			parse_address(&dhcp->serveraddress, value, "DHCPSID");
		else if (strcmp(var, "DHCPSNAME") == 0)
			strlcpy(dhcp->servername, value,
				sizeof(dhcp->servername));
		else if (strcmp(var, "LEASEDFROM") == 0)
			parse_uint(&dhcp->leasedfrom, value, "LEASEDFROM");
		else if (strcmp(var, "LEASETIME") == 0)
			parse_uint(&dhcp->leasetime, value, "LEASETIME");
		else if (strcmp(var, "RENEWALTIME") == 0)
			parse_uint(&dhcp->renewaltime, value, "RENEWALTIME");
		else if (strcmp(var, "REBINDTIME") == 0)
			parse_uint(&dhcp->rebindtime, value, "REBINDTIME");
	}

	fclose (fp);
	free(line);
	return true;
}

#endif

