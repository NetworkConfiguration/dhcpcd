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

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "common.h"
#include "config.h"
#include "dhcpf.h"
#include "if-options.h"
#include "logger.h"
#include "net.h"

/* Don't set any optional arguments here so we retain POSIX
 * compatibility with getopt */
#define OPTS "bc:df:h:i:kl:m:no:pqr:s:t:u:v:xABC:DEF:GI:KLO:Q:TVX:"

const struct option cf_options[] = {
	{"background",    no_argument,        NULL, 'b'},
	{"script",        required_argument,  NULL, 'c'},
	{"debug",         no_argument,        NULL, 'd'},
	{"config",        required_argument,  NULL, 'f'},
	{"hostname",      optional_argument,  NULL, 'h'},
	{"vendorclassid", optional_argument,  NULL, 'i'},
	{"release",       no_argument,        NULL, 'k'},
	{"leasetime",     required_argument,  NULL, 'l'},
	{"metric",        required_argument,  NULL, 'm'},
	{"rebind",        no_argument,        NULL, 'n'},
	{"option",        required_argument,  NULL, 'o'},
	{"persistent",    no_argument,        NULL, 'p'},
	{"quiet",         no_argument,        NULL, 'q'},
	{"request",       optional_argument,  NULL, 'r'},
	{"inform",        optional_argument,  NULL, 's'},
	{"timeout",       required_argument,  NULL, 't'},
	{"userclass",     required_argument,  NULL, 'u'},
	{"vendor",        required_argument,  NULL, 'v'},
	{"exit",          no_argument,        NULL, 'x'},
	{"noarp",         no_argument,        NULL, 'A'},
	{"nobackground",  no_argument,        NULL, 'B'},
	{"nohook",	  required_argument,  NULL, 'C'},
	{"duid",          no_argument,        NULL, 'D'},
	{"lastlease",     no_argument,        NULL, 'E'},
	{"fqdn",          optional_argument,  NULL, 'F'},
	{"nogateway",     no_argument,        NULL, 'G'},
	{"clientid",      optional_argument,  NULL, 'I'},
	{"nolink",        no_argument,        NULL, 'K'},
	{"noipv4ll",      no_argument,        NULL, 'L'},
	{"nooption",      optional_argument,  NULL, 'O'},
	{"require",       required_argument,  NULL, 'Q'},
	{"test",          no_argument,        NULL, 'T'},
	{"variables",     no_argument,        NULL, 'V'},
	{"blacklist",     required_argument,  NULL, 'X'},
	{NULL,            0,                  NULL, '\0'}
};

static int
atoint(const char *s)
{
	char *t;
	long n;

	errno = 0;
	n = strtol(s, &t, 0);
	if ((errno != 0 && n == 0) || s == t ||
	    (errno == ERANGE && (n == LONG_MAX || n == LONG_MIN)))
	{
		logger(LOG_ERR, "`%s' out of range", s);
		return -1;
	}

	return (int)n;
}

static char * 
add_environ(struct if_options *ifo, const char *value, int uniq)
{
	char **newlist;
	char **lst = ifo->environ;
	size_t i = 0, l, lv;
	char *match = NULL, *p;

	match = xstrdup(value);
	p = strchr(match, '=');
	if (p)
		*p++ = '\0';
	l = strlen(match);

	while (lst && lst[i]) {
		if (match && strncmp(lst[i], match, l) == 0) {
			if (uniq) {
				free(lst[i]);
				lst[i] = xstrdup(value);
			} else {
				/* Append a space and the value to it */
				l = strlen(lst[i]);
				lv = strlen(p);
				lst[i] = xrealloc(lst[i], l + lv + 2);
				lst[i][l] = ' ';
				memcpy(lst[i] + l + 1, p, lv);
				lst[i][l + lv + 1] = '\0';
			}
			free(match);
			return lst[i];
		}
		i++;
	}

	newlist = xrealloc(lst, sizeof(char *) * (i + 2));
	newlist[i] = xstrdup(value);
	newlist[i + 1] = NULL;
	ifo->environ = newlist;
	free(match);
	return newlist[i];
}

#define parse_string(buf, len, arg) parse_string_hwaddr(buf, len, arg, 0)
static ssize_t
parse_string_hwaddr(char *sbuf, ssize_t slen, const char *str, int clid)
{
	ssize_t l;
	const char *p;
	int i, punt_last = 0;
	char c[4];

	/* If surrounded by quotes then it's a string */
	if (*str == '"') {
		str++;
		l = strlen(str);
		p = str + l - 1;
		if (*p == '"')
			punt_last = 1;
	} else {
		l = hwaddr_aton(NULL, str);
		if (l > 1) {
			if (l > slen) {
				errno = ENOBUFS;
				return -1;
			}
			hwaddr_aton((uint8_t *)sbuf, str);
			return l;
		}
	}

	/* Process escapes */
	l = 0;
	/* If processing a string on the clientid, first byte should be
	 * 0 to indicate a non hardware type */
	if (clid) {
		*sbuf++ = 0;
		l++;
	}
	c[3] = '\0';
	while (*str) {
		if (++l > slen) {
			errno = ENOBUFS;
			return -1;
		}
		if (*str == '\\') {
			str++;
			switch(*str++) {
			case '\0':
				break;
			case 'b':
				*sbuf++ = '\b';
				break;
			case 'n':
				*sbuf++ = '\n';
				break;
			case 'r':
				*sbuf++ = '\r';
				break;
			case 't':
				*sbuf++ = '\t';
				break;
			case 'x':
				/* Grab a hex code */
				c[1] = '\0';
				for (i = 0; i < 2; i++) {
					if (isxdigit((unsigned char)*str) == 0)
						break;
					c[i] = *str++;
				}
				if (c[1] != '\0') {
					c[2] = '\0';
					*sbuf++ = strtol(c, NULL, 16);
				} else
					l--;
				break;
			case '0':
				/* Grab an octal code */
				c[2] = '\0';
				for (i = 0; i < 3; i++) {
					if (*str < '0' || *str > '7')
						break;
					c[i] = *str++;
				}
				if (c[2] != '\0') {
					i = strtol(c, NULL, 8);
					if (i > 255)
						i = 255;
					*sbuf ++= i;
				} else
					l--;
				break;
			default:
				*sbuf++ = *str++;
			}
		} else
			*sbuf++ = *str++;
	}
	if (punt_last)
		*--sbuf = '\0';
	return l;
}

static int
parse_option(struct if_options *ifo, int opt, const char *arg)
{
	int i;
	char *p;
	ssize_t s;
	struct in_addr addr;

	switch(opt) {
	case 'b':
		ifo->options |= DHCPCD_BACKGROUND;
		break;
	case 'c':
		strlcpy(ifo->script, arg, sizeof(ifo->script));
		break;
	case 'd':
		break;
	case 'h':
		if (arg)
			s = parse_string(ifo->hostname + 1,
					 HOSTNAME_MAX_LEN, arg);
		else
			s = 0;
		if (s == -1) {
			logger(LOG_ERR, "hostname: %s", strerror(errno));
			return -1;
		}
		if (s != 0 && ifo->hostname[1] == '.') {
			logger(LOG_ERR, "hostname cannot begin with a .");
			return -1;
		}
		ifo->hostname[0] = (uint8_t)s;
		break;
	case 'i':
		if (arg)
			s = parse_string((char *)ifo->vendorclassid + 1,
					 VENDORCLASSID_MAX_LEN, arg);
		else
			s = 0;
		if (s == -1) {
			logger(LOG_ERR, "vendorclassid: %s", strerror(errno));
			return -1;
		}
		*ifo->vendorclassid = (uint8_t)s;
		break;
	case 'k':
		break;
	case 'l':
		if (*arg == '-') {
			logger(LOG_ERR,
			       "leasetime must be a positive value");
			return -1;
		}
		errno = 0;
		ifo->leasetime = (uint32_t)strtol(arg, NULL, 0);
		if (errno == EINVAL || errno == ERANGE) {
			logger(LOG_ERR, "`%s' out of range", arg);
			return -1;
		}
		break;
	case 'm':
		ifo->metric = atoint(arg);
		if (ifo->metric < 0) {
			logger(LOG_ERR, "metric must be a positive value");
			return -1;
		}
		break;
	case 'n':
		break;
	case 'o':
		if (make_option_mask(ifo->requestmask, arg, 1) != 0) {
			logger(LOG_ERR, "unknown option `%s'", arg);
			return -1;
		}
		break;
	case 'p':
		ifo->options |= DHCPCD_PERSISTENT;
		break;
	case 'q':
		setloglevel(LOG_WARNING);
		break;
	case 's':
		ifo->options |= DHCPCD_INFORM;
		ifo->options |= DHCPCD_PERSISTENT;
		ifo->options &= ~DHCPCD_ARP;
		if (!arg || *arg == '\0') {
			ifo->request_address.s_addr = 0;
			break;
		} else {
			if ((p = strchr(arg, '/'))) {
				/* nullify the slash, so the -r option
				 * can read the address */
				*p++ = '\0';
				if (sscanf(p, "%d", &i) != 1 ||
				    inet_cidrtoaddr(i, &ifo->request_netmask) != 0)
				{
					logger(LOG_ERR,
					       "`%s' is not a valid CIDR",
					       p);
					return -1;
				}
			}
		}
		/* FALLTHROUGH */
	case 'r':
		if (!(ifo->options & DHCPCD_INFORM))
			ifo->options |= DHCPCD_REQUEST;
		if (arg && !inet_aton(arg, &ifo->request_address)) {
			logger(LOG_ERR, "`%s' is not a valid IP address",
			       arg);
			return -1;
		}
		break;
	case 't':
		ifo->timeout = atoint(arg);
		if (ifo->timeout < 0) {
			logger (LOG_ERR, "timeout must be a positive value");
			return -1;
		}
		break;
	case 'u':
		s = USERCLASS_MAX_LEN - ifo->userclass[0] - 1;
		s = parse_string((char *)ifo->userclass + ifo->userclass[0] + 2,
				 s, arg);
		if (s == -1) {
			logger(LOG_ERR, "userclass: %s", strerror(errno));
			return -1;
		}
		if (s != 0) {
			ifo->userclass[ifo->userclass[0] + 1] = s;
			ifo->userclass[0] += s + 1;
		}
		break;
	case 'v':
		p = strchr(arg, ',');
		if (!p || !p[1]) {
			logger(LOG_ERR, "invalid vendor format");
			return -1;
		}
		*p = '\0';
		i = atoint(arg);
		arg = p + 1;
		if (i < 1 || i > 254) {
			logger(LOG_ERR, "vendor option should be between"
					" 1 and 254 inclusive");
			return -1;
		}
		s = VENDOR_MAX_LEN - ifo->vendor[0] - 2;
		if (inet_aton(arg, &addr) == 1) {
			if (s < 6) {
				s = -1;
				errno = ENOBUFS;
			} else
				memcpy(ifo->vendor + ifo->vendor[0] + 3,
				       &addr.s_addr, sizeof(addr.s_addr));
		} else {
			s = parse_string((char *)ifo->vendor + ifo->vendor[0] + 3,
					 s, arg);
		}
		if (s == -1) {
			logger(LOG_ERR, "vendor: %s", strerror(errno));
			return -1;
		}
		if (s != 0) {
			ifo->vendor[ifo->vendor[0] + 1] = i;
			ifo->vendor[ifo->vendor[0] + 2] = s;
			ifo->vendor[0] += s + 2;
		}
		break;
	case 'x':
		break;
	case 'A':
		ifo->options &= ~DHCPCD_ARP;
		/* IPv4LL requires ARP */
		ifo->options &= ~DHCPCD_IPV4LL;
		break;
	case 'B':
		ifo->options &= ~DHCPCD_DAEMONISE;
		break;
	case 'C':
		/* Commas to spaces for shell */
		while ((p = strchr(arg, ',')))
			*p = ' ';
		s = strlen("skip_hooks=") + strlen(arg) + 1;
		p = xmalloc(sizeof(char) * s);
		snprintf(p, s, "skip_hooks=%s", arg);
		add_environ(ifo, p, 0);
		free(p);
		break;
	case 'D':
		ifo->options |= DHCPCD_DUID;
		break;
	case 'E':
		ifo->options |= DHCPCD_LASTLEASE;
		break;
	case 'F':
		if (!arg) {
			ifo->fqdn = FQDN_BOTH;
			break;
		}
		if (strcmp(arg, "none") == 0)
			ifo->fqdn = FQDN_NONE;
		else if (strcmp(arg, "ptr") == 0)
			ifo->fqdn = FQDN_PTR;
		else if (strcmp(arg, "both") == 0)
			ifo->fqdn = FQDN_BOTH;
		else if (strcmp(arg, "disable") == 0)
			ifo->fqdn = FQDN_DISABLE;
		else {
			logger(LOG_ERR, "invalid value `%s' for FQDN", arg);
			return -1;
		}
		break;
	case 'G':
		ifo->options &= ~DHCPCD_GATEWAY;
		break;
	case 'I':
		/* Strings have a type of 0 */;
		ifo->clientid[1] = 0;
		if (arg)
			s = parse_string_hwaddr((char *)ifo->clientid + 1,
						CLIENTID_MAX_LEN, arg, 1);
		else
			s = 0;
		if (s == -1) {
			logger(LOG_ERR, "clientid: %s", strerror(errno));
			return -1;
		}
		ifo->clientid[0] = (uint8_t)s;
		if (s == 0) {
			ifo->options &= ~DHCPCD_DUID;
			ifo->options &= ~DHCPCD_CLIENTID;
		}
		break;
	case 'K':
		ifo->options &= ~DHCPCD_LINK;
		break;
	case 'L':
		ifo->options &= ~DHCPCD_IPV4LL;
		break;
	case 'O':
		if (make_option_mask(ifo->requestmask, arg, -1) != 0 ||
		    make_option_mask(ifo->requiremask, arg, -1) != 0 ||
		    make_option_mask(ifo->nomask, arg, 1) != 0)
		{
			logger(LOG_ERR, "unknown option `%s'", arg);
			return -1;
		}
		break;
	case 'Q':
		if (make_option_mask(ifo->requiremask, arg, 1) != 0 ||
		    make_option_mask(ifo->requestmask, arg, 1) != 0)
		{
			logger(LOG_ERR, "unknown option `%s'", arg);
			return -1;
		}
		break;
	case 'X':
		if (!inet_aton(arg, &addr)) {
			logger(LOG_ERR, "`%s' is not a valid IP address",
			       arg);
			return -1;
		}
		ifo->blacklist = xrealloc(ifo->blacklist,
		    sizeof(in_addr_t) * (ifo->blacklist_len + 1));
		ifo->blacklist[ifo->blacklist_len] = addr.s_addr;
		ifo->blacklist_len++;
		break;
	default:
		return 0;
	}

	return 1;
}

static int
parse_config_line(struct if_options *ifo, const char *opt, char *line)
{
	unsigned int i;

	for (i = 0; i < sizeof(cf_options) / sizeof(cf_options[0]); i++) {
		if (!cf_options[i].name ||
		    strcmp(cf_options[i].name, opt) != 0)
			continue;

		if (cf_options[i].has_arg == required_argument && !line) {
			fprintf(stderr,
				PACKAGE ": option requires an argument -- %s\n",
				opt);
			return -1;
		}

		return parse_option(ifo, cf_options[i].val, line);
	}

	fprintf(stderr, PACKAGE ": unknown option -- %s\n", opt);
	return -1;
}

struct if_options *
read_config(const char *file, const char *ifname)
{
	struct if_options *ifo;
	FILE *f;
	size_t len = 0;
	char *line, *option, *p, *buffer = NULL;
	int skip = 0;

	/* Seed our default options */
	ifo = xzalloc(sizeof(*ifo));
	ifo->options |= DHCPCD_CLIENTID | DHCPCD_GATEWAY | DHCPCD_DAEMONISE;
	ifo->options |= DHCPCD_ARP | DHCPCD_IPV4LL | DHCPCD_LINK;
	ifo->timeout = DEFAULT_TIMEOUT;
	ifo->metric = -1;
	gethostname(ifo->hostname + 1, sizeof(ifo->hostname));
	if (strcmp(ifo->hostname + 1, "(none)") == 0 ||
	    strcmp(ifo->hostname + 1, "localhost") == 0)
		ifo->hostname[1] = '\0';
	*ifo->hostname = strlen(ifo->hostname + 1);
	strlcpy(ifo->script, SCRIPT, sizeof(ifo->script));
	ifo->vendorclassid[0] = snprintf((char *)ifo->vendorclassid + 1,
					     VENDORCLASSID_MAX_LEN,
					     "%s %s", PACKAGE, VERSION);

	/* Parse our options file */
	f = fopen(file, "r");
	if (!f)
		return ifo;

	while ((get_line(&buffer, &len, f))) {
		line = buffer;
		while ((option = strsep(&line, " \t")))
			if (*option != '\0')
				break;
		if (!option || *option == '\0' || *option == '#')
			continue;
		/* Trim leading whitespace */
		if (line) {
			while (*line != '\0' && (*line == ' ' || *line == '\t'))
				line++;
		}
		/* Trim trailing whitespace */
		if (line && *line) {
			p = line + strlen(line) - 1;
			while (p != line &&
					(*p == ' ' || *p == '\t') &&
					*(p - 1) != '\\')
				*p-- = '\0';
		}
		/* Start of an interface block, skip if not ours */
		if (strcmp(option, "interface") == 0) {
			if (ifname && line && strcmp(line, ifname) == 0)
				skip = 0;
			else
				skip = 1;
			continue;
		}
		if (skip)
			continue;
		if (parse_config_line(ifo, option, line) != 1) {
			break;
		}
	}
	free(buffer);
	fclose(f);

	/* Terminate the encapsulated options */
	if (ifo->vendor[0]) {
		ifo->vendor[0]++;
		ifo->vendor[ifo->vendor[0]] = DHO_END;
	}
	return ifo;
}

int
add_options(struct if_options *ifo, int argc, char **argv)
{
	int oi, opt, r = 1;

	optind = 0;
	while ((opt = getopt_long(argc, argv, IF_OPTS, cf_options, &oi)) != -1)
	{
		r = parse_option(ifo, opt, optarg);
		if (r != 1)
			break;
	}
	/* Terminate the encapsulated options */
	if (r == 1 && ifo->vendor[0]) {
		ifo->vendor[0]++;
		ifo->vendor[ifo->vendor[0]] = DHO_END;
	}
	return r;
}

void
free_options(struct if_options *ifo)
{
	size_t i;

	if (ifo) {
		if (ifo->environ) {
			i = 0;
			while (ifo->environ[i])
				free(ifo->environ[i++]);
			free(ifo->environ);
		}
		free(ifo->blacklist);
		free(ifo);
	}
}
