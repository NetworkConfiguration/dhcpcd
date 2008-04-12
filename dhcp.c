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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"

#define OPT_REQUEST	(1 << 0)
#define OPT_UINT8	(1 << 3)
#define OPT_UINT16	(1 << 4)
#define OPT_UINT32	(1 << 5)
#define OPT_IPV4	(1 << 6)
#define OPT_STRING	(1 << 7)
#define OPT_RFC3361	(1 << 10)
#define OPT_RFC3397	(1 << 11)

#define OPT_IPV4R	OPT_IPV4 | OPT_REQUEST
#define OPT_UINT32R	OPT_UINT32 | OPT_REQUEST
#define OPT_UINT16R	OPT_UINT16 | OPT_REQUEST
#define OPT_STRINGR	OPT_STRING | OPT_REQUEST

struct dhcp_option {
	uint8_t option;
	int type;
	const char *var;
};

const struct dhcp_option dhcp_options[] = {
	{ DHCP_SERVERID,	OPT_IPV4,	"SERVERID" },
	{ DHCP_NETMASK,		OPT_IPV4R,	NULL },
	{ DHCP_BROADCAST,	OPT_IPV4R,	NULL },
	{ DHCP_LEASETIME,	OPT_UINT32,	NULL },
	{ DHCP_RENEWALTIME,	OPT_UINT32R,	NULL },
	{ DHCP_REBINDTIME,	OPT_UINT32R,	NULL },
	{ DHCP_MTU,		OPT_UINT16R,	"MTU" },
	{ DHCP_STATICROUTE,	OPT_IPV4R,	NULL },
	{ DHCP_ROUTER,		OPT_IPV4R,	NULL },
	{ DHCP_HOSTNAME,	OPT_STRINGR,	"HOSTNAME" },
	{ DHCP_DNSSERVER,	OPT_IPV4R,	"DNSSERVER" },
	{ DHCP_DNSDOMAIN,	OPT_STRINGR,	"DNSDOMAIN" },
	{ DHCP_DNSSEARCH,	OPT_STRINGR | OPT_RFC3397,	"DNSSEARCH" },
	{ DHCP_NTPSERVER,	OPT_IPV4R,	"NTPSERVER" },
	{ DHCP_NISSERVER,	OPT_IPV4R,	"NISSERVER" },
	{ DHCP_NISDOMAIN,	OPT_IPV4R,	"NISDOMAIN" },
	{ DHCP_ROOTPATH,	OPT_STRINGR,	"ROOTPATH" },
	{ DHCP_SIPSERVER,	OPT_STRINGR | OPT_RFC3361,	"SIPSERVER" },
	{ DHCP_MESSAGE,		OPT_STRING,	NULL},
	{ 0, 0, NULL }
};

static int
valid_length(uint8_t option, const uint8_t *data, int *type)
{
	uint8_t l = *data;
	uint8_t i;

	if (l == 0)
		return -1;

	for (i = 0; i < sizeof(dhcp_options) / sizeof(dhcp_options[0]); i++) {
		if (dhcp_options[i].option != option)
			continue;
		
		if (type)
			*type = dhcp_options[i].type;
		
		if (dhcp_options[i].type & OPT_STRING)
			return 0;

		if (dhcp_options[i].type & OPT_UINT32) {
			if (l == sizeof(uint32_t))
				return 0;
			return -1;
		}

		if (dhcp_options[i].type & OPT_IPV4)
			return l % sizeof(uint32_t);
	}

	/* unknown option, so let it pass */
	return 0;
}

static const uint8_t *
_get_option(const struct dhcp_message *dhcp, uint8_t opt, int *type)
{
	const uint8_t *p = dhcp->options;
	const uint8_t *e = p + sizeof(dhcp->options);
	uint8_t l;
	uint8_t o = 0;

	while (p < e) {
		o = *p++;
		if (o == opt) {
			if (valid_length(o, p, type) != -1)
				return p;
			errno = EINVAL;
			return NULL;
		}
		switch (o) {
		case DHCP_PAD:
			continue;
		case DHCP_END:
			if (o) {
				if (o & 1) {
					/* bit 1 set means parse boot file */
					o &= ~1;
					p = dhcp->bootfile;
					e = p + sizeof(dhcp->bootfile);
				} else if (o & 2) {
					/* bit 2 set means parse server name */
					o &= ~2;
					p = dhcp->servername;
					e = p + sizeof(dhcp->servername);
				}
			}
			break;
		case DHCP_OPTIONSOVERLOADED:
			/* Ensure we only get this option once */
			if (!(o & 4)) {
				o = p[1];
				o |= 4;
			}
			break;
		}
			
		l = *p++;
		p += l;
	}

	errno = ENOENT;
	return NULL;
}

const uint8_t *
get_option(const struct dhcp_message *dhcp, uint8_t opt)
{
	return _get_option(dhcp, opt, NULL);
}

int
get_option_addr(uint32_t *a, const struct dhcp_message *dhcp, uint8_t option)
{
	const uint8_t *p = get_option(dhcp, option);

	if (!p)
		return -1;
	memcpy(a, p + 1, sizeof(*a));
	return 0;
}

int
get_option_uint32(uint32_t *i, const struct dhcp_message *dhcp, uint8_t option)
{
	uint32_t a;

	if (get_option_addr(&a, dhcp, option) == -1)
		return -1;

	*i = ntohl(a);
	return 0;
}

int
get_option_uint16(uint16_t *i, const struct dhcp_message *dhcp, uint8_t option)
{
	const uint8_t *p = get_option(dhcp, option);
	uint16_t d;

	if (!p)
		return -1;
	memcpy(&d, p + 1, sizeof(d));
	*i = ntohs(d);
	return 0;
}

int
get_option_uint8(uint8_t *i, const struct dhcp_message *dhcp, uint8_t option)
{
	const uint8_t *p = get_option(dhcp, option);

	if (!p)
		return -1;
	*i = *(p + 1);
	return 0;
}

/* Decode an RFC3397 DNS search order option into a space
 * seperated string. Returns length of string (including 
 * terminating zero) or zero on error. out may be NULL
 * to just determine output length. */
static unsigned int
decode_rfc3397(const uint8_t *p, char *out)
{
	uint8_t len = *p++;
	const uint8_t *r, *q = p;
	unsigned int count = 0, l, hops;
	uint8_t ltype;

	while (q - p < len) {
		r = NULL;
		hops = 0;
		while ((l = *q++)) {
			ltype = l & 0xc0;
			if (ltype == 0x80 || ltype == 0x40)
				return 0;
			else if (ltype == 0xc0) { /* pointer */
				l = (l & 0x3f) << 8;
				l |= *q++;
				/* save source of first jump. */
				if (!r)
					r = q;
				hops++;
				if (hops > 255)
					return 0;
				q = p + l;
				if (q - p >= len)
					return 0;
			} else {
				/* straightforward name segment, add with '.' */
				count += l + 1;
				if (out) {
					memcpy(out, q, l);
					out += l;
					*out++ = '.';
				}
				q += l;
			}
		}
		/* change last dot to space */
		if (out)
			*(out - 1) = ' ';
		if (r)
			q = r;
	}

	/* change last space to zero terminator */
	if (out)
		*(out - 1) = 0;

	return count;  
}

struct rt *
decode_rfc3442(const uint8_t *data)
{
	const uint8_t *p = data;
	const uint8_t *e;
	uint8_t l;
	uint8_t cidr;
	uint8_t ocets;
	struct rt *routes = NULL;
	struct rt *rt = NULL;

	l = *p++;
	/* Minimum is 5 -first is CIDR and a router length of 4 */
	if (l < 5)
		return NULL;

	e = p + l;
	while (p < e) {
		cidr = *p++;
		printf ("cd %d\n", cidr);
		if (cidr > 32) {
			free_routes(routes);
			errno = EINVAL;
			return NULL;
		}

		if (rt) {
			rt->next = xmalloc(sizeof(*rt));
			rt = rt->next;
		} else {
			routes = rt = xmalloc(sizeof(*routes));
		}
		rt->next = NULL;

		ocets = (cidr + 7) / 8;
		/* If we have ocets then we have a destination and netmask */
		if (ocets > 0) {
			memcpy(&rt->dest.s_addr, p, (size_t)ocets);
			memset(&rt->net.s_addr, 255, (size_t)ocets - 1);
			memset((uint8_t *)&rt->net.s_addr +
			       (ocets - 1),
			       (256 - (1 << (32 - cidr) % 8)), 1);
			p += ocets;
		} else {
			rt->dest.s_addr = 0;
			rt->net.s_addr = 0;
		}

		/* Finally, snag the router */
		memcpy(&rt->gate.s_addr, p, 4);
		p += 4;
	}
	return routes;
}

static char *
decode_rfc3361(const uint8_t *data)
{
	uint8_t len = *data++;
	uint8_t enc;
	unsigned int l;
	char *sip = NULL;
	struct in_addr addr;
	char *p;

	if (len < 2) {
		errno = EINVAL;
		return 0;
	}

	enc = *data++;
	len--;
	switch (enc) {
	case 0:
		if ((l = decode_rfc3397(data, NULL)) > 0) {
			sip = xmalloc(len);
			decode_rfc3397(data, sip);
		}
		break;
	case 1:
		if (len == 0 || len % 4 != 0) {
			errno = EINVAL;
			break;
		}
		addr.s_addr = INADDR_BROADCAST;
		l = ((len / sizeof(addr.s_addr)) * ((4 * 4) + 1)) + 1;
		sip = p = xmalloc(l);
		while (l != 0) {
			memcpy(&addr.s_addr, data, sizeof(addr.s_addr));
			data += sizeof(addr.s_addr);
			p += snprintf(p, l - (p - sip), "%s ", inet_ntoa(addr));
			l -= sizeof(addr.s_addr);
		}
		*--p = '\0';
		break;
	default:
		errno = EINVAL;
		return 0;
	}

	return sip;
}

char *
get_option_string(const struct dhcp_message *dhcp, uint8_t option)
{
	int type;
	const uint8_t *p;
	uint8_t l;
	char *s;

	p =  _get_option(dhcp, option, &type);
	if (!p)
		return NULL;

	if (type & OPT_RFC3397) {
		type = decode_rfc3397(p, NULL);
		if (!type) {
			errno = EINVAL;
			return NULL;
		}
		s = xmalloc(sizeof(char) * type);
		decode_rfc3397(p, s);
		return s;
	}

	if (type & OPT_RFC3361)
		return decode_rfc3361(p);


	l = *p++;
	s = xmalloc(sizeof(char) * (l + 1));
	memcpy(s, p, l);
	s[l] = '\0';
	return s;
}

/* This calculates the netmask that we should use for static routes.
 * This IS different from the calculation used to calculate the netmask
 * for an interface address. */
static uint32_t
route_netmask(uint32_t ip_in)
{
	/* used to be unsigned long - check if error */
	uint32_t p = ntohl(ip_in);
	uint32_t t;

	if (IN_CLASSA(p))
		t = ~IN_CLASSA_NET;
	else {
		if (IN_CLASSB(p))
			t = ~IN_CLASSB_NET;
		else {
			if (IN_CLASSC(p))
				t = ~IN_CLASSC_NET;
			else
				t = 0;
		}
	}

	while (t & p)
		t >>= 1;

	return (htonl(~t));
}

/* We need to obey routing options.
 * If we have a CSR then we only use that.
 * Otherwise we add static routes and then routers. */
struct rt *
get_option_routes(const struct dhcp_message *dhcp)
{
	const uint8_t *p;
	const uint8_t *e;
	struct rt *routes = NULL;
	struct rt *route = NULL;
	uint8_t l;

	/* If we have CSR's then we MUST use these only */
	p = get_option(dhcp, DHCP_CSR);
	/* Check for crappy MS option */
	if (!p)
		p = get_option(dhcp, DHCP_MSCSR);
	if (p) {
		routes = decode_rfc3442(p);
		if (routes)
			return routes;
	}

	/* OK, get our static routes first. */
	p = get_option(dhcp, DHCP_STATICROUTE);
	if (p) {
		l = *p++;
		e = p + l;
		while (p < e) {
			if (route) {
				route->next = xmalloc(sizeof(*route));
				route = route->next;
			} else
				routes = route = xmalloc(sizeof(*routes));
			route->next = NULL;
			memcpy(&route->dest.s_addr, p, 4);
			p += 4;
			memcpy(&route->gate.s_addr, p, 4);
			p += 4;
			route->net.s_addr = route_netmask(route->dest.s_addr);
		}
	}

	/* Now grab our routers */
	p = get_option(dhcp, DHCP_ROUTER);
	if (p) {
		l = *p++;
		e = p + l;
		while (p < e) {
			if (route) {
				route->next = xzalloc(sizeof(*route));
				route = route->next;
			} else
				routes = route = xzalloc(sizeof(*route));
			memcpy(&route->gate.s_addr, p, 4);
			p += 4;
		}
	}

	return routes;
}

ssize_t
make_message(struct dhcp_message **message,
	     const struct interface *iface, const struct dhcp_lease *lease,
	     uint32_t xid, uint8_t type, const struct options *options)
{
	struct dhcp_message *dhcp;
	uint8_t *m;
	uint8_t *p;
	uint8_t *n_params = NULL;
	size_t l;
	time_t up = uptime() - iface->start_uptime;
	uint32_t ul;
	uint16_t sz;

	dhcp = xzalloc(sizeof (*dhcp));
	m = (uint8_t *)dhcp;
	p = (uint8_t *)&dhcp->options;

	if ((type == DHCP_INFORM ||
	     type == DHCP_RELEASE ||
	     type == DHCP_REQUEST) &&
	    !IN_LINKLOCAL(ntohl(iface->addr.s_addr)))
	{
		dhcp->ciaddr = iface->addr.s_addr;
		/* Just incase we haven't actually configured the address yet */
		if (type == DHCP_INFORM && iface->addr.s_addr == 0)
			dhcp->ciaddr = lease->addr.s_addr;
		/* Zero the address if we're currently on a different subnet */
		if (type == DHCP_REQUEST &&
		    iface->net.s_addr != lease->net.s_addr)
			dhcp->ciaddr = 0;
	}

	dhcp->op = DHCP_BOOTREQUEST;
	dhcp->hwtype = iface->family;
	switch (iface->family) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		dhcp->hwlen = ETHER_ADDR_LEN;
		memcpy(&dhcp->chaddr, &iface->hwaddr,
		       ETHER_ADDR_LEN);
		break;
	case ARPHRD_IEEE1394:
	case ARPHRD_INFINIBAND:
		dhcp->hwlen = 0;
		if (dhcp->ciaddr == 0)
			dhcp->flags = htons(BROADCAST_FLAG);
		break;
	}

	if (up < 0 || up > (time_t)UINT16_MAX)
		dhcp->secs = htons((uint16_t)UINT16_MAX);
	else
		dhcp->secs = htons(up);
	dhcp->xid = xid;
	dhcp->cookie = htonl(MAGIC_COOKIE);

	*p++ = DHCP_MESSAGETYPE; 
	*p++ = 1;
	*p++ = type;

	if (type == DHCP_REQUEST) {
		*p++ = DHCP_MAXMESSAGESIZE;
		*p++ = 2;
		sz = get_mtu(iface->name);
		if (sz < MTU_MIN) {
			if (set_mtu(iface->name, MTU_MIN) == 0)
				sz = MTU_MIN;
		}
		sz = htons(sz);
		memcpy(p, &sz, 2);
		p += 2;
	}

	*p++ = DHCP_CLIENTID;
	*p++ = iface->clientid_len;
	memcpy(p, iface->clientid, iface->clientid_len);
	p+= iface->clientid_len;

	if (type != DHCP_DECLINE && type != DHCP_RELEASE) {
		if (options->userclass_len > 0) {
			*p++ = DHCP_USERCLASS;
			*p++ = options->userclass_len;
			memcpy(p, &options->userclass, options->userclass_len);
			p += options->userclass_len;
		}

		if (*options->classid > 0) {
			*p++ = DHCP_CLASSID;
			*p++ = l = strlen(options->classid);
			memcpy(p, options->classid, l);
			p += l;
		}
	}

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST) {
#define PUTADDR(_type, _val) \
		{ \
			*p++ = _type; \
			*p++ = 4; \
			memcpy(p, &_val.s_addr, 4); \
			p += 4; \
		}
		if (lease->addr.s_addr &&
			lease->addr.s_addr != iface->addr.s_addr &&
			!IN_LINKLOCAL(ntohl(lease->addr.s_addr)))
		{
			PUTADDR(DHCP_ADDRESS, lease->addr);
			if (lease->server.s_addr)
				PUTADDR(DHCP_SERVERID, lease->server);
		}
#undef PUTADDR

		if (options->leasetime != 0) {
			*p++ = DHCP_LEASETIME;
			*p++ = 4;
			ul = htonl(options->leasetime);
			memcpy(p, &ul, 4);
			p += 4;
		}
	}

	if (type == DHCP_DISCOVER ||
	    type == DHCP_INFORM ||
	    type == DHCP_REQUEST)
	{
		if (options->hostname[0]) {
			if (options->fqdn == FQDN_DISABLE) {
				*p++ = DHCP_HOSTNAME;
				*p++ = l = strlen(options->hostname);
				memcpy(p, options->hostname, l);
				p += l;
			} else {
				/* Draft IETF DHC-FQDN option (81) */
				*p++ = DHCP_FQDN;
				*p++ = (l = strlen(options->hostname)) + 3;
				/* Flags: 0000NEOS
				 * S: 1 => Client requests Server to update
				 *         a RR in DNS as well as PTR
				 * O: 1 => Server indicates to client that
				 *         DNS has been updated
				 * E: 1 => Name data is DNS format
				 * N: 1 => Client requests Server to not
				 *         update DNS
				 */
				*p++ = options->fqdn & 0x9;
				*p++ = 0; /* from server for PTR RR */
				*p++ = 0; /* from server for A RR if S=1 */
				memcpy(p, options->hostname, l);
				p += l;
			}
		}

		*p++ = DHCP_PARAMETERREQUESTLIST;
		n_params = p;
		*p++ = 0;
		for (l = 0; l < sizeof(dhcp_options) / sizeof(dhcp_options[0]); l++) {
			if (!(dhcp_options[l].type & OPT_REQUEST))
				continue;
			switch (dhcp_options[l].option) {
			case DHCP_RENEWALTIME:	/* FALLTHROUGH */
			case DHCP_REBINDTIME:
				if (type == DHCP_INFORM)
					continue;
				break;
			case DHCP_CSR:
				if (options->domscsr > 1)
					continue;
				break;
			}
			*p++ = dhcp_options[l].option;
		}
		if (options->domscsr)
			*p++ = DHCP_MSCSR;
		*n_params = p - n_params - 1;
	}
	*p++ = DHCP_END;

#ifdef BOOTP_MESSAGE_LENTH_MIN
	/* Some crappy DHCP servers think they have to obey the BOOTP minimum
	 * message length.
	 * They are wrong, but we should still cater for them. */
	while (p - m < BOOTP_MESSAGE_LENTH_MIN)
		*p++ = DHCP_PAD;
#endif

	*message = dhcp;
	return p - m;
}

ssize_t
write_lease(const struct interface *iface, const struct dhcp_message *dhcp)
{
	int fd;
	ssize_t bytes = sizeof(*dhcp);
	const uint8_t *p = dhcp->options;
	const uint8_t *e = p + sizeof(dhcp->options);
	uint8_t l;
	uint8_t o = 0;

	fd = open(iface->leasefile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1)
		return -1;

	/* Only write as much as we need */
	while (p < e) {
		o = *p;
		if (o == DHCP_END) {
			bytes = p - (const uint8_t *)dhcp;
			break;
		}
		p++;
		if (o != DHCP_PAD) {
			l = *p++;
			p += l;
		}
	}
	bytes = write(fd, dhcp, bytes);
	close(fd);
	return bytes;
}

struct dhcp_message *
read_lease(const struct interface *iface)
{
	int fd;
	struct dhcp_message *dhcp;
	ssize_t bytes;
	
	fd = open(iface->leasefile, O_RDONLY);
	if (fd == -1)
		return NULL;
	dhcp = xmalloc(sizeof(*dhcp));
	memset(dhcp, 0, sizeof(*dhcp));
	bytes = read(fd, dhcp, sizeof(*dhcp));
	close(fd);
	if (bytes < 0) {
		free(dhcp);
		dhcp = NULL;
	}
	return dhcp;
}

/* Create a malloced string of cstr, changing ' to '\''
 * so the contents work in a shell */
char *
clean_metas(const char *cstr)
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

ssize_t
write_options(FILE *f, const struct dhcp_message *dhcp)
{
	uint8_t i;
	const uint8_t *p, *e, *t;
	char *s;
	char *c;
	uint32_t u32;
	uint16_t u16;
	uint8_t u8;
	struct in_addr addr;
	ssize_t retval = 0;

	for (i = 0; i < sizeof(dhcp_options) / sizeof(dhcp_options[0]); i++) {
		if (!dhcp_options[i].var)
			continue;

		retval += fprintf(f, "%s=", dhcp_options[i].var);

		if (dhcp_options[i].type & OPT_STRING) {
			s = get_option_string(dhcp, dhcp_options[i].type);
			if (s) {
				c = clean_metas(s);
				retval += fprintf(f, "'%s'", c);
				free(c);
				free(s);
			} 
		}

		if (dhcp_options[i].type & OPT_UINT32) {
			if (get_option_uint32(&u32, dhcp,
						dhcp_options[i].option) == 0)
				retval += fprintf(f, "%d", u32);
		}

		if (dhcp_options[i].type & OPT_UINT16) {
			if (get_option_uint16(&u16, dhcp,
						dhcp_options[i].option) == 0)
				retval += fprintf(f, "%d", u16);
		}

		if (dhcp_options[i].type & OPT_IPV4) {
			p = get_option(dhcp, dhcp_options[i].option);
			if (p) {
				if (fputc('\'', f))
					retval++;
				u8 = *p++;
				t = p;
				e = p + u8;
				while (p < e) {
					memcpy(&addr.s_addr, p,
							sizeof(addr.s_addr));
					if (t != p)
						retval += fprintf(f, " ");
					retval += fprintf(f, "%s",
							inet_ntoa(addr));
					p += sizeof(addr.s_addr);
				}
				if (fputc('\'', f))
					retval++;
			}
		}
	
		if (fputc('\n', f))
			retval++;	
	}
	return retval;
}
