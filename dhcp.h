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

#ifndef DHCP_H
#define DHCP_H

#include <arpa/inet.h>

#include <stdint.h>

#include "config.h"
#include "dhcpcd.h"
#include "net.h"

/* Max MTU - defines dhcp option length */
#define MTU_MAX             1500
#define MTU_MIN             576

/* UDP port numbers for DHCP */
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define MAGIC_COOKIE        0x63825363
#define BROADCAST_FLAG      0x8000

/* DHCP message OP code */
#define DHCP_BOOTREQUEST    1
#define DHCP_BOOTREPLY      2

/* DHCP message type */
#define DHCP_DISCOVER       1
#define DHCP_OFFER          2
#define DHCP_REQUEST        3
#define DHCP_DECLINE        4
#define DHCP_ACK            5
#define DHCP_NAK            6
#define DHCP_RELEASE        7
#define DHCP_INFORM         8

/* DHCP options */
enum DHCP_OPTIONS
{
	DHCP_PAD                    = 0,
	DHCP_NETMASK                = 1,
	DHCP_TIMEOFFSET             = 2,
	DHCP_ROUTER                 = 3,
	DHCP_TIMESERVER             = 4,
	DHCP_NAMESERVER             = 5,
	DHCP_DNSSERVER              = 6,
	DHCP_LOGSERVER              = 7,
	DHCP_COOKIESERVER           = 8,
	DHCP_LPRSERVER              = 9,
	DHCP_IMPRESSSERVER          = 10,
	DHCP_RESOURCELOCATIONSERVER = 11,
	DHCP_HOSTNAME               = 12,
	DHCP_BOOTFILESIZE           = 13,
	DHCP_MERITDUMPFILE          = 14,
	DHCP_DNSDOMAIN              = 15,
	DHCP_SWAPSERVER             = 16,
	DHCP_ROOTPATH               = 17,
	DHCP_EXTENSIONSPATH         = 18,
	DHCP_IPFORWARDING           = 19,
	DHCP_NONLOCALSOURCEROUTING  = 20,
	DHCP_POLICYFILTER           = 21,
	DHCP_MAXDGRAMSIZE           = 22,
	DHCP_DEFAULTIPTTL           = 23,
	DHCP_PATHMTUAGINGTIMEOUT    = 24,
	DHCP_PATHMTUPLATEAUTABLE    = 25,
	DHCP_MTU                    = 26,
	DHCP_ALLSUBNETSLOCAL        = 27,
	DHCP_BROADCAST              = 28,
	DHCP_MASKDISCOVERY          = 29,
	DHCP_MASKSUPPLIER           = 30,
	DHCP_ROUTERDISCOVERY        = 31,
	DHCP_ROUTERSOLICITATIONADDR = 32,
	DHCP_STATICROUTE            = 33,
	DHCP_TRAILERENCAPSULATION   = 34,
	DHCP_ARPCACHETIMEOUT        = 35,
	DHCP_ETHERNETENCAPSULATION  = 36,
	DHCP_TCPDEFAULTTTL          = 37,
	DHCP_TCPKEEPALIVEINTERVAL   = 38,
	DHCP_TCPKEEPALIVEGARBAGE    = 39,
	DHCP_NISDOMAIN              = 40,
	DHCP_NISSERVER              = 41,
	DHCP_NTPSERVER              = 42,
	DHCP_VENDORSPECIFICINFO     = 43,
	DHCP_NETBIOSNAMESERVER      = 44,
	DHCP_NETBIOSDGRAMSERVER     = 45,
	DHCP_NETBIOSNODETYPE        = 46,
	DHCP_NETBIOSSCOPE           = 47,
	DHCP_XFONTSERVER            = 48,
	DHCP_XDISPLAYMANAGER        = 49,
	DHCP_ADDRESS                = 50,
	DHCP_LEASETIME              = 51,
	DHCP_OPTIONSOVERLOADED      = 52,
	DHCP_MESSAGETYPE            = 53,
	DHCP_SERVERID               = 54,
	DHCP_PARAMETERREQUESTLIST   = 55,
	DHCP_MESSAGE                = 56,
	DHCP_MAXMESSAGESIZE         = 57,
	DHCP_RENEWALTIME            = 58,
	DHCP_REBINDTIME             = 59,
	DHCP_CLASSID                = 60,
	DHCP_CLIENTID               = 61,
	DHCP_NISPLUSDOMAIN          = 64,
	DHCP_NISPLUSSERVER          = 65,
	DHCP_MOBILEIPHOMEAGENT      = 68,
	DHCP_SMTPSERVER             = 69,
	DHCP_POP3SERVER             = 70,
	DHCP_NNTPSERVER             = 71,
	DHCP_WWWSERVER              = 72,
	DHCP_FINGERSERVER           = 73,
	DHCP_IRCSERVER              = 74,
	DHCP_STREETTALKSERVER       = 75,
	DHCP_STREETTALKDASERVER     = 76,
	DHCP_USERCLASS              = 77,  /* RFC 3004 */
	DHCP_FQDN                   = 81,
	DHCP_DNSSEARCH              = 119, /* RFC 3397 */
	DHCP_SIPSERVER              = 120, /* RFC 3361 */
	DHCP_CSR                    = 121, /* RFC 3442 */
	DHCP_MSCSR                  = 249, /* MS code for RFC 3442 */
	DHCP_END                    = 255
};

/* SetFQDNHostName values - lsnybble used in flags
 * byte (see buildmsg.c), hsnybble to create order
 * and to allow 0x00 to mean disable
 */
enum FQQN {
	FQDN_DISABLE    = 0x00,
	FQDN_NONE       = 0x18,
	FQDN_PTR        = 0x20,
	FQDN_BOTH       = 0x31
};

struct fqdn
{
	uint8_t flags;
	uint8_t r1;
	uint8_t r2;
	char *name;
};

/* Sizes for DHCP options */
#define DHCP_CHADDR_LEN         16
#define SERVERNAME_LEN          64
#define BOOTFILE_LEN            128
#define DHCP_UDP_LEN            (20 + 8)
#define DHCP_BASE_LEN           (4 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 4)
#define DHCP_RESERVE_LEN        (4 + 4 + 4 + 4 + 2)
#define DHCP_FIXED_LEN          (DHCP_BASE_LEN + DHCP_CHADDR_LEN + \
				 + SERVERNAME_LEN + BOOTFILE_LEN)
#define DHCP_OPTION_LEN         (MTU_MAX - DHCP_FIXED_LEN - DHCP_UDP_LEN \
				 - DHCP_RESERVE_LEN)

/* Some crappy DHCP servers require the BOOTP minimum length */
#define BOOTP_MESSAGE_LENTH_MIN 300

struct dhcp_message {
	uint8_t op;           /* message type */
	uint8_t hwtype;       /* hardware address type */
	uint8_t hwlen;        /* hardware address length */
	uint8_t hwopcount;    /* should be zero in client message */
	uint32_t xid;            /* transaction id */
	uint16_t secs;           /* elapsed time in sec. from boot */
	uint16_t flags;
	uint32_t ciaddr;         /* (previously allocated) client IP */
	uint32_t yiaddr;         /* 'your' client IP address */
	uint32_t siaddr;         /* should be zero in client's messages */
	uint32_t giaddr;         /* should be zero in client's messages */
	uint8_t chaddr[DHCP_CHADDR_LEN];  /* client's hardware address */
	uint8_t servername[SERVERNAME_LEN];    /* server host name */
	uint8_t bootfile[BOOTFILE_LEN];    /* boot file name */
	uint32_t cookie;
	uint8_t options[DHCP_OPTION_LEN]; /* message options - cookie */
};

struct dhcp_lease {
	struct in_addr addr;
	struct in_addr net;
	uint32_t leasetime;
	uint32_t renewaltime;
	uint32_t rebindtime;
	struct in_addr server;
	uint32_t leasedfrom;
	uint8_t frominfo;
};

#define add_reqmask(var, val) (var[val >> 3] |= 1 << (val & 7))
#define has_reqmask(var, val) (var[val >> 3] & (1 << (val & 7)))
int make_reqmask(struct options *options, char **opts);
const uint8_t *get_option(const struct dhcp_message *, uint8_t);
char *get_option_string(const struct dhcp_message *, uint8_t);
int get_option_addr(uint32_t *, const struct dhcp_message *, uint8_t);
int get_option_uint32(uint32_t *, const struct dhcp_message *, uint8_t);
int get_option_uint16(uint16_t *, const struct dhcp_message *, uint8_t);
int get_option_uint8(uint8_t *, const struct dhcp_message *, uint8_t);
struct rt *get_option_routes(const struct dhcp_message *);
struct rt *decode_rfc3442(const uint8_t *);
ssize_t make_message(struct dhcp_message **,
			const struct interface *, const struct dhcp_lease *,
	     		uint32_t, uint8_t, const struct options *);
int valid_dhcp_packet(unsigned char *);

ssize_t write_lease(const struct interface *, const struct dhcp_message *);
struct dhcp_message *read_lease(const struct interface *iface);

ssize_t write_string(FILE *f, const uint8_t *, ssize_t);
ssize_t write_options(FILE *f, const struct dhcp_message *);
#endif
