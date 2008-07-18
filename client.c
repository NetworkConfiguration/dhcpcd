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
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#ifdef __linux__
# include <netinet/ether.h>
#endif

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "client.h"
#include "configure.h"
#include "dhcp.h"
#include "dhcpcd.h"
#include "net.h"
#include "logger.h"
#include "signals.h"

#ifdef ENABLE_IPV4LL
# ifndef ENABLE_ARP
 # error "IPv4LL requires ENABLE_ARP to work"
# endif
# define IPV4LL_LEASETIME 	2
#endif

/* Some platforms don't define INFTIM */
#ifndef INFTIM
# define INFTIM                 -1
#endif

#define STATE_INIT              0
#define STATE_DISCOVERING	1
#define STATE_REQUESTING        2
#define STATE_BOUND             3
#define STATE_RENEWING          4
#define STATE_REBINDING         5
#define STATE_REBOOT            6
#define STATE_RENEW_REQUESTED   7
#define STATE_INIT_IPV4LL	8
#define STATE_PROBING		9
#define STATE_ANNOUNCING	10
#define STATE_CARRIER		11

/* Constants taken from RFC 2131. */
#define T1			0.5
#define T2			0.875
#define DHCP_BASE		4
#define DHCP_MAX		64
#define DHCP_RAND_MIN		-1
#define DHCP_RAND_MAX		1
#define DHCP_ARP_FAIL		10

/* We should define a maximum for the NAK exponential backoff */ 
#define NAKOFF_MAX              60

#define SOCKET_CLOSED           0
#define SOCKET_OPEN             1

/* These are for IPV4LL, RFC 3927. */
#define PROBE_WAIT		 1
#define PROBE_NUM		 3
#define PROBE_MIN		 1
#define PROBE_MAX		 2
#define ANNOUNCE_WAIT		 2
/* BSD systems always do a grauitous ARP when assigning an address,
 * so we can do one less announce. */
#ifdef BSD
# define ANNOUNCE_NUM		 1
#else
# define ANNOUNCE_NUM		 2
#endif
#define ANNOUNCE_INTERVAL	 2
#define MAX_CONFLICTS		10
#define RATE_LIMIT_INTERVAL	60
#define DEFEND_INTERVAL		10


/* number of usecs in a second. */
#define USECS_SECOND		1000000
/* As we use timevals, we should use the usec part for
 * greater randomisation. */
#define DHCP_RAND_MIN_U		DHCP_RAND_MIN * USECS_SECOND
#define DHCP_RAND_MAX_U		DHCP_RAND_MAX * USECS_SECOND
#define PROBE_MIN_U		PROBE_MIN * USECS_SECOND
#define PROBE_MAX_U		PROBE_MAX * USECS_SECOND

struct if_state {
	int options;
	struct interface *interface;
	struct dhcp_message *offer;
	struct dhcp_message *new;
	struct dhcp_message *old;
	struct dhcp_lease lease;
	struct timeval start;
	struct timeval timeout;
	struct timeval stop;
	int state;
	int messages;
	time_t nakoff;
	uint32_t xid;
	int socket;
	int *pid_fd;
	int signal_fd;
#ifdef ENABLE_ARP
	int probes;
	int claims;
	int conflicts;
	time_t defend;
	struct in_addr fail;
#endif
};

struct dhcp_op {
        uint8_t value;
        const char *name;
};

static const struct dhcp_op const dhcp_ops[] = {
	{ DHCP_DISCOVER, "DHCP_DISCOVER" },
	{ DHCP_OFFER,    "DHCP_OFFER" },
	{ DHCP_REQUEST,  "DHCP_REQUEST" },
	{ DHCP_DECLINE,  "DHCP_DECLINE" },
	{ DHCP_ACK,      "DHCP_ACK" },
	{ DHCP_NAK,      "DHCP_NAK" },
	{ DHCP_RELEASE,  "DHCP_RELEASE" },
	{ DHCP_INFORM,   "DHCP_INFORM" },
	{ 0, NULL }
};

static const char *
get_dhcp_op(uint8_t type)
{
	const struct dhcp_op *d;

	for (d = dhcp_ops; d->name; d++)
		if (d->value == type)
			return d->name;
	return NULL;
}

static int
daemonise(struct if_state *state, const struct options *options)
{
	pid_t pid;
	sigset_t full;
	sigset_t old;
#ifdef THERE_IS_NO_FORK
	char **argv;
	int i;
#else
	char buf = '\0';
	int sidpipe[2];
#endif

	if (state->options & DHCPCD_DAEMONISED ||
	    !(options->options & DHCPCD_DAEMONISE))
		return 0;

	sigfillset(&full);
	sigprocmask(SIG_SETMASK, &full, &old);

#ifndef THERE_IS_NO_FORK
	/* Setup a signal pipe so parent knows when to exit. */
	if (pipe(sidpipe) == -1) {
		logger(LOG_ERR,"pipe: %s", strerror(errno));
		return -1;
	}

	logger(LOG_DEBUG, "forking to background");
	switch (pid = fork()) {
		case -1:
			logger(LOG_ERR, "fork: %s", strerror(errno));
			exit(EXIT_FAILURE);
			/* NOTREACHED */
		case 0:
			setsid();
			/* Notify parent it's safe to exit as we've detached. */
			close(sidpipe[0]);
			write(sidpipe[1], &buf, 1);
			close(sidpipe[1]);
			close_fds();
			break;
		default:
			/* Reset signals as we're the parent about to exit. */
			signal_reset();
			/* Wait for child to detach */
			close(sidpipe[1]);
			read(sidpipe[0], &buf, 1);
			close(sidpipe[0]);
			break;
	}
#else
	logger(LOG_INFO, "forking to background");

	/* We need to add --daemonise to our options */
	argv = xmalloc(sizeof(char *) * (dhcpcd_argc + 4));
	argv[0] = dhcpcd;
	for (i = 1; i < dhcpcd_argc; i++)
		argv[i] = dhcpcd_argv[i];
	argv[i] = (char *)"--daemonised";
	if (dhcpcd_skiproutes) {
		argv[++i] = (char *)"--skiproutes";
		argv[++i] = dhcpcd_skiproutes;
	}
	argv[i + 1] = NULL;

	switch (pid = vfork()) {
		case -1:
			logger(LOG_ERR, "vfork: %s", strerror(errno));
			_exit(EXIT_FAILURE);
		case 0:
			signal_reset();
			sigprocmask(SIG_SETMASK, &old, NULL);
			execvp(dhcpcd, argv);
			/* Must not use stdio here. */
			write(STDERR_FILENO, "exec failed\n", 12);
			_exit(EXIT_FAILURE);
	}

	free(argv);
#endif

	/* Done with the fd now */
	if (pid != 0) {
		writepid(*state->pid_fd, pid);
		close(*state->pid_fd);
		*state->pid_fd = -1;
	}

	sigprocmask(SIG_SETMASK, &old, NULL);

	state->state = STATE_BOUND;
	if (pid == 0) {
		state->options |= DHCPCD_DAEMONISED;
		return 0;
	}

	state->options |= DHCPCD_PERSISTENT | DHCPCD_FORKED;
	return -1;
}

#ifndef MINIMAL
#define THIRTY_YEARS_IN_SECONDS    946707779
static size_t
get_duid(unsigned char *duid, const struct interface *iface)
{
	FILE *f;
	uint16_t type = 0;
	uint16_t hw = 0;
	uint32_t ul;
	time_t t;
	int x = 0;
	unsigned char *p = duid;
	size_t len = 0, l = 0;
	char *buffer = NULL, *line, *option;

	/* If we already have a DUID then use it as it's never supposed
	 * to change once we have one even if the interfaces do */
	if ((f = fopen(DUID, "r"))) {
		while ((get_line(&buffer, &len, f))) {
			line = buffer;
			while ((option = strsep(&line, " \t")))
				if (*option != '\0')
					break;
			if (!option || *option == '\0' || *option == '#')
				continue;
			l = hwaddr_aton(NULL, option);
			if (l && l <= DUID_LEN) {
				hwaddr_aton(duid, option);
				break;
			}
			l = 0;
		}
		fclose(f);
		free(buffer);
		if (l)
			return l;
	} else {
		if (errno != ENOENT)
			return 0;
	}

	/* No file? OK, lets make one based on our interface */
	if (!(f = fopen(DUID, "w")))
		return 0;
	type = htons(1); /* DUI-D-LLT */
	memcpy(p, &type, 2);
	p += 2;
	hw = htons(iface->family);
	memcpy(p, &hw, 2);
	p += 2;
	/* time returns seconds from jan 1 1970, but DUID-LLT is
	 * seconds from jan 1 2000 modulo 2^32 */
	t = time(NULL) - THIRTY_YEARS_IN_SECONDS;
	ul = htonl(t & 0xffffffff);
	memcpy(p, &ul, 4);
	p += 4;
	/* Finally, add the MAC address of the interface */
	memcpy(p, iface->hwaddr, iface->hwlen);
	p += iface->hwlen;
	len = p - duid;
	x = fprintf(f, "%s\n", hwaddr_ntoa(duid, len));
	fclose(f);
	/* Failed to write the duid? scrub it, we cannot use it */
	if (x < 1) {
		len = 0;
		unlink(DUID);
	}
	return len;
}
#endif

#ifdef ENABLE_IPV4LL
static struct dhcp_message*
ipv4ll_get_dhcp(uint32_t old_addr)
{
	uint32_t u32;
	struct dhcp_message *dhcp;
	uint8_t *p;

	dhcp = xzalloc(sizeof(*dhcp));
	/* Put some LL options in */
	p = dhcp->options;
	*p++ = DHCP_SUBNETMASK;
	*p++ = sizeof(u32);
	u32 = htonl(LINKLOCAL_MASK);
	memcpy(p, &u32, sizeof(u32));
	p += sizeof(u32);
	*p++ = DHCP_BROADCAST;
	*p++ = sizeof(u32);
	u32 = htonl(LINKLOCAL_BRDC);
	memcpy(p, &u32, sizeof(u32));
	p += sizeof(u32);
	*p++ = DHCP_END;

	for (;;) {
		dhcp->yiaddr = htonl(LINKLOCAL_ADDR |
				     (((uint32_t)abs((int)arc4random())
				       % 0xFD00) + 0x0100));
		if (dhcp->yiaddr != old_addr &&
		    IN_LINKLOCAL(ntohl(dhcp->yiaddr)))
			break;
	}
	return dhcp;
}
#endif

static void
get_lease(struct dhcp_lease *lease, const struct dhcp_message *dhcp)
{
	lease->frominfo = 0;
	lease->addr.s_addr = dhcp->yiaddr;

	if (get_option_addr(&lease->net.s_addr, dhcp, DHCP_SUBNETMASK) == -1)
		lease->net.s_addr = get_netmask(dhcp->yiaddr);
	if (get_option_uint32(&lease->leasetime, dhcp, DHCP_LEASETIME) != 0)
		lease->leasetime = DEFAULT_LEASETIME;
	if (get_option_uint32(&lease->renewaltime, dhcp, DHCP_RENEWALTIME) != 0)
		lease->renewaltime = 0;
	if (get_option_uint32(&lease->rebindtime, dhcp, DHCP_REBINDTIME) != 0)
		lease->rebindtime = 0;
}

static int
get_old_lease(struct if_state *state)
{
	struct interface *iface = state->interface;
	struct dhcp_lease *lease = &state->lease;
	struct dhcp_message *dhcp = NULL;
	struct timeval tv;
	unsigned int offset = 0;
	struct stat sb;

	if (stat(iface->leasefile, &sb) == -1) {
		if (errno != ENOENT)
			logger(LOG_ERR, "stat: %s", strerror(errno));
		goto eexit;
	}
	if (!IN_LINKLOCAL(ntohl(iface->addr.s_addr)))
		logger(LOG_INFO, "trying to use old lease in `%s'",
		       iface->leasefile);
	if ((dhcp = read_lease(iface)) == NULL) {
		logger(LOG_INFO, "read_lease: %s", strerror(errno));
		goto eexit;
	}
	get_lease(&state->lease, dhcp);
	lease->frominfo = 1;
	lease->leasedfrom = sb.st_mtime;

	/* Vitaly important we remove the server information here */
	state->lease.server.s_addr = 0;
	dhcp->servername[0] = '\0';

	if (!IN_LINKLOCAL(ntohl(dhcp->yiaddr))) {
#ifndef THERE_IS_NO_FORK
		if (!(state->options & DHCPCD_LASTLEASE))
			goto eexit;
#endif

		/* Ensure that we can still use the lease */
		if (gettimeofday(&tv, NULL) == -1) {
			logger(LOG_ERR, "gettimeofday: %s", strerror(errno));
			goto eexit;
		}

		offset = tv.tv_sec - lease->leasedfrom;
		if (lease->leasedfrom &&
		    tv.tv_sec - lease->leasedfrom > lease->leasetime)
		{
			logger(LOG_ERR, "lease expired %u seconds ago",
			       offset + lease->leasetime);
			/* Persistent interfaces should still try and use the
			 * lease if we can't contact a DHCP server.
			 * We just set the timeout to 1 second. */
			if (state->options & DHCPCD_PERSISTENT)
				offset = lease->renewaltime - 1;
			else
				goto eexit;
		}
	}

	if (lease->leasedfrom == 0)
		offset = 0;
	iface->start_uptime = uptime();
	tv.tv_sec = lease->renewaltime - offset;
	tv.tv_usec = 0;
	get_time(&state->timeout);
	timeradd(&state->timeout, &tv, &state->timeout);
	free(state->old);
	state->old = state->new;
	state->new = NULL;
	state->offer = dhcp;
	return 0;

eexit:
	lease->addr.s_addr = 0;
	free(dhcp);
	return -1;
}

static int
client_setup(struct if_state *state, const struct options *options)
{
	struct interface *iface = state->interface;
	struct dhcp_lease *lease = &state->lease;
	struct in_addr addr;
	struct timeval tv;
#ifndef MINIMAL
	size_t len = 0;
	unsigned char *duid = NULL;
	uint32_t ul;
#endif

	state->state = STATE_INIT;
	state->nakoff = 1;
	state->options = options->options;
	timerclear(&tv);

	if (options->request_address.s_addr == 0 &&
	    (options->options & DHCPCD_INFORM ||
	     options->options & DHCPCD_REQUEST ||
	     options->options & DHCPCD_DAEMONISED))
	{
		if (get_old_lease(state) != 0)
			return -1;
		timerclear(&state->timeout);

		if (!(options->options & DHCPCD_DAEMONISED) &&
		    IN_LINKLOCAL(ntohl(lease->addr.s_addr)))
		{
			logger(LOG_ERR, "cannot request a link local address");
			return -1;
		}
#ifdef THERE_IS_NO_FORK
		if (options->options & DHCPCD_DAEMONISED) {
			iface->addr.s_addr = lease->addr.s_addr;
			iface->net.s_addr = lease->net.s_addr;
			state->new = state->offer;
			state->offer = NULL;
			get_option_addr(&lease->server.s_addr,
					state->new, DHCP_SERVERID);
#ifdef ENABLE_ARP
			open_socket(iface, ETHERTYPE_ARP);
			state->state = STATE_ANNOUNCING;
			tv.tv_sec = ANNOUNCE_INTERVAL;
#else
			state->state = STATE_BOUND;
			tv.tv_sec = state->lease.renewaltime;
#endif
			get_time(&state->timeout);
			timeradd(&state->timeout, &tv, &state->timeout);
		}
#endif
	} else {
		lease->addr.s_addr = options->request_address.s_addr;
		lease->net.s_addr = options->request_netmask.s_addr;
	}

	/* If INFORMing, ensure the interface has the address */
	if (state->options & DHCPCD_INFORM &&
	    has_address(iface->name, &lease->addr, &lease->net) < 1)
	{
		addr.s_addr = lease->addr.s_addr | ~lease->net.s_addr;
		logger(LOG_DEBUG, "adding IP address %s/%d",
		       inet_ntoa(lease->addr), inet_ntocidr(lease->net));
		if (add_address(iface->name, &lease->addr,
				&lease->net, &addr) == -1)
		{
			logger(LOG_ERR, "add_address: %s", strerror(errno));
			return -1;
		}
		iface->addr.s_addr = lease->addr.s_addr;
		iface->net.s_addr = lease->net.s_addr;
	}

#ifndef MINIMAL
	if (*options->clientid) {
		iface->clientid = xmalloc(options->clientid[0] + 1);
		memcpy(iface->clientid,
		       options->clientid, options->clientid[0] + 1);
	} else if (options->options & DHCPCD_CLIENTID) {
		if (options->options & DHCPCD_DUID) {
			duid = xmalloc(DUID_LEN);
			if ((len = get_duid(duid, iface)) == 0)
				logger(LOG_ERR, "get_duid: %s",
				       strerror(errno));
		}

		if (len > 0) {
			logger(LOG_INFO, "DUID = %s",
			       hwaddr_ntoa(duid, len));

			iface->clientid = xmalloc(len + 6);
			iface->clientid[0] = len + 5;
			iface->clientid[1] = 255; /* RFC 4361 */

			/* IAID is 4 bytes, so if the iface name is 4 bytes
			 * or less, use it */
			ul = strlen(iface->name);
			if (ul < 5) {
				memcpy(iface->clientid + 2, iface->name, ul);
				if (ul < 4)
					memset(iface->clientid + 2 + ul,
					       0, 4 - ul);
			} else {
				/* Name isn't 4 bytes, so use the index */
				ul = htonl(if_nametoindex(iface->name));
				memcpy(iface->clientid + 2, &ul, 4);
			}

			memcpy(iface->clientid + 6, duid, len);
			free(duid);
		}
		if (len == 0) {
			len = iface->hwlen + 1;
			iface->clientid = xmalloc(len + 1);
			iface->clientid[0] = len;
			iface->clientid[1] = iface->family;
			memcpy(iface->clientid + 2, iface->hwaddr, iface->hwlen);
		}
	}
#endif
	if (state->options & DHCPCD_LINK) {
		open_link_socket(iface);
		if (carrier_status(iface->name) == 0) {
			if (!(state->options & DHCPCD_BACKGROUND))
				logger(LOG_INFO, "waiting for carrier");
			state->state = STATE_CARRIER;
			tv.tv_sec = options->timeout;
			tv.tv_usec = 0;
			get_time(&state->start);
			timeradd(&state->start, &tv, &state->stop);
		}
	}

	return 0;
}

static int 
do_socket(struct if_state *state, int mode)
{
	if (state->interface->raw_fd != -1) {
		close(state->interface->raw_fd);
		state->interface->raw_fd = -1;
	}
	if (mode == SOCKET_CLOSED) {
		if (state->interface->udp_fd != -1) {
			close(state->interface->udp_fd);
			state->interface->udp_fd = -1;
		}
#ifdef ENABLE_ARP
		if (state->interface->arp_fd != -1) {
			close(state->interface->arp_fd);
			state->interface->arp_fd = -1;
		}
#endif
	}

	if (mode == SOCKET_OPEN &&
	    state->interface->udp_fd == -1 &&
	    state->lease.addr.s_addr != 0 &&
	    open_udp_socket(state->interface) == -1)
		logger(LOG_ERR, "open_udp_socket: %s", strerror(errno));

	if (mode == SOCKET_OPEN) 
		if (open_socket(state->interface, ETHERTYPE_IP) == -1) {
			logger(LOG_ERR, "open_socket: %s", strerror(errno));
			return -1;
		}
	state->socket = mode;
	return 0;
}

static ssize_t
send_message(struct if_state *state, int type, const struct options *options)
{
	struct dhcp_message *dhcp;
	uint8_t *udp;
	ssize_t len;
	ssize_t r;
	struct in_addr from;
	struct in_addr to;
	in_addr_t a = 0;

	logger(LOG_DEBUG, "sending %s with xid 0x%x",
	       get_dhcp_op(type), state->xid);
	state->messages++;
	if (state->messages < 0)
		state->messages = INT_MAX;
	/* If we couldn't open a UDP port for our IP address
	 * then we cannot renew.
	 * This could happen if our IP was pulled out from underneath us. */
	if (state->interface->udp_fd == -1) {
		a = state->interface->addr.s_addr;
		state->interface->addr.s_addr = 0;
	}
	len = make_message(&dhcp, state->interface, &state->lease, state->xid,
			   type, options);
	if (state->interface->udp_fd == -1)
		state->interface->addr.s_addr = a;
	from.s_addr = dhcp->ciaddr;
	if (from.s_addr)
		to.s_addr = state->lease.server.s_addr;
	else
		to.s_addr = 0;
	if (to.s_addr) {
		r = send_packet(state->interface, to, (uint8_t *)dhcp, len);
		if (r == -1)
			logger(LOG_ERR, "send_packet: %s", strerror(errno));
	} else {
		len = make_udp_packet(&udp, (uint8_t *)dhcp, len, from, to);
		free(dhcp);
		r = send_raw_packet(state->interface, ETHERTYPE_IP, udp, len);
		free(udp);
		if (r == -1)
			logger(LOG_ERR, "send_raw_packet: %s", strerror(errno));
	}

	/* Failed to send the packet? Return to the init state */
	if (r == -1) {
		state->state = STATE_INIT;
		timerclear(&state->timeout);
		timerclear(&state->stop);
		do_socket(state, SOCKET_CLOSED);
	}
	return r;
}

static void
drop_config(struct if_state *state, const char *reason,
	    const struct options *options)
{
	configure(state->interface, reason, NULL, state->new,
		  &state->lease, options, 0);
	free(state->old);
	state->old = NULL;
	free(state->new);
	state->new = NULL;

	state->lease.addr.s_addr = 0;
}

static int
wait_for_packet(struct if_state *state)
{
	struct pollfd fds[3]; /* iface, arp, signal */
	int retval, nfds = 0;
	time_t timeout = 0;
	struct timeval now, d, *ref;
	static time_t last_stop_sec = 0, last_timeout_sec = 0;
	static long int last_stop_usec = 0, last_timeout_usec = 0;

	/* We always listen to signals */
	fds[nfds].fd = state->signal_fd;
	fds[nfds].events = POLLIN;
	nfds++;
	/* And links */
	if (state->interface->link_fd != -1) {
		fds[nfds].fd = state->interface->link_fd;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	ref = NULL;
	if (timerisset(&state->stop) &&
	    timercmp(&state->stop, &now, >))
		ref = &state->stop;
	if (timerisset(&state->timeout) &&
	    timercmp(&state->timeout, &now, >) &&
	    (!ref || timercmp(&state->timeout, ref, <)))
		ref = &state->timeout;

	if (state->lease.leasetime == ~0U &&
	    state->state == STATE_BOUND)
	{
		logger(LOG_DEBUG, "waiting for infinity");
		timeout = INFTIM;
	} else if (state->state == STATE_CARRIER && !ref)
		timeout = INFTIM;
	else {
		if (state->interface->raw_fd != -1) {
			fds[nfds].fd = state->interface->raw_fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}
#ifdef ENABLE_ARP
		if (state->interface->arp_fd != -1) {
			fds[nfds].fd = state->interface->arp_fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}
#endif
	}

wait_again:
	get_time(&now);
	if (timeout != INFTIM) {
		if (!ref)
			return 0;
		timersub(ref, &now, &d);
		/* This should be safe and not overflow as the biggest
		 * diff is uint32_t seconds from the DHCP message. */
		timeout = d.tv_sec * 1000 + (d.tv_usec + 999) / 1000;
		/* Only report waiting time if changed */
		if (last_stop_sec != state->stop.tv_sec ||
		    last_stop_usec != state->stop.tv_usec ||
		    last_timeout_sec != state->timeout.tv_sec ||
		    last_timeout_usec != state->timeout.tv_usec)
		{
			logger(LOG_DEBUG, "waiting for %0.2f seconds",
			       (float)timeout / 1000);
			last_stop_sec = state->stop.tv_sec;
			last_stop_usec = state->stop.tv_usec;
			last_timeout_sec = state->timeout.tv_sec;
			last_timeout_usec = state->timeout.tv_usec;
		}
		/* However, we could overflow INT_MAX and annoy poll. */
		if (timeout < 0 || timeout > INT_MAX)
			timeout = INT_MAX;
	}

	retval = poll(fds, nfds, timeout);
	if (timeout != INFTIM) {
		get_time(&now);
		if (timercmp(&now, &state->timeout, >))
			timerclear(&state->timeout);
	}
	if (retval == -1) {
		if (errno == EINTR)
			return 0;
		logger(LOG_ERR, "poll: %s", strerror(errno));
	} else if (retval == 0) {
		/* If our timeout overflowed, wait again. */
		if (timeout == INT_MAX)
			goto wait_again;
	} else if (!(fds[0].revents & POLLIN)) {
		/* Check if any of the fd's have an error
		 * if there is no data on the signal fd. */
		while (--nfds > 0) {
			if (fds[nfds].revents & POLLERR) {
				logger(LOG_ERR, "error on fd %d", fds[nfds].fd);
				do_socket(state, SOCKET_CLOSED);
				state->state = STATE_RENEW_REQUESTED;
				timerclear(&state->timeout);
				timerclear(&state->stop);
				return 0;
			}
		}
	}
	return retval;
}

static int
handle_signal(int sig, struct if_state *state,  const struct options *options)
{
	struct dhcp_lease *lease = &state->lease;

	switch (sig) {
	case SIGINT:
		logger(LOG_INFO, "received SIGINT, stopping");
		if (!(state->options & DHCPCD_PERSISTENT))
			drop_config(state, "STOP", options);
		return -1;
	case SIGTERM:
		logger(LOG_INFO, "received SIGTERM, stopping");
		if (!(state->options & DHCPCD_PERSISTENT))
			drop_config(state, "STOP", options);
		return -1;
	case SIGALRM:
		logger(LOG_INFO, "received SIGALRM, renewing lease");
		do_socket(state, SOCKET_CLOSED);
		state->state = STATE_RENEW_REQUESTED;
		timerclear(&state->timeout);
		timerclear(&state->stop);
		return 0;
	case SIGHUP:
		logger(LOG_INFO, "received SIGHUP, releasing lease");
		if (lease->addr.s_addr &&
		    !IN_LINKLOCAL(ntohl(lease->addr.s_addr)))
		{
			do_socket(state, SOCKET_OPEN);
			state->xid = arc4random();
			send_message(state, DHCP_RELEASE, options);
			do_socket(state, SOCKET_CLOSED);
		}
		drop_config(state, "RELEASE", options);
		return -1;
	default:
		logger (LOG_ERR,
			"received signal %d, but don't know what to do with it",
			sig);
	}

	return 0;
}

static int bind_dhcp(struct if_state *state, const struct options *options)
{
	struct interface *iface = state->interface;
	struct dhcp_lease *lease = &state->lease;
	const char *reason = NULL;
	struct timeval tv;
	int retval;

	free(state->old);
	state->old = state->new;
	state->new = state->offer;
	state->offer = NULL;
	state->messages = 0;
#ifdef ENABLE_ARP
	state->conflicts = 0;
	state->defend = 0;
#endif

	if (options->options & DHCPCD_INFORM) {
		if (options->request_address.s_addr != 0)
			lease->addr.s_addr = options->request_address.s_addr;
		else
			lease->addr.s_addr = iface->addr.s_addr;
		logger(LOG_INFO, "received approval for %s",
		       inet_ntoa(lease->addr));
		state->state = STATE_BOUND;
		state->lease.leasetime = ~0U;
		reason = "INFORM";
	} else if (IN_LINKLOCAL(htonl(state->new->yiaddr))) {
		get_lease(lease, state->new);
		logger(LOG_INFO, "using IPv4LL address %s",
		       inet_ntoa(lease->addr));
		state->state = STATE_INIT;
		timerclear(&state->timeout);
		reason = "IPV4LL";
	} else {
		if (gettimeofday(&tv, NULL) == 0)
			lease->leasedfrom = tv.tv_sec;

		get_lease(lease, state->new);
		if (lease->frominfo)
			reason = "TIMEOUT";

		if (lease->leasetime == ~0U) {
			lease->renewaltime = lease->rebindtime = lease->leasetime;
			state->timeout.tv_sec = 1; /* So we wait for infinity */
			logger(LOG_INFO, "leased %s for infinity",
			       inet_ntoa(lease->addr));
			state->state = STATE_BOUND;
		} else {
			logger(LOG_INFO, "leased %s for %u seconds",
			       inet_ntoa(lease->addr), lease->leasetime);

			if (lease->rebindtime >= lease->leasetime) {
				lease->rebindtime = lease->leasetime * T2;
				logger(LOG_ERR,
				       "rebind time greater than lease "
				       "time, forcing to %u seconds",
				       lease->rebindtime);
			}

			if (lease->renewaltime > lease->rebindtime) {
				lease->renewaltime = lease->leasetime * T1;
				logger(LOG_ERR,
				       "renewal time greater than rebind time, "
				       "forcing to %u seconds",
				       lease->renewaltime);
			}

			if (!lease->renewaltime) {
				lease->renewaltime = lease->leasetime * T1;
				logger(LOG_INFO,
				       "no renewal time supplied, assuming %d seconds",
				       lease->renewaltime);
			} else
				logger(LOG_DEBUG, "renew in %u seconds",
				       lease->renewaltime);

			if (!lease->rebindtime) {
				lease->rebindtime = lease->leasetime * T2;
				logger(LOG_INFO,
				       "no rebind time supplied, assuming %d seconds",
				       lease->rebindtime);
			} else
				logger(LOG_DEBUG, "rebind in %u seconds",
				       lease->rebindtime);

			tv.tv_sec = lease->renewaltime;
			tv.tv_usec = 0;
			get_time(&state->timeout);
			timeradd(&state->timeout, &tv, &state->timeout);
		}
		state->state = STATE_BOUND;
	}

	state->xid = 0;
	timerclear(&state->stop);
	if (!reason) {
		if (state->old) {
			if (state->old->yiaddr == state->new->yiaddr &&
			    lease->server.s_addr)
				reason = "RENEW";
			else
				reason = "REBIND";
		} else
			reason = "BOUND";
	}
	retval = configure(iface, reason, state->new, state->old,
			   &state->lease, options, 1);
	if (retval != 0)
		return -1;
	return daemonise(state, options);
}

static int
handle_timeout_fail(struct if_state *state, const struct options *options)
{
	struct dhcp_lease *lease = &state->lease;
	struct interface *iface = state->interface;
	int gotlease = -1;
	const char *reason = NULL;
	struct timeval tv;

	timerclear(&tv);
	/* Clear our timers and counters as we've failed.
	 * We'll either abort or move to another state with new timers */
	timerclear(&state->timeout);
	timerclear(&state->stop);
	state->messages = 0;

	switch (state->state) {
	case STATE_CARRIER:     /* FALLTHROUGH */
	case STATE_DISCOVERING: /* FALLTHROUGH */
	case STATE_REQUESTING:
		if (IN_LINKLOCAL(ntohl(iface->addr.s_addr))) {
			if (!(state->options & DHCPCD_DAEMONISED))
				logger(LOG_ERR, "timed out");
		} else {
			if (iface->addr.s_addr != 0 &&
			    !(state->options & DHCPCD_INFORM))
				logger(LOG_ERR, "lost lease");
			else
				logger(LOG_ERR, "timed out");
		}
		do_socket(state, SOCKET_CLOSED);
		if (state->options & DHCPCD_INFORM ||
		    state->options & DHCPCD_TEST)
			return -1;

		if (state->state != STATE_CARRIER &&
		    (state->options & DHCPCD_IPV4LL ||
		     state->options & DHCPCD_LASTLEASE))
			gotlease = get_old_lease(state);

#ifdef ENABLE_IPV4LL
		if (state->state != STATE_CARRIER &&
		    state->options & DHCPCD_IPV4LL &&
		    gotlease != 0)
		{
			logger(LOG_INFO, "probing for an IPV4LL address");
			free(state->offer);
			state->offer = ipv4ll_get_dhcp(0);
			gotlease = 0;
		}
#endif

#ifdef ENABLE_ARP
		if (gotlease == 0 &&
		    state->offer->yiaddr != iface->addr.s_addr)
		{
			state->state = STATE_PROBING;
			state->claims = 0;
			state->probes = 0;
			state->conflicts = 0;
			return 0;
		}
#endif

		if (gotlease == 0)
			return bind_dhcp(state, options);

		if (iface->addr.s_addr)
			reason = "EXPIRE";
		else
			reason = "FAIL";
		drop_config(state, reason, options);
		if (!(state->options & DHCPCD_DAEMONISED) &&
		    (state->options & DHCPCD_DAEMONISE))
			return -1;
		if (state->state == STATE_CARRIER)
			return 0;
		state->state = STATE_INIT;
		break;
	
	case STATE_RENEWING:
		logger(LOG_ERR, "failed to renew, attempting to rebind");
		lease->addr.s_addr = 0;
		state->state = STATE_REBINDING;
		if (lease->server.s_addr == 0)
			tv.tv_sec = options->timeout;
		else
			tv.tv_sec = lease->rebindtime - lease->renewaltime;
		break;
	case STATE_REBINDING:
		logger(LOG_ERR, "failed to rebind, attempting to discover");
		reason = "EXPIRE";
		drop_config(state, reason, options);
		state->state = STATE_INIT;
		break;
	default:
		logger(LOG_DEBUG, "handle_timeout_failed: invalid state %d",
		       state->state);
	}

	get_time(&state->start);
	if (timerisset(&tv))
		timeradd(&state->start, &tv, &state->stop);

	/* This effectively falls through into the handle_timeout funtion */
	return 0;
}

static int
handle_timeout(struct if_state *state, const struct options *options)
{
	struct dhcp_lease *lease = &state->lease;
	struct interface *iface = state->interface;
	int i = 0;
	struct timeval tv;
#ifdef ENABLE_ARP
	struct in_addr addr;

	timerclear(&tv);
	switch (state->state) {
#ifdef ENABLE_IPV4LL
	case STATE_INIT_IPV4LL:
		logger(LOG_INFO, "probing for an IPV4LL address");
		state->state = STATE_PROBING;
		free(state->offer);
		state->offer = ipv4ll_get_dhcp(0);
		state->claims = 0;
		state->probes = 0;
		/* FALLTHROUGH */
#endif
	case STATE_PROBING:
		if (iface->arp_fd == -1)
			open_socket(iface, ETHERTYPE_ARP);
		if (state->probes < PROBE_NUM) {
			if (state->probes == 0) {
				addr.s_addr = state->offer->yiaddr;
				logger(LOG_INFO, "checking %s is available"
				       " on attached networks",
				       inet_ntoa(addr));
			}
			state->probes++;
			logger(LOG_DEBUG, "sending ARP probe #%d",
			       state->probes);
			if (state->probes < PROBE_NUM) 
				tv.tv_usec = (arc4random() %
					      (PROBE_MAX_U - PROBE_MIN_U)) +
					     PROBE_MIN_U;
			else
				tv.tv_sec = ANNOUNCE_WAIT;
			i = send_arp(iface, ARPOP_REQUEST, 0, state->offer->yiaddr);
			if (i == -1)
				logger(LOG_ERR, "send_arp: %s", strerror(errno));
			i = 0;
		} else {
			/* We've waited for ANNOUNCE_WAIT after the final probe
			 * so the address is now ours */
			i = bind_dhcp(state, options);
			state->state = STATE_ANNOUNCING;
			tv.tv_sec = ANNOUNCE_INTERVAL;
		}
		break;
	case STATE_ANNOUNCING:
		if (state->claims < ANNOUNCE_NUM) {
			state->claims++;
			logger(LOG_DEBUG, "sending ARP announce #%d",
			       state->claims);
			i = send_arp(iface, ARPOP_REQUEST,
				     state->new->yiaddr, state->new->yiaddr);
			if (i == -1)
				logger(LOG_ERR, "send_arp: %s", strerror(errno));
			if (state->claims < ANNOUNCE_NUM)
				tv.tv_sec = ANNOUNCE_INTERVAL;
			else if (IN_LINKLOCAL(htonl(lease->addr.s_addr))) {
				/* We should pretend to be at the end of the DHCP negotation cycle */
				state->state = STATE_INIT;
				state->messages = DHCP_MAX / DHCP_BASE;
				state->probes = 0;
				state->claims = 0;
				timerclear(&state->stop);
				goto dhcp_timeout;
			} else {
				state->state = STATE_BOUND;
				tv.tv_sec = lease->renewaltime -
					(ANNOUNCE_INTERVAL * ANNOUNCE_NUM);
				close(iface->arp_fd);
				iface->arp_fd = -1;
			}
			i = 0;
		}
		break;
	}
	if (timerisset(&tv)) {
		timerclear(&state->stop);
		get_time(&state->timeout);
		timeradd(&state->timeout, &tv, &state->timeout);
		return i;
	}
#endif

	if (timerisset(&state->stop)) {
		get_time(&state->timeout);
		if (timercmp(&state->timeout, &state->stop, >))
			return handle_timeout_fail(state, options);
	}
	timerclear(&tv);

	switch (state->state) {
	case STATE_INIT:  /* FALLTHROUGH */
	case STATE_BOUND: /* FALLTHROUGH */
	case STATE_RENEW_REQUESTED:
		up_interface(iface->name);
		do_socket(state, SOCKET_OPEN);
		state->xid = arc4random();
		state->nakoff = 1;
		iface->start_uptime = uptime();
		get_time(&state->start);
		timerclear(&state->stop);
	}

	switch(state->state) {
	case STATE_CARRIER:
		logger(LOG_INFO, "waiting for carrier");
		get_time(&state->start);
		tv.tv_sec = options->timeout;
		timeradd(&state->start, &tv, &state->stop);
		return 0;
	case STATE_INIT:
		if (!(state->state && DHCPCD_DAEMONISED) &&
		    options->timeout &&		
		    !IN_LINKLOCAL(htonl(iface->addr.s_addr)))
		{
			get_time(&state->start);
			tv.tv_sec = options->timeout;
			timeradd(&state->start, &tv, &state->stop);
		}
		if (lease->addr.s_addr == 0 ||
		    IN_LINKLOCAL(ntohl(iface->addr.s_addr)))
		{
			logger(LOG_INFO, "broadcasting for a lease");
			state->state = STATE_DISCOVERING;
		} else if (state->options & DHCPCD_INFORM) {
			logger(LOG_INFO, "broadcasting inform for %s",
			       inet_ntoa(lease->addr));
			state->state = STATE_REQUESTING;
		} else {
			logger(LOG_INFO, "broadcasting for a lease of %s",
			       inet_ntoa(lease->addr));
			state->state = STATE_REQUESTING;
		}
		break;
	case STATE_RENEW_REQUESTED:
		/* If a renew was requested (ie, didn't timeout)
		 * we need to remove the server address so we enter the
		 * INIT-REBOOT state correctly. */
		lease->server.s_addr = 0;
		state->messages = 0;
#ifdef ENABLE_IPV4LL
		if (IN_LINKLOCAL(ntohl(lease->addr.s_addr))) {
			state->state = STATE_PROBING;
			free(state->offer);
			state->offer = read_lease(state->interface);
			state->probes = 0;
			state->claims = 0;
			timerclear(&state->timeout);
			return 0;
		}
#endif
		if (lease->addr.s_addr) {
			logger(LOG_INFO, "renewing lease of %s",
			       inet_ntoa(lease->addr));
			state->state = STATE_RENEWING;
			tv.tv_sec = options->timeout;
			timeradd(&state->start, &tv, &state->stop);
			break;
		}
		/* FALLTHROUGH */
	case STATE_BOUND:
		if (lease->addr.s_addr == 0 ||
		    IN_LINKLOCAL(ntohl(lease->addr.s_addr)))
		{
			lease->addr.s_addr = 0;
			state->state = STATE_INIT;
			timerclear(&state->timeout);
			return 0;
		}
		logger(LOG_INFO, "renewing lease of %s",inet_ntoa(lease->addr));
		state->state = STATE_RENEWING;
		tv.tv_sec = lease->rebindtime - lease->renewaltime;
		timeradd(&state->start, &tv, &state->stop);
		break;
	}

	switch (state->state) {
	case STATE_DISCOVERING:
		send_message(state, DHCP_DISCOVER, options);
		break;
	case STATE_REQUESTING:
		if (state->options & DHCPCD_INFORM) {
			send_message(state, DHCP_INFORM, options);
			break;
		}
		/* FALLTHROUGH */
	case STATE_RENEWING:   /* FALLTHROUGH */
	case STATE_REBINDING:
		send_message(state, DHCP_REQUEST, options);
		break;
	}

#ifdef ENABLE_ARP
dhcp_timeout:
#endif
	get_time(&state->timeout);
	tv.tv_sec = DHCP_BASE;
	for (i = 1; i < state->messages; i++) {
		tv.tv_sec *= 2;
		if (tv.tv_sec > DHCP_MAX) {
			tv.tv_sec = DHCP_MAX;
			break;
		}
	}
	tv.tv_sec += DHCP_RAND_MIN;
	tv.tv_usec = arc4random() % (DHCP_RAND_MAX_U - DHCP_RAND_MIN_U);
	timeradd(&state->timeout, &tv, &state->timeout);
	return 0;
}

static int
handle_dhcp(struct if_state *state, struct dhcp_message **dhcpp,
	    const struct options *options)
{
	struct timespec ts;
	struct dhcp_message *dhcp = *dhcpp;
	struct interface *iface = state->interface;
	struct dhcp_lease *lease = &state->lease;
	char *addr;
	struct in_addr saddr;
	uint8_t type;
	int r;

	if (get_option_uint8(&type, dhcp, DHCP_MESSAGETYPE) == -1) {
		logger(LOG_ERR, "no DHCP type in message");
		return -1;
	}

	/* reset the message counter */
	state->messages = 0;

	/* We should restart on a NAK */
	if (type == DHCP_NAK) {
		addr = get_option_string(dhcp, DHCP_MESSAGE);
		logger(LOG_WARNING, "received NAK: %s", addr);
		free(addr);
		state->state = STATE_INIT;
		timerclear(&state->timeout);
		timerclear(&state->stop);
		lease->addr.s_addr = 0;

		/* If we constantly get NAKS then we should slowly back off */
		if (state->nakoff > 0) {
			logger(LOG_DEBUG, "sleeping for %lu seconds",
			       (unsigned long)state->nakoff);
			ts.tv_sec = state->nakoff;
			ts.tv_nsec = 0;
			state->nakoff *= 2;
			if (state->nakoff > NAKOFF_MAX)
				state->nakoff = NAKOFF_MAX;
			nanosleep(&ts, NULL);
		}

		return 0;
	}

	/* No NAK, so reset the backoff */
	state->nakoff = 1;

	if (type == DHCP_OFFER && state->state == STATE_DISCOVERING) {
		lease->addr.s_addr = dhcp->yiaddr;
		addr = xstrdup(inet_ntoa(lease->addr));
		r = get_option_addr(&lease->server.s_addr, dhcp, DHCP_SERVERID);
		if (dhcp->servername[0] && r == 0)
			logger(LOG_INFO, "offered %s from %s `%s'",
			       addr, inet_ntoa(lease->server),
			       dhcp->servername);
		else if (r == 0)
			logger(LOG_INFO, "offered %s from %s",
			       addr, inet_ntoa(lease->server));
		else
			logger(LOG_INFO, "offered %s", addr);
		free(addr);

		if (state->options & DHCPCD_TEST) {
			exec_script(options, iface->name, "TEST", dhcp, NULL);
			free(dhcp);
			return 0;
		}

		free(dhcp);
		state->state = STATE_REQUESTING;
		timerclear(&state->timeout);
		return 0;
	}

	if (type == DHCP_OFFER) {
		saddr.s_addr = dhcp->yiaddr;
		logger(LOG_INFO, "got subsequent offer of %s, ignoring ",
		       inet_ntoa(saddr));
		free(dhcp);
		return 0;
	}

	/* We should only be dealing with acks */
	if (type != DHCP_ACK) {
		logger(LOG_ERR, "%d not an ACK or OFFER", type);
		free(dhcp);
		return 0;
	}
	    
	switch (state->state) {
	case STATE_RENEW_REQUESTED:
	case STATE_REQUESTING:
	case STATE_RENEWING:
	case STATE_REBINDING:
		if (!(state->options & DHCPCD_INFORM)) {
			saddr.s_addr = dhcp->yiaddr;
			logger(LOG_INFO, "lease of %s acknowledged",
			       inet_ntoa(saddr));
		}
		break;
	default:
		logger(LOG_ERR, "wrong state %d", state->state);
	}

	do_socket(state, SOCKET_CLOSED);
	free(state->offer);
	state->offer = dhcp;
	*dhcpp = NULL;

#ifdef ENABLE_ARP
	if (state->options & DHCPCD_ARP &&
	    iface->addr.s_addr != state->offer->yiaddr)
	{
		state->state = STATE_PROBING;
		timerclear(&state->timeout);
		state->claims = 0;
		state->probes = 0;
		state->conflicts = 0;
		timerclear(&state->stop);
		return 0;
	}
#endif

	return bind_dhcp(state, options);		
}

static int
handle_dhcp_packet(struct if_state *state, const struct options *options)
{
	uint8_t *packet;
	struct interface *iface = state->interface;
	struct dhcp_message *dhcp;
	const uint8_t *pp;
	uint8_t *p;
	ssize_t bytes;
	int retval = -1;

	/* We loop through until our buffer is empty.
	 * The benefit is that if we get >1 DHCP packet in our buffer and
	 * the first one fails for any reason, we can use the next. */
	packet = xmalloc(udp_dhcp_len);
	dhcp = xmalloc(sizeof(*dhcp));
	for(;;) {
		bytes = get_raw_packet(iface, ETHERTYPE_IP,
				       packet, udp_dhcp_len);
		if (bytes == 0) {
			retval = 0;
			break;
		}
		if (bytes == -1)
			break;
		if (valid_udp_packet(packet) == -1)
			continue;
		bytes = get_udp_data(&pp, packet);
		if ((size_t)bytes > sizeof(*dhcp)) {
			logger(LOG_ERR, "packet greater than DHCP size");
			continue;
		}
		memcpy(dhcp, pp, bytes);
		if (dhcp->cookie != htonl(MAGIC_COOKIE)) {
			logger(LOG_DEBUG, "bogus cookie, ignoring");
			continue;
		}
		if (state->xid != dhcp->xid) {
			logger(LOG_DEBUG,
			       "ignoring packet with xid 0x%x as"
			       " it's not ours (0x%x)",
			       dhcp->xid, state->xid);
			continue;
		}
		/* We should ensure that the packet is terminated correctly
		 * if we have space for the terminator */
		if ((size_t)bytes < sizeof(struct dhcp_message)) {
			p = (uint8_t *)dhcp + bytes - 1;
			while (p > dhcp->options && *p == DHCP_PAD)
				p--;
			if (*p != DHCP_END)
				*++p = DHCP_END;
		}
		free(packet);
		if (handle_dhcp(state, &dhcp, options) == 0) {
			/* Fake the fact we forked so we return 0 to userland */
			if (state->options & DHCPCD_TEST)
				state->options |= DHCPCD_FORKED;
			else
				return 0;
		}
		if (state->options & DHCPCD_FORKED)
			return -1;
	}

	free(packet);
	free(dhcp);
	return retval;
}

#ifdef ENABLE_ARP
static int
handle_arp_packet(struct if_state *state)
{
	struct arphdr reply;
	uint32_t reply_s;
	uint32_t reply_t;
	uint8_t arp_reply[sizeof(reply) + 2 * sizeof(reply_s) + 2 * HWADDR_LEN];
	uint8_t *hw_s, *hw_t;
	ssize_t bytes;
	struct interface *iface = state->interface;

	state->fail.s_addr = 0;
	for(;;) {
		bytes = get_raw_packet(iface, ETHERTYPE_ARP,
				       arp_reply, sizeof(arp_reply));
		if (bytes == 0 || bytes == -1)
			return (int)bytes;
		/* We must have a full ARP header */
		if ((size_t)bytes < sizeof(reply))
			continue;
		memcpy(&reply, arp_reply, sizeof(reply));
		/* Protocol must be IP. */
		if (reply.ar_pro != htons(ETHERTYPE_IP))
			continue;
		if (reply.ar_pln != sizeof(reply_s))
			continue;
		/* Only these types are recognised */
		if (reply.ar_op != htons(ARPOP_REPLY) &&
		    reply.ar_op != htons(ARPOP_REQUEST))
			continue;

		/* Get pointers to the hardware addreses */
		hw_s = arp_reply + sizeof(reply);
		hw_t = hw_s + reply.ar_hln + reply.ar_pln;
		/* Ensure we got all the data */
		if ((hw_t + reply.ar_hln + reply.ar_pln) - arp_reply > bytes)
			continue;
		/* Ignore messages from ourself */
		if (reply.ar_hln == iface->hwlen &&
		    memcmp(hw_s, iface->hwaddr, iface->hwlen) == 0)
			continue;
		/* Copy out the IP addresses */
		memcpy(&reply_s, hw_s + reply.ar_hln, reply.ar_pln);
		memcpy(&reply_t, hw_t + reply.ar_hln, reply.ar_pln);

		/* Check for conflict */
		if (state->offer && 
		    (reply_s == state->offer->yiaddr ||
		     (reply_s == 0 && reply_t == state->offer->yiaddr)))
			state->fail.s_addr = state->offer->yiaddr;

		/* Handle IPv4LL conflicts */
		if (IN_LINKLOCAL(htonl(iface->addr.s_addr)) &&
		    (reply_s == iface->addr.s_addr ||
		     (reply_s == 0 && reply_t == iface->addr.s_addr)))
			state->fail.s_addr = iface->addr.s_addr;

		if (state->fail.s_addr) {
			logger(LOG_ERR, "hardware address %s claims %s",
			       hwaddr_ntoa((unsigned char *)hw_s,
					   (size_t)reply.ar_hln),
			       inet_ntoa(state->fail));
			errno = EEXIST;
			return -1;
		}
	}
}

static int
handle_arp_fail(struct if_state *state, const struct options *options)
{
	struct timeval tv;
	time_t up;

	if (IN_LINKLOCAL(htonl(state->fail.s_addr))) {
		if (state->fail.s_addr == state->interface->addr.s_addr) {
			up = uptime();
			if (state->defend + DEFEND_INTERVAL > up) {
				drop_config(state, "FAIL", options);
				state->conflicts = -1;
				/* drop through to set conflicts to 0 */
			} else {
				state->defend = up;
				return 0;
			}
		}
		do_socket(state, SOCKET_CLOSED);
		state->conflicts++;
		state->state = STATE_INIT_IPV4LL;
		timerclear(&state->stop);
		if (state->conflicts > MAX_CONFLICTS)
			tv.tv_sec = RATE_LIMIT_INTERVAL;
		else
			tv.tv_sec = PROBE_WAIT;
		tv.tv_usec = 0;
		get_time(&state->timeout);
		timeradd(&state->timeout, &tv, &state->timeout);
		return 0;
	}

	do_socket(state, SOCKET_OPEN);
	send_message(state, DHCP_DECLINE, options);
	do_socket(state, SOCKET_CLOSED);
	state->state = STATE_INIT;
	get_time(&state->timeout);
	tv.tv_sec = DHCP_ARP_FAIL;
	tv.tv_usec = 0;
	timeradd(&state->timeout, &tv, &state->timeout);
	return 0;
}
#endif

static int
handle_link(struct if_state *state)
{
	int retval;

	retval = link_changed(state->interface);
	if (retval == -1) {
		logger(LOG_ERR, "link_changed: %s", strerror(errno));
		return -1;
	}
	if (retval == 0)
		return 0;
	switch (carrier_status(state->interface->name)) {
	case -1:
		logger(LOG_ERR, "carrier_status: %s", strerror(errno));
		return -1;
	case 0:
		logger(LOG_INFO, "carrier lost");
		state->state = STATE_CARRIER;
		do_socket(state, SOCKET_CLOSED);
		break;
	default:
		logger(LOG_INFO, "carrier acquired");
		state->state = STATE_RENEW_REQUESTED;
		timerclear(&state->stop);
		break;
	}
	timerclear(&state->timeout);
	return 0;
}

int
dhcp_run(const struct options *options, int *pid_fd)
{
	struct interface *iface;
	struct if_state *state = NULL;
	int retval = -1;
	int sig;

	iface = read_interface(options->interface, options->metric);
	if (!iface) {
		logger(LOG_ERR, "read_interface: %s", strerror(errno));
		goto eexit;
	}

	logger(LOG_INFO, "hardware address = %s",
	       hwaddr_ntoa(iface->hwaddr, iface->hwlen));

	state = xzalloc(sizeof(*state));
	state->pid_fd = pid_fd;
	state->interface = iface;

	if (client_setup(state, options) == -1)
		goto eexit;
	if (signal_init() == -1)
		goto eexit;
	if (signal_setup() == -1)
		goto eexit;

	state->signal_fd = signal_fd();

	if (state->options & DHCPCD_BACKGROUND)
		if (daemonise(state, options) == -1)
			goto eexit;

	for (;;) {
		retval = wait_for_packet(state);

		/* We should always handle our signals first */
		if ((sig = (signal_read(state->signal_fd))) != -1) {
			retval = handle_signal(sig, state, options);
		} else if (retval == 0)
			retval = handle_timeout(state, options);
		else if (retval == -1) {
			if (errno == EINTR)
				/* The interupt will be handled above */
				retval = 0;
		} else if (retval > 0) {
			if (fd_hasdata(iface->link_fd) == 1)
				retval = handle_link(state);
			else if (fd_hasdata(iface->raw_fd) == 1)
				retval = handle_dhcp_packet(state, options);
#ifdef ENABLE_ARP
			else if (fd_hasdata(iface->arp_fd) == 1) {
				retval = handle_arp_packet(state);
				if (retval == -1)
					retval = handle_arp_fail(state, options);
			}
#endif
			else
				retval = 0;
		}

		if (retval != 0)
			break;
	}

eexit:
	if (iface) {
		do_socket(state, SOCKET_CLOSED);
		if (iface->link_fd != -1)
		    close(iface->link_fd);
		free_routes(iface->routes);
		free(iface->clientid);
		free(iface->buffer);
		free(iface);
	}

	if (state) {
		if (state->options & DHCPCD_FORKED)
			retval = 0;
		if (state->options & DHCPCD_DAEMONISED)
			unlink(options->pidfile);
		free(state->offer);
		free(state->new);
		free(state->old);
		free(state);
	}

	return retval;
}
