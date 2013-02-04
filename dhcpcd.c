/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2013 Roy Marples <roy@marples.name>
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

const char copyright[] = "Copyright (c) 2006-2013 Roy Marples";

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#include <net/route.h> /* For RTM_CHGADDR */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include "arp.h"
#include "config.h"
#include "common.h"
#include "control.h"
#include "dhcpcd.h"
#include "dhcp6.h"
#include "eloop.h"
#include "if-options.h"
#include "if-pref.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipv6ns.h"
#include "ipv6rs.h"
#include "net.h"
#include "platform.h"
#include "script.h"
#include "signals.h"

/* Wait N nanoseconds between sending a RELEASE and dropping the address.
 * This gives the kernel enough time to actually send it. */
#define RELEASE_DELAY_S		0
#define RELEASE_DELAY_NS	10000000

char vendor[VENDORCLASSID_MAX_LEN];
int pidfd = -1;
struct interface *ifaces = NULL;
struct if_options *if_options = NULL;
int ifac = 0;
char **ifav = NULL;
int ifdc = 0;
char **ifdv = NULL;

sigset_t dhcpcd_sigset;

static char *cffile;
static char *pidfile;
static int linkfd = -1;
static char **ifv;
static int ifc;
static char **margv;
static int margc;

static pid_t
read_pid(void)
{
	FILE *fp;
	pid_t pid;

	if ((fp = fopen(pidfile, "r")) == NULL) {
		errno = ENOENT;
		return 0;
	}
	if (fscanf(fp, "%d", &pid) != 1)
		pid = 0;
	fclose(fp);
	return pid;
}

static void
usage(void)
{

printf("usage: "PACKAGE"\t[-46ABbDdEGgHJKkLnpqTVw]\n"
	"\t\t[-C, --nohook hook] [-c, --script script]\n"
	"\t\t[-e, --env value] [-F, --fqdn FQDN] [-f, --config file]\n"
	"\t\t[-h, --hostname hostname] [-I, --clientid clientid]\n"
	"\t\t[-i, --vendorclassid vendorclassid] [-l, --leasetime seconds]\n"
	"\t\t[-m, --metric metric] [-O, --nooption option]\n"
	"\t\t[-o, --option option] [-Q, --require option]\n"
	"\t\t[-r, --request address] [-S, --static value]\n"
	"\t\t[-s, --inform address[/cidr]] [-t, --timeout seconds]\n"
	"\t\t[-u, --userclass class] [-v, --vendor code, value]\n"
	"\t\t[-W, --whitelist address[/cidr]] [-y, --reboot seconds]\n"
	"\t\t[-X, --blacklist address[/cidr]] [-Z, --denyinterfaces pattern]\n"
	"\t\t[-z, --allowinterfaces pattern] [interface] [...]\n"
	"       "PACKAGE"\t-k, --release [interface]\n"
	"       "PACKAGE"\t-U, --dumplease interface\n"
	"       "PACKAGE"\t--version\n"
	"       "PACKAGE"\t-x, --exit [interface]\n");
}

static void
cleanup(void)
{
#ifdef DEBUG_MEMORY
	struct interface *iface;
	int i;

	free_options(if_options);

	while (ifaces) {
		iface = ifaces;
		ifaces = iface->next;
		free_interface(iface);
	}

	for (i = 0; i < ifac; i++)
		free(ifav[i]);
	free(ifav);
	for (i = 0; i < ifdc; i++)
		free(ifdv[i]);
	free(ifdv);
#endif

	if (linkfd != -1)
		close(linkfd);
	if (pidfd > -1) {
		if (options & DHCPCD_MASTER) {
			if (control_stop() == -1)
				syslog(LOG_ERR, "control_stop: %m");
		}
		close(pidfd);
		unlink(pidfile);
	}
#ifdef DEBUG_MEMORY
	free(pidfile);
#endif

	if (options & DHCPCD_STARTED && !(options & DHCPCD_FORKED))
		syslog(LOG_INFO, "exited");
}

/* ARGSUSED */
static void
handle_exit_timeout(_unused void *arg)
{
	int timeout;

	syslog(LOG_ERR, "timed out");
	if (!(options & DHCPCD_IPV4) || !(options & DHCPCD_TIMEOUT_IPV4LL)) {
		if (options & DHCPCD_MASTER) {
			daemonise();
			return;
		} else
			exit(EXIT_FAILURE);
	}
	options &= ~DHCPCD_TIMEOUT_IPV4LL;
	timeout = (PROBE_NUM * PROBE_MAX) + (PROBE_WAIT * 2);
	syslog(LOG_WARNING, "allowing %d seconds for IPv4LL timeout", timeout);
	eloop_timeout_add_sec(timeout, handle_exit_timeout, NULL);
}

pid_t
daemonise(void)
{
#ifdef THERE_IS_NO_FORK
	return -1;
#else
	pid_t pid;
	char buf = '\0';
	int sidpipe[2], fd;

	eloop_timeout_delete(handle_exit_timeout, NULL);
	if (options & DHCPCD_DAEMONISED || !(options & DHCPCD_DAEMONISE))
		return 0;
	/* Setup a signal pipe so parent knows when to exit. */
	if (pipe(sidpipe) == -1) {
		syslog(LOG_ERR, "pipe: %m");
		return -1;
	}
	syslog(LOG_DEBUG, "forking to background");
	switch (pid = fork()) {
	case -1:
		syslog(LOG_ERR, "fork: %m");
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	case 0:
		setsid();
		/* Notify parent it's safe to exit as we've detached. */
		close(sidpipe[0]);
		if (write(sidpipe[1], &buf, 1) == -1)
			syslog(LOG_ERR, "failed to notify parent: %m");
		close(sidpipe[1]);
		if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		break;
	default:
		/* Wait for child to detach */
		close(sidpipe[1]);
		if (read(sidpipe[0], &buf, 1) == -1)
			syslog(LOG_ERR, "failed to read child: %m");
		close(sidpipe[0]);
		break;
	}
	/* Done with the fd now */
	if (pid != 0) {
		syslog(LOG_INFO, "forked to background, child pid %d",pid);
		writepid(pidfd, pid);
		close(pidfd);
		pidfd = -1;
		options |= DHCPCD_FORKED;
		exit(EXIT_SUCCESS);
	}
	options |= DHCPCD_DAEMONISED;
	return pid;
#endif
}

struct interface *
find_interface(const char *ifname)
{
	struct interface *ifp;
	
	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (strcmp(ifp->name, ifname) == 0)
			return ifp;
	return NULL;
}

static void
stop_interface(struct interface *iface)
{
	struct interface *ifp, *ifl = NULL;

	syslog(LOG_INFO, "%s: removing interface", iface->name);

	// Remove the interface from our list
	for (ifp = ifaces; ifp; ifp = ifp->next) {
		if (ifp == iface)
			break;
		ifl = ifp;
	}
	if (ifl)
		ifl->next = ifp->next;
	else
		ifaces = ifp->next;

	dhcp6_drop(iface, NULL);
	ipv6rs_drop(iface);
//	if (strcmp(iface->state->reason, "RELEASE") != 0)
		dhcp_drop(iface, "STOP");
	dhcp_close(iface);
	eloop_timeout_delete(NULL, iface);
	free_interface(ifp);
	if (!(options & (DHCPCD_MASTER | DHCPCD_TEST)))
		exit(EXIT_FAILURE);
}

static void
configure_interface1(struct interface *ifp)
{
	struct if_options *ifo = ifp->options;

	/* Do any platform specific configuration */
	if_conf(ifp);

	if (ifp->flags & IFF_POINTOPOINT && !(ifo->options & DHCPCD_INFORM))
		ifo->options |= DHCPCD_STATIC;
	if (ifp->flags & IFF_NOARP ||
	    ifo->options & (DHCPCD_INFORM | DHCPCD_STATIC))
		ifo->options &= ~(DHCPCD_ARP | DHCPCD_IPV4LL);
	if (!(ifp->flags & (IFF_POINTOPOINT | IFF_LOOPBACK | IFF_MULTICAST)))
		ifo->options &= ~DHCPCD_IPV6RS;
	if (ifo->options & DHCPCD_LINK && carrier_status(ifp) == -1)
		ifo->options &= ~DHCPCD_LINK;
	
	if (ifo->metric != -1)
		ifp->metric = ifo->metric;

	/* We want to disable kernel interface RA as early as possible. */
	if (options & DHCPCD_IPV6RS && ifo->options & DHCPCD_IPV6RS) {
		if (check_ipv6(ifp->name) != 1)
			ifo->options &= ~DHCPCD_IPV6RS;
	}

	/* If we haven't specified a ClientID and our hardware address
	 * length is greater than DHCP_CHADDR_LEN then we enforce a ClientID
	 * of the hardware address family and the hardware address. */
	if (ifp->hwlen > DHCP_CHADDR_LEN)
		ifo->options |= DHCPCD_CLIENTID;

	/* Firewire and InfiniBand interfaces require ClientID and
	 * the broadcast option being set. */
	switch (ifp->family) {
	case ARPHRD_IEEE1394:	/* FALLTHROUGH */
	case ARPHRD_INFINIBAND:
		ifo->options |= DHCPCD_CLIENTID | DHCPCD_BROADCAST;
		break;
	}
}

int
select_profile(struct interface *ifp, const char *profile)
{
	struct if_options *ifo;
	int ret;

	ret = 0;
	ifo = read_config(cffile, ifp->name, ifp->ssid, profile);
	if (ifo == NULL) {
		syslog(LOG_DEBUG, "%s: no profile %s", ifp->name, profile);
		ret = -1;
		goto exit;
	}
	if (profile != NULL) {
		strlcpy(ifp->profile, profile, sizeof(ifp->profile));
		syslog(LOG_INFO, "%s: selected profile %s",
		    ifp->name, profile);
	} else
		*ifp->profile = '\0';
	free_options(ifp->options);
	ifp->options = ifo;

exit:
	if (profile)
		configure_interface1(ifp);
	return ret;
}

static void
configure_interface(struct interface *ifp, int argc, char **argv)
{

	select_profile(ifp, NULL);
	add_options(ifp->options, argc, argv);
	configure_interface1(ifp);
}

void
handle_carrier(int action, int flags, const char *ifname)
{
	struct interface *ifp;
	int carrier;

	if (!(options & DHCPCD_LINK))
		return;
	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (strcmp(ifp->name, ifname) == 0)
			break;
	if (!ifp) {
		if (options & DHCPCD_LINK)
			handle_interface(1, ifname);
		return;
	}
	if (!(ifp->options->options & DHCPCD_LINK))
		return;

	if (action) {
		carrier = action == 1 ? 1 : 0;
		ifp->flags = flags;
	} else
		carrier = carrier_status(ifp);

	if (carrier == -1)
		syslog(LOG_ERR, "%s: carrier_status: %m", ifname);
	else if (carrier == 0 || ~ifp->flags & IFF_UP) {
		if (ifp->carrier != LINK_DOWN) {
			ifp->carrier = LINK_DOWN;
			syslog(LOG_INFO, "%s: carrier lost", ifp->name);
			dhcp_close(ifp);
			dhcp6_drop(ifp, "EXPIRE6");
			ipv6rs_drop(ifp);
			dhcp_drop(ifp, "NOCARRIER");
		}
	} else if (carrier == 1 && !(~ifp->flags & IFF_UP)) {
		if (ifp->carrier != LINK_UP) {
			ifp->carrier = LINK_UP;
			syslog(LOG_INFO, "%s: carrier acquired", ifp->name);
			if (ifp->wireless)
				getifssid(ifp->name, ifp->ssid);
			configure_interface(ifp, margc, margv);
			script_runreason(ifp, "CARRIER");
			start_interface(ifp);
		}
	}
}

void
start_interface(void *arg)
{
	struct interface *ifp = arg;
	struct if_options *ifo = ifp->options;
	int nolease;

	handle_carrier(0, 0, ifp->name);
	if (ifp->carrier == LINK_DOWN) {
		syslog(LOG_INFO, "%s: waiting for carrier", ifp->name);
		return;
	}

	if (options & DHCPCD_IPV6RS && ifo->options & DHCPCD_IPV6RS &&
	    !(ifo->options & DHCPCD_INFORM))
		ipv6rs_start(ifp);

	if (ifo->options & DHCPCD_IPV6) {
		if (ifo->options & DHCPCD_INFORM)
			nolease = dhcp6_start(ifp, 0);
		else if (!(ifo->options & DHCPCD_IPV6RS))
			nolease = dhcp6_start(ifp, 1);
		else
			nolease = 0;
		if (nolease == -1)
			syslog(LOG_ERR, "%s: dhcp6_start: %m", ifp->name);
	}

	if (ifo->options & DHCPCD_IPV4)
		dhcp_start(ifp);
}

static void
init_state(struct interface *ifp, int argc, char **argv)
{
	const char *reason = NULL;

	configure_interface(ifp, argc, argv);
	if (!(options & DHCPCD_TEST))
		script_runreason(ifp, "PREINIT");

	if (ifp->options->options & DHCPCD_LINK) {
		switch (carrier_status(ifp)) {
		case 0:
			ifp->carrier = LINK_DOWN;
			reason = "NOCARRIER";
			break;
		case 1:
			ifp->carrier = LINK_UP;
			reason = "CARRIER";
			break;
		default:
			ifp->carrier = LINK_UNKNOWN;
			return;
		}
		if (reason && !(options & DHCPCD_TEST))
			script_runreason(ifp, reason);
	} else
		ifp->carrier = LINK_UNKNOWN;
}

void
handle_interface(int action, const char *ifname)
{
	struct interface *ifs, *ifp, *ifn, *ifl = NULL;
	const char * const argv[] = { ifname }; 
	int i;

	if (action == -1) {
		ifp = find_interface(ifname);
		if (ifp != NULL)
			stop_interface(ifp);
		return;
	}

	/* If running off an interface list, check it's in it. */
	if (ifc) {
		for (i = 0; i < ifc; i++)
			if (strcmp(ifv[i], ifname) == 0)
				break;
		if (i >= ifc)
			return;
	}

	ifs = discover_interfaces(-1, UNCONST(argv));
	for (ifp = ifs; ifp; ifp = ifp->next) {
		if (strcmp(ifp->name, ifname) != 0)
			continue;
		/* Check if we already have the interface */
		for (ifn = ifaces; ifn; ifn = ifn->next) {
			if (strcmp(ifn->name, ifp->name) == 0)
				break;
			ifl = ifn;
		}
		if (ifn) {
			/* The flags and hwaddr could have changed */
			ifn->flags = ifp->flags;
			ifn->hwlen = ifp->hwlen;
			if (ifp->hwlen != 0)
				memcpy(ifn->hwaddr, ifp->hwaddr, ifn->hwlen);
		} else {
			if (ifl)
				ifl->next = ifp;
			else
				ifaces = ifp;
		}
		init_state(ifp, 0, NULL);
		start_interface(ifp);
	}
}

#ifdef RTM_CHGADDR
void
handle_hwaddr(const char *ifname, unsigned char *hwaddr, size_t hwlen)
{
	struct interface *ifp;
	struct if_options *ifo;
	struct dhcp_state *state;

	for (ifp = ifaces; ifp; ifp = ifp->next)
		if (strcmp(ifp->name, ifname) == 0 && ifp->hwlen <= hwlen) {
			state = D_STATE(ifp);
			if (state == NULL)
				continue;
			ifo = ifp->options;
			if (!(ifo->options &
			    (DHCPCD_INFORM | DHCPCD_STATIC | DHCPCD_CLIENTID))
	    		    && state->new != NULL &&
			    state->new->cookie == htonl(MAGIC_COOKIE))
			{
				syslog(LOG_INFO,
				    "%s: expiring for new hardware address",
				    ifp->name);
				dhcp_drop(ifp, "EXPIRE");
			}
			memcpy(ifp->hwaddr, hwaddr, hwlen);
			ifp->hwlen = hwlen;
			if (!(ifo->options &
			    (DHCPCD_INFORM | DHCPCD_STATIC | DHCPCD_CLIENTID)))
			{
				syslog(LOG_DEBUG, "%s: using hwaddr %s",
				    ifp->name,
		    		    hwaddr_ntoa(ifp->hwaddr, ifp->hwlen));
				state->interval = 0;
				state->nakoff = 0;
				start_interface(ifp);
			}
		}
	free(hwaddr);
}
#endif

/* ARGSUSED */
static void
handle_link(_unused void *arg)
{

	if (manage_link(linkfd) == -1)
		syslog(LOG_ERR, "manage_link: %m");
}

static void
if_reboot(struct interface *ifp, int argc, char **argv)
{
	int oldopts;

	oldopts = ifp->options->options;
	configure_interface(ifp, argc, argv);
	dhcp_reboot(ifp, oldopts);
	start_interface(ifp);
}

static void
reconf_reboot(int action, int argc, char **argv, int oi)
{
	struct interface *ifl, *ifn, *ifp, *ifs, *ift;
	
	ifs = discover_interfaces(argc - oi, argv + oi);
	if (ifs == NULL)
		return;

	for (ifp = ifs; ifp && (ift = ifp->next, 1); ifp = ift) {
		ifl = NULL;
		for (ifn = ifaces; ifn; ifn = ifn->next) {
			if (strcmp(ifn->name, ifp->name) == 0)
				break;
			ifl = ifn;
		}
		if (ifn) {
			if (action)
				if_reboot(ifn, argc, argv);
			else
				ipv4_applyaddr(ifn);
			free_interface(ifp);
		} else {
			ifp->next = NULL;
			init_state(ifp, argc, argv);
			start_interface(ifp);
			if (ifl)
				ifl->next = ifp;
			else
				ifaces = ifp;
		}
	}

	sort_interfaces();
}

void
handle_signal(int sig)
{
	struct interface *ifp;
	struct if_options *ifo;
	int do_release, i;

	do_release = 0;
	switch (sig) {
	case SIGINT:
		syslog(LOG_INFO, "received SIGINT, stopping");
		break;
	case SIGTERM:
		syslog(LOG_INFO, "received SIGTERM, stopping");
		break;
	case SIGALRM:
		syslog(LOG_INFO, "received SIGALRM, rebinding");
		for (i = 0; i < ifac; i++)
			free(ifav[i]);
		free(ifav);
		ifav = NULL;
		ifac = 0;
		for (i = 0; i < ifdc; i++)
			free(ifdv[i]);
		free(ifdv);
		ifdc = 0;
		ifdv = NULL;
		ifo = read_config(cffile, NULL, NULL, NULL);
		add_options(ifo, margc, margv);
		/* We need to preserve these two options. */
		if (options & DHCPCD_MASTER)
			ifo->options |= DHCPCD_MASTER;
		if (options & DHCPCD_DAEMONISED)
			ifo->options |= DHCPCD_DAEMONISED;
		options = ifo->options;
		free_options(ifo);
		reconf_reboot(1, ifc, ifv, 0);
		return;
	case SIGHUP:
		syslog(LOG_INFO, "received SIGHUP, releasing");
		do_release = 1;
		break;
	case SIGUSR1:
		syslog(LOG_INFO, "received SIGUSR, reconfiguring");
		for (ifp = ifaces; ifp; ifp = ifp->next)
			ipv4_applyaddr(ifp);
		return;
	case SIGPIPE:
		syslog(LOG_WARNING, "received SIGPIPE");
		return;
	default:
		syslog(LOG_ERR,
		    "received signal %d, but don't know what to do with it",
		    sig);
		return;
	}

	if (options & DHCPCD_TEST)
		exit(EXIT_FAILURE);

	/* As drop_dhcp could re-arrange the order, we do it like this. */
	for (;;) {
		/* Be sane and drop the last config first */
		for (ifp = ifaces; ifp; ifp = ifp->next) {
			if (ifp->next == NULL)
				break;
		}
		if (ifp == NULL)
			break;
		if (ifp->carrier != LINK_DOWN &&
		    (do_release ||
			ifp->options->options & DHCPCD_RELEASE))
			dhcp_release(ifp);
		stop_interface(ifp);
	}
	exit(EXIT_FAILURE);
}

int
handle_args(struct fd_list *fd, int argc, char **argv)
{
	struct interface *ifp;
	int do_exit = 0, do_release = 0, do_reboot = 0;
	int opt, oi = 0;
	ssize_t len;
	size_t l;
	struct iovec iov[2];
	char *tmp, *p;

	if (fd != NULL) {
		/* Special commands for our control socket */
		if (strcmp(*argv, "--version") == 0) {
			len = strlen(VERSION) + 1;
			iov[0].iov_base = &len;
			iov[0].iov_len = sizeof(ssize_t);
			iov[1].iov_base = UNCONST(VERSION);
			iov[1].iov_len = len;
			if (writev(fd->fd, iov, 2) == -1) {
				syslog(LOG_ERR, "writev: %m");
				return -1;
			}
			return 0;
		} else if (strcmp(*argv, "--getconfigfile") == 0) {
			len = strlen(cffile ? cffile : CONFIG) + 1;
			iov[0].iov_base = &len;
			iov[0].iov_len = sizeof(ssize_t);
			iov[1].iov_base = cffile ? cffile : UNCONST(CONFIG);
			iov[1].iov_len = len;
			if (writev(fd->fd, iov, 2) == -1) {
				syslog(LOG_ERR, "writev: %m");
				return -1;
			}
			return 0;
		} else if (strcmp(*argv, "--getinterfaces") == 0) {
			len = 0;
			if (argc == 1) {
				for (ifp = ifaces; ifp; ifp = ifp->next) {
					len++;
					if (D6_STATE_RUNNING(ifp))
						len++;
					if (ipv6rs_has_ra(ifp))
						len++;
				}
				len = write(fd->fd, &len, sizeof(len));
				if (len != sizeof(len))
					return -1;
				for (ifp = ifaces; ifp; ifp = ifp->next)
					send_interface(fd->fd, ifp);
				return 0;
			}
			opt = 0;
			while (argv[++opt] != NULL) {
				for (ifp = ifaces; ifp; ifp = ifp->next)
					if (strcmp(argv[opt], ifp->name) == 0) {
						len++;
						if (D6_STATE_RUNNING(ifp))
							len++;
						if (ipv6rs_has_ra(ifp))
							len++;
					}
			}
			len = write(fd->fd, &len, sizeof(len));
			if (len != sizeof(len))
				return -1;
			opt = 0;
			while (argv[++opt] != NULL) {
				for (ifp = ifaces; ifp; ifp = ifp->next)
					if (strcmp(argv[opt], ifp->name) == 0)
						send_interface(fd->fd, ifp);
			}
			return 0;
		} else if (strcmp(*argv, "--listen") == 0) {
			fd->listener = 1;
			return 0;
		}
	}

	/* Log the command */
	len = 0;
	for (opt = 0; opt < argc; opt++)
		len += strlen(argv[opt]) + 1;
	tmp = p = xmalloc(len + 1);
	for (opt = 0; opt < argc; opt++) {
		l = strlen(argv[opt]);
		strlcpy(p, argv[opt], l + 1);
		p += l;
		*p++ = ' ';
	}
	*--p = '\0';
	syslog(LOG_INFO, "control command: %s", tmp);
	free(tmp);

	optind = 0;
	while ((opt = getopt_long(argc, argv, IF_OPTS, cf_options, &oi)) != -1)
	{
		switch (opt) {
		case 'g':
			/* Assumed if below not set */
			break;
		case 'k':
			do_release = 1;
			break;
		case 'n':
			do_reboot = 1;
			break;
		case 'x':
			do_exit = 1;
			break;
		}
	}

	/* We need at least one interface */
	if (optind == argc) {
		syslog(LOG_ERR, "handle_args: no interface");
		return -1;
	}

	if (do_release || do_exit) {
		for (oi = optind; oi < argc; oi++) {
			for (ifp = ifaces; ifp; ifp = ifp->next)
				if (strcmp(ifp->name, argv[oi]) == 0)
					break;
			if (!ifp)
				continue;
			if (do_release)
				ifp->options->options |= DHCPCD_RELEASE;
			if (ifp->options->options & DHCPCD_RELEASE &&
			    ifp->carrier != LINK_DOWN)
				dhcp_release(ifp);
			stop_interface(ifp);
		}
		return 0;
	}

	reconf_reboot(do_reboot, argc, argv, optind);
	return 0;
}

int
main(int argc, char **argv)
{
	struct interface *iface;
	uint16_t family = 0;
	int opt, oi = 0, sig = 0, i, control_fd;
	size_t len;
	pid_t pid;
	struct timespec ts;
	struct utsname utn;
	const char *platform;

	closefrom(3);
	openlog(PACKAGE, LOG_PERROR | LOG_PID, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_INFO));

	/* Test for --help and --version */
	if (argc > 1) {
		if (strcmp(argv[1], "--help") == 0) {
			usage();
			exit(EXIT_SUCCESS);
		} else if (strcmp(argv[1], "--version") == 0) {
			printf(""PACKAGE" "VERSION"\n%s\n", copyright);
			exit(EXIT_SUCCESS);
		}
	}

	platform = hardware_platform();
	if (uname(&utn) == 0)
		snprintf(vendor, VENDORCLASSID_MAX_LEN,
		    "%s-%s:%s-%s:%s%s%s", PACKAGE, VERSION,
		    utn.sysname, utn.release, utn.machine,
		    platform ? ":" : "", platform ? platform : "");
	else
		snprintf(vendor, VENDORCLASSID_MAX_LEN,
		    "%s-%s", PACKAGE, VERSION);

	i = 0;
	while ((opt = getopt_long(argc, argv, IF_OPTS, cf_options, &oi)) != -1)
	{
		switch (opt) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'f':
			cffile = optarg;
			break;
		case 'g':
			sig = SIGUSR1;
			break;
		case 'k':
			sig = SIGHUP;
			break;
		case 'n':
			sig = SIGALRM;
			break;
		case 'x':
			sig = SIGTERM;
			break;
		case 'T':
			i = 1;
			break;
		case 'U':
			i = 2;
			break;
		case 'V':
			printf("Interface options:\n");
			if_printoptions();
#ifdef INET
			if (family == 0 || family == AF_INET) {
				printf("\nDHCPv4 options:\n");
				dhcp_printoptions();
			}
#endif
#ifdef INET6
			if (family == 0 || family == AF_INET6) {
				printf("\nDHCPv6 options:\n");
				dhcp6_printoptions();
			}
#endif
			exit(EXIT_SUCCESS);
		case '?':
			usage();
			exit(EXIT_FAILURE);
		}
	}

	margv = argv;
	margc = argc;
	if_options = read_config(cffile, NULL, NULL, NULL);
	opt = add_options(if_options, argc, argv);
	if (opt != 1) {
		if (opt == 0)
			usage();
		exit(EXIT_FAILURE);
	}
	options = if_options->options;
	if (i != 0) {
		if (i == 1)
			options |= DHCPCD_TEST;
		else
			options |= DHCPCD_DUMPLEASE;
		options |= DHCPCD_PERSISTENT;
		options &= ~DHCPCD_DAEMONISE;
	}
	
#ifdef THERE_IS_NO_FORK
	options &= ~DHCPCD_DAEMONISE;
#endif

	if (options & DHCPCD_DEBUG)
		setlogmask(LOG_UPTO(LOG_DEBUG));
	if (options & DHCPCD_QUIET)
		close(STDERR_FILENO);

	if (!(options & (DHCPCD_TEST | DHCPCD_DUMPLEASE))) {
		/* If we have any other args, we should run as a single dhcpcd
		 *  instance for that interface. */
		len = strlen(PIDFILE) + IF_NAMESIZE + 2;
		pidfile = xmalloc(len);
		if (optind == argc - 1)
			snprintf(pidfile, len, PIDFILE, "-", argv[optind]);
		else {
			snprintf(pidfile, len, PIDFILE, "", "");
			options |= DHCPCD_MASTER;
		}
	}

	if (chdir("/") == -1)
		syslog(LOG_ERR, "chdir `/': %m");
	atexit(cleanup);

	if (options & DHCPCD_DUMPLEASE) {
		if (optind != argc - 1) {
			syslog(LOG_ERR, "dumplease requires an interface");
			exit(EXIT_FAILURE);
		}
		if (dhcp_dump(argv[optind]) == -1)
			exit(EXIT_FAILURE);
		exit(EXIT_SUCCESS);
	}

	if (!(options & (DHCPCD_MASTER | DHCPCD_TEST))) {
		control_fd = control_open();
		if (control_fd != -1) {
			syslog(LOG_INFO,
			    "sending commands to master dhcpcd process");
			i = control_send(argc, argv);
			if (i > 0) {
				syslog(LOG_DEBUG, "send OK");
				exit(EXIT_SUCCESS);
			} else {
				syslog(LOG_ERR, "failed to send commands");
				exit(EXIT_FAILURE);
			}
		} else {
			if (errno != ENOENT)
				syslog(LOG_ERR, "control_open: %m");
		}
	}

	if (geteuid())
		syslog(LOG_WARNING,
		    PACKAGE " will not work correctly unless run as root");

	if (sig != 0) {
		pid = read_pid();
		if (pid != 0)
			syslog(LOG_INFO, "sending signal %d to pid %d",
			    sig, pid);
		if (pid == 0 || kill(pid, sig) != 0) {
			if (sig != SIGALRM && errno != EPERM)
				syslog(LOG_ERR, ""PACKAGE" not running");
			if (pid != 0 && errno != ESRCH) {
				syslog(LOG_ERR, "kill: %m");
				exit(EXIT_FAILURE);
			}
			unlink(pidfile);
			if (sig != SIGALRM)
				exit(EXIT_FAILURE);
		} else {
			if (sig == SIGALRM || sig == SIGUSR1)
				exit(EXIT_SUCCESS);
			/* Spin until it exits */
			syslog(LOG_INFO, "waiting for pid %d to exit", pid);
			ts.tv_sec = 0;
			ts.tv_nsec = 100000000; /* 10th of a second */
			for(i = 0; i < 100; i++) {
				nanosleep(&ts, NULL);
				if (read_pid() == 0)
					exit(EXIT_SUCCESS);
			}
			syslog(LOG_ERR, "pid %d failed to exit", pid);
			exit(EXIT_FAILURE);
		}
	}

	if (!(options & DHCPCD_TEST)) {
		if ((pid = read_pid()) > 0 &&
		    kill(pid, 0) == 0)
		{
			syslog(LOG_ERR, ""PACKAGE
			    " already running on pid %d (%s)",
			    pid, pidfile);
			exit(EXIT_FAILURE);
		}

		/* Ensure we have the needed directories */
		if (mkdir(RUNDIR, 0755) == -1 && errno != EEXIST)
			syslog(LOG_ERR, "mkdir `%s': %m", RUNDIR);
		if (mkdir(DBDIR, 0755) == -1 && errno != EEXIST)
			syslog(LOG_ERR, "mkdir `%s': %m", DBDIR);

		pidfd = open(pidfile, O_WRONLY | O_CREAT | O_NONBLOCK, 0664);
		if (pidfd == -1)
			syslog(LOG_ERR, "open `%s': %m", pidfile);
		else {
			/* Lock the file so that only one instance of dhcpcd
			 * runs on an interface */
			if (flock(pidfd, LOCK_EX | LOCK_NB) == -1) {
				syslog(LOG_ERR, "flock `%s': %m", pidfile);
				exit(EXIT_FAILURE);
			}
			if (set_cloexec(pidfd) == -1)
				exit(EXIT_FAILURE);
			writepid(pidfd, getpid());
		}
	}

	syslog(LOG_INFO, "version " VERSION " starting");
	options |= DHCPCD_STARTED;

#ifdef DEBUG_MEMORY
	eloop_init();
#endif

	/* This blocks all signals we're interested in.
	 * eloop uses pselect(2) so that the signals are unblocked
	 * when we're testing fd's.
	 * This allows us to ensure a consistent state is maintained
	 * regardless of when we are interrupted .*/
	if (signal_setup(handle_signal, &dhcpcd_sigset) == -1) {
		syslog(LOG_ERR, "signal_setup: %m");
		exit(EXIT_FAILURE);
	}

	if (options & DHCPCD_MASTER) {
		if (control_start() == -1)
			syslog(LOG_ERR, "control_start: %m");
	}

	if (open_sockets() == -1) {
		syslog(LOG_ERR, "open_sockets: %m");
		exit(EXIT_FAILURE);
	}
	if (if_options->options & DHCPCD_LINK) {
		linkfd = open_link_socket();
		if (linkfd == -1)
			syslog(LOG_ERR, "open_link_socket: %m");
		else
			eloop_event_add(linkfd, handle_link, NULL);
	}

#if 0
	if (options & DHCPCD_IPV6RS && disable_rtadv() == -1) {
		syslog(LOG_ERR, "ipv6rs: %m");
		options &= ~DHCPCD_IPV6RS;
	}
#endif

	if (options & DHCPCD_IPV6 && ipv6_init() == -1) {
		options &= ~DHCPCD_IPV6;
		syslog(LOG_ERR, "ipv6_init: %m");
	}
	if (options & DHCPCD_IPV6RS && !check_ipv6(NULL))
		options &= ~DHCPCD_IPV6RS;
	if (options & DHCPCD_IPV6RS)
		ipv6rs_init();

	ifc = argc - optind;
	ifv = argv + optind;

	/* When running dhcpcd against a single interface, we need to retain
	 * the old behaviour of waiting for an IP address */
	if (ifc == 1)
		options |= DHCPCD_WAITIP;

	ifaces = discover_interfaces(ifc, ifv);
	for (i = 0; i < ifc; i++) {
		for (iface = ifaces; iface; iface = iface->next)
			if (strcmp(iface->name, ifv[i]) == 0)
				break;
		if (!iface)
			syslog(LOG_ERR, "%s: interface not found or invalid",
			    ifv[i]);
	}
	if (!ifaces) {
		if (ifc == 0)
			syslog(LOG_ERR, "no valid interfaces found");
		else
			exit(EXIT_FAILURE);
		if (!(options & DHCPCD_LINK)) {
			syslog(LOG_ERR,
			    "aborting as link detection is disabled");
			exit(EXIT_FAILURE);
		}
	}

	if (options & DHCPCD_BACKGROUND)
		daemonise();

	opt = 0;
	for (iface = ifaces; iface; iface = iface->next) {
		init_state(iface, argc, argv);
		if (iface->carrier != LINK_DOWN)
			opt = 1;
	}

	if (!(options & DHCPCD_BACKGROUND)) {
		/* If we don't have a carrier, we may have to wait for a second
		 * before one becomes available if we brought an interface up */
		if (opt == 0 &&
		    options & DHCPCD_LINK &&
		    options & DHCPCD_WAITUP &&
		    !(options & DHCPCD_WAITIP))
		{
			ts.tv_sec = 1;
			ts.tv_nsec = 0;
			nanosleep(&ts, NULL);
			for (iface = ifaces; iface; iface = iface->next) {
				handle_carrier(0, 0, iface->name);
				if (iface->carrier != LINK_DOWN) {
					opt = 1;
					break;
				}
			}
		}
		if (options & DHCPCD_MASTER)
			i = if_options->timeout;
		else if (ifaces)
			i = ifaces->options->timeout;
		else
			i = 0;
		if (opt == 0 &&
		    options & DHCPCD_LINK &&
		    !(options & DHCPCD_WAITIP))
		{
			syslog(LOG_WARNING, "no interfaces have a carrier");
			daemonise();
		} else if (i > 0) {
			if (options & DHCPCD_IPV4LL)
				options |= DHCPCD_TIMEOUT_IPV4LL;
			eloop_timeout_add_sec(i, handle_exit_timeout, NULL);
		}
	}
	free_options(if_options);
	if_options = NULL;

	sort_interfaces();
	for (iface = ifaces; iface; iface = iface->next)
		eloop_timeout_add_sec(0, start_interface, iface);

	eloop_start(&dhcpcd_sigset);
	exit(EXIT_SUCCESS);
}
