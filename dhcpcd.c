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

const char copyright[] = "Copyright (c) 2006-2008 Roy Marples";

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <errno.h>
#include <getopt.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "client.h"
#include "dhcpcd.h"
#include "dhcp.h"
#include "net.h"
#include "logger.h"

static int doversion = 0;
static int dohelp = 0;
#define EXTRA_OPTS
static const struct option longopts[] = {
	{"arp",         no_argument,        NULL, 'a'},
	{"script",      required_argument,  NULL, 'c'},
	{"debug",       no_argument,        NULL, 'd'},
	{"hostname",    optional_argument,  NULL, 'h'},
	{"classid",     optional_argument,  NULL, 'i'},
	{"release",     no_argument,        NULL, 'k'},
	{"leasetime",   required_argument,  NULL, 'l'},
	{"metric",      required_argument,  NULL, 'm'},
	{"renew",       no_argument,        NULL, 'n'},
	{"option",	required_argument,  NULL, 'o'},
	{"persistent",  no_argument,        NULL, 'p'},
	{"inform",      optional_argument,  NULL, 's'},
	{"request",     optional_argument,  NULL, 'r'},
	{"timeout",     required_argument,  NULL, 't'},
	{"userclass",   required_argument,  NULL, 'u'},
	{"exit",        no_argument,        NULL, 'x'},
	{"lastlease",   no_argument,        NULL, 'E'},
	{"fqdn",        optional_argument,  NULL, 'F'},
	{"nogateway",   no_argument,        NULL, 'G'},
	{"sethostname", no_argument,        NULL, 'H'},
	{"clientid",    optional_argument,  NULL, 'I'},
	{"noipv4ll",    no_argument,        NULL, 'L'},
	{"nomtu",       no_argument,        NULL, 'M'},
	{"nontp",       no_argument,        NULL, 'N'},
	{"nooptions",   no_argument,        NULL, 'O'},
	{"nodns",       no_argument,        NULL, 'R'},
	{"msscr",       no_argument,        NULL, 'S'},
	{"test",        no_argument,        NULL, 'T'},
	{"nonis",       no_argument,        NULL, 'Y'},
	{"help",        no_argument,        &dohelp, 1},
	{"version",     no_argument,        &doversion, 1},
#ifdef THERE_IS_NO_FORK
	{"daemonised",	no_argument,        NULL, 'f'},
	{"skiproutes",  required_argument,  NULL, 'g'},
#endif
	{NULL,          0,                  NULL, 0}
};

#ifdef THERE_IS_NO_FORK
char dhcpcd[PATH_MAX];
char **dhcpcd_argv = NULL;
int dhcpcd_argc = 0;
char *dhcpcd_skiproutes = NULL;
#undef EXTRA_OPTS
#define EXTRA_OPTS "fg:"
#endif

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

static pid_t
read_pid(const char *pidfile)
{
	FILE *fp;
	pid_t pid = 0;

	if ((fp = fopen(pidfile, "r")) == NULL) {
		errno = ENOENT;
		return 0;
	}

	fscanf(fp, "%d", &pid);
	fclose(fp);

	return pid;
}

static void
usage(void)
{
	printf("usage: "PACKAGE" [-adknpEGHMNORSTY] [-c script] [-h hostname] [-i classID]\n"
	       "              [-l leasetime] [-m metric] [-o option] [-r ipaddress]\n"
	       "              [-s ipaddress] [-t timeout] [-u userclass] [-F none | ptr | both]\n"
	       "              [-I clientID] <interface>\n");
}

int
main(int argc, char **argv)
{
	struct options *options;
	int userclasses = 0;
	int opt;
	int option_index = 0;
	char *prefix;
	pid_t pid;
	int debug = 0;
	int i;
	int j;
	int pidfd = -1;
	int sig = 0;
	int retval = EXIT_FAILURE;
	char *p;
	int doopts = 1, dodns = 1, dohostname = 0, donis = 1, dontp = 1;

	/* Close any un-needed fd's */
	for (i = getdtablesize() - 1; i >= 3; --i)
		close (i);

	openlog(PACKAGE, LOG_PID, LOG_LOCAL0);

	options = xzalloc(sizeof(*options));
	options->script = (char *)DEFAULT_SCRIPT;
	snprintf(options->classid, CLASS_ID_MAX_LEN, "%s %s",
		 PACKAGE, VERSION);

	options->options |= DHCPCD_GATEWAY | DHCPCD_IPV4LL | DHCPCD_DUID |
		DHCPCD_DAEMONISE;
	options->timeout = DEFAULT_TIMEOUT;

	gethostname(options->hostname, sizeof(options->hostname));
	if (strcmp(options->hostname, "(none)") == 0 ||
	    strcmp(options->hostname, "localhost") == 0)
		*options->hostname = '\0';

	/* Don't set any optional arguments here so we retain POSIX
	 * compatibility with getopt */
	while ((opt = getopt_long(argc, argv, EXTRA_OPTS
				  "c:dh:i:kl:m:no:pr:s:t:u:xAEF:GHI:LMNORSTY",
				  longopts, &option_index)) != -1)
	{
		switch (opt) {
		case 0:
			if (longopts[option_index].flag)
				break;
			logger(LOG_ERR,	"option `%s' should set a flag",
			       longopts[option_index].name);
			goto abort;
		case 'c':
			options->script = optarg;
			break;
		case 'd':
			debug++;
			switch (debug) {
			case 1:
				setloglevel(LOG_DEBUG);
				break;
			case 2:
				options->options &= ~DHCPCD_DAEMONISE;
				break;
			}
			break;
#ifdef THERE_IS_NO_FORK
		case 'f':
			options->options |= DHCPCD_DAEMONISED;
			close_fds();
			break;
		case 'g':
			dhcpcd_skiproutes = xstrdup(optarg);
			break;
#endif
		case 'h':
			if (!optarg)
				*options->hostname = '\0';
			else if (strlen(optarg) > MAXHOSTNAMELEN) {
				logger(LOG_ERR,
					"`%s' too long for HostName string,"
					" max is %d", optarg, MAXHOSTNAMELEN);
				goto abort;
			} else
				strlcpy(options->hostname, optarg,
					sizeof(options->hostname));
			break;
		case 'i':
			if (!optarg) {
				*options->classid = '\0';
			} else if (strlen(optarg) > CLASS_ID_MAX_LEN) {
				logger(LOG_ERR,
				       "`%s' too long for ClassID string,"
				       " max is %d", optarg, CLASS_ID_MAX_LEN);
				goto abort;
			} else
				strlcpy(options->classid, optarg,
					sizeof(options->classid));
			break;
		case 'k':
			sig = SIGHUP;
			break;
		case 'l':
			if (*optarg == '-') {
				logger(LOG_ERR,
				       "leasetime must be a positive value");
				goto abort;
			}
			errno = 0;
			options->leasetime = (uint32_t)strtol(optarg, NULL, 0);
			if (errno == EINVAL || errno == ERANGE) {
				logger(LOG_ERR, "`%s' out of range", optarg);
				goto abort;
			}
			break;
		case 'm':
			options->metric = atoint(optarg);
			if (options->metric < 0) {
				logger(LOG_ERR,
				       "metric must be a positive value");
				goto abort;
			}
			break;
		case 'n':
			sig = SIGALRM;
			break;
		case 'o':
			if (make_reqmask(options, &optarg) != 0) {
				logger(LOG_ERR, "unknown option `%s'", optarg);
				goto abort;
			}
		case 'p':
			options->options |= DHCPCD_PERSISTENT;
			break;
		case 's':
			options->options |= DHCPCD_INFORM;
			options->options &= ~DHCPCD_ARP;
			if (!optarg || strlen(optarg) == 0) {
				options->request_address.s_addr = 0;
				break;
			} else {
				if ((p = strchr(optarg, '/'))) {
					/* nullify the slash, so the -r option
					 * can read the address */
					*p++ = '\0';
					if (sscanf(p, "%d", &i) != 1 ||
					    inet_cidrtoaddr(i, &options->request_netmask) != 0)
					{
						logger(LOG_ERR,
						       "`%s' is not a valid CIDR",
						       p);
						goto abort;
					}
				}
			}
			/* FALLTHROUGH */
		case 'r':
			if (!(options->options & DHCPCD_INFORM))
				options->options |= DHCPCD_REQUEST;
			if (strlen(optarg) > 0 &&
			    !inet_aton(optarg, &options->request_address))
			{ 
				logger(LOG_ERR,
				       "`%s' is not a valid IP address",
				       optarg);
				goto abort;
			}
			break;
		case 't':
			options->timeout = atoint(optarg);
			if (options->timeout < 0) {
				logger (LOG_ERR, "timeout must be a positive value");
				goto abort;
			}
			break;
		case 'u':
			j = 0;
			for (i = 0; i < userclasses; i++)
				j += (int)options->userclass[j] + 1;
				if (j + 1 + strlen(optarg) > USERCLASS_MAX_LEN) {
					logger(LOG_ERR,
					       "userclass overrun, max is %d",
					       USERCLASS_MAX_LEN);
					goto abort;
				}
				userclasses++;
				memcpy(options->userclass + j + 1 ,
				       optarg, strlen(optarg));
				options->userclass[j] = strlen(optarg);
				options->userclass_len += (strlen(optarg)) + 1;
			break;
		case 'x':
			sig = SIGTERM;
			break;
		case 'A':
#ifndef ENABLE_ARP
			logger (LOG_ERR, "arp not compiled into dhcpcd");
			goto abort;
#endif
			options->options &= ~DHCPCD_ARP;
			/* IPv4LL requires ARP */
			options->options &= ~DHCPCD_IPV4LL;
			break;
		case 'E':
			options->options |= DHCPCD_LASTLEASE;
			break;
		case 'F':
			if (!optarg) {
				options->fqdn = FQDN_BOTH;
				break;
			}
			if (strncmp(optarg, "none", strlen(optarg)) == 0)
				options->fqdn = FQDN_NONE;
			else if (strncmp(optarg, "ptr", strlen(optarg)) == 0)
				options->fqdn = FQDN_PTR;
			else if (strncmp(optarg, "both", strlen(optarg)) == 0)
				options->fqdn = FQDN_BOTH;
			else {
				logger(LOG_ERR, "invalid value `%s' for FQDN",
				       optarg);
				goto abort;
			}
			break;
		case 'G':
			options->options &= ~DHCPCD_GATEWAY;
			break;
		case 'H':
			dohostname = 1;
			break;
		case 'I':
			if (optarg) {
				if (strlen(optarg) > CLIENT_ID_MAX_LEN) {
					logger(LOG_ERR, "`%s' is too long for"
					       " ClientID, max is %d",
					       optarg, CLIENT_ID_MAX_LEN);
					goto abort;
				}
				if (strlcpy(options->clientid, optarg,
					    sizeof(options->clientid)) == 0)
					/* empty string disabled duid */
					options->options &= ~DHCPCD_DUID;
			} else {
				memset(options->clientid, 0,
				       sizeof(options->clientid));
				options->options &= ~DHCPCD_DUID;
			}
			break;
		case 'L':
			options->options &= ~DHCPCD_IPV4LL;
			break;
		case 'M':
			options->options &= ~DHCPCD_MTU;
			break;
		case 'N':
			dontp = 0;
			break;
		case 'O':
			doopts = 0;
			break;
		case 'R':
			dodns = 0;
			break;
		case 'S':
			options->domscsr++;
			break;
		case 'T':
			options->options |= DHCPCD_TEST | DHCPCD_PERSISTENT;
			break;
		case 'Y':
			donis = 0;
			break;
		case '?':
			usage();
			goto abort;
		default:
			usage();
			goto abort;
		}
	}
	if (doversion) {
		printf(""PACKAGE" "VERSION"\n");
		printf("Compile time options:"
#ifdef ENABLE_ARP
			" ARP"
#endif
#ifdef ENABLE_DUID
			" DUID"
#endif
#ifdef ENABLE_INFO_COMPAT
			" INFO_COMPAT"
#endif
#ifdef ENABLE_IPV4LL
			" IPV4LL"
#endif
#ifdef THERE_IS_NO_FORK
			" THERE_IS_NO_FORK"
#endif
			"\n");
	}

	if (dohelp)
		usage();

	if (doopts) {
		if (dodns) {
			add_reqmask(options->reqmask, DHCP_DNSSERVER);
			add_reqmask(options->reqmask, DHCP_DNSDOMAIN);
			add_reqmask(options->reqmask, DHCP_DNSSEARCH);
		}
		if (dohostname)
			add_reqmask(options->reqmask, DHCP_HOSTNAME);
		if (donis) {
			add_reqmask(options->reqmask, DHCP_NISSERVER);
			add_reqmask(options->reqmask, DHCP_NISDOMAIN);
		}
		if (dontp)
			add_reqmask(options->reqmask, DHCP_NTPSERVER);
	}

#ifdef THERE_IS_NO_FORK
	dhcpcd_argv = argv;
	dhcpcd_argc = argc;
	if (!realpath(argv[0], dhcpcd)) {
		logger(LOG_ERR, "unable to resolve the path `%s': %s",
		       argv[0], strerror(errno));
		goto abort;
	}
#endif

	if (optind < argc) {
		if (strlen(argv[optind]) > IF_NAMESIZE) {
			logger(LOG_ERR,
			       "`%s' too long for an interface name (max=%d)",
			       argv[optind], IF_NAMESIZE);
			goto abort;
		}
		strlcpy(options->interface, argv[optind],
			sizeof(options->interface));
	} else {
		/* If only version was requested then exit now */
		if (doversion || dohelp) {
			retval = 0;
			goto abort;
		}

		logger(LOG_ERR, "no interface specified");
		goto abort;
	}

	if (strchr(options->hostname, '.')) {
		if (options->fqdn == FQDN_DISABLE)
			options->fqdn = FQDN_BOTH;
	} else
		options->fqdn = FQDN_DISABLE;

	if (options->request_address.s_addr == 0 &&
	    options->options & DHCPCD_INFORM)
	{
		if (get_address(options->interface,
				&options->request_address,
				&options->request_netmask) == 0)
			options->options |= DHCPCD_KEEPADDRESS;
	}

	if (IN_LINKLOCAL(ntohl (options->request_address.s_addr))) {
		logger(LOG_ERR,
		       "you are not allowed to request a link local address");
		goto abort;
	}

	if (geteuid())
		logger(LOG_WARNING, PACKAGE " will not work correctly unless"
		       " run as root");

	prefix = xmalloc(sizeof(char) * (IF_NAMESIZE + 3));
	snprintf(prefix, IF_NAMESIZE, "%s: ", options->interface);
	setlogprefix(prefix);
	snprintf(options->pidfile, sizeof(options->pidfile), PIDFILE,
		 options->interface);
	free(prefix);

	chdir("/");
	umask(022);

	if (options->options & DHCPCD_TEST) {
		if (options->options & DHCPCD_REQUEST ||
		    options->options & DHCPCD_INFORM) {
			logger(LOG_ERR,
			       "cannot test with --inform or --request");
			goto abort;
		}

		if (options->options & DHCPCD_LASTLEASE) {
			logger(LOG_ERR, "cannot test with --lastlease");
			goto abort;
		}

		if (sig != 0) {
			logger(LOG_ERR,
			       "cannot test with --release or --renew");
			goto abort;
		}
	}

	if (sig != 0) {
		i = -1;
		pid = read_pid(options->pidfile);
		if (pid != 0)
			logger(LOG_INFO, "sending signal %d to pid %d",
			       sig, pid);

		if (!pid || (i = kill(pid, sig)))
			logger(sig == SIGALRM ? LOG_INFO : LOG_ERR,
			       ""PACKAGE" not running");

		if (pid != 0 && (sig != SIGALRM || i != 0))
			unlink(options->pidfile);

		if (i == 0) {
			retval = EXIT_SUCCESS;
			goto abort;
		}

		if (sig != SIGALRM)
			goto abort;	
	}

	if (!(options->options & DHCPCD_TEST) &&
	    !(options->options & DHCPCD_DAEMONISED))
	{
		if ((pid = read_pid(options->pidfile)) > 0 &&
		    kill(pid, 0) == 0)
		{
			logger(LOG_ERR, ""PACKAGE
			       " already running on pid %d (%s)",
			       pid, options->pidfile);
			goto abort;
		}

		pidfd = open(options->pidfile,
			     O_WRONLY | O_CREAT | O_NONBLOCK, 0664);
		if (pidfd == -1) {
			logger(LOG_ERR, "open `%s': %s",
			       options->pidfile, strerror(errno));
			goto abort;
		}

		/* Lock the file so that only one instance of dhcpcd runs
		 * on an interface */
		if (flock(pidfd, LOCK_EX | LOCK_NB) == -1) {
			logger(LOG_ERR, "flock `%s': %s",
			       options->pidfile, strerror(errno));
			goto abort;
		}

		close_on_exec(pidfd);
		writepid(pidfd, getpid());
		logger(LOG_INFO, PACKAGE " " VERSION " starting");
	}

	/* Seed random */
	srandomdev();

#ifdef __linux__
	/* Massage our filters per platform */
	setup_packet_filters();
#endif

	if (dhcp_run(options, &pidfd) == 0)
		retval = EXIT_SUCCESS;

abort:
	/* If we didn't daemonise then we need to punt the pidfile now */
	if (pidfd > -1) {
		close(pidfd);
		unlink(options->pidfile);
	}

	free(options);

#ifdef THERE_IS_NO_FORK
	/* There may have been an error before the dhcp_run function
	 * clears this, so just do it here to be safe */
	free(dhcpcd_skiproutes);
#endif

	exit(retval);
	/* NOTREACHED */
}
