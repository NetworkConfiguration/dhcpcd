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

/* We need to define this to get kill on GNU systems */
#ifdef __linux__
#define _BSD_SOURCE
#define _POSIX_SOURCE
#endif

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <paths.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "client.h"
#include "dhcpcd.h"
#include "dhcp.h"
#include "interface.h"
#include "logger.h"
#include "socket.h"
#include "version.h"

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
	{"persistent",  no_argument,        NULL, 'p'},
	{"inform",      optional_argument,  NULL, 's'},
	{"request",     optional_argument,  NULL, 'r'},
	{"timeout",     required_argument,  NULL, 't'},
	{"userclass",   required_argument,  NULL, 'u'},
	{"exit",        no_argument,        NULL, 'x'},
	{"lastlease",   no_argument,        NULL, 'E'},
	{"fqdn",        required_argument,  NULL, 'F'},
	{"nogateway",   no_argument,        NULL, 'G'},
	{"sethostname", no_argument,        NULL, 'H'},
	{"clientid",    optional_argument,  NULL, 'I'},
	{"noipv4ll",    no_argument,        NULL, 'L'},
	{"nomtu",       no_argument,        NULL, 'M'},
	{"nontp",       no_argument,        NULL, 'N'},
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

static int atoint (const char *s)
{
	char *t;
	long n;

	errno = 0;
	n = strtol (s, &t, 0);
	if ((errno != 0 && n == 0) || s == t ||
	    (errno == ERANGE && (n == LONG_MAX || n == LONG_MIN)))
	{
		logger (LOG_ERR, "`%s' out of range", s);
		return (-1);	
	}

	return ((int) n);
}

static pid_t read_pid (const char *pidfile)
{
	FILE *fp;
	pid_t pid = 0;

	if ((fp = fopen (pidfile, "r")) == NULL) {
		errno = ENOENT;
		return 0;
	}

	fscanf (fp, "%d", &pid);
	fclose (fp);

	return (pid);
}

static void usage (void)
{
	printf ("usage: "PACKAGE" [-adknpEGHMNRSTY] [-c script] [-h hostname] [-i classID]\n"
		"              [-l leasetime] [-m metric] [-r ipaddress] [-s ipaddress]\n"
		"              [-t timeout] [-u userclass] [-F none | ptr | both]\n"
		"              [-I clientID] <interface>\n");
}

int main(int argc, char **argv)
{
	options_t *options;
	int userclasses = 0;
	int opt;
	int option_index = 0;
	char *prefix;
	pid_t pid;
	int debug = 0;
	int i;
	int pidfd = -1;
	int sig = 0;
	int retval = EXIT_FAILURE;

	/* Close any un-needed fd's */
	for (i = getdtablesize() - 1; i >= 3; --i)
		close (i);

	openlog (PACKAGE, LOG_PID, LOG_LOCAL0);

	options = xzalloc (sizeof (*options));
	options->script = (char *) DEFAULT_SCRIPT;
	snprintf (options->classid, CLASS_ID_MAX_LEN, "%s %s",
		  PACKAGE, VERSION);
	options->classid_len = strlen (options->classid);

	options->doarp = true;
	options->dodns = true;
	options->domtu = true;
	options->donis = true;
	options->dontp = true;
	options->dogateway = true;
	options->daemonise = true;
	options->doinform = false;
	options->doipv4ll = true;
	options->doduid = true;
	options->timeout = DEFAULT_TIMEOUT;

	gethostname (options->hostname, sizeof (options->hostname));
	if (strcmp (options->hostname, "(none)") == 0 ||
	    strcmp (options->hostname, "localhost") == 0)
		memset (options->hostname, 0, sizeof (options->hostname));

	/* Don't set any optional arguments here so we retain POSIX
	 * compatibility with getopt */
	while ((opt = getopt_long(argc, argv, EXTRA_OPTS
				  "c:dh:i:kl:m:npr:s:t:u:xAEF:GHI:LMNRSTY",
				  longopts, &option_index)) != -1)
	{
		switch (opt) {
			case 0:
				if (longopts[option_index].flag)
					break;
				logger (LOG_ERR,
					"option `%s' should set a flag",
					longopts[option_index].name);
				goto abort;
			case 'c':
				options->script = optarg;
				break;
			case 'd':
				debug++;
				switch (debug) {
					case 1:
						setloglevel (LOG_DEBUG);
						break;
					case 2:
						options->daemonise = false;
						break;
				}
				break;
#ifdef THERE_IS_NO_FORK
			case 'f':
				options->daemonised = true;
				close_fds ();
				break;
			case 'g':
				dhcpcd_skiproutes = xstrdup (optarg);
				break;
#endif
			case 'h':
				if (! optarg)
					memset (options->hostname, 0,
						sizeof (options->hostname));
				else if (strlen (optarg) > MAXHOSTNAMELEN) {
					logger (LOG_ERR,
						"`%s' too long for HostName string, max is %d",
						optarg, MAXHOSTNAMELEN);
					goto abort;
				} else
					strlcpy (options->hostname, optarg,
						 sizeof (options->hostname));
				break;
			case 'i':
				if (! optarg) {
					memset (options->classid, 0,
						sizeof (options->classid));
					options->classid_len = 0;
				} else if (strlen (optarg) > CLASS_ID_MAX_LEN) {
					logger (LOG_ERR,
						"`%s' too long for ClassID string, max is %d",
						optarg, CLASS_ID_MAX_LEN);
					goto abort;
				} else
					options->classid_len = strlcpy (options->classid, optarg,
									sizeof (options->classid));
				break;
			case 'k':
				sig = SIGHUP;
				break;
			case 'l':
				if (*optarg == '-') {
					logger (LOG_ERR,
						"leasetime must be a positive value");
					goto abort;
				}
				errno = 0;
				options->leasetime = (uint32_t) strtol (optarg, NULL, 0);
				if (errno == EINVAL || errno == ERANGE) {
					logger (LOG_ERR, "`%s' out of range", optarg);
					goto abort;
				}
				break;
			case 'm':
				options->metric = atoint (optarg);
				if (options->metric < 0) {
					logger (LOG_ERR,
						"metric must be a positive value");
					goto abort;
				}
				break;
			case 'n':
				sig = SIGALRM;
				break;
			case 'p':
				options->persistent = true;
				break;
			case 's':
				options->doinform = true;
				options->doarp = false;
				if (! optarg || strlen (optarg) == 0) {
					options->request_address.s_addr = 0;
					break;
				} else {
					char *slash = strchr (optarg, '/');
					if (slash) {
						int cidr;
						/* nullify the slash, so the -r option can read the
						 * address */
						*slash++ = '\0';
						if (sscanf (slash, "%d", &cidr) != 1 ||
						    inet_cidrtoaddr (cidr, &options->request_netmask) != 0) {
							logger (LOG_ERR, "`%s' is not a valid CIDR", slash);
							goto abort;
						}
					}
				}
				/* FALLTHROUGH */
			case 'r':
				if (! options->doinform)
					options->dorequest = true;
				if (strlen (optarg) > 0 &&
				    ! inet_aton (optarg, &options->request_address))
				{ 
					logger (LOG_ERR, "`%s' is not a valid IP address", optarg);
					goto abort;
				}
				break;
			case 't':
				options->timeout = atoint (optarg);
				if (options->timeout < 0) {
					logger (LOG_ERR, "timeout must be a positive value");
					goto abort;
				}
				break;
			case 'u':
				{
					int offset = 0;
					for (i = 0; i < userclasses; i++)
						offset += (int) options->userclass[offset] + 1;
					if (offset + 1 + strlen (optarg) > USERCLASS_MAX_LEN) {
						logger (LOG_ERR, "userclass overrun, max is %d",
							USERCLASS_MAX_LEN);
						goto abort;
					}
					userclasses++;
					memcpy (options->userclass + offset + 1 , optarg, strlen (optarg));
					options->userclass[offset] = strlen (optarg);
					options->userclass_len += (strlen (optarg)) + 1;
				}
				break;
			case 'x':
				sig = SIGTERM;
				break;
			case 'A':
#ifndef ENABLE_ARP
				logger (LOG_ERR,
					"arp not compiled into dhcpcd");
				goto abort;
#endif
				options->doarp = false;
				break;
			case 'E':
#ifndef ENABLE_INFO
				logger (LOG_ERR,
					"info not compiled into dhcpcd");
				goto abort;
#endif
				options->dolastlease = true;
				break;
			case 'F':
				if (strncmp (optarg, "none", strlen (optarg)) == 0)
					options->fqdn = FQDN_NONE;
				else if (strncmp (optarg, "ptr", strlen (optarg)) == 0)
					options->fqdn = FQDN_PTR;
				else if (strncmp (optarg, "both", strlen (optarg)) == 0)
					options->fqdn = FQDN_BOTH;
				else {
					logger (LOG_ERR, "invalid value `%s' for FQDN", optarg);
					goto abort;
				}
				break;
			case 'G':
				options->dogateway = false;
				break;
			case 'H':
				options->dohostname++;
				break;
			case 'I':
				if (optarg) {
					if (strlen (optarg) > CLIENT_ID_MAX_LEN) {
						logger (LOG_ERR, "`%s' is too long for ClientID, max is %d",
							optarg, CLIENT_ID_MAX_LEN);
						goto abort;
					}
					options->clientid_len = strlcpy (options->clientid, optarg,
									 sizeof (options->clientid));
					/* empty string disabled duid */
					if (options->clientid_len == 0)
						options->doduid = false;

				} else {
					memset (options->clientid, 0, sizeof (options->clientid));
					options->doduid = false;
				}
				break;
			case 'L':
				options->doipv4ll = false;
				break;
			case 'M':
				options->domtu = false;
				break;
			case 'N':
				options->dontp = false;
				break;
			case 'R':
				options->dodns = false;
				break;
			case 'S':
				options->domscsr++;
				break;
			case 'T':
#ifndef ENABLE_INFO
				logger (LOG_ERR, "info support not compiled into dhcpcd");
				goto abort;
#endif
				options->test = true;
				options->persistent = true;
				break;
			case 'Y':
				options->donis = false;
				break;
			case '?':
				usage ();
				goto abort;
			default:
				usage ();
				goto abort;
		}
	}
	if (doversion) {
		printf (""PACKAGE" "VERSION"\n");
		printf ("Compile time options:"
#ifdef ENABLE_ARP
			" ARP"
#endif
#ifdef ENABLE_DUID
			" DUID"
#endif
#ifdef ENABLE_INFO
			" INFO"
#endif
#ifdef ENABLE_INFO_COMPAT
			" INFO_COMPAT"
#endif
#ifdef ENABLE_IPV4LL
			" IPV4LL"
#endif
#ifdef ENABLE_NIS
			" NIS"
#endif
#ifdef ENABLE_NTP
			" NTP"
#endif
#ifdef SERVICE
			" " SERVICE
#endif
#ifdef ENABLE_RESOLVCONF
			" RESOLVCONF"
#endif
#ifdef THERE_IS_NO_FORK
			" THERE_IS_NO_FORK"
#endif
			"\n");
	}

	if (dohelp)
		usage ();

#ifdef THERE_IS_NO_FORK
	dhcpcd_argv = argv;
	dhcpcd_argc = argc;
	if (! realpath (argv[0], dhcpcd)) {
		logger (LOG_ERR, "unable to resolve the path `%s': %s",
			argv[0], strerror (errno));
		goto abort;
	}
#endif

	if (optind < argc) {
		if (strlen (argv[optind]) > IF_NAMESIZE) {
			logger (LOG_ERR,
				"`%s' too long for an interface name (max=%d)",
				argv[optind], IF_NAMESIZE);
			goto abort;
		}
		strlcpy (options->interface, argv[optind],
			 sizeof (options->interface));
	} else {
		/* If only version was requested then exit now */
		if (doversion || dohelp) {
			retval = 0;
			goto abort;
		}

		logger (LOG_ERR, "no interface specified");
		goto abort;
	}

	if (strchr (options->hostname, '.')) {
		if (options->fqdn == FQDN_DISABLE)
			options->fqdn = FQDN_BOTH;
	} else
		options->fqdn = FQDN_DISABLE;

	if (options->request_address.s_addr == 0 && options->doinform) {
		if ((options->request_address.s_addr =
		     get_address (options->interface)) != 0)
			options->keep_address = true;
	}

	if (IN_LINKLOCAL (ntohl (options->request_address.s_addr))) {
		logger (LOG_ERR,
			"you are not allowed to request a link local address");
		goto abort;
	}

	if (geteuid ()) {
		logger (LOG_ERR, "you need to be root to run " PACKAGE);
		goto abort;
	}

	prefix = xmalloc (sizeof (char) * (IF_NAMESIZE + 3));
	snprintf (prefix, IF_NAMESIZE, "%s: ", options->interface);
	setlogprefix (prefix);
	snprintf (options->pidfile, sizeof (options->pidfile), PIDFILE,
		  options->interface);
	free (prefix);

	chdir ("/");
	umask (022);

	if (mkdir (INFODIR, S_IRUSR | S_IWUSR |S_IXUSR | S_IRGRP | S_IXGRP
		   | S_IROTH | S_IXOTH) && errno != EEXIST)
	{
		logger (LOG_ERR,
			"mkdir(\"%s\",0): %s\n", INFODIR, strerror (errno));
		goto abort;
	}

	if (mkdir (ETCDIR, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP
		   | S_IROTH | S_IXOTH) && errno != EEXIST)
	{
		logger (LOG_ERR,
			"mkdir(\"%s\",0): %s\n", ETCDIR, strerror (errno));
		goto abort;
	}

	if (options->test) {
		if (options->dorequest || options->doinform) {
			logger (LOG_ERR,
				"cannot test with --inform or --request");
			goto abort;
		}

		if (options->dolastlease) {
			logger (LOG_ERR, "cannot test with --lastlease");
			goto abort;
		}

		if (sig != 0) {
			logger (LOG_ERR,
				"cannot test with --release or --renew");
			goto abort;
		}
	}

	if (sig != 0) {
		int killed = -1;
		pid = read_pid (options->pidfile);
		if (pid != 0)
			logger (LOG_INFO, "sending signal %d to pid %d",
				sig, pid);

		if (! pid || (killed = kill (pid, sig)))
			logger (sig == SIGALRM ? LOG_INFO : LOG_ERR,
				""PACKAGE" not running");

		if (pid != 0 && (sig != SIGALRM || killed != 0))
			unlink (options->pidfile);

		if (killed == 0) {
			retval = EXIT_SUCCESS;
			goto abort;
		}

		if (sig != SIGALRM)
			goto abort;	
	}

	if (! options->test && ! options->daemonised) {
		if ((pid = read_pid (options->pidfile)) > 0 &&
		    kill (pid, 0) == 0)
		{
			logger (LOG_ERR, ""PACKAGE
				" already running on pid %d (%s)",
				pid, options->pidfile);
			goto abort;
		}

		pidfd = open (options->pidfile,
			      O_WRONLY | O_CREAT | O_NONBLOCK, 0660);
		if (pidfd == -1) {
			logger (LOG_ERR, "open `%s': %s",
				options->pidfile, strerror (errno));
			goto abort;
		}

		/* Lock the file so that only one instance of dhcpcd runs
		 * on an interface */
		if (flock (pidfd, LOCK_EX | LOCK_NB) == -1) {
			logger (LOG_ERR, "flock `%s': %s",
				options->pidfile, strerror (errno));
			goto abort;
		}

		/* dhcpcd.sh should not interhit this fd */
		if ((i = fcntl (pidfd, F_GETFD, 0)) == -1 ||
		    fcntl (pidfd, F_SETFD, i | FD_CLOEXEC) == -1)
			logger (LOG_ERR, "fcntl: %s", strerror (errno));

		writepid (pidfd, getpid ());
		logger (LOG_INFO, PACKAGE " " VERSION " starting");
	}

	/* Seed random */
	srandomdev ();

	/* Massage our filters per platform */
	setup_packet_filters ();

	if (dhcp_run (options, &pidfd) == 0)
		retval = EXIT_SUCCESS;

abort:
	/* If we didn't daemonise then we need to punt the pidfile now */
	if (pidfd > -1) {
		close (pidfd);
		unlink (options->pidfile);
	}

	free (options);

#ifdef THERE_IS_NO_FORK
	/* There may have been an error before the dhcp_run function
	 * clears this, so just do it here to be safe */
	free (dhcpcd_skiproutes);
#endif

	logger (LOG_INFO, "exiting");

	exit (retval);
	/* NOTREACHED */
}
