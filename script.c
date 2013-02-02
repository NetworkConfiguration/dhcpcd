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

#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
/* We can't include spawn.h here because it may not exist.
 * config.h will pull it in, or our compat one. */
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "dhcp6.h"
#include "if-options.h"
#include "if-pref.h"
#include "ipv6rs.h"
#include "net.h"
#include "script.h"
#include "signals.h"

#define DEFAULT_PATH	"PATH=/usr/bin:/usr/sbin:/bin:/sbin"

static const char *if_params[] = {
	"interface",
	"reason",
	"pid",
	"ifmetric",
	"ifwireless",
	"ifflags",
	"ssid",
	"profile",
	"interface_order",
	NULL
};

void
if_printoptions(void)
{
	const char **p;

	for (p = if_params; *p; p++)
		printf(" -  %s\n", *p);
}

static int
exec_script(char *const *argv, char *const *env)
{
	pid_t pid;
	posix_spawnattr_t attr;
	short flags;
	sigset_t defsigs;
	int i;

	/* posix_spawn is a safe way of executing another image
	 * and changing signals back to how they should be. */
	if (posix_spawnattr_init(&attr) == -1)
		return -1;
	flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
	posix_spawnattr_setflags(&attr, flags);
	sigemptyset(&defsigs);
	for (i = 0; i < handle_sigs[i]; i++)
		sigaddset(&defsigs, handle_sigs[i]);
	posix_spawnattr_setsigdefault(&attr, &defsigs);
	posix_spawnattr_setsigmask(&attr, &dhcpcd_sigset);
	errno = 0;
	i = posix_spawn(&pid, argv[0], NULL, &attr, argv, env);
	if (i) {
		errno = i;
		return -1;
	}
	return pid;
}

static char *
make_var(const char *prefix, const char *var)
{
	size_t len;
	char *v;

	len = strlen(prefix) + strlen(var) + 2;
	v = xmalloc(len);
	snprintf(v, len, "%s_%s", prefix, var);
	return v;
}


static void
append_config(char ***env, ssize_t *len,
    const char *prefix, const char *const *config)
{
	ssize_t i, j, e1;
	char **ne, *eq;

	if (config == NULL)
		return;

	ne = *env;
	for (i = 0; config[i] != NULL; i++) {
		eq = strchr(config[i], '=');
		e1 = eq - config[i] + 1;
		for (j = 0; j < *len; j++) {
			if (strncmp(ne[j] + strlen(prefix) + 1,
				config[i], e1) == 0)
			{
				free(ne[j]);
				ne[j] = make_var(prefix, config[i]);
				break;
			}
		}
		if (j == *len) {
			j++;
			ne = xrealloc(ne, sizeof(char *) * (j + 1));
			ne[j - 1] = make_var(prefix, config[i]);
			*len = j;
		}
	}
	*env = ne;
}

static size_t
arraytostr(const char *const *argv, char **s)
{
	const char *const *ap;
	char *p;
	size_t len, l;

	len = 0;
	ap = argv;
	while (*ap)
		len += strlen(*ap++) + 1;
	*s = p = xmalloc(len);
	ap = argv;
	while (*ap) {
		l = strlen(*ap) + 1;
		memcpy(p, *ap, l);
		p += l;
		ap++;
	}
	return len;
}

static ssize_t
make_env(const struct interface *iface, const char *reason, char ***argv)
{
	char **env, *p;
	ssize_t e, elen, l;
	const struct if_options *ifo = iface->state->options;
	const struct interface *ifp;
	int dhcp, dhcp6, ra;
	const struct dhcp6_state *d6_state;

	dhcp = dhcp6 = ra = 0;
	d6_state = D6_STATE(iface);
	if (strcmp(reason, "TEST") == 0) {
		if (d6_state && d6_state->new)
			dhcp6 = 1;
		else if (ipv6rs_has_ra(iface))
			ra = 1;
		else
			dhcp = 1;
	} else if (reason[strlen(reason) - 1] == '6')
		dhcp6 = 1;
	else if (strcmp(reason, "ROUTERADVERT") == 0)
		ra = 1;
	else
		dhcp = 1;

	/* When dumping the lease, we only want to report interface and
	   reason - the other interface variables are meaningless */
	if (options & DHCPCD_DUMPLEASE)
		elen = 2;
	else
		elen = 10;

	/* Make our env */
	env = xmalloc(sizeof(char *) * (elen + 1));
	e = strlen("interface") + strlen(iface->name) + 2;
	env[0] = xmalloc(e);
	snprintf(env[0], e, "interface=%s", iface->name);
	e = strlen("reason") + strlen(reason) + 2;
	env[1] = xmalloc(e);
	snprintf(env[1], e, "reason=%s", reason);
	if (options & DHCPCD_DUMPLEASE)
		goto dumplease;

 	e = 20;
	env[2] = xmalloc(e);
	snprintf(env[2], e, "pid=%d", getpid());
	env[3] = xmalloc(e);
	snprintf(env[3], e, "ifmetric=%d", iface->metric);
	env[4] = xmalloc(e);
	snprintf(env[4], e, "ifwireless=%d", iface->wireless);
	env[5] = xmalloc(e);
	snprintf(env[5], e, "ifflags=%u", iface->flags);
	env[6] = xmalloc(e);
	snprintf(env[6], e, "ifmtu=%d", get_mtu(iface->name));
	l = e = strlen("interface_order=");
	for (ifp = ifaces; ifp; ifp = ifp->next)
		e += strlen(ifp->name) + 1;
	p = env[7] = xmalloc(e);
	strlcpy(p, "interface_order=", e);
	e -= l;
	p += l;
	for (ifp = ifaces; ifp; ifp = ifp->next) {
		l = strlcpy(p, ifp->name, e);
		p += l;
		e -= l;
		*p++ = ' ';
		e--;
	}
	*--p = '\0';
	if (strcmp(reason, "TEST") == 0) {
		env[8] = strdup("if_up=false");
		env[9] = strdup("if_down=false");
	} else if ((dhcp && iface->state->new) ||
	    (dhcp6 && d6_state->new) ||
	    (ra && ipv6rs_has_ra(iface)))
	{
		env[8] = strdup("if_up=true");
		env[9] = strdup("if_down=false");
	} else {
		env[8] = strdup("if_up=false");
		env[9] = strdup("if_down=true");
	}
	if (*iface->state->profile) {
		e = strlen("profile=") + strlen(iface->state->profile) + 2;
		env[elen] = xmalloc(e);
		snprintf(env[elen++], e, "profile=%s", iface->state->profile);
	}
	if (iface->wireless) {
		e = strlen("new_ssid=") + strlen(iface->ssid) + 2;
		if (iface->state->new != NULL ||
		    strcmp(iface->state->reason, "CARRIER") == 0)
		{
			env = xrealloc(env, sizeof(char *) * (elen + 2));
			env[elen] = xmalloc(e);
			snprintf(env[elen++], e, "new_ssid=%s", iface->ssid);
		}
		if (iface->state->old != NULL ||
		    strcmp(iface->state->reason, "NOCARRIER") == 0)
		{
			env = xrealloc(env, sizeof(char *) * (elen + 2));
			env[elen] = xmalloc(e);
			snprintf(env[elen++], e, "old_ssid=%s", iface->ssid);
		}
	}
	if (dhcp && iface->state->old) {
		e = configure_env(NULL, NULL, iface->state->old, iface);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += configure_env(env + elen, "old",
			    iface->state->old, iface);
		}
		append_config(&env, &elen, "old",
		    (const char *const *)ifo->config);
	}
	if (dhcp6 && d6_state->old) {
		e = dhcp6_env(NULL, NULL, iface,
		    d6_state->old, d6_state->old_len);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += dhcp6_env(env + elen, "old", iface,
			    d6_state->old, d6_state->old_len);
		}
	}

dumplease:
	if (dhcp && iface->state->new) {
		e = configure_env(NULL, NULL, iface->state->new, iface);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += configure_env(env + elen, "new",
			    iface->state->new, iface);
		}
		append_config(&env, &elen, "new",
		    (const char *const *)ifo->config);
	}
	if (dhcp6 && d6_state->new) {
		e = dhcp6_env(NULL, NULL, iface,
		    d6_state->new, d6_state->new_len);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += dhcp6_env(env + elen, "new", iface,
			    d6_state->new, d6_state->new_len);
		}
	}
	if (ra) {
		e = ipv6rs_env(NULL, NULL, iface);
		if (e > 0) {
			env = xrealloc(env, sizeof(char *) * (elen + e + 1));
			elen += ipv6rs_env(env + elen, NULL, iface);
		}
	}

	/* Add our base environment */
	if (ifo->environ) {
		e = 0;
		while (ifo->environ[e++])
			;
		env = xrealloc(env, sizeof(char *) * (elen + e + 1));
		e = 0;
		while (ifo->environ[e]) {
			env[elen + e] = xstrdup(ifo->environ[e]);
			e++;
		}
		elen += e;
	}
	env[elen] = '\0';

	*argv = env;
	return elen;
}

static int
send_interface1(int fd, const struct interface *iface, const char *reason)
{
	char **env, **ep, *s;
	ssize_t elen;
	struct iovec iov[2];
	int retval;

	make_env(iface, reason, &env);
	elen = arraytostr((const char *const *)env, &s);
	iov[0].iov_base = &elen;
	iov[0].iov_len = sizeof(ssize_t);
	iov[1].iov_base = s;
	iov[1].iov_len = elen;
	retval = writev(fd, iov, 2);
	ep = env;
	while (*ep)
		free(*ep++);
	free(env);
	free(s);
	return retval;
}

int
send_interface(int fd, const struct interface *iface)
{
	int retval = 0;
	if (send_interface1(fd, iface, iface->state->reason) == -1)
		retval = -1;
	if (ipv6rs_has_ra(iface)) {
		if (send_interface1(fd, iface, "ROUTERADVERT") == -1)
			retval = -1;
	}
	if (D6_STATE_RUNNING(iface)) {
		if (send_interface1(fd, iface, "INFORM6") == -1)
			retval = -1;
	}
	return retval;
}

int
script_runreason(const struct interface *iface, const char *reason)
{
	char *const argv[2] = { UNCONST(iface->state->options->script), NULL };
	char **env = NULL, **ep;
	char *path, *bigenv;
	ssize_t e, elen = 0;
	pid_t pid;
	int status = 0;
	const struct fd_list *fd;
	struct iovec iov[2];

	if (iface->state->options->script == NULL ||
	    iface->state->options->script[0] == '\0' ||
	    strcmp(iface->state->options->script, "/dev/null") == 0)
		return 0;

	if (reason == NULL)
		reason = iface->state->reason;
	syslog(LOG_DEBUG, "%s: executing `%s', reason %s",
	    iface->name, argv[0], reason);

	/* Make our env */
	elen = make_env(iface, reason, &env);
	env = xrealloc(env, sizeof(char *) * (elen + 2));
	/* Add path to it */
	path = getenv("PATH");
	if (path) {
		e = strlen("PATH") + strlen(path) + 2;
		env[elen] = xmalloc(e);
		snprintf(env[elen], e, "PATH=%s", path);
	} else
		env[elen] = xstrdup(DEFAULT_PATH);
	env[++elen] = '\0';

	pid = exec_script(argv, env);
	if (pid == -1)
		syslog(LOG_ERR, "%s: %s: %m", __func__, argv[0]);
	else if (pid != 0) {
		/* Wait for the script to finish */
		while (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR) {
				syslog(LOG_ERR, "waitpid: %m");
				status = 0;
				break;
			}
		}
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status))
				syslog(LOG_ERR,
				    "%s: %s: WEXITSTATUS %d",
				    __func__, argv[0], WEXITSTATUS(status));
		} else if (WIFSIGNALED(status))
			syslog(LOG_ERR, "%s: %s: %s",
			    __func__, argv[0], strsignal(WTERMSIG(status)));
	}

	/* Send to our listeners */
	bigenv = NULL;
	for (fd = control_fds; fd != NULL; fd = fd->next) {
		if (fd->listener) {
			if (bigenv == NULL) {
				elen = arraytostr((const char *const *)env,
				    &bigenv);
				iov[0].iov_base = &elen;
				iov[0].iov_len = sizeof(ssize_t);
				iov[1].iov_base = bigenv;
				iov[1].iov_len = elen;
			}
			if (writev(fd->fd, iov, 2) == -1)
				syslog(LOG_ERR, "%s: writev: %m", __func__);
		}
	}
	free(bigenv);

	/* Cleanup */
	ep = env;
	while (*ep)
		free(*ep++);
	free(env);
	return WEXITSTATUS(status);
}
