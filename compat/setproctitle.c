/*
 * Copyright (C) 2002-2019 Igor Sysoev
 * Copyright (C) 2011-2019 Nginx, Inc.
 * All rights reserved.
 *
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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "dhcpcd.h"

#ifdef __sun
#define SETPROCTITLE_PAD	' '
extern const char **environ;
#else
#define	SETPROCTITLE_PAD	'\0'
#endif

static struct dhcpcd_ctx *setproctitle_ctx;
static int setproctitle_argc;
static const char *setproctitle_argv_last;
static char **setproctitle_argv;
static char *setproctitle_buf;

int
setproctitle_init(struct dhcpcd_ctx *ctx, int argc, char **argv)
{
	size_t i, len;
	char *p;

	setproctitle_ctx = ctx;
	len = 0;
	for (i = 0; environ[i] != NULL; i++)
		 len += strlen(environ[i]) + 1;
	if ((setproctitle_buf = malloc(len)) == NULL)
		return -1;

	setproctitle_argc = argc;
	setproctitle_argv = argv;
	setproctitle_argv_last = setproctitle_argv[0];
	for (i = 0; setproctitle_argv[i] != NULL; i++) {
		if (setproctitle_argv_last == setproctitle_argv[i])
			setproctitle_argv_last = setproctitle_argv[i] +
			    strlen(setproctitle_argv[i]) + 1;
	}

	p = setproctitle_buf;
	for (i = 0; environ[i] != NULL; i++) {
		if (setproctitle_argv_last != environ[i])
			continue;
		len = strlen(environ[i]) + 1;
		setproctitle_argv_last = environ[i] + len;
		strlcpy(p, environ[i], len);
		environ[i] = p;
		p += len;
	}

	setproctitle_argv_last--;
	return 0;
}

void
setproctitle_free(void)
{

	free(setproctitle_buf);
}

void
setproctitle(const char *fmt, ...)
{
	const char *progname;
	char *p;
	int n;
	va_list args;
#if 0
	progname = getprogname();
#else
	progname = "dhcpcd";
#endif

	setproctitle_argv[1] = NULL;
#define	LAST_SIZE	(size_t)(setproctitle_argv_last - p)

	p = setproctitle_argv[0];
	n = snprintf(p, LAST_SIZE, "%s: ", progname);
	if (n == -1)
		return;
	p += n;

	va_start(args, fmt);
	n = vsnprintf(p, LAST_SIZE, fmt, args);
	va_end(args);
	if (n == -1)
		return;
	p += n;

#ifdef __sun
	size_t len;
	int i;

	len = 0;
	for (i = 0; i < setproctitle_ctx->argc; i++) {
		len += strlen(setproctitle_ctx->argv[i]) + 1;
	}

	if (len > (size_t)(p - setproctitle_argv[0])) {
		p += strlcpy(p, " (", LAST_SIZE);
		for (i = 0; i < setproctitle_argc; i++) {
			p += strlcpy(p, setproctitle_ctx->argv[i], LAST_SIZE);
			p += strlcpy(p, " ", LAST_SIZE);
		}
	}

	if (*(p - 1) == ' ')
		*(p - 1) = ')';
#endif

	if (setproctitle_argv_last - p > 0)
		memset(p, SETPROCTITLE_PAD, LAST_SIZE);
}
