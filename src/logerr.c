/*
 * logerr: errx with logging
 * Copyright (c) 2006-2017 Roy Marples <roy@marples.name>
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

#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "logerr.h"

#ifndef	LOGERR_SYSLOG_FACILITY
#define	LOGERR_SYSLOG_FACILITY	LOG_DAEMON
#endif
#ifndef	LOGERR_SYSLOG_OPTS
#define	LOGERR_SYSLOG_OPTS	LOG_PID
#endif

struct logctx {
	unsigned int	 log_opts;
	FILE		*log_file;
};

static struct logctx _logctx = {
	.log_opts = LOGERR_WLOG,
	.log_file = NULL,
};

__printflike(2, 0) static void
vlogprintf(FILE *stream, const char *fmt, va_list args)
{
	va_list a;

	va_copy(a, args);
	vfprintf(stream, fmt, a);
	fputc('\n', stream);
	va_end(a);
}

/*
 * NetBSD's gcc has been modified to check for the non standard %m in printf
 * like functions and warn noisily about it that they should be marked as
 * syslog like instead.
 * This is all well and good, but our logger also goes via vfprintf and
 * when marked as a sysloglike funcion, gcc will then warn us that the
 * function should be printflike instead!
 * This creates an infinte loop of gcc warnings.
 * Until NetBSD solves this issue, we have to disable a gcc diagnostic
 * for our fully standards compliant code in the logger function.
 */
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 5))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-format-attribute"
#endif
__printflike(2, 0) static void
vlogmessage(int pri, const char *fmt, va_list args)
{

	if (pri <= LOG_ERR ||
	    (!(_logctx.log_opts & LOGERR_QUIET) && pri <= LOG_INFO) ||
	    (_logctx.log_opts & LOGERR_DEBUG && pri <= LOG_DEBUG))
		vlogprintf(stderr, fmt, args);

	if (!(_logctx.log_opts & LOGERR_WLOG))
		return;

	if (_logctx.log_file != NULL) {
		struct timeval tv;

		if (pri == LOG_DEBUG && !(_logctx.log_opts & LOGERR_DEBUG))
			return;

		/* Write the time, syslog style. month day time - */
		if (gettimeofday(&tv, NULL) != -1) {
			time_t now;
			struct tm tmnow;
			char buf[32];

			now = tv.tv_sec;
			tzset();
			localtime_r(&now, &tmnow);
			strftime(buf, sizeof(buf), "%b %d %T ", &tmnow);
			fprintf(_logctx.log_file, "%s", buf);
		}

		vlogprintf(_logctx.log_file, fmt, args);
	} else
		vsyslog(pri, fmt, args);
}
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 5))
#pragma GCC diagnostic pop
#endif

__printflike(2, 3) static void
logmessage(int pri, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogmessage(pri, fmt, args);
	va_end(args);
}

__printflike(2, 0) static void
vlogerrmessage(int pri, const char *fmt, va_list args)
{
	int _errno = errno;
	char buf[1024];

	vsnprintf(buf, sizeof(buf), fmt, args);
	logmessage(pri, "%s: %s", buf, strerror(_errno));
}

void
logdebug(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogmessage(LOG_DEBUG, fmt, args);
	va_end(args);
}

void
loginfo(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogmessage(LOG_INFO, fmt, args);
	va_end(args);
}

void
logwarn(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogerrmessage(LOG_WARNING, fmt, args);
	va_end(args);
}

void
logwarnx(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogmessage(LOG_WARNING, fmt, args);
	va_end(args);
}

void
logerr(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogerrmessage(LOG_ERR, fmt, args);
	va_end(args);
}

void
logerrx(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogerrmessage(LOG_ERR, fmt, args);
	va_end(args);
}

void
logsetopts(unsigned int opts)
{

	_logctx.log_opts = opts;
	setlogmask(LOG_UPTO(opts & LOGERR_DEBUG ? LOG_DEBUG : LOG_INFO));
}

int
logopen(const char *path)
{

	if (path == NULL) {
		openlog(NULL, LOGERR_SYSLOG_OPTS, LOGERR_SYSLOG_FACILITY);
		return 1;
	}

	if ((_logctx.log_file = fopen(path, "w")) == NULL)
		return -1;
	setlinebuf(_logctx.log_file);
	return fileno(_logctx.log_file);
}

void
logclose()
{

	closelog();
	if (_logctx.log_file == NULL)
		return;
	fclose(_logctx.log_file);
	_logctx.log_file = NULL;
}
