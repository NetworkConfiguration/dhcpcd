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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "logger.h"

static int loglevel = LOG_WARNING;
static char logprefix[12] = {0};

static const char *syslog_level_msg[] = {
	[LOG_EMERG]     = "EMERGENCY!",
	[LOG_ALERT]     = "ALERT!",
	[LOG_CRIT]      = "Critical!",
	[LOG_WARNING]   = "Warning",
	[LOG_ERR]       = "Error",
	[LOG_INFO]      = "Info",
	[LOG_DEBUG]     = "Debug",
	[LOG_DEBUG + 1] = NULL
};

static const char *syslog_level[] = {
	[LOG_EMERG]     = "LOG_EMERG",
	[LOG_ALERT]     = "LOG_ALERT",
	[LOG_CRIT]      = "LOG_CRIT",
	[LOG_ERR]       = "LOG_ERR",
	[LOG_WARNING]   = "LOG_WARNING",
	[LOG_NOTICE]    = "LOG_NOTICE",
	[LOG_INFO]      = "LOG_INFO",
	[LOG_DEBUG]     = "LOG_DEBUG",
	[LOG_DEBUG + 1]     = NULL
};

int logtolevel (const char *priority)
{
	int i = 0;

	while (syslog_level[i]) {
		if (!strcmp (priority, syslog_level[i]))
			return i;
		i++;
	}
	return -1;
}

void setloglevel (int level)
{
	loglevel = level;
}

void setlogprefix (const char *prefix)
{
	snprintf (logprefix, sizeof (logprefix), "%s", prefix);
}

void logger(int level, const char *fmt, ...)
{
	va_list p;
	va_list p2;
	FILE *f = stderr;

	va_start (p, fmt);
	va_copy (p2, p);

	if (level <= LOG_ERR || level <= loglevel) {
		if (level == LOG_DEBUG || level == LOG_INFO)
			f = stdout;
		fprintf (f, "%s, %s", syslog_level_msg[level], logprefix);
		vfprintf (f, fmt, p);
		fputc ('\n', f);

		/* stdout, stderr may be re-directed to some kind of buffer.
		 * So we always flush to ensure it's written. */
		fflush (f);
	}

	if (level < LOG_DEBUG || level <= loglevel) {
		int len = strlen (logprefix);
		int fmt2len = strlen (fmt) + len + 1;
		char *fmt2 = malloc (sizeof (char) * fmt2len);
		char *pf = fmt2;
		if (fmt2) {
			memcpy (pf, logprefix, len);
			pf += len;
			strlcpy (pf, fmt, fmt2len - len);
			vsyslog (level, fmt2, p2);
			free (fmt2);
		} else {
			vsyslog (level, fmt, p2);
			syslog (LOG_ERR, "logger: memory exhausted");
			exit (EXIT_FAILURE);
		}
	}

	va_end (p2);
	va_end (p);
}

