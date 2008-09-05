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

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "dhcpcd.h"
#include "if-options.h"
#include "logger.h"

/* For printf implementation that lack %m conversion in printf.
 * uClibc does support it, but it's not enabled by default. */
#ifndef HAVE_PRINTF_M
# ifdef __GLIBC__
#  if !defined(__UCLIBC__) && !defined (__dietlibc__)
#   define HAVE_PRINT_M 1
#  endif
# endif
# ifndef HAVE_PRINT_M
#  define HAVE_PRINT_M 0
# endif
#endif

/* Mac length of format string when we don't have printf with %m */
#define FMT_LEN 1024

static int loglevel = LOG_INFO;

void
setloglevel(int level)
{
	loglevel = level;
}

void
logger(int level, const char *fmt, ...)
{
	va_list va1, va2;
	FILE *f = stderr;
#if HAVE_PRINTF_M
#else
	char fm[FMT_LEN];
	char *fp, *e = NULL, *ep;
	const char *p;
	size_t el = 0, fl = sizeof(fm);
#endif

	va_start(va1, fmt);
	va_copy(va2, va1);
	if (!(options & DHCPCD_DAEMONISED) &&
	    (level <= LOG_ERR || level <= loglevel))
	{
#if HAVE_PRINTF_M
		vfprintf(f, fmt, va1);
#else
		for (p = fmt, fp = fm; *p; p++) {
			if (*p == '%' && p[1] == 'm') {
				if (!e) {
					e = strerror(errno);
					el = strlen(e);
				}
				ep = e;
				while (fl && *ep) {
					*fp++ = *ep++;
					fl--;
				}
				p++;
			} else if (*p == '%' && p[1] == '%' && fl > 2) {
				*fp++ = '%';
				*fp++ = '%';
				p++;
				fl -= 2;
			} else {
				if (fl > 1) {
					*fp++ = *p;
					fl--;
				}
			}
		}
		*fp = '\0';
		vfprintf(f, fm, va1);
#endif
		fputc('\n', f);
	}
	if (level < LOG_DEBUG || level <= loglevel)
		vsyslog(level, fmt, va2);
	va_end(va2);
	va_end(va1);
}
