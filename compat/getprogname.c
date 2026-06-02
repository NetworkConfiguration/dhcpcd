/*
 * getprogname: Portable
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2006-2025 Roy Marples <roy@marples.name>
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "defs.h"
#include "getprogname.h"

static char *progname;
static bool progname_free;
static bool progname_atexit;

static void
freeprogname(void)
{
	if (progname_free)
		free(progname);
	progname = NULL;
}

const char *
getprogname(void)
{
#if defined(__linux__)
	const char *p;

	/* Use PATH_MAX + 1 to avoid truncation. */
	if (progname == NULL) {
		/* readlink(2) does not append a NULL byte,
		 * so zero the buffer. */
		if ((progname = calloc(1, PATH_MAX + 1)) == NULL)
			return NULL;
		progname_free = true;
		if (!progname_atexit) {
			atexit(freeprogname);
			progname_atexit = true;
		}
		if (readlink("/proc/self/exe", progname, PATH_MAX + 1) == -1) {
			free(progname);
			progname = NULL;
			return NULL;
		}
	}
	if (progname[0] == '[')
		return NULL;
	p = strrchr(progname, '/');
	if (p == NULL)
		return progname;
	return p + 1;
#else
#warning "no OS support for getprogname(3)"
	UNUSED(progname_atexit);
	return PACKAGE;
#endif
}

void
setprogname(const char *name)
{
	freeprogname();
	progname = UNCONST(name);
	progname_free = false;
}
