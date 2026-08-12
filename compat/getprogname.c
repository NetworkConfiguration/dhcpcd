/*
 * getprogname: compat
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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "common.h"
#include "defs.h"
#include "getprogname.h"

/* Although progname functions are desgined to work with a constant pointer,
 * we know setproctitle might abuse argv[0] so we take a copy of it. */
struct progname {
	const char *progname;
	char *progname_free;
	bool progname_init;
	bool progname_set;
};
static struct progname progname = { .progname = NULL };

static void
progname_exit(void)
{
	free(progname.progname_free);
}

static bool
progname_init(void)
{
	if (!progname.progname_init) {
		if (atexit(progname_exit) != 0)
			return false;
		progname.progname_init = true;
	}

	return true;
}

const char *
getprogname(void)
{
	if (!progname_init())
		return NULL;

	if (progname.progname_set)
		return progname.progname;

#if defined(HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	progname.progname_free = strdup(program_invocation_short_name);
	if (progname.progname_free == NULL)
		progname.progname = PACKAGE; /* fallback */
	else
		progname.progname = progname.progname_free;
#else
#warning "no OS support for getprogname(3)"
	progname.progname = PACKAGE;
#endif

	progname.progname_set = true;
	return progname.progname;
}

void
setprogname(const char *name)
{
	const char *p;

	/* We might be given a path */
	for (p = name + (strlen(name) - 1); p != name; p--) {
		if (*p == '/') {
			name = p + 1;
			break;
		}
	}

	progname.progname = name;
	progname.progname_set = true;
}
