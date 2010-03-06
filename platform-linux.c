/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2010 Roy Marples <roy@marples.name>
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
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "platform.h"

static const char *mproc = 
#if defined(__alpha__)
	"system type"
#elif defined(__arm__)
	"Hardware"
#elif defined(__avr32__)
	"cpu family"
#elif defined(__bfin__)
	"BOARD Name"
#elif defined(__cris__)
	"cpu model"
#elif defined(__frv__)
	"System"
#elif defined(__i386__) || defined(__x86_64__)
	"vendor_id"
#elif defined(__ia64__)
	"vendor"
#elif defined(__hppa__)
	"model"
#elif defined(__m68k__)
	"MMU"
#elif defined(__mips__)
	"system type"
#elif defined(__powerpc__) || defined(__powerpc64__)
	"machine"
#elif defined(__s390__) || defined(__s390x__)
	"Manufacturer"
#elif defined(__sh__)
	"machine"
#elif defined(sparc) || defined(__sparc__)
	"cpu"
#elif defined(__vax__)
	"cpu"
#else
	NULL
#endif
	;

char *
hardware_platform(void)
{
	FILE *fp;
	char *buf, *p;

	if (mproc == NULL) {
		errno = EINVAL;
		return NULL;
	}

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL)
		return NULL;

	p = NULL;
	while ((buf = get_line(fp))) {
		if (strncmp(buf, mproc, strlen(mproc)) == 0) {
			p = strchr(buf, ':');
			if (p != NULL && ++p != NULL) {
				while (*p == ' ')
					p++;
				break;
			}
		}
	}
	fclose(fp);

	if (p == NULL)
		errno = ESRCH;
	return p;
}
