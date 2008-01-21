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

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "config.h"
#include "common.h"
#include "duid.h"
#include "logger.h"

#ifdef ENABLE_DUID

#define THIRTY_YEARS_IN_SECONDS    946707779

void get_duid (interface_t *iface)
{
	FILE *fp;
	uint16_t type = 0;
	uint16_t hw = 0;
	uint32_t ul;
	time_t t;
	unsigned char *p = iface->duid;
	int x = 0;

	if (! iface)
		return;

	/* Remove any existing */
	iface->duid[0] = '\0';
	iface->duid_length = 0;

	/* If we already have a DUID then use it as it's never supposed
	 * to change once we have one even if the interfaces do */
	if ((fp = fopen (DUIDFILE, "r"))) {
		char *fduid;
		char *fdp;
		fduid = fdp = xmalloc ((sizeof (char) * DUID_LEN * 2) + 1);
		if (fscanf (fp, "%260s", fduid) == 1) {
			char c[3];
			c[2] = '\0';
			while (*fdp) {
				c[0] = *fdp++;
				c[1] = *fdp++;
				*p++ = (char) strtol (c, NULL, 16);
			}
		}
		free (fduid);
		iface->duid_length = p - iface->duid;
		fclose (fp);
		return;
	}

	if (errno != ENOENT) {
		logger (LOG_ERR, "fopen `%s': %s", DUIDFILE, strerror (errno));
		return;
	}

	/* No file? OK, lets make one based on our interface */
	type = htons (1); /* DUI-D-LLT */
	memcpy (p, &type, 2);
	p += 2;

	hw = htons (iface->family);
	memcpy (p, &hw, 2);
	p += 2;

	/* time returns seconds from jan 1 1970, but DUID-LLT is
	 * seconds from jan 1 2000 modulo 2^32 */
	t = time (NULL) - THIRTY_YEARS_IN_SECONDS;
	ul = htonl (t & 0xffffffff);
	memcpy (p, &ul, 4);
	p += 4;

	/* Finally, add the MAC address of the interface */
	memcpy (p, iface->hwaddr, iface->hwlen);
	p += iface->hwlen;

	iface->duid_length = p - iface->duid;

	if (! (fp = fopen (DUIDFILE, "w")))
		logger (LOG_ERR, "fopen `%s': %s", DUIDFILE, strerror (errno));
	else {
		size_t i;
		for (i = 0; i < iface->duid_length; i++)
			x += fprintf (fp, "%.2X", iface->duid[i]);
		fprintf (fp, "\n");
		fclose (fp);
	}

	/* Failed to write the duid? scrub it, we cannot use it */
	if (x < 1) {
		memset (iface->duid, 0, sizeof (iface->duid));
		iface->duid_length = 0;
	}
}
#endif
