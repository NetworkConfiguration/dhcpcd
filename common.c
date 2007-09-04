/*
 * dhcpcd - DHCP client daemon -
 * Copyright 2006-2007 Roy Marples <uberlord@gentoo.org>
 * 
 * dhcpcd is an RFC2131 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "logger.h"

/* OK, this should be in dhcpcd.c
 * It's here to make dhcpcd more readable */
#ifdef __linux__
void srandomdev (void)
{
	int fd;
	unsigned long seed;

	fd = open ("/dev/urandom", 0);
	if (fd == -1 || read (fd,  &seed, sizeof (seed)) == -1) {
		logger (LOG_WARNING, "Could not load seed from /dev/urandom: %s",
				strerror (errno));
		seed = time (0);
	}
	if (fd >= 0)
		close(fd);

	srandom (seed);
}
#endif

/* strlcpy is nice, shame glibc does not define it */
#ifdef __GLIBC__
#  if ! defined (__UCLIBC__) && ! defined (__dietlibc__)
size_t strlcpy (char *dst, const char *src, size_t size)
{
	const char *s = src;
	size_t n = size;

	if (n && --n)
		do {
			if (! (*dst++ = *src++))
				break;
		} while (--n);

	if (! n) {
		if (size)
			*dst = '\0';
		while (*src++);
	}

	return (src - s - 1);
}
#  endif
#endif

/* Close our fd's */
void close_fds (void)
{
	int fd;

	if ((fd = open ("/dev/null", O_RDWR)) == -1) {
		logger (LOG_ERR, "open `/dev/null': %s", strerror (errno));
		return;
	}

	dup2 (fd, fileno (stdin));
	dup2 (fd, fileno (stdout));
	dup2 (fd, fileno (stderr));
	if (fd > 2)
		close (fd);
}

/* Handy function to get the time.
 * We only care about time advancements, not the actual time itself
 * Which is why we use CLOCK_MONOTONIC, but it is not available on all
 * platforms.
 */
int get_time (struct timeval *tp)
{
#ifdef CLOCK_MONOTONIC
	struct timespec ts;

	if (clock_gettime (CLOCK_MONOTONIC, &ts) == -1) {
		logger (LOG_ERR, "clock_gettime: %s", strerror (errno));
		return (-1);
	}

	tp->tv_sec = ts.tv_sec;
	tp->tv_usec = ts.tv_nsec / 1000;
	return (0);
#else
	if (gettimeofday (tp, NULL) == -1) {
		logger (LOG_ERR, "gettimeofday: %s", strerror (errno));
		return (-1);
	}
	return (0);
#endif
}

time_t uptime (void)
{
	struct timeval tp;

	if (get_time (&tp) == -1)
		return (-1);

	return (tp.tv_sec);
}

void *xmalloc (size_t s)
{
	void *value = malloc (s);

	if (value)
		return (value);

	logger (LOG_ERR, "memory exhausted");
	exit (EXIT_FAILURE);
}

char *xstrdup (const char *str)
{
	char *value;

	if (! str)
		return (NULL);

	if ((value = strdup (str)))
		return (value);

	logger (LOG_ERR, "memory exhausted");
	exit (EXIT_FAILURE);
}

