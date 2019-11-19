/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#define prctl_arg(x) ((unsigned long)x)

static char *setproctitle_argv;

int setproctitle(const char *fmt, ...)
{
	const char *progname;
	char title[1024], *tp;
	size_t tl, n;
	va_list args;
	int ret;

#if 0
	progname = getprogname();
#else
	progname = "dhcpcd";
#endif

	tp = title;
	tl = sizeof(title);
	n = strlcpy(tp, progname, tl);
	tp += n;
	tl -= n;
	n = strlcpy(tp, ": ", tl);
	tp += n;
	tl -= n;
	va_start(args, fmt);
	vsnprintf(tp, tl, fmt, args);
	va_end(args);

#if defined(__linux__) && defined(PR_SET_MM_MAP)
	int fd, i;
	char *buf_ptr, *tmp_proctitle;
	char buf[BUFSIZ];
	ssize_t bytes_read;
	size_t len;

	/*
	 * We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	unsigned long start_data, end_data, start_brk, start_code, end_code,
	    start_stack, arg_start, arg_end, env_start, env_end;
	long brk_val;
	struct prctl_mm_map prctl_map;

	fd = open("/proc/self/stat", O_RDONLY);
	if (fd == -1)
		return -1;
	bytes_read = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (bytes_read == -1)
		return -1;

	buf[bytes_read] = '\0';

	/* Skip the first 25 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	buf_ptr = strchr(buf, ' ');
	for (i = 0; i < 24; i++) {
		if (!buf_ptr)
			return -1;
		buf_ptr = strchr(buf_ptr + 1, ' ');
	}
	if (!buf_ptr)
		return -1;

	i = sscanf(buf_ptr, "%lu %lu %lu", &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!buf_ptr)
			return -1;
		buf_ptr = strchr(buf_ptr + 1, ' ');
	}

	if (!buf_ptr)
		return -1;

	i = sscanf(buf_ptr, "%lu %lu %lu %*u %*u %lu %lu", &start_data,
		   &end_data, &start_brk, &env_start, &env_end);
	if (i != 5)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	len = strlen(title) + 1;

	tmp_proctitle = realloc(setproctitle_argv, len);
	if (!tmp_proctitle)
		return -1;

	setproctitle_argv = tmp_proctitle;

	arg_start = (unsigned long)setproctitle_argv;
	arg_end = arg_start + len;

	brk_val = syscall(__NR_brk, 0);

	prctl_map = (struct prctl_mm_map){
	    .start_code = start_code,
	    .end_code = end_code,
	    .start_stack = start_stack,
	    .start_data = start_data,
	    .end_data = end_data,
	    .start_brk = start_brk,
	    .brk = (unsigned long long)brk_val,
	    .arg_start = arg_start,
	    .arg_end = arg_end,
	    .env_start = env_start,
	    .env_end = env_end,
	    .auxv = NULL,
	    .auxv_size = 0,
	    .exe_fd = (unsigned int)-1,
	};

	ret = prctl(PR_SET_MM, prctl_arg(PR_SET_MM_MAP), prctl_arg(&prctl_map),
		    prctl_arg(sizeof(prctl_map)), prctl_arg(0));
	if (ret == 0)
		(void)strlcpy((char *)arg_start, title, len);
#else
	/* Solaris doesn't work with the ARGV stamping approach.
	 * Is there any other way? */
	ret = -1;
	errno = ENOTSUP;
#endif
	return ret;
}

void
setproctitle_free(void)
{

	free(setproctitle_argv);
}
