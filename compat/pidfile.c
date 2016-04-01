/*
 * pidfile_lock and pidfile_read
 * Copyright (c) 2016 Roy Marples <roy@marples.name>
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

#include <sys/file.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pidfile.h"
#include "../config.h"

static pid_t pidfile_pid;
static char *pidfile_path;
static int pidfile_fd = -1;

/* Close and optionally remove an existent pidfile,
 * if it was created by this process.
 *
 * Returns 0 on success, otherwise -1. */
static void
pidfile_cleanup(void)
{

	if (pidfile_fd != -1) {
		close(pidfile_fd);
		pidfile_fd = -1;
	}
	if (pidfile_path != NULL) {
		if (pidfile_pid == getpid())
			unlink(pidfile_path);
		free(pidfile_path);
		pidfile_path = NULL;
	}

	pidfile_pid = 0;
}

/* Returns the pid inside path on success, otherwise -1.
 * If no path is give, use the last pidfile path, othewise the default one. */
pid_t
pidfile_read(const char *path)
{
	char buf[16], *eptr;
	int fd, error, e;
	ssize_t n;
	pid_t pid;

	if ((fd = open(path, O_RDONLY)) == -1)
		return  -1;

	n = read(fd, buf, sizeof(buf) - 1);
	error = errno;
	(void) close(fd);
	if (n == -1) {
		errno = error;
		return -1;
	}
	buf[n] = '\0';
	pid = (pid_t)strtoi(buf, &eptr, 10, 1, INT_MAX, &e);
	if (e && !(e == ENOTSUP && *eptr == '\n')) {
		errno = e;
		return -1;
	}
	return pid;
}

/* Locks the pidfile specified by path and writes the process pid to it.
 *
 * Returns 0 on success, otherwise the pid of the process who owns the
 * lock if it can be read, otherwise -1. */
pid_t
pidfile_lock(const char *path)
{
	static bool reg_atexit = false;

	if (!reg_atexit) {
		if (atexit(pidfile_cleanup) == -1)
			return -1;
		reg_atexit = true;
	}

	/* If path has changed (no good reason), clean up the old pidfile. */
	if (pidfile_path != NULL && strcmp(pidfile_path, path) != 0)
		pidfile_cleanup();

	if (pidfile_fd == -1) {
		pid_t pid = -1;
		int opt;

		opt = O_WRONLY | O_CREAT | O_NONBLOCK;
#ifdef O_CLOEXEC
		opt |= O_CLOEXEC;
#endif
#ifdef O_EXLOCK
		opt |= O_EXLOCK;
#endif
		/* Grab an fd to ensure pidfile is created. */
		if ((pidfile_fd = open(path, opt, 0666)) == -1) {
			if (errno == EAGAIN)
				pid = pidfile_read(path);
		} else if ((pidfile_path = strdup(path)) == NULL) {
			int error = errno;

			(void) close(pidfile_fd);
			(void) unlink(path);
			errno = error;
		}
		if (pidfile_fd == -1)
			return pid;

#ifndef O_EXLOCK
		if (flock(pidfile_fd, LOCK_EX | LOCK_NB) == -1) {
			int error = errno;

			(void) close(pidfile_fd);
			pidfile_fd = -1;
			/* Don't unlink, other process has lock. */
			errno = error;
			return errno == EAGAIN ? pidfile_read(path) : -1;
		}
#endif
#ifndef O_CLOEXEC
		if ((opt = fcntl(pidfile_fd, F_GETFD)) == -1 ||
		    fcntl(pidfile_fd, F_SETFD, opt | FD_CLOEXEC) == -1)
		{
			int error = errno;

			(void) close(fd);
			(void) unlink(path);
			errno = error;
			return -1;
		}
#endif
	}

	pidfile_pid = getpid();

	/* Truncate the file, as we could be re-writing it after forking.
	 * Then write the pidfile. */
	if (ftruncate(pidfile_fd, 0) == -1 ||
	    lseek(pidfile_fd, 0, SEEK_SET) == -1 ||
	    dprintf(pidfile_fd, "%d\n", pidfile_pid) == -1)
	{
		int error = errno;

		pidfile_cleanup();
		errno = error;
		return -1;
	}

	/* Hold the fd open to persist the lock. */
	return 0;
}
