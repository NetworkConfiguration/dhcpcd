/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * eloop - portable event based main loop.
 * Copyright (c) 2006-2020 Roy Marples <roy@marples.name>
 * All rights reserved.

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

#if (defined(__unix__) || defined(unix)) && !defined(USG)
#include <sys/param.h>
#endif
#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* config.h should define HAVE_PPOLL, etc. */
#if defined(HAVE_CONFIG_H) && !defined(NO_CONFIG_H)
#include "config.h"
#endif

#if defined(HAVE_KQUEUE) || defined(HAVE_EPOLL) || defined(HAVE_PPOLL)
#elif defined(HAVE_POLLTS)
#define ppoll pollts
#elif !defined(HAVE_PSELECT)
#pragma message("Compiling eloop with pselect(2) support.")
#define HAVE_PSELECT
#define ppoll eloop_ppoll
#endif

#if defined(HAVE_KQUEUE)
#include <sys/event.h>
#if defined(__DragonFly__) || defined(__FreeBSD__)
#define	_kevent(kq, cl, ncl, el, nel, t) \
	kevent((kq), (cl), (int)(ncl), (el), (int)(nel), (t))
#else
#define	_kevent kevent
#endif
#define NFD 2
#elif defined(HAVE_EPOLL)
#include <sys/epoll.h>
#define	NFD 1
#else
#include <poll.h>
#define USE_POLL
#define NFD 1
#endif

#include "eloop.h"

#ifndef UNUSED
#define UNUSED(a) (void)((a))
#endif
#ifndef __unused
#ifdef __GNUC__
#define __unused   __attribute__((__unused__))
#else
#define __unused
#endif
#endif

#ifdef HAVE_PSELECT
#include <sys/select.h>
#endif

/* Our structures require TAILQ macros, which really every libc should
 * ship as they are useful beyond belief.
 * Sadly some libc's don't have sys/queue.h and some that do don't have
 * the TAILQ_FOREACH macro. For those that don't, the application using
 * this implementation will need to ship a working queue.h somewhere.
 * If we don't have sys/queue.h found in config.h, then
 * allow QUEUE_H to override loading queue.h in the current directory. */
#ifndef TAILQ_FOREACH
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#elif defined(QUEUE_H)
#define __QUEUE_HEADER(x) #x
#define _QUEUE_HEADER(x) __QUEUE_HEADER(x)
#include _QUEUE_HEADER(QUEUE_H)
#else
#include "queue.h"
#endif
#endif

#ifdef ELOOP_DEBUG
#include <stdio.h>
#endif

/*
 * Allow a backlog of signals.
 * If you use many eloops in the same process, they should all
 * use the same signal handler or have the signal handler unset.
 * Otherwise the signal might not behave as expected.
 */
#define ELOOP_NSIGNALS	5

/*
 * time_t is a signed integer of an unspecified size.
 * To adjust for time_t wrapping, we need to work the maximum signed
 * value and use that as a maximum.
 */
#ifndef TIME_MAX
#define	TIME_MAX	((1ULL << (sizeof(time_t) * NBBY - 1)) - 1)
#endif
/* The unsigned maximum is then simple - multiply by two and add one. */
#ifndef UTIME_MAX
#define	UTIME_MAX	(TIME_MAX * 2) + 1
#endif

struct eloop_event {
	TAILQ_ENTRY(eloop_event) next;
	int fd;
	void (*read_cb)(void *);
	void *read_cb_arg;
	void (*write_cb)(void *);
	void *write_cb_arg;
#ifdef USE_POLL
	struct pollfd *pollfd;
#endif
};

struct eloop_timeout {
	TAILQ_ENTRY(eloop_timeout) next;
	unsigned int seconds;
	unsigned int nseconds;
	void (*callback)(void *);
	void *arg;
	int queue;
};

struct eloop {
	TAILQ_HEAD (event_head, eloop_event) events;
	size_t nevents;
	struct event_head free_events;
	bool events_need_setup;

	struct timespec now;
	TAILQ_HEAD (timeout_head, eloop_timeout) timeouts;
	struct timeout_head free_timeouts;

	const int *signals;
	size_t nsignals;
	void (*signal_cb)(int, void *);
	void *signal_cb_ctx;

#if defined(HAVE_KQUEUE) || defined(HAVE_EPOLL)
	int fd;
#endif
#if defined(HAVE_KQUEUE)
	struct kevent *fds;
#elif defined(HAVE_EPOLL)
	struct epoll_event *fds;
#else
	struct pollfd *fds;
#endif
	size_t nfds;

	int exitnow;
	int exitcode;
	bool cleared;
};

#ifdef HAVE_REALLOCARRAY
#define	eloop_realloca	reallocarray
#else
/* Handy routing to check for potential overflow.
 * reallocarray(3) and reallocarr(3) are not portable. */
#define SQRT_SIZE_MAX (((size_t)1) << (sizeof(size_t) * CHAR_BIT / 2))
static void *
eloop_realloca(void *ptr, size_t n, size_t size)
{

	if ((n | size) >= SQRT_SIZE_MAX && n > SIZE_MAX / size) {
		errno = EOVERFLOW;
		return NULL;
	}
	return realloc(ptr, n * size);
}
#endif

#ifdef HAVE_PSELECT
/* Wrapper around pselect, to imitate the ppoll call. */
int
eloop_ppoll(struct pollfd * fds, nfds_t nfds,
    const struct timespec *ts, const sigset_t *sigmask)
{
	fd_set read_fds, write_fds;
	nfds_t n;
	int maxfd, r;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	maxfd = 0;
	for (n = 0; n < nfds; n++) {
		if (fds[n].events & POLLIN) {
			FD_SET(fds[n].fd, &read_fds);
			if (fds[n].fd > maxfd)
				maxfd = fds[n].fd;
		}
		if (fds[n].events & POLLOUT) {
			FD_SET(fds[n].fd, &write_fds);
			if (fds[n].fd > maxfd)
				maxfd = fds[n].fd;
		}
	}

	r = pselect(maxfd + 1, &read_fds, &write_fds, NULL, ts, sigmask);
	if (r > 0) {
		for (n = 0; n < nfds; n++) {
			fds[n].revents =
			    FD_ISSET(fds[n].fd, &read_fds) ? POLLIN : 0;
			if (FD_ISSET(fds[n].fd, &write_fds))
				fds[n].revents |= POLLOUT;
		}
	}

	return r;
}
#endif

unsigned long long
eloop_timespec_diff(const struct timespec *tsp, const struct timespec *usp,
    unsigned int *nsp)
{
	unsigned long long tsecs, usecs, secs;
	long nsecs;

	if (tsp->tv_sec < 0) /* time wreapped */
		tsecs = UTIME_MAX - (unsigned long long)(-tsp->tv_sec);
	else
		tsecs = (unsigned long long)tsp->tv_sec;
	if (usp->tv_sec < 0) /* time wrapped */
		usecs = UTIME_MAX - (unsigned long long)(-usp->tv_sec);
	else
		usecs = (unsigned long long)usp->tv_sec;

	if (usecs > tsecs) /* time wrapped */
		secs = (UTIME_MAX - usecs) + tsecs;
	else
		secs = tsecs - usecs;

	nsecs = tsp->tv_nsec - usp->tv_nsec;
	if (nsecs < 0) {
		if (secs == 0)
			nsecs = 0;
		else {
			secs--;
			nsecs += NSEC_PER_SEC;
		}
	}
	if (nsp != NULL)
		*nsp = (unsigned int)nsecs;
	return secs;
}

static void
eloop_reduce_timers(struct eloop *eloop)
{
	struct timespec now;
	unsigned long long secs;
	unsigned int nsecs;
	struct eloop_timeout *t;

	clock_gettime(CLOCK_MONOTONIC, &now);
	secs = eloop_timespec_diff(&now, &eloop->now, &nsecs);

	TAILQ_FOREACH(t, &eloop->timeouts, next) {
		if (secs > t->seconds) {
			t->seconds = 0;
			t->nseconds = 0;
		} else {
			t->seconds -= (unsigned int)secs;
			if (nsecs > t->nseconds) {
				if (t->seconds == 0)
					t->nseconds = 0;
				else {
					t->seconds--;
					t->nseconds = NSEC_PER_SEC
					    - (nsecs - t->nseconds);
				}
			} else
				t->nseconds -= nsecs;
		}
	}

	eloop->now = now;
}

static int
eloop_event_setup_fds(struct eloop *eloop)
{
	struct eloop_event *e, *ne;
#if defined(HAVE_KQUEUE)
	struct kevent *pfd;
	size_t nfds = eloop->nsignals;
#elif defined(HAVE_EPOLL)
	struct epoll_event *pfd;
	size_t nfds = 0;
#else
	struct pollfd *pfd;
	size_t nfds = 0;
#endif

	nfds += eloop->nevents * NFD;
	if (eloop->nfds < nfds) {
		pfd = eloop_realloca(eloop->fds, nfds, sizeof(*pfd));
		if (pfd == NULL)
			return -1;
		eloop->fds = pfd;
		eloop->nfds = nfds;
	}

#ifdef USE_POLL
	pfd = eloop->fds;
#endif
	TAILQ_FOREACH_SAFE(e, &eloop->events, next, ne) {
		if (e->fd == -1) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
			continue;
		}
#ifdef ELOOP_DEBUG
		fprintf(stderr, "%s(%d) fd=%d, rcb=%p, wcb=%p\n",
		    __func__, getpid(), e->fd, e->read_cb, e->write_cb);
#endif
#ifdef USE_POLL
		e->pollfd = pfd;
		pfd->fd = e->fd;
		pfd->events = 0;
		if (e->read_cb != NULL)
			pfd->events |= POLLIN;
		if (e->write_cb != NULL)
			pfd->events |= POLLOUT;
		pfd->revents = 0;
		pfd++;
#endif
	}

	eloop->events_need_setup = false;
	return 0;
}

size_t
eloop_event_count(const struct eloop *eloop)
{

	return eloop->nevents;
}

int
eloop_event_add_rw(struct eloop *eloop, int fd,
    void (*read_cb)(void *), void *read_cb_arg,
    void (*write_cb)(void *), void *write_cb_arg)
{
	struct eloop_event *e;
	bool added;
#if defined(HAVE_KQUEUE)
	struct kevent ke[2];
	size_t n;
#elif defined(HAVE_EPOLL)
	struct epoll_event epe;
	int op;
#endif

	assert(eloop != NULL);
	assert(read_cb != NULL || write_cb != NULL);
	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(e, &eloop->events, next) {
		if (e->fd == fd)
			break;
	}

	if (e == NULL) {
		added = true;
		e = TAILQ_FIRST(&eloop->free_events);
		if (e != NULL)
			TAILQ_REMOVE(&eloop->free_events, e, next);
		else {
			e = malloc(sizeof(*e));
			if (e == NULL) {
				return -1;
			}
		}
		TAILQ_INSERT_HEAD(&eloop->events, e, next);
		eloop->nevents++;
		e->fd = fd;
		e->read_cb = read_cb;
		e->read_cb_arg = read_cb_arg;
		e->write_cb = write_cb;
		e->write_cb_arg = write_cb_arg;
		goto setup;
	} else
		added = false;

	if (read_cb != NULL) {
		e->read_cb = read_cb;
		e->read_cb_arg = read_cb_arg;
	}
	if (write_cb != NULL) {
		e->write_cb = write_cb;
		e->write_cb_arg = write_cb_arg;
	}

setup:
#if defined(HAVE_KQUEUE)
	EV_SET(&ke[0], (uintptr_t)fd, EVFILT_READ, EV_ADD, 0, 0, e);
	if (e->write_cb != NULL) {
		EV_SET(&ke[1], (uintptr_t)fd, EVFILT_WRITE, EV_ADD, 0, 0, e);
		n = 2;
	} else
		n = 1;
	if (_kevent(eloop->fd, ke, n, NULL, 0, NULL) == -1) {
		if (added) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
		}
		return -1;
	}
#elif defined(HAVE_EPOLL)
	memset(&epe, 0, sizeof(epe));
	epe.data.ptr = e;
	if (e->read_cb != NULL)
		epe.events |= EPOLLIN;
	if (e->write_cb != NULL)
		epe.events |= EPOLLOUT;

	op = added ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
	if (epoll_ctl(eloop->fd, op, fd, &epe) == -1) {
		if (added) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
		}
		return -1;
	}
#else
	e->pollfd = NULL;
	UNUSED(added);
#endif
	eloop->events_need_setup = true;
	return 0;
}

int
eloop_event_add(struct eloop *eloop, int fd,
    void (*read_cb)(void *), void *read_cb_arg)
{

	return eloop_event_add_rw(eloop, fd, read_cb, read_cb_arg, NULL, NULL);
}

int
eloop_event_add_w(struct eloop *eloop, int fd,
    void (*write_cb)(void *), void *write_cb_arg)
{

	return eloop_event_add_rw(eloop, fd, NULL,NULL, write_cb, write_cb_arg);
}

int
eloop_event_delete_write(struct eloop *eloop, int fd, int write_only)
{
	struct eloop_event *e;
#ifdef HAVE_KQUEUE
#endif

	assert(eloop != NULL);
	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(e, &eloop->events, next) {
		if (e->fd == fd)
			break;
	}
	if (e == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (write_only) {
#if defined(HAVE_KQUEUE)
		if (e->write_cb != NULL) {
			struct kevent ke;

			EV_SET(&ke, (uintptr_t)e->fd,
			    EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
			if (_kevent(eloop->fd, &ke, 1, NULL, 0, NULL) == -1)
				return -1;
		}
#elif defined(HAVE_EPOLL)
		if (e->write_cb != NULL) {
			struct epoll_event epe;

			memset(&epe, 0, sizeof(epe));
			epe.data.ptr = e;
			if (e->read_cb != NULL)
			    epe.events |= EPOLLIN;
			if (epoll_ctl(eloop->fd,
			    e->read_cb != NULL ? EPOLL_CTL_MOD : EPOLL_CTL_DEL,
			    e->fd, &epe) == -1)
				return -1;
		}
#else
		if (e->pollfd != NULL) {
			e->pollfd->events &= ~POLLOUT;
			e->pollfd->revents &= ~POLLOUT;
		}
#endif
		e->write_cb = NULL;
		e->write_cb_arg = NULL;
		return 0;
	}

	e->fd = -1;
	eloop->nevents--;
	eloop->events_need_setup = true;
	return 1;
}

/*
 * This implementation should cope with UINT_MAX seconds on a system
 * where time_t is INT32_MAX. It should also cope with the monotonic timer
 * wrapping, although this is highly unlikely.
 * unsigned int should match or be greater than any on wire specified timeout.
 */
static int
eloop_q_timeout_add(struct eloop *eloop, int queue,
    unsigned int seconds, unsigned int nseconds,
    void (*callback)(void *), void *arg)
{
	struct eloop_timeout *t, *tt = NULL;

	assert(eloop != NULL);
	assert(callback != NULL);
	assert(nseconds <= NSEC_PER_SEC);

	/* Remove existing timeout if present. */
	TAILQ_FOREACH(t, &eloop->timeouts, next) {
		if (t->callback == callback && t->arg == arg) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			break;
		}
	}

	if (t == NULL) {
		/* No existing, so allocate or grab one from the free pool. */
		if ((t = TAILQ_FIRST(&eloop->free_timeouts))) {
			TAILQ_REMOVE(&eloop->free_timeouts, t, next);
		} else {
			if ((t = malloc(sizeof(*t))) == NULL)
				return -1;
		}
	}

	eloop_reduce_timers(eloop);

	t->seconds = seconds;
	t->nseconds = nseconds;
	t->callback = callback;
	t->arg = arg;
	t->queue = queue;

	/* The timeout list should be in chronological order,
	 * soonest first. */
	TAILQ_FOREACH(tt, &eloop->timeouts, next) {
		if (t->seconds < tt->seconds ||
		    (t->seconds == tt->seconds && t->nseconds < tt->nseconds))
		{
			TAILQ_INSERT_BEFORE(tt, t, next);
			return 0;
		}
	}
	TAILQ_INSERT_TAIL(&eloop->timeouts, t, next);
	return 0;
}

int
eloop_q_timeout_add_tv(struct eloop *eloop, int queue,
    const struct timespec *when, void (*callback)(void *), void *arg)
{

	if (when->tv_sec < 0 || (unsigned long)when->tv_sec > UINT_MAX) {
		errno = EINVAL;
		return -1;
	}
	if (when->tv_nsec < 0 || when->tv_nsec > NSEC_PER_SEC) {
		errno = EINVAL;
		return -1;
	}

	return eloop_q_timeout_add(eloop, queue,
	    (unsigned int)when->tv_sec, (unsigned int)when->tv_sec,
	    callback, arg);
}

int
eloop_q_timeout_add_sec(struct eloop *eloop, int queue, unsigned int seconds,
    void (*callback)(void *), void *arg)
{

	return eloop_q_timeout_add(eloop, queue, seconds, 0, callback, arg);
}

int
eloop_q_timeout_add_msec(struct eloop *eloop, int queue, unsigned long when,
    void (*callback)(void *), void *arg)
{
	unsigned long seconds, nseconds;

	seconds = when / MSEC_PER_SEC;
	if (seconds > UINT_MAX) {
		errno = EINVAL;
		return -1;
	}

	nseconds = (when % MSEC_PER_SEC) * NSEC_PER_MSEC;
	return eloop_q_timeout_add(eloop, queue,
		(unsigned int)seconds, (unsigned int)nseconds, callback, arg);
}

int
eloop_q_timeout_delete(struct eloop *eloop, int queue,
    void (*callback)(void *), void *arg)
{
	struct eloop_timeout *t, *tt;
	int n;

	assert(eloop != NULL);

	n = 0;
	TAILQ_FOREACH_SAFE(t, &eloop->timeouts, next, tt) {
		if ((queue == 0 || t->queue == queue) &&
		    t->arg == arg &&
		    (!callback || t->callback == callback))
		{
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			TAILQ_INSERT_TAIL(&eloop->free_timeouts, t, next);
			n++;
		}
	}
	return n;
}

void
eloop_exit(struct eloop *eloop, int code)
{

	assert(eloop != NULL);

	eloop->exitcode = code;
	eloop->exitnow = 1;
}

void
eloop_enter(struct eloop *eloop)
{

	assert(eloop != NULL);

	eloop->exitnow = 0;
}

/* Must be called after fork(2) */
int
eloop_forked(struct eloop *eloop)
{
#if defined(HAVE_KQUEUE) || defined(HAVE_EPOLL)
	struct eloop_event *e;
#if defined(HAVE_KQUEUE)
	struct kevent *pfds, *pfd;
	size_t i;
#elif defined(HAVE_EPOLL)
	struct epoll_event epe = { .events = 0 };
#endif

	assert(eloop != NULL);
#if defined(HAVE_KQUEUE) || defined(HAVE_EPOLL)
	if (eloop->fd != -1)
		close(eloop->fd);
	if (eloop_open(eloop) == -1)
		return -1;
#endif

#ifdef HAVE_KQUEUE
	pfds = malloc((eloop->nsignals + (eloop->nevents * NFD)) * sizeof(*pfds));
	pfd = pfds;

	if (eloop->signal_cb != NULL) {
		for (i = 0; i < eloop->nsignals; i++) {
			EV_SET(pfd++, (uintptr_t)eloop->signals[i],
			    EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		}
	} else
		i = 0;
#endif

	TAILQ_FOREACH(e, &eloop->events, next) {
		if (e->fd == -1)
			continue;
#if defined(HAVE_KQUEUE)
		if (e->read_cb != NULL) {
			EV_SET(pfd++, (uintptr_t)e->fd,
			    EVFILT_READ, EV_ADD, 0, 0, e);
			i++;
		}
		if (e->write_cb != NULL) {
			EV_SET(pfd++, (uintptr_t)e->fd,
			    EVFILT_WRITE, EV_ADD, 0, 0, e);
			i++;
		}
#elif defined(HAVE_EPOLL)
		memset(&epe, 0, sizeof(epe));
		epe.data.ptr = e;
		if (e->read_cb != NULL)
			epe.events |= EPOLLIN;
		if (e->write_cb != NULL)
			epe.events |= EPOLLOUT;
		if (epoll_ctl(eloop->fd, EPOLL_CTL_ADD, e->fd, &epe) == -1)
			return -1;
#endif
	}

#if defined(HAVE_KQUEUE)
	if (i == 0)
		return 0;
	return _kevent(eloop->fd, pfds, i, NULL, 0, NULL);
#else
	return 0;
#endif
#else
	UNUSED(eloop);
	return 0;
#endif
}

int
eloop_open(struct eloop *eloop)
{
	int fd;

	assert(eloop != NULL);
#if defined(HAVE_KQUEUE1)
	fd = kqueue1(O_CLOEXEC);
#elif defined(HAVE_KQUEUE)
	int flags;

	fd = kqueue();
	flags = fcntl(fd, F_GETFD, 0);
	if (!(flags != -1 && !(flags & FD_CLOEXEC) &&
	    fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0))
	{
		close(fd);
		return -1;
	}
#elif defined(HAVE_EPOLL)
	fd = epoll_create1(EPOLL_CLOEXEC);
#else
	fd = 0;
#endif

#ifndef USE_POLL
	eloop->fd = fd;
#endif

	return fd;
}

int
eloop_signal_set_cb(struct eloop *eloop,
    const int *signals, size_t nsignals,
    void (*signal_cb)(int, void *), void *signal_cb_ctx)
{
#ifdef HAVE_KQUEUE
	size_t i;
	struct kevent *ke, *kes;
#endif
	int error = 0;

	assert(eloop != NULL);

#ifdef HAVE_KQUEUE
	ke = kes = malloc(MAX(eloop->nsignals, nsignals) * sizeof(*kes));
	if (kes == NULL)
		return -1;
	for (i = 0; i < eloop->nsignals; i++) {
		EV_SET(ke++, (uintptr_t)eloop->signals[i],
		    EVFILT_SIGNAL, EV_DELETE, 0, 0, NULL);
	}
	if (i != 0 && _kevent(eloop->fd, kes, i, NULL, 0, NULL) == -1) {
		error = -1;
		goto out;
	}
#endif

	eloop->signals = signals;
	eloop->nsignals = nsignals;
	eloop->signal_cb = signal_cb;
	eloop->signal_cb_ctx = signal_cb_ctx;

#ifdef HAVE_KQUEUE
	if (signal_cb == NULL)
		goto out;
	ke = kes;
	for (i = 0; i < eloop->nsignals; i++) {
		EV_SET(ke++, (uintptr_t)eloop->signals[i],
		    EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	}
	if (i != 0 && _kevent(eloop->fd, kes, i, NULL, 0, NULL) == -1)
		error = -1;
out:
	free(kes);
#endif

	return error;
}

#ifndef HAVE_KQUEUE
static volatile int _eloop_sig[ELOOP_NSIGNALS];
static volatile size_t _eloop_nsig;

static void
eloop_signal3(int sig, __unused siginfo_t *siginfo, __unused void *arg)
{

	if (_eloop_nsig == __arraycount(_eloop_sig)) {
#ifdef ELOOP_DEBUG
		fprintf(stderr, "%s: signal storm, discarding signal %d\n",
		    __func__, sig);
#endif
		return;
	}

	_eloop_sig[_eloop_nsig++] = sig;
}
#endif

int
eloop_signal_mask(struct eloop *eloop, sigset_t *oldset)
{
	sigset_t newset;
	size_t i;
#ifndef HAVE_KQUEUE
	struct sigaction sa = {
	    .sa_sigaction = eloop_signal3,
	    .sa_flags = SA_SIGINFO,
	};
#endif

	assert(eloop != NULL);

	sigemptyset(&newset);
	for (i = 0; i < eloop->nsignals; i++)
		sigaddset(&newset, eloop->signals[i]);
	if (sigprocmask(SIG_SETMASK, &newset, oldset) == -1)
		return -1;

#ifndef HAVE_KQUEUE
	sigemptyset(&sa.sa_mask);

	for (i = 0; i < eloop->nsignals; i++) {
		if (sigaction(eloop->signals[i], &sa, NULL) == -1)
			return -1;
	}
#endif

	return 0;
}

struct eloop *
eloop_new(void)
{
	struct eloop *eloop;

	eloop = calloc(1, sizeof(*eloop));
	if (eloop == NULL)
		return NULL;

	/* Check we have a working monotonic clock. */
	if (clock_gettime(CLOCK_MONOTONIC, &eloop->now) == -1) {
		free(eloop);
		return NULL;
	}

	TAILQ_INIT(&eloop->events);
	TAILQ_INIT(&eloop->free_events);
	TAILQ_INIT(&eloop->timeouts);
	TAILQ_INIT(&eloop->free_timeouts);
	eloop->exitcode = EXIT_FAILURE;

	if (eloop_open(eloop) == -1) {
		eloop_free(eloop);
		return NULL;
	}

	return eloop;
}

void
eloop_clear(struct eloop *eloop, ...)
{
	va_list va1, va2;
	int except_fd;
	struct eloop_event *e, *ne;
	struct eloop_timeout *t;

	if (eloop == NULL)
		return;

	va_start(va1, eloop);
	TAILQ_FOREACH_SAFE(e, &eloop->events, next, ne) {
		va_copy(va2, va1);
		do
			except_fd = va_arg(va2, int);
		while (except_fd != -1 && except_fd != e->fd);
		va_end(va2);
		if (e->fd == except_fd && e->fd != -1)
			continue;
		TAILQ_REMOVE(&eloop->events, e, next);
		if (e->fd != -1) {
			close(e->fd);
			eloop->nevents--;
		}
		free(e);
	}
	va_end(va1);

	/* Free the pollfd buffer and ensure it's re-created before
	 * the next run. This allows us to shrink it incase we use a lot less
	 * signals and fds to respond to after forking. */
	free(eloop->fds);
	eloop->fds = NULL;
	eloop->nfds = 0;
	eloop->events_need_setup = true;

	while ((e = TAILQ_FIRST(&eloop->free_events))) {
		TAILQ_REMOVE(&eloop->free_events, e, next);
		free(e);
	}
	while ((t = TAILQ_FIRST(&eloop->timeouts))) {
		TAILQ_REMOVE(&eloop->timeouts, t, next);
		free(t);
	}
	while ((t = TAILQ_FIRST(&eloop->free_timeouts))) {
		TAILQ_REMOVE(&eloop->free_timeouts, t, next);
		free(t);
	}
	eloop->cleared = true;
}

void
eloop_free(struct eloop *eloop)
{

	eloop_clear(eloop, -1);
#if defined(HAVE_KQUEUE) || defined(HAVE_EPOLL)
	if (eloop != NULL && eloop->fd != -1)
		close(eloop->fd);
#endif
	free(eloop);
}

#if defined(HAVE_KQUEUE)
static int
eloop_run_kqueue(struct eloop *eloop, struct timespec *ts)
{
	int n, nn;
	struct kevent *ke;
	struct eloop_event *e;

	n = _kevent(eloop->fd, NULL, 0, eloop->fds, eloop->nevents, ts);
	if (n == -1)
		return -1;

	for (nn = n, ke = eloop->fds; nn != 0; nn--, ke++) {
		if (eloop->cleared)
			break;
		e = (struct eloop_event *)ke->udata;
#if 0
		/* What to do with this?
		 * Currently we behave like ppoll and just try the
		 * socket and get the error there. */
		if (ke->flags & EV_ERROR)
			errno = (int)ke->data;
#endif
		switch (ke->filter) {
		case EVFILT_SIGNAL:
			eloop->signal_cb((int)ke->ident,
			    eloop->signal_cb_ctx);
			break;
		case EVFILT_WRITE:
			e->write_cb(e->write_cb_arg);
			break;
		case EVFILT_READ:
			e->read_cb(e->read_cb_arg);
			break;
		}
	}
	return n;
}

#elif defined(HAVE_EPOLL)

static int
eloop_run_epoll(struct eloop *eloop, struct timespec *ts, sigset_t *signals)
{
	int timeout, n, nn;
	struct epoll_event *epe;
	struct eloop_event *e;

	if (ts != NULL) {
		if (ts->tv_sec > INT_MAX / 1000 ||
		    (ts->tv_sec == INT_MAX / 1000 &&
		     ((ts->tv_nsec + 999999) / 1000000 > INT_MAX % 1000000)))
			timeout = INT_MAX;
		else
			timeout = (int)(ts->tv_sec * 1000 +
			    (ts->tv_nsec + 999999) / 1000000);
	} else
		timeout = -1;

	if (signals != NULL)
		n = epoll_pwait(eloop->fd, eloop->fds,
		    (int)eloop->nevents, timeout, signals);
	else
		n = epoll_wait(eloop->fd, eloop->fds,
		    (int)eloop->nevents, timeout);
	if (n == -1)
		return -1;

	for (nn = n, epe = eloop->fds; nn != 0; nn--, epe++) {
		if (eloop->cleared)
			break;
		e = (struct eloop_event *)epe->data.ptr;
		if (epe->events & EPOLLOUT &&
		    e->fd != -1 && e->write_cb != NULL)
			e->write_cb(e->write_cb_arg);
		if (epe->events && (EPOLLIN | EPOLLERR | EPOLLHUP) &&
		    e->fd != -1 && e->read_cb != NULL)
			e->read_cb(e->read_cb_arg);
	}
	return n;
}

#else

static int
eloop_run_ppoll(struct eloop *eloop, struct timespec *ts, sigset_t *signals)
{
	int n, nn;
	struct eloop_event *e;

	n = ppoll(eloop->fds, (nfds_t)eloop->nevents, ts, signals);
	if (n == -1 || n == 0)
		return n;

	nn = n;
	TAILQ_FOREACH(e, &eloop->events, next) {
		if (eloop->cleared)
			break;
		/* Skip freshly added events */
		if (e->pollfd == NULL)
			continue;
		if (e->pollfd->revents)
			nn--;
		if (e->fd != -1 && e->pollfd->revents & POLLOUT &&
		    e->write_cb != NULL)
			e->write_cb(e->write_cb_arg);
		if (e->fd != -1 &&
		    e->pollfd != NULL && e->pollfd->revents &&
		    e->read_cb != NULL)
			e->read_cb(e->read_cb_arg);
		if (nn == 0)
			break;
	}
	return n;
}
#endif

int
eloop_start(struct eloop *eloop, sigset_t *signals)
{
	int error;
	struct eloop_timeout *t;
	struct timespec ts, *tsp;

	assert(eloop != NULL);
#if defined(HAVE_KQUEUE)
	UNUSED(signals);
#endif

	for (;;) {
		if (eloop->exitnow)
			break;

#ifndef HAVE_KQUEUE
		if (_eloop_nsig != 0) {
			int n = _eloop_sig[--_eloop_nsig];

			if (eloop->signal_cb != NULL)
				eloop->signal_cb(n, eloop->signal_cb_ctx);
			continue;
		}
#endif

		t = TAILQ_FIRST(&eloop->timeouts);
		if (t == NULL && eloop->nevents == 0)
			break;

		if (t != NULL)
			eloop_reduce_timers(eloop);

		if (t != NULL && t->seconds == 0 && t->nseconds == 0) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			t->callback(t->arg);
			TAILQ_INSERT_TAIL(&eloop->free_timeouts, t, next);
			continue;
		}

		if (t != NULL) {
			if (t->seconds > INT_MAX) {
				ts.tv_sec = (time_t)INT_MAX;
				ts.tv_nsec = 0;
			} else {
				ts.tv_sec = (time_t)t->seconds;
				ts.tv_nsec = (long)t->nseconds;
			}
			tsp = &ts;
		} else
			tsp = NULL;

		eloop->cleared = false;
		if (eloop->events_need_setup)
			eloop_event_setup_fds(eloop);

#if defined(HAVE_KQUEUE)
		UNUSED(signals);
		error = eloop_run_kqueue(eloop, tsp);
#elif defined(HAVE_EPOLL)
		error = eloop_run_epoll(eloop, tsp, signals);
#else
		error = eloop_run_ppoll(eloop, tsp, signals);
#endif
		if (error == -1) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
	}

	return eloop->exitcode;
}
