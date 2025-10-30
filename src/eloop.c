/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * eloop - portable event based main loop.
 * Copyright (c) 2006-2025 Roy Marples <roy@marples.name>
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

/*
 * On BSD use kqueue(2)
 * On Linux use epoll(7)
 * Everywhere else use ppoll(2)
 */
#ifdef BSD
#include <sys/event.h>
#define USE_KQUEUE
#define NFD 2
#if defined(__NetBSD__) || defined(__OpenBSD__)
#define HAVE_KQUEUE1
#endif
#if defined(__DragonFly__) || defined(__FreeBSD__)
#define _kevent(kq, cl, ncl, el, nel, t) \
	kevent((kq), (cl), (int)(ncl), (el), (int)(nel), (t))
#else
#define _kevent kevent
#endif
#elif defined(__linux__)
#include <sys/epoll.h>
#define USE_EPOLL
#else
#include <poll.h>
#define USE_PPOLL
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eloop.h"
#include "queue.h"

/*
 * Allow a backlog of signals.
 * If you use many eloops in the same process, they should all
 * use the same signal handler or have the signal handler unset.
 * Otherwise the signal might not behave as expected.
 */
#define ELOOP_NSIGNALS 5

/*
 * time_t is a signed integer of an unspecified size.
 * To adjust for time_t wrapping, we need to work the maximum signed
 * value and use that as a maximum.
 */
#ifndef TIME_MAX
#define TIME_MAX ((1ULL << (sizeof(time_t) * NBBY - 1)) - 1)
#endif
/* The unsigned maximum is then simple - multiply by two and add one. */
#ifndef UTIME_MAX
#define UTIME_MAX (TIME_MAX * 2) + 1
#endif

#ifndef NFD
#define NFD 1
#endif

#ifndef UNUSED
#define UNUSED(a) (void)(a)
#endif

struct eloop_event {
	TAILQ_ENTRY(eloop_event) next;
	int fd;
	void (*cb)(void *, unsigned short);
	void *cb_arg;
	unsigned short events;
#ifdef USE_PPOLL
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
	TAILQ_HEAD(event_head, eloop_event) events;
	size_t nevents;
	struct event_head free_events;

	struct timespec now;
	TAILQ_HEAD(timeout_head, eloop_timeout) timeouts;
	struct timeout_head free_timeouts;

	const int *signals;
	size_t nsignals;
	sigset_t sigset;
	void (*signal_cb)(int, void *);
	void *signal_cb_ctx;

#if defined(USE_KQUEUE) || defined(USE_EPOLL)
	int fd;
#endif
#if defined(USE_KQUEUE)
	struct kevent *fds;
#elif defined(USE_EPOLL)
	struct epoll_event *fds;
#elif defined(USE_PPOLL)
	struct pollfd *fds;
#endif
	size_t nfds;

	int exitcode;
	bool exitnow;
	bool events_need_setup;
	bool events_invalid;
};

#ifdef HAVE_REALLOCARRAY
#define eloop_realloca reallocarray
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

static int
eloop_event_setup_fds(struct eloop *eloop)
{
	struct eloop_event *e, *ne;
#if defined(USE_KQUEUE)
	struct kevent *pfd;
	size_t nfds = eloop->nsignals;
#elif defined(USE_EPOLL)
	struct epoll_event *pfd;
	size_t nfds = 0;
#elif defined(USE_PPOLL)
	struct pollfd *pfd;
	size_t nfds = 0;
#endif

	nfds += eloop->nevents;
	if (eloop->nfds < nfds) {
		pfd = eloop_realloca(eloop->fds, nfds, sizeof(*pfd));
		if (pfd == NULL)
			return -1;
		eloop->fds = pfd;
		eloop->nfds = nfds;
	}

#ifdef USE_PPOLL
	pfd = eloop->fds;
#endif
	TAILQ_FOREACH_SAFE(e, &eloop->events, next, ne) {
		if (e->fd == -1) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
			continue;
		}
#ifdef USE_PPOLL
		e->pollfd = pfd;
		pfd->fd = e->fd;
		pfd->events = 0;
		if (e->events & ELE_READ)
			pfd->events |= POLLIN;
		if (e->events & ELE_WRITE)
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
eloop_event_add(struct eloop *eloop, int fd, unsigned short events,
    void (*cb)(void *, unsigned short), void *cb_arg)
{
	struct eloop_event *e;
	bool added;
#if defined(USE_KQUEUE)
	struct kevent ke[2], *kep = &ke[0];
	size_t n;
#elif defined(USE_EPOLL)
	struct epoll_event epe;
	int op;
#endif

	if (fd == -1 || !(events & (ELE_READ | ELE_WRITE | ELE_HANGUP))) {
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
		e->events = 0;
	} else
		added = false;

	e->cb = cb;
	e->cb_arg = cb_arg;

#if defined(USE_KQUEUE)
	n = 2;
	if (events & ELE_READ && !(e->events & ELE_READ))
		EV_SET(kep++, (uintptr_t)fd, EVFILT_READ, EV_ADD, 0, 0, e);
	else if (!(events & ELE_READ) && e->events & ELE_READ)
		EV_SET(kep++, (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, e);
	else
		n--;
	if (events & ELE_WRITE && !(e->events & ELE_WRITE))
		EV_SET(kep++, (uintptr_t)fd, EVFILT_WRITE, EV_ADD, 0, 0, e);
	else if (!(events & ELE_WRITE) && e->events & ELE_WRITE)
		EV_SET(kep++, (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, e);
	else
		n--;
#ifdef EVFILT_PROCDESC
	if (events & ELE_HANGUP)
		EV_SET(kep++, (uintptr_t)fd, EVFILT_PROCDESC, EV_ADD, NOTE_EXIT,
		    0, e);
	else
		n--;
#endif
	if (n != 0 && _kevent(eloop->fd, ke, n, NULL, 0, NULL) == -1) {
		if (added) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
		}
		return -1;
	}
#elif defined(USE_EPOLL)
	memset(&epe, 0, sizeof(epe));
	epe.data.ptr = e;
	if (events & ELE_READ)
		epe.events |= EPOLLIN;
	if (events & ELE_WRITE)
		epe.events |= EPOLLOUT;
	op = added ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
	if (epe.events != 0 && epoll_ctl(eloop->fd, op, fd, &epe) == -1) {
		if (added) {
			TAILQ_REMOVE(&eloop->events, e, next);
			TAILQ_INSERT_TAIL(&eloop->free_events, e, next);
		}
		return -1;
	}
#elif defined(USE_PPOLL)
	e->pollfd = NULL;
	UNUSED(added);
#endif
	e->events = events;
	eloop->events_need_setup = true;
	return 0;
}

int
eloop_event_delete(struct eloop *eloop, int fd)
{
	struct eloop_event *e;
#if defined(USE_KQUEUE)
	struct kevent ke[2], *kep = &ke[0];
	size_t n;
#endif

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

#if defined(USE_KQUEUE)
	n = 0;
	if (e->events & ELE_READ) {
		EV_SET(kep++, (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, e);
		n++;
	}
	if (e->events & ELE_WRITE) {
		EV_SET(kep++, (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, e);
		n++;
	}
	if (n != 0 && _kevent(eloop->fd, ke, n, NULL, 0, NULL) == -1)
		return -1;
#elif defined(USE_EPOLL)
	if (epoll_ctl(eloop->fd, EPOLL_CTL_DEL, fd, NULL) == -1)
		return -1;
#endif

	e->fd = -1;
	eloop->nevents--;
	eloop->events_need_setup = true;
	return 1;
}

unsigned long long
eloop_timespec_diff(const struct timespec *tsp, const struct timespec *usp,
    unsigned int *nsp)
{
	unsigned long long tsecs, usecs, secs;
	long nsecs;

	if (tsp->tv_sec < 0) /* time wrapped */
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

static int
eloop_reduce_timers(struct eloop *eloop)
{
	struct timespec now;
	unsigned long long secs;
	unsigned int nsecs;
	struct eloop_timeout *t;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return -1;
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
					t->nseconds = NSEC_PER_SEC -
					    (nsecs - t->nseconds);
				}
			} else
				t->nseconds -= nsecs;
		}
	}

	eloop->now = now;
	return 0;
}

/*
 * This implementation should cope with UINT_MAX seconds on a system
 * where time_t is INT32_MAX. It should also cope with the monotonic timer
 * wrapping, although this is highly unlikely.
 * unsigned int should match or be greater than any on wire specified timeout.
 */
static int
eloop_q_timeout_add(struct eloop *eloop, int queue, unsigned int seconds,
    unsigned int nseconds, void (*callback)(void *), void *arg)
{
	struct eloop_timeout *t, *tt = NULL;

	/* Remove existing timeout if present. */
	TAILQ_FOREACH(t, &eloop->timeouts, next) {
		if (t->callback == callback && t->arg == arg) {
			TAILQ_REMOVE(&eloop->timeouts, t, next);
			break;
		}
	}

	if (eloop_reduce_timers(eloop) == -1) {
		if (t != NULL)
			free(t);
		return -1;
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

	t->seconds = seconds;
	t->nseconds = nseconds;
	t->callback = callback;
	t->arg = arg;
	t->queue = queue;

	/* The timeout list should be in chronological order,
	 * soonest first. */
	TAILQ_FOREACH(tt, &eloop->timeouts, next) {
		if (t->seconds < tt->seconds ||
		    (t->seconds == tt->seconds && t->nseconds < tt->nseconds)) {
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

	return eloop_q_timeout_add(eloop, queue, (unsigned int)when->tv_sec,
	    (unsigned int)when->tv_sec, callback, arg);
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
	return eloop_q_timeout_add(eloop, queue, (unsigned int)seconds,
	    (unsigned int)nseconds, callback, arg);
}

int
eloop_q_timeout_delete(struct eloop *eloop, int queue, void (*callback)(void *),
    void *arg)
{
	struct eloop_timeout *t, *tt;
	int n;

	n = 0;
	TAILQ_FOREACH_SAFE(t, &eloop->timeouts, next, tt) {
		if ((queue == 0 || t->queue == queue) && t->arg == arg &&
		    (!callback || t->callback == callback)) {
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
	eloop->exitcode = code;
	eloop->exitnow = true;
}

#if defined(USE_KQUEUE) || defined(USE_EPOLL)
static int
eloop_open(struct eloop *eloop)
{
	int fd;

#if defined(HAVE_KQUEUE1)
	fd = kqueue1(O_CLOEXEC);
#elif defined(USE_KQUEUE)
	int flags;

	fd = kqueue();
	flags = fcntl(fd, F_GETFD, 0);
	if (!(flags != -1 && !(flags & FD_CLOEXEC) &&
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0)) {
		close(fd);
		return -1;
	}
#elif defined(USE_EPOLL)
	fd = epoll_create1(EPOLL_CLOEXEC);
#endif

	eloop->fd = fd;
	return fd;
}
#endif

static void
eloop_clear(struct eloop *eloop, unsigned short flags)
{
	if (eloop == NULL)
		return;

	if (!(flags & ELF_KEEP_SIGNALS)) {
		eloop->signals = NULL;
		eloop->nsignals = 0;
		eloop->signal_cb = NULL;
		eloop->signal_cb_ctx = NULL;
	}

	if (!(flags & ELF_KEEP_EVENTS)) {
		struct eloop_event *e, *en;

		TAILQ_FOREACH_SAFE(e, &eloop->events, next, en)
			free(e);
		TAILQ_INIT(&eloop->events);

		TAILQ_FOREACH_SAFE(e, &eloop->free_events, next, en)
			free(e);
		TAILQ_INIT(&eloop->free_events);

		eloop->nevents = 0;
		eloop->events_invalid = true;
	}

	if (!(flags & ELF_KEEP_TIMEOUTS)) {
		struct eloop_timeout *t, *tn;

		TAILQ_FOREACH_SAFE(t, &eloop->timeouts, next, tn)
			free(t);
		TAILQ_INIT(&eloop->timeouts);

		TAILQ_FOREACH_SAFE(t, &eloop->free_timeouts, next, tn)
			free(t);
		TAILQ_INIT(&eloop->free_timeouts);
	}
}

/* Must be called after fork(2) */
int
eloop_forked(struct eloop *eloop, unsigned short flags)
{
#if defined(USE_KQUEUE) || defined(USE_EPOLL)
	struct eloop_event *e;
#if defined(USE_KQUEUE)
	struct kevent *pfds, *pfd;
	size_t i;
	int err;
#elif defined(USE_EPOLL)
	struct epoll_event epe = { .events = 0 };
#endif

#if defined(USE_KQUEUE) || defined(USE_EPOLL)
	/* The fd is invalid after a fork, no need to close it. */
	eloop->fd = -1;
	if (flags && eloop_open(eloop) == -1)
		return -1;
#endif
	eloop_clear(eloop, flags);
	if (!flags)
		return 0;

#ifdef USE_KQUEUE
	pfds = malloc(
	    (eloop->nsignals + (eloop->nevents * NFD)) * sizeof(*pfds));
	if (pfds == NULL)
		return -1;
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
#if defined(USE_KQUEUE)
		if (e->events & ELE_READ) {
			EV_SET(pfd++, (uintptr_t)e->fd, EVFILT_READ, EV_ADD, 0,
			    0, e);
			i++;
		}
		if (e->events & ELE_WRITE) {
			EV_SET(pfd++, (uintptr_t)e->fd, EVFILT_WRITE, EV_ADD, 0,
			    0, e);
			i++;
		}
#elif defined(USE_EPOLL)
		memset(&epe, 0, sizeof(epe));
		epe.data.ptr = e;
		if (e->events & ELE_READ)
			epe.events |= EPOLLIN;
		if (e->events & ELE_WRITE)
			epe.events |= EPOLLOUT;
		if (epoll_ctl(eloop->fd, EPOLL_CTL_ADD, e->fd, &epe) == -1)
			return -1;
#endif
	}

#if defined(USE_KQUEUE)
	if (i == 0)
		err = 0;
	else
		err = _kevent(eloop->fd, pfds, i, NULL, 0, NULL);
	free(pfds);
	return err;
#else
	return 0;
#endif
#else
	eloop_clear(eloop, flags);
	return 0;
#endif
}

int
eloop_signal_set_cb(struct eloop *eloop, const int *signals, size_t nsignals,
    void (*signal_cb)(int, void *), void *signal_cb_ctx)
{
#ifdef USE_KQUEUE
	size_t i;
	struct kevent *ke, *kes;
#endif
	int error = 0;

#ifdef USE_KQUEUE
	ke = kes = malloc(MAX(eloop->nsignals, nsignals) * sizeof(*kes));
	if (kes == NULL)
		return -1;
	for (i = 0; i < eloop->nsignals; i++) {
		EV_SET(ke++, (uintptr_t)eloop->signals[i], EVFILT_SIGNAL,
		    EV_DELETE, 0, 0, NULL);
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

#ifdef USE_KQUEUE
	if (signal_cb == NULL)
		goto out;
	ke = kes;
	for (i = 0; i < eloop->nsignals; i++) {
		EV_SET(ke++, (uintptr_t)eloop->signals[i], EVFILT_SIGNAL,
		    EV_ADD, 0, 0, NULL);
	}
	if (i != 0 && _kevent(eloop->fd, kes, i, NULL, 0, NULL) == -1)
		error = -1;
out:
	free(kes);
#endif

	return error;
}

#ifndef USE_KQUEUE
static volatile int eloop_sig[ELOOP_NSIGNALS];
static volatile size_t eloop_nsig;

static void
eloop_signal3(int sig, siginfo_t *siginfo, void *arg)
{
	(void)(siginfo);
	(void)(arg);

	if (eloop_nsig == sizeof(eloop_sig) / sizeof(eloop_sig[0])) {
#ifdef ELOOP_DEBUG
		fprintf(stderr, "%s: signal storm, discarding signal %d\n",
		    __func__, sig);
#endif
		return;
	}
	eloop_sig[eloop_nsig++] = sig;
}
#endif

int
eloop_signal_mask(struct eloop *eloop)
{
	sigset_t newset;
	size_t i;
#ifndef USE_KQUEUE
	struct sigaction sa = {
		.sa_sigaction = eloop_signal3,
		.sa_flags = SA_SIGINFO,
	};
#endif

	sigemptyset(&newset);
	for (i = 0; i < eloop->nsignals; i++)
		sigaddset(&newset, eloop->signals[i]);
	if (sigprocmask(SIG_SETMASK, &newset, &eloop->sigset) == -1)
		return -1;

#ifndef USE_KQUEUE
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

#if defined(USE_KQUEUE) || defined(USE_EPOLL)
	if (eloop_open(eloop) == -1) {
		eloop_free(eloop);
		return NULL;
	}
#endif

	return eloop;
}

struct eloop *
eloop_new_with_signals(struct eloop *eloop)
{
	struct eloop *e;
	int err;

	e = eloop_new();
	if (e == NULL)
		return NULL;

	err = eloop_signal_set_cb(e, eloop->signals, eloop->nsignals,
	    eloop->signal_cb, eloop->signal_cb_ctx);
	if (err == -1) {
		eloop_free(e);
		return NULL;
	}
	memcpy(&e->sigset, &eloop->sigset, sizeof(e->sigset));

	return e;
}

void
eloop_free(struct eloop *eloop)
{
	if (eloop == NULL)
		return;

	eloop_clear(eloop, 0);
#if defined(USE_KQUEUE) || defined(USE_EPOLL)
	if (eloop->fd != -1)
		close(eloop->fd);
#endif
	free(eloop);
}

#if defined(USE_KQUEUE)
static int
eloop_run_kqueue(struct eloop *eloop, const struct timespec *ts)
{
	int n, nn;
	struct kevent *ke;
	struct eloop_event *e;
	unsigned short events;

	n = _kevent(eloop->fd, NULL, 0, eloop->fds, eloop->nevents, ts);
	if (n == -1)
		return -1;

	for (nn = n, ke = eloop->fds; nn != 0; nn--, ke++) {
		if (eloop->exitnow || eloop->events_invalid)
			break;
		e = (struct eloop_event *)ke->udata;
		if (ke->filter == EVFILT_SIGNAL) {
			eloop->signal_cb((int)ke->ident, eloop->signal_cb_ctx);
			continue;
		}
		if (ke->filter == EVFILT_READ)
			events = ELE_READ;
		else if (ke->filter == EVFILT_WRITE)
			events = ELE_WRITE;
#ifdef EVFILT_PROCDESC
		else if (ke->filter == EVFILT_PROCDESC &&
		    ke->fflags & NOTE_EXIT)
			/* exit status is in ke->data
			 * should we do anything with it? */
			events = ELE_HANGUP;
#endif
		else
			continue; /* assert? */
		if (ke->flags & EV_EOF)
			events |= ELE_HANGUP;
		if (ke->flags & EV_ERROR)
			events |= ELE_ERROR;
		e->cb(e->cb_arg, events);
	}
	return n;
}

#elif defined(USE_EPOLL)

static int
eloop_run_epoll(struct eloop *eloop, const struct timespec *ts)
{
	int timeout, n, nn;
	struct epoll_event *epe;
	struct eloop_event *e;
	unsigned short events;

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

	n = epoll_pwait(eloop->fd, eloop->fds, (int)eloop->nevents, timeout,
	    &eloop->sigset);
	if (n == -1)
		return -1;

	for (nn = n, epe = eloop->fds; nn != 0; nn--, epe++) {
		if (eloop->exitnow || eloop->events_invalid)
			break;
		e = (struct eloop_event *)epe->data.ptr;
		if (e->fd == -1)
			continue;
		events = 0;
		if (epe->events & EPOLLIN)
			events |= ELE_READ;
		if (epe->events & EPOLLOUT)
			events |= ELE_WRITE;
		if (epe->events & EPOLLHUP)
			events |= ELE_HANGUP;
		if (epe->events & EPOLLERR)
			events |= ELE_ERROR;
		e->cb(e->cb_arg, events);
	}
	return n;
}

#elif defined(USE_PPOLL)

static int
eloop_run_ppoll(struct eloop *eloop, const struct timespec *ts)
{
	int n, nn;
	struct eloop_event *e;
	struct pollfd *pfd;
	unsigned short events;

	n = ppoll(eloop->fds, (nfds_t)eloop->nevents, ts, &eloop->sigset);
	if (n == -1 || n == 0)
		return n;

	nn = n;
	TAILQ_FOREACH(e, &eloop->events, next) {
		if (eloop->exitnow || eloop->events_invalid)
			break;
		/* Skip freshly added events */
		if ((pfd = e->pollfd) == NULL)
			continue;
		if (e->pollfd->revents) {
			nn--;
			events = 0;
			if (pfd->revents & POLLIN)
				events |= ELE_READ;
			if (pfd->revents & POLLOUT)
				events |= ELE_WRITE;
			if (pfd->revents & POLLHUP)
				events |= ELE_HANGUP;
			if (pfd->revents & POLLERR)
				events |= ELE_ERROR;
			if (pfd->revents & POLLNVAL)
				events |= ELE_NVAL;
			if (events)
				e->cb(e->cb_arg, events);
		}
		if (nn == 0)
			break;
	}
	return n;
}

#endif

int
eloop_start(struct eloop *eloop)
{
	int error;
	struct eloop_timeout *t;
	struct timespec ts, *tsp;

	eloop->exitnow = false;

	for (;;) {
		if (eloop->exitnow)
			break;
		if (eloop->events_invalid) {
			eloop->events_invalid = false;
			eloop->events_need_setup = true;
		}

#ifndef USE_KQUEUE
		if (eloop_nsig != 0) {
			int n = eloop_sig[--eloop_nsig];

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

		if (eloop->events_need_setup)
			eloop_event_setup_fds(eloop);

#if defined(USE_KQUEUE)
		error = eloop_run_kqueue(eloop, tsp);
#elif defined(USE_EPOLL)
		error = eloop_run_epoll(eloop, tsp);
#elif defined(USE_PPOLL)
		error = eloop_run_ppoll(eloop, tsp);
#endif
		if (error == -1) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
	}

	return eloop->exitcode;
}
