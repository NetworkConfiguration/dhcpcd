/* 
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2012 Roy Marples <roy@marples.name>
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

#include <sys/time.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include "common.h"
#include "dhcpcd.h"
#include "eloop.h"

static struct timeval now;

static struct event {
	int fd;
	void (*callback)(void *);
	void *arg;
	struct event *next;
} *events;
static struct event *free_events;

static struct timeout {
	struct timeval when;
	void (*callback)(void *);
	void *arg;
	int queue;
	struct timeout *next;
} *timeouts;
static struct timeout *free_timeouts;

void
eloop_event_add(int fd, void (*callback)(void *), void *arg)
{
	struct event *e, *last = NULL;

	/* We should only have one callback monitoring the fd */
	for (e = events; e; e = e->next) {
		if (e->fd == fd) {
			e->callback = callback;
			e->arg = arg;
			return;
		}
		last = e;
	}

	/* Allocate a new event if no free ones already allocated */
	if (free_events) {
		e = free_events;
		free_events = e->next;
	} else
		e = xmalloc(sizeof(*e));
	e->fd = fd;
	e->callback = callback;
	e->arg = arg;
	e->next = NULL;
	if (last)
		last->next = e;
	else
		events = e;
}

void
eloop_event_delete(int fd)
{
	struct event *e, *last = NULL;

	for (e = events; e; e = e->next) {
		if (e->fd == fd) {
			if (last)
				last->next = e->next;
			else
				events = e->next;
			e->next = free_events;
			free_events = e;
			break;
		}
		last = e;
	}
}

void
eloop_q_timeout_add_tv(int queue,
    const struct timeval *when, void (*callback)(void *), void *arg)
{
	struct timeval w;
	struct timeout *t, *tt = NULL;

	get_monotonic(&now);
	timeradd(&now, when, &w);
	/* Check for time_t overflow. */
	if (timercmp(&w, &now, <)) {
		errno = ERANGE;
		return;
	}

	/* Remove existing timeout if present */
	for (t = timeouts; t; t = t->next) {
		if (t->callback == callback && t->arg == arg) {
			if (tt)
				tt->next = t->next;
			else
				timeouts = t->next;
			break;
		}
		tt = t;
	}

	if (!t) {
		/* No existing, so allocate or grab one from the free pool */
		if (free_timeouts) {
			t = free_timeouts;
			free_timeouts = t->next;
		} else
			t = xmalloc(sizeof(*t));
	}

	t->when.tv_sec = w.tv_sec;
	t->when.tv_usec = w.tv_usec;
	t->callback = callback;
	t->arg = arg;
	t->queue = queue;

	/* The timeout list should be in chronological order,
	 * soonest first.
	 * This is the easiest algorithm - check the head, then middle
	 * and finally the end. */
	if (!timeouts || timercmp(&t->when, &timeouts->when, <)) {
		t->next = timeouts;
		timeouts = t;
		return;
	} 
	for (tt = timeouts; tt->next; tt = tt->next)
		if (timercmp(&t->when, &tt->next->when, <)) {
			t->next = tt->next;
			tt->next = t;
			return;
		}
	tt->next = t;
	t->next = NULL;
}

void
eloop_q_timeout_add_sec(int queue, time_t when,
    void (*callback)(void *), void *arg)
{
	struct timeval tv;

	tv.tv_sec = when;
	tv.tv_usec = 0;
	eloop_q_timeout_add_tv(queue, &tv, callback, arg);
}

/* This deletes all timeouts for the interface EXCEPT for ones with the
 * callbacks given. Handy for deleting everything apart from the expire
 * timeout. */
static void
eloop_q_timeouts_delete_v(int queue, void *arg,
    void (*callback)(void *), va_list v)
{
	struct timeout *t, *tt, *last = NULL;
	va_list va;
	void (*f)(void *);

	for (t = timeouts; t && (tt = t->next, 1); t = tt) {
		if (t->queue == queue && t->arg == arg &&
		    t->callback != callback)
		{
			va_copy(va, v);
			while ((f = va_arg(va, void (*)(void *))))
				if (f == t->callback)
					break;
			va_end(va);
			if (!f) {
				if (last)
					last->next = t->next;
				else
					timeouts = t->next;
				t->next = free_timeouts;
				free_timeouts = t;
				continue;
			}
		}
		last = t;
	}
}

void
eloop_q_timeouts_delete(int queue, void *arg, void (*callback)(void *), ...)
{
	va_list va;

	va_start(va, callback);
	eloop_q_timeouts_delete_v(queue, arg, callback, va);
	va_end(va);
}

void
eloop_q_timeout_delete(int queue, void (*callback)(void *), void *arg)
{
	struct timeout *t, *tt, *last = NULL;

	for (t = timeouts; t && (tt = t->next, 1); t = tt) {
		if (t->queue == queue && t->arg == arg &&
		    (!callback || t->callback == callback))
		{
			if (last)
				last->next = t->next;
			else
				timeouts = t->next;
			t->next = free_timeouts;
			free_timeouts = t;
			continue;
		}
		last = t;
	}
}

#ifdef DEBUG_MEMORY
/* Define this to free all malloced memory.
 * Normally we don't do this as the OS will do it for us at exit,
 * but it's handy for debugging other leaks in valgrind. */
static void
eloop_cleanup(void)
{
	struct event *e;
	struct timeout *t;

	while (events) {
		e = events->next;
		free(events);
		events = e;
	}
	while (free_events) {
		e = free_events->next;
		free(free_events);
		free_events = e;
	}
	while (timeouts) {
		t = timeouts->next;
		free(timeouts);
		timeouts = t;
	}
	while (free_timeouts) {
		t = free_timeouts->next;
		free(free_timeouts);
		free_timeouts = t;
	}
}

void
eloop_init(void)
{

	atexit(eloop_cleanup);
}
#endif

_noreturn void
eloop_start(const sigset_t *cursigs)
{
	int n, max_fd;
	fd_set read_fds;
	struct event *e;
	struct timeout *t;
	struct timeval tv;
	struct timespec ts;
	const struct timespec *tsp;

	for (;;) {
		/* Run all timeouts first */
		if (timeouts) {
			get_monotonic(&now);
			if (timercmp(&now, &timeouts->when, >)) {
				t = timeouts;
				timeouts = timeouts->next;
				t->callback(t->arg);
				t->next = free_timeouts;
				free_timeouts = t;
				continue;
			}
			timersub(&timeouts->when, &now, &tv);
			TIMEVAL_TO_TIMESPEC(&tv, &ts);
			tsp = &ts;
		} else
			/* No timeouts, so wait forever */
			tsp = NULL;

		max_fd = -1;
		FD_ZERO(&read_fds);
		for (e = events; e; e = e->next) {
			FD_SET(e->fd, &read_fds);
			if (e->fd > max_fd)
				max_fd = e->fd;
		}
		if (tsp == NULL && max_fd == -1) {
			syslog(LOG_ERR, "nothing to do");
			exit(EXIT_FAILURE);
		}

		n = pselect(max_fd + 1, &read_fds, NULL, NULL, tsp, cursigs);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "pselect: %m");
			exit(EXIT_FAILURE);
		}
		
		/* Process any triggered events. */
		if (n) {
			for (e = events; e; e = e->next) {
				if (FD_ISSET(e->fd, &read_fds)) {
					e->callback(e->arg);
					/* We need to break here as the
					 * callback could destroy the next
					 * fd to process. */
					break;
				}
			}
		}
	}
}
