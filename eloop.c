/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2015 Roy Marples <roy@marples.name>
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

/* Needed for ppoll(2) */
#define _GNU_SOURCE

#include <sys/time.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"
#include "common.h"
#include "dhcpcd.h"
#include "eloop.h"

#if defined(HAVE_EPOLL)
#include <sys/epoll.h>
#define eloop_event_setup_fds(ctx)
#else
#include <poll.h>
static void
eloop_event_setup_fds(struct eloop_ctx *ctx)
{
	struct eloop_event *e;
	size_t i;

	i = 0;
	TAILQ_FOREACH(e, &ctx->events, next) {
		ctx->fds[i].fd = e->fd;
		ctx->fds[i].events = 0;
		if (e->read_cb)
			ctx->fds[i].events |= POLLIN;
		if (e->write_cb)
			ctx->fds[i].events |= POLLOUT;
		ctx->fds[i].revents = 0;
		e->pollfd = &ctx->fds[i];
		i++;
	}
}
#endif

int
eloop_event_add(struct eloop_ctx *ctx, int fd,
    void (*read_cb)(void *), void *read_cb_arg,
    void (*write_cb)(void *), void *write_cb_arg)
{
	struct eloop_event *e;
#ifdef HAVE_EPOLL
	struct epoll_event epe, *nfds;
#else
	struct pollfd *nfds;
#endif

#ifdef HAVE_EPOLL
	memset(&epe, 0, sizeof(epe));
	epe.data.fd = fd;
	epe.events = EPOLLIN;
	if (write_cb)
		epe.events |= EPOLLOUT;
#endif

	/* We should only have one callback monitoring the fd */
	TAILQ_FOREACH(e, &ctx->events, next) {
		if (e->fd == fd) {
			if (read_cb) {
				e->read_cb = read_cb;
				e->read_cb_arg = read_cb_arg;
			}
			if (write_cb) {
				e->write_cb = write_cb;
				e->write_cb_arg = write_cb_arg;
			}
#ifdef HAVE_EPOLL
			epe.data.ptr = e;
			return epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD,
			    fd, &epe);
#else
			eloop_event_setup_fds(ctx);
			return 0;
#endif
		}
	}

	/* Allocate a new event if no free ones already allocated */
	if ((e = TAILQ_FIRST(&ctx->free_events))) {
		TAILQ_REMOVE(&ctx->free_events, e, next);
	} else {
		e = malloc(sizeof(*e));
		if (e == NULL)
			goto err;
	}

	/* Ensure we can actually listen to it */
	ctx->events_len++;
	if (ctx->events_len > ctx->fds_len) {
		nfds = realloc(ctx->fds, sizeof(*ctx->fds) * (ctx->fds_len+5));
		if (nfds == NULL)
			goto err;
		ctx->fds_len += 5;
		ctx->fds = nfds;
	}


	/* Now populate the structure and add it to the list */
	e->fd = fd;
	e->read_cb = read_cb;
	e->read_cb_arg = read_cb_arg;
	e->write_cb = write_cb;
	e->write_cb_arg = write_cb_arg;

#ifdef HAVE_EPOLL
	epe.data.ptr = e;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &epe) == -1)
		goto err;
#endif

	/* The order of events should not matter.
	 * However, some PPP servers love to close the link right after
	 * sending their final message. So to ensure dhcpcd processes this
	 * message (which is likely to be that the DHCP addresses are wrong)
	 * we insert new events at the queue head as the link fd will be
	 * the first event added. */
	TAILQ_INSERT_HEAD(&ctx->events, e, next);
	eloop_event_setup_fds(ctx);
	return 0;

err:
	syslog(LOG_ERR, "%s: %m", __func__);
	if (e) {
		ctx->events_len--;
		TAILQ_INSERT_TAIL(&ctx->free_events, e, next);
	}
	return -1;
}

void
eloop_event_delete(struct eloop_ctx *ctx, int fd, int write_only)
{
	struct eloop_event *e;

	TAILQ_FOREACH(e, &ctx->events, next) {
		if (e->fd == fd) {
			if (write_only) {
				e->write_cb = NULL;
				e->write_cb_arg = NULL;
			} else {
				TAILQ_REMOVE(&ctx->events, e, next);
#ifdef HAVE_EPOLL
				/* NULL event is safe because we
				 * rely on epoll_pwait which as added
				 * after the delete without event was fixed. */
				epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL,
				    fd, NULL);
#endif
				TAILQ_INSERT_TAIL(&ctx->free_events, e, next);
				ctx->events_len--;
			}
			eloop_event_setup_fds(ctx);
			break;
		}
	}
}

int
eloop_q_timeout_add_tv(struct eloop_ctx *ctx, int queue,
    const struct timespec *when, void (*callback)(void *), void *arg)
{
	struct timespec now, w;
	struct eloop_timeout *t, *tt = NULL;

	get_monotonic(&now);
	timespecadd(&now, when, &w);
	/* Check for time_t overflow. */
	if (timespeccmp(&w, &now, <)) {
		errno = ERANGE;
		return -1;
	}

	/* Remove existing timeout if present */
	TAILQ_FOREACH(t, &ctx->timeouts, next) {
		if (t->callback == callback && t->arg == arg) {
			TAILQ_REMOVE(&ctx->timeouts, t, next);
			break;
		}
	}

	if (t == NULL) {
		/* No existing, so allocate or grab one from the free pool */
		if ((t = TAILQ_FIRST(&ctx->free_timeouts))) {
			TAILQ_REMOVE(&ctx->free_timeouts, t, next);
		} else {
			t = malloc(sizeof(*t));
			if (t == NULL) {
				syslog(LOG_ERR, "%s: %m", __func__);
				return -1;
			}
		}
	}

	t->when = w;
	t->callback = callback;
	t->arg = arg;
	t->queue = queue;

	/* The timeout list should be in chronological order,
	 * soonest first. */
	TAILQ_FOREACH(tt, &ctx->timeouts, next) {
		if (timespeccmp(&t->when, &tt->when, <)) {
			TAILQ_INSERT_BEFORE(tt, t, next);
			return 0;
		}
	}
	TAILQ_INSERT_TAIL(&ctx->timeouts, t, next);
	return 0;
}

int
eloop_q_timeout_add_sec(struct eloop_ctx *ctx, int queue, time_t when,
    void (*callback)(void *), void *arg)
{
	struct timespec tv;

	tv.tv_sec = when;
	tv.tv_nsec = 0;
	return eloop_q_timeout_add_tv(ctx, queue, &tv, callback, arg);
}

int
eloop_timeout_add_now(struct eloop_ctx *ctx,
    void (*callback)(void *), void *arg)
{

	if (ctx->timeout0 != NULL) {
		syslog(LOG_WARNING, "%s: timeout0 already set", __func__);
		return eloop_q_timeout_add_sec(ctx, 0, 0, callback, arg);
	}

	ctx->timeout0 = callback;
	ctx->timeout0_arg = arg;
	return 0;
}

void
eloop_q_timeout_delete(struct eloop_ctx *ctx, int queue,
    void (*callback)(void *), void *arg)
{
	struct eloop_timeout *t, *tt;

	TAILQ_FOREACH_SAFE(t, &ctx->timeouts, next, tt) {
		if ((queue == 0 || t->queue == queue) &&
		    t->arg == arg &&
		    (!callback || t->callback == callback))
		{
			TAILQ_REMOVE(&ctx->timeouts, t, next);
			TAILQ_INSERT_TAIL(&ctx->free_timeouts, t, next);
		}
	}
}

void
eloop_exit(struct eloop_ctx *ctx, int code)
{

	ctx->exitcode = code;
	ctx->exitnow = 1;
}

struct eloop_ctx *
eloop_init(void)
{
	struct eloop_ctx *ctx;
	struct timespec now;

	/* Check we have a working monotonic clock. */
	if (get_monotonic(&now) == -1)
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx) {
		TAILQ_INIT(&ctx->events);
		TAILQ_INIT(&ctx->free_events);
		TAILQ_INIT(&ctx->timeouts);
		TAILQ_INIT(&ctx->free_timeouts);
		ctx->exitcode = EXIT_FAILURE;
#ifdef HAVE_EPOLL
		if ((ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
			free(ctx);
			return NULL;
		}
#endif

	}

	return ctx;
}


void eloop_free(struct eloop_ctx *ctx)
{
	struct eloop_event *e;
	struct eloop_timeout *t;

	if (ctx == NULL)
		return;

	while ((e = TAILQ_FIRST(&ctx->events))) {
		TAILQ_REMOVE(&ctx->events, e, next);
		free(e);
	}
	while ((e = TAILQ_FIRST(&ctx->free_events))) {
		TAILQ_REMOVE(&ctx->free_events, e, next);
		free(e);
	}
	while ((t = TAILQ_FIRST(&ctx->timeouts))) {
		TAILQ_REMOVE(&ctx->timeouts, t, next);
		free(t);
	}
	while ((t = TAILQ_FIRST(&ctx->free_timeouts))) {
		TAILQ_REMOVE(&ctx->free_timeouts, t, next);
		free(t);
	}
	free(ctx->fds);
	free(ctx);
}

int
eloop_start(struct dhcpcd_ctx *dctx)
{
	struct eloop_ctx *ctx;
	int n;
	struct eloop_event *e;
	struct eloop_timeout *t;
	struct timespec now, ts, *tsp;
	void (*t0)(void *);
#if defined(HAVE_EPOLL) || !defined(USE_SIGNALS)
	int timeout;
#endif
#ifdef HAVE_EPOLL
	int i;
#endif

	ctx = dctx->eloop;
	for (;;) {
		if (ctx->exitnow)
			break;

		/* Run all timeouts first */
		if (ctx->timeout0) {
			t0 = ctx->timeout0;
			ctx->timeout0 = NULL;
			t0(ctx->timeout0_arg);
			continue;
		}
		if ((t = TAILQ_FIRST(&ctx->timeouts))) {
			get_monotonic(&now);
			if (timespeccmp(&now, &t->when, >)) {
				TAILQ_REMOVE(&ctx->timeouts, t, next);
				t->callback(t->arg);
				TAILQ_INSERT_TAIL(&ctx->free_timeouts, t, next);
				continue;
			}
			timespecsub(&t->when, &now, &ts);
			tsp = &ts;
		} else
			/* No timeouts, so wait forever */
			tsp = NULL;

		if (tsp == NULL && ctx->events_len == 0) {
			syslog(LOG_ERR, "nothing to do");
			break;
		}

#if defined(HAVE_EPOLL) || !defined(USE_SIGNALS)
		if (tsp == NULL)
			timeout = -1;
		else if (tsp->tv_sec > INT_MAX / 1000 ||
		    (tsp->tv_sec == INT_MAX / 1000 &&
		    (tsp->tv_nsec + 999999) / 1000000 > INT_MAX % 1000000))
			timeout = INT_MAX;
		else
			timeout = (int)(tsp->tv_sec * 1000 +
			    (tsp->tv_nsec + 999999) / 1000000);
#endif

#ifdef HAVE_EPOLL
#ifdef USE_SIGNALS
		n = epoll_pwait(ctx->epoll_fd, ctx->fds, (int)ctx->events_len,
		    timeout, &dctx->sigset);
#else
		n = epoll_wait(ctx->epoll_fd, ctx->fds, (int)ctx->events_len,
		    timeout);
#endif
#else
#ifdef USE_SIGNALS
		n = pollts(ctx->fds, (nfds_t)ctx->events_len,
		    tsp, &dctx->sigset);
#else
		n = poll(ctx->fds, (nfds_t)ctx->events_len, timeout);
#endif
#endif
		if (n == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "poll: %m");
			break;
		}

		/* Process any triggered events. */
#ifdef HAVE_EPOLL
		for (i = 0; i < n; i++) {
			e = (struct eloop_event *)ctx->fds[i].data.ptr;
			if (ctx->fds[i].events & EPOLLOUT &&
			    e->write_cb)
			{
				e->write_cb(e->write_cb_arg);
				/* We need to break here as the
				 * callback could destroy the next
				 * fd to process. */
				break;
			}
			if (ctx->fds[i].events &&
			    ctx->fds[i].events &
			    (EPOLLIN | EPOLLERR | EPOLLHUP))
			{
				e->read_cb(e->read_cb_arg);
				/* We need to break here as the
				 * callback could destroy the next
				 * fd to process. */
				break;
			}
		}
#else
		if (n > 0) {
			TAILQ_FOREACH(e, &ctx->events, next) {
				if (e->pollfd->revents & POLLOUT &&
				    e->write_cb)
				{
					e->write_cb(e->write_cb_arg);
					/* We need to break here as the
					 * callback could destroy the next
					 * fd to process. */
					break;
				}
				if (e->pollfd->revents) {
					e->read_cb(e->read_cb_arg);
					/* We need to break here as the
					 * callback could destroy the next
					 * fd to process. */
					break;
				}
			}
		}
#endif
	}

	return ctx->exitcode;
}
