/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2014 Roy Marples <roy@marples.name>
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

#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcpcd.h"
#include "control.h"
#include "eloop.h"

#ifndef SUN_LEN
#define SUN_LEN(su) \
            (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif


struct fd_list *control_fds = NULL;

static void
control_remove(void *arg)
{
	struct fd_list *l, *n, *last = NULL;

	l = control_fds;
	while (l) {
		n = l->next;
		if (l == arg) {
			close(l->fd);
			eloop_event_delete(l->fd);
			if (last == NULL)
				control_fds = l->next;
			else
				last->next = l->next;
			free(l);
			break;
		}
		last = l;
		l = n;
	}
}

static void
control_handle_data(void *arg)
{
	struct fd_list *l = arg;
	char buffer[1024], *e, *p, *argvp[255], **ap;
	ssize_t bytes;
	int argc;

	bytes = read(l->fd, buffer, sizeof(buffer) - 1);
	if (bytes == -1 || bytes == 0) {
		control_remove(l);
		return;
	}
	buffer[bytes] = '\0';
	p = buffer;
	e = buffer + bytes;
	argc = 0;
	ap = argvp;
	while (p < e && (size_t)argc < sizeof(argvp)) {
		argc++;
		*ap++ = p;
		p += strlen(p) + 1;
	}
	handle_args(l, argc, argvp);
}

/* ARGSUSED */
static void
control_handle(void *arg)
{
	struct control_ctx *ctx;
	struct sockaddr_un run;
	socklen_t len;
	struct fd_list *l;
	int f;

	ctx = arg;
	len = sizeof(run);
	if ((f = accept(ctx->fd, (struct sockaddr *)&run, &len)) == -1)
		return;
	set_cloexec(f);
	l = malloc(sizeof(*l));
	if (l) {
		l->fd = f;
		l->listener = 0;
		l->next = control_fds;
		control_fds = l;
		eloop_event_add(l->fd, control_handle_data, l);
	}
}

static int
make_sock(struct control_ctx *ctx, struct sockaddr_un *sun)
{

	if ((ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;
	strlcpy(sun->sun_path, CONTROLSOCKET, sizeof(sun->sun_path));
	return SUN_LEN(sun);
}

int
control_start(struct control_ctx *ctx)
{
	struct sockaddr_un sun;
	int len;

	if ((len = make_sock(ctx, &sun)) == -1)
		return -1;
	unlink(CONTROLSOCKET);
	if (bind(ctx->fd, (struct sockaddr *)&sun, len) == -1 ||
	    chmod(CONTROLSOCKET,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1 ||
	    set_cloexec(ctx->fd) == -1 ||
	    set_nonblock(ctx->fd) == -1 ||
	    listen(ctx->fd, sizeof(control_fds)) == -1)
	{
		close(ctx->fd);
		ctx->fd = -1;
		return -1;
	}
	eloop_event_add(ctx->fd, control_handle, ctx);
	return ctx->fd;
}

int
control_stop(struct control_ctx *ctx)
{
	int retval = 0;
	struct fd_list *l;

	eloop_event_delete(ctx->fd);
	if (shutdown(ctx->fd, SHUT_RDWR) == -1)
		retval = 1;
	ctx->fd = -1;
	if (unlink(CONTROLSOCKET) == -1)
		retval = -1;

	l = control_fds;
	while (l != NULL) {
		control_fds = l->next;
		eloop_event_delete(l->fd);
		shutdown(l->fd, SHUT_RDWR);
		free(l);
		l = control_fds;
	}

	return retval;
}

int
control_open(struct control_ctx *ctx)
{
	struct sockaddr_un sun;
	int len;

	if ((len = make_sock(ctx, &sun)) == -1)
		return -1;
	return connect(ctx->fd, (struct sockaddr *)&sun, len);
}

int
control_send(struct control_ctx *ctx, int argc, char * const *argv)
{
	char buffer[1024], *p;
	int i;
	size_t len;

	if (argc > 255) {
		errno = ENOBUFS;
		return -1;
	}
	p = buffer;
	for (i = 0; i < argc; i++) {
		len = strlen(argv[i]) + 1;
		if ((p - buffer) + len > sizeof(buffer)) {
			errno = ENOBUFS;
			return -1;
		}
		memcpy(p, argv[i], len);
		p += len;
	}
	return write(ctx->fd, buffer, p - buffer);
}
