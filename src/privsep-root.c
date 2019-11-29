/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Priviledge Separation for dhcpcd, privileged actioneer
 * Copyright (c) 2006-2019 Roy Marples <roy@marples.name>
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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dhcpcd.h"
#include "eloop.h"
#include "if.h"
#include "logerr.h"
#include "privsep.h"
#include "script.h"

struct psr_error
{
	ssize_t psr_result;
	int psr_errno;
	char psr_pad[sizeof(ssize_t) - sizeof(int)];
};

struct psr_ctx {
	struct dhcpcd_ctx *psr_ctx;
	struct psr_error psr_error;
};

static void
ps_root_readerrorsig(__unused int sig, void *arg)
{
	struct dhcpcd_ctx *ctx = arg;

	eloop_exit(ctx->ps_eloop, EXIT_FAILURE);
}

static void
ps_root_readerrorcb(void *arg)
{
	struct psr_ctx *psr_ctx = arg;
	struct dhcpcd_ctx *ctx = psr_ctx->psr_ctx;
	struct psr_error *psr_error = &psr_ctx->psr_error;
	ssize_t len;
	int exit_code = EXIT_FAILURE;

	len = read(ctx->ps_root_fd, psr_error, sizeof(*psr_error));
	if (len == 0 || len == -1) {
		logerr(__func__);
		psr_error->psr_result = -1;
		psr_error->psr_errno = errno;
	} else if ((size_t)len < sizeof(*psr_error)) {
		logerrx("%s: psr_error truncated", __func__);
		psr_error->psr_result = -1;
		psr_error->psr_errno = EINVAL;
	} else
		exit_code = EXIT_SUCCESS;

	eloop_exit(ctx->ps_eloop, exit_code);
}

ssize_t
ps_root_readerror(struct dhcpcd_ctx *ctx)
{
	struct psr_ctx psr_ctx = { .psr_ctx = ctx };

	if (eloop_event_add(ctx->ps_eloop, ctx->ps_root_fd,
	    ps_root_readerrorcb, &psr_ctx) == -1)
	{
		logerr(__func__);
		return -1;
	}

	eloop_start(ctx->ps_eloop, &ctx->sigset);

	errno = psr_ctx.psr_error.psr_errno;
	return psr_ctx.psr_error.psr_result;
}

static ssize_t
ps_root_writeerror(struct dhcpcd_ctx *ctx, ssize_t result)
{
	struct psr_error psr = {
		.psr_result = result,
		.psr_errno = errno,
	};

	return write(ctx->ps_root_fd, &psr, sizeof(psr));
}

static ssize_t
ps_root_doioctl(unsigned long req, void *data, size_t len)
{
	int s, err;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s != -1)
		err = ioctl(s, req, data, len);
	else
		err = -1;
	if (s != -1)
		close(s);
	return err;
}

static ssize_t
ps_root_run_script(struct dhcpcd_ctx *ctx, const void *data, size_t len)
{
	const char *envbuf = data;
	char * const argv[] = { UNCONST(data), NULL };
	pid_t pid;
	int status;

#ifdef PRIVSEP_DEBUG
	logdebugx("%s: IN %zu", __func__, len);
#endif

	if (len == 0)
		return 0;

	/* Script is the first one, find the environment buffer. */
	while (*envbuf != '\0') {
		if (len == 0)
			return EINVAL;
		envbuf++;
		len--;
	}

	if (len != 0) {
		envbuf++;
		len--;
	}

#ifdef PRIVSEP_DEBUG
	logdebugx("%s: run script: %s", __func__, argv[0]);
#endif

	if (script_buftoenv(ctx, UNCONST(envbuf), len) == NULL)
		return -1;

	pid = script_exec(ctx, argv, ctx->script_env);
	if (pid == -1)
		return -1;
	/* Wait for the script to finish */
	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR) {
			logerr(__func__);
			status = 0;
			break;
		}
	}
	return status;
}

static ssize_t
ps_root_recvmsgcb(void *arg, struct ps_msghdr *psm, struct msghdr *msg)
{
	struct dhcpcd_ctx *ctx = arg;
	uint8_t cmd;
	struct ps_process *psp;
	struct iovec *iov = msg->msg_iov;
	void *data = iov->iov_base;
	size_t len = iov->iov_len;
	ssize_t err;

	cmd = (uint8_t)(psm->ps_cmd & ~(PS_START | PS_STOP));
	psp = ps_findprocess(ctx, &psm->ps_id);

#ifdef PRIVSEP_DEBUG
	logerrx("%s: IN cmd %x, psp %p", __func__, psm->ps_cmd, psp);
#endif

	if (!(psm->ps_cmd & PS_START) && psp != NULL) {
		if (psm->ps_cmd & PS_STOP) {
			int ret = ps_dostop(ctx, &psp->psp_pid, &psp->psp_fd);

			ps_freeprocess(psp);
			return ret;
		}
		return ps_sendpsmmsg(ctx, psp->psp_fd, psm, msg);
	}

	if (psm->ps_cmd & PS_STOP && psp == NULL)
		return 0;

	/* All these should just be PS_START */
	switch (cmd) {
#ifdef INET
#ifdef ARP
	case PS_BPF_ARP:	/* FALLTHROUGH */
#endif
	case PS_BPF_BOOTP:
		return ps_bpf_cmd(ctx, psm, msg);
#endif
#ifdef INET
	case PS_BOOTP:
		return ps_inet_cmd(ctx, psm, msg);
#endif
#ifdef INET6
#ifdef DHCP6
	case PS_DHCP6:	/* FALLTHROUGH */
#endif
	case PS_ND:
		return ps_inet_cmd(ctx, psm, msg);
#endif
	default:
		break;
	}

	assert(msg->msg_iovlen == 1);

	/* Reset errno */
	errno = 0;

	switch (psm->ps_cmd) {
	case PS_IOCTL:
		err = ps_root_doioctl(psm->ps_flags, data, len);
		break;
	case PS_SCRIPT:
		err = ps_root_run_script(ctx, data, len);
		break;
	default:
		err = ps_root_os(psm, msg);
		break;
	}

	return ps_root_writeerror(ctx, err);
}

/* Receive from state engine, do an action. */
static void
ps_root_recvmsg(void *arg)
{
	struct dhcpcd_ctx *ctx = arg;

	if (ps_recvpsmsg(ctx, ctx->ps_root_fd, ps_root_recvmsgcb, ctx) == -1 &&
	    errno != ECONNRESET)
		logerr(__func__);
}

static int
ps_root_startcb(void *arg)
{
	struct dhcpcd_ctx *ctx = arg;

	setproctitle("[privileged actioneer]");
	ctx->ps_root_pid = getpid();
	return 0;
}

static void
ps_root_signalcb(int sig, void *arg)
{
	struct dhcpcd_ctx *ctx = arg;

	/* Ignore SIGINT, respect PS_STOP command or SIGTERM. */
	if (sig == SIGINT)
		return;

	logerrx("process %d unexpectedly terminating on signal %d",
	    getpid(), sig);
	if (ctx->ps_root_pid == getpid()) {
		shutdown(ctx->ps_root_fd, SHUT_RDWR);
		shutdown(ctx->ps_data_fd, SHUT_RDWR);
	}
	eloop_exit(ctx->eloop, sig == SIGTERM ? EXIT_SUCCESS : EXIT_FAILURE);
}

static ssize_t
ps_root_dispatchcb(void *arg, struct ps_msghdr *psm, struct msghdr *msg)
{
	struct dhcpcd_ctx *ctx = arg;
	ssize_t err;

	err = ps_bpf_dispatch(ctx, psm, msg);
	if (err == -1 && errno == ENOTSUP)
		err = ps_inet_dispatch(ctx, psm, msg);
	return err;
}

static void
ps_root_dispatch(void *arg)
{
	struct dhcpcd_ctx *ctx = arg;

	if (ps_recvpsmsg(ctx, ctx->ps_data_fd, ps_root_dispatchcb, ctx) == -1)
		logerr(__func__);
}

pid_t
ps_root_start(struct dhcpcd_ctx *ctx)
{
	int fd[2];
	pid_t pid;

#define	SOCK_CXNB	SOCK_CLOEXEC | SOCK_NONBLOCK
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CXNB, 0, fd) == -1)
		return -1;

	pid = ps_dostart(ctx, &ctx->ps_root_pid, &ctx->ps_root_fd,
	    ps_root_recvmsg, NULL, ctx,
	    ps_root_startcb, ps_root_signalcb, 0);

	if (pid == 0) {
		ctx->ps_data_fd = fd[1];
		close(fd[0]);
		return 0;
	} else if (pid == -1)
		return -1;

	ctx->ps_data_fd = fd[0];
	close(fd[1]);
	if (eloop_event_add(ctx->eloop, ctx->ps_data_fd,
	    ps_root_dispatch, ctx) == -1)
		logerr(__func__);

	if ((ctx->ps_eloop = eloop_new()) == NULL) {
		logerr(__func__);
		return -1;
	}

	if (eloop_signal_set_cb(ctx->ps_eloop,
	    dhcpcd_signals, dhcpcd_signals_len,
	    ps_root_readerrorsig, ctx) == -1)
	{
		logerr(__func__);
		return -1;
	}
	return pid;
}

int
ps_root_stop(struct dhcpcd_ctx *ctx)
{

	return ps_dostop(ctx, &ctx->ps_root_pid, &ctx->ps_root_fd);
}

ssize_t
ps_root_script(const struct interface *ifp, const void *data, size_t len)
{
	char buf[PS_BUFLEN], *p = buf;
	size_t blen = PS_BUFLEN, slen = strlen(ifp->options->script) + 1;

#ifdef PRIVSEP_DEBUG
	logdebugx("%s: sending script: %zu %s len %zu",
	    __func__, slen, ifp->options->script, len);
#endif

	if (slen > blen) {
		errno = ENOBUFS;
		return -1;
	}
	memcpy(p, ifp->options->script, slen);
	p += slen;
	blen -= slen;

	if (len > blen) {
		errno = ENOBUFS;
		return -1;
	}
	memcpy(p, data, len);

#ifdef PRIVSEP_DEBUG
	logdebugx("%s: sending script data: %zu", __func__, slen + len);
#endif

	if (ps_sendcmd(ifp->ctx, ifp->ctx->ps_root_fd, PS_SCRIPT, 0,
	    buf, slen + len) == -1)
		return -1;

	return ps_root_readerror(ifp->ctx);
}

ssize_t
ps_root_ioctl(struct dhcpcd_ctx *ctx, unsigned long req, void *data, size_t len)
{
	if (ps_sendcmd(ctx, ctx->ps_root_fd, PS_IOCTL, req, data, len) == -1)
		return -1;
	return ps_root_readerror(ctx);
}
