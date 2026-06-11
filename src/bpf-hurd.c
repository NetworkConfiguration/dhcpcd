/*
 * BPF Hurd interface
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/ioctl.h>

#include <net/if_ether.h>

#include <device/device.h>
#include <errno.h>
#include <hurd/ports.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "logerr.h"
#include "queue.h"

const char *bpf_name = "Berkeley Packet Filter (Hurd)";

/* mach ports are not useable in select/poll etc.
 * To work around this we receive messages in a separate thread,
 * push the message to a queue and write a single byte to a
 * pipe which can be used in select/poll in the main thread
 * to notify there is something on the list to process. */
struct bpf_msg {
	STAILQ_ENTRY(bpf_msg) bm_next;
	struct net_rcv_msg bm_msg;
};
STAILQ_HEAD(bpf_msg_head, bpf_msg);

struct bpf_hurd {
	struct bpf *bh_bpf;
	device_t bh_dev;
	mach_port_t bh_port;
	int bh_fd;
	pthread_t bh_thread;
	int bh_thread_error;
	pthread_mutex_t bh_mutex;
	struct bpf_msg_head bh_msgs;
	struct bpf_msg *bh_msg;
};

/* Tells the kernel this is BPF. */
static struct bpf_insn bpf_hurd_hdr[] = {
	{ NETF_IN | NETF_OUT | NETF_BPF, 0, 0, 0 },
};
#define BPF_HURD_HDR_LEN __arraycount(bpf_hurd_hdr)

#define plogerr(f, e)	 logerrx("%s: %s: %s", __func__, (f), strerror((e)))
#define clogerr(f, e) \
	if ((e) != 0) \
	plogerr((f), (e))

static void
bpf_hurd_free(struct bpf_hurd *bh)
{
	int err;
	struct bpf_msg *bm;

	if (bh == NULL)
		return;

	if (bh->bh_thread_error == 0) {
		err = pthread_cancel(bh->bh_thread);
		clogerr("pthread_cancel", err);
		err = pthread_join(bh->bh_thread, NULL);
		clogerr("pthread_join", err);
	}

	err = pthread_mutex_destroy(&bh->bh_mutex);
	clogerr("pthread_mutex_destroy", err);

	while (!STAILQ_EMPTY(&bh->bh_msgs)) {
		bm = STAILQ_FIRST(&bh->bh_msgs);
		STAILQ_REMOVE_HEAD(&bh->bh_msgs, bm_next);
		free(bm);
	}
	free(bh->bh_msg);

	if (bh->bh_fd != -1)
		close(bh->bh_fd);

	if (bh->bh_port != MACH_PORT_NULL)
		mach_port_deallocate(mach_task_self(), bh->bh_port);
	if (bh->bh_dev != MACH_PORT_NULL) {
		device_close(bh->bh_dev);
		mach_port_deallocate(mach_task_self(), bh->bh_dev);
	}

	free(bh);
}

static void *
bpf_hurd_recv(void *arg)
{
	struct bpf_hurd *bh = arg;
	sigset_t sigset;
	int cs, ct;
	kern_return_t kr;
	uint8_t tickle = 0xff;

	pthread_setname_np(pthread_self(), "dhcpcd_bpf_pipe_thread");

	/* We really don't want to hande SIGPIPE */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	/* mach_msg is NOT a pthreads cancellation point.
	 * We set async-cancel so it can be cancelled.
	 * This could be avoided by using a small timeout and
	 * calling pthread_testcancel(), but that would be
	 * inefficient. */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &cs);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ct);

	for (;;) {
		kr = mach_msg(&bh->bh_msg->bm_msg.msg_hdr,
		    MACH_RCV_MSG | MACH_RCV_INTERRUPT, 0,
		    sizeof(bh->bh_msg->bm_msg), bh->bh_port,
		    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr == MACH_RCV_INTERRUPTED || kr == MACH_RCV_TIMEOUT)
			pthread_testcancel();
		else if (kr != KERN_SUCCESS) {
			errno = kr;
			logerr("%s: mach_msg", __func__);
			break;
		}

		/* This is the critical section, disable cancellation. */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);

		/* Add the msg to the list under a mutex. */
		pthread_mutex_lock(&bh->bh_mutex);
		STAILQ_INSERT_TAIL(&bh->bh_msgs, bh->bh_msg, bm_next);
		pthread_mutex_unlock(&bh->bh_mutex);

		/* malloc a new msg buffer for the next mach_msg.
		 * We don't need to do this under a mutex becuase the main
		 * thread never looks at it while we are running.
		 * We do this before write because that's a cancellation
		 * point and we want to guarantee bh_msg is valid. */
		bh->bh_msg = malloc(sizeof(*bh->bh_msg));
		if (bh->bh_msg == NULL) {
			logerr("%s: malloc", __func__);
			break;
		}

		/* All resource allocations done, allow cancellations again. */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &cs);

		/* tickle the pipe so the main thread knows it has
		 * something to process. */
		if (write(bh->bh_fd, &tickle, sizeof(tickle)) == -1) {
			logerr("%s: write", __func__);
			break;
		}
	}

	return NULL;
}

static struct bpf_hurd *
bpf_hurd_open(struct bpf *bpf)
{
	struct bpf_hurd *bh;
	mach_port_t port;
	kern_return_t kr;
	int err, fd[2];

	port = file_name_lookup(bpf->bpf_ifp->name, O_READ | O_WRITE, 0);
	if (port == MACH_PORT_NULL)
		return NULL;

	bh = malloc(sizeof(*bh));
	if (bh == NULL)
		return NULL;

	bh->bh_bpf = bpf;
	bh->bh_dev = MACH_PORT_NULL;
	bh->bh_port = MACH_PORT_NULL;
	bh->bh_fd = -1;
	/* pthread_t is opqaque so we store the return to work out validity */
	bh->bh_thread_error = -1;
	STAILQ_INIT(&bh->bh_msgs);
	bh->bh_msg = NULL;

	err = pthread_mutex_init(&bh->bh_mutex, NULL);
	if (err != 0) {
		plogerr("pthread_mutex_init", err);
		mach_port_deallocate(mach_task_self(), port);
		free(bh);
		return NULL;
	}

	if ((bh->bh_msg = malloc(sizeof(*bh->bh_msg))) == NULL) {
		logerr("%s: malloc", __func__);
		goto err;
	}

	kr = device_open(port, D_READ | D_WRITE, "eth", &bh->bh_dev);
	mach_port_deallocate(mach_task_self(), port);
	if (kr != KERN_SUCCESS) {
		plogerr("device_open", kr);
		errno = kr;
		goto err;
	}

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &bh->bh_port);
	if (kr != KERN_SUCCESS) {
		plogerr("mach_port_allocate", kr);
		errno = kr;
		goto err;
	}

	if (pipe2(fd, O_CLOEXEC) == -1) {
		logerr("%s: pipe", __func__);
		goto err;
	}

	bpf->bpf_fd = fd[0];
	bh->bh_fd = fd[1];

	bh->bh_thread_error = pthread_create(&bh->bh_thread, NULL,
	    bpf_hurd_recv, bh);
	if (bh->bh_thread_error != 0) {
		plogerr("pthread_create", bh->bh_thread_error);
		errno = bh->bh_thread_error;
		goto err;
	}

	return bh;

err:
	bpf_hurd_free(bh);
	return NULL;
}

struct bpf *
bpf_open(const struct interface *ifp,
    int (*filter)(const struct bpf *, const struct in_addr *),
    const struct in_addr *ia)
{
	struct bpf *bpf;
	int mtu;

	bpf = calloc(1, sizeof(*bpf));
	if (bpf == NULL)
		return NULL;

	mtu = ifp->mtu ? ifp->mtu : ETH_DATA_LEN;
	bpf->bpf_ifp = ifp;
	bpf->bpf_size = bpf_frame_header_len(ifp) + (size_t)mtu;

	bpf->bpf_buffer = malloc(bpf->bpf_size);
	if (bpf->bpf_buffer == NULL) {
		logerr("%s: malloc", __func__);
		goto err;
	}

	bpf->bpf_flags = BPF_EOF;

	bpf->bpf_handle = bpf_hurd_open(bpf);
	if (bpf->bpf_handle == NULL) {
		logerr("%s: bpf_hurd_open", __func__);
		goto err;
	}

	if (filter(bpf, ia) == -1) {
		logerr("%s: filter", __func__);
		goto err;
	}

	return bpf;

err:
	bpf_close(bpf);
	return NULL;
}

ssize_t
bpf_read(struct bpf *bpf, void *data, size_t len)
{
	const struct interface *ifp = bpf->bpf_ifp;
	struct bpf_hurd *bh = bpf->bpf_handle;
	uint8_t tickle;
	ssize_t rlen;
	struct bpf_msg *bm;
	struct net_rcv_msg *msg;
	size_t plen, fhlen;
	char *pkt;

	/* We only read one packet per call. */
	bpf->bpf_flags |= BPF_EOF;

	rlen = read(bpf->bpf_fd, &tickle, sizeof(tickle));
	if (rlen == 0 || rlen == -1)
		return rlen;

	pthread_mutex_lock(&bh->bh_mutex);
	bm = STAILQ_FIRST(&bh->bh_msgs);
	if (bm != NULL)
		STAILQ_REMOVE_HEAD(&bh->bh_msgs, bm_next);
	pthread_mutex_unlock(&bh->bh_mutex);

	if (bm == NULL) {
		errno = ESRCH;
		return -1;
	}

	fhlen = bpf_frame_header_len(ifp);
	msg = &bm->bm_msg;
	/* This is always fhlen + mtu by the looks of it */
	plen = fhlen + msg->net_rcv_msg_packet_count -
	    sizeof(struct packet_header);
	if (plen > len) {
		errno = ENOBUFS;
		rlen = -1;
		goto out;
	}

	pkt = msg->packet + sizeof(struct packet_header) - fhlen;
	memcpy(data, pkt, plen);
	rlen = (ssize_t)plen;

	if (bpf_frame_bcast(bpf->bpf_ifp, data) == 0)
		bpf->bpf_flags |= BPF_BCAST;
	else
		bpf->bpf_flags &= ~BPF_BCAST;

out:
	free(bm);
	return rlen;
}

ssize_t
bpf_writev(const struct bpf *bpf, struct iovec *iov, int iovcnt)
{
	int i;
	size_t len = 0;
	uint8_t *bp = bpf->bpf_buffer;
	struct bpf_hurd *bh = bpf->bpf_handle;
	kern_return_t kr;

	for (i = 0; i < iovcnt; i++) {
		/* This should be impossible. */
		if (iov[i].iov_len > bpf->bpf_size - len) {
			errno = ENOBUFS;
			return -1;
		}

		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
		len += iov[i].iov_len;
	}

	kr = device_write(bh->bh_dev, D_NOWAIT, 0, bpf->bpf_buffer, len, &i);
	if (kr != KERN_SUCCESS) {
		errno = kr;
		logerrx(__func__);
		return -1;
	}
	return i;
}

int
bpf_setfilter(const struct bpf *bpf, void *filter, unsigned int filter_len)
{
	/* This is a very limiting size for the kernel filter .... */
	filter_t cmds[NET_MAX_FILTER];
	mach_msg_type_number_t ncmds = 4 + 4 * filter_len;
	kern_return_t kr;
	struct bpf_hurd *bh = bpf->bpf_handle;

	if (ncmds > NET_MAX_FILTER) {
		errno = ENOBUFS;
		return -1;
	}

	memcpy(cmds, bpf_hurd_hdr, sizeof(bpf_hurd_hdr));
	memcpy(cmds + 4, filter, filter_len * sizeof(struct bpf_insn));

	kr = device_set_filter(bh->bh_dev, bh->bh_port, MACH_MSG_TYPE_MAKE_SEND,
	    0, cmds, ncmds);
	if (kr != KERN_SUCCESS)
		errno = kr;
	return kr == 0 ? 0 : -1;
}

int
bpf_setwfilter(const struct bpf *bpf, void *filter, unsigned int filter_len)
{
#warning a compromised Hurd BPF can inject arbitary packets
	UNUSED(bpf);
	UNUSED(filter);
	UNUSED(filter_len);
	errno = ENOSYS;
	return -1;
}

int
bpf_lockfilter(const struct bpf *bpf)
{
	UNUSED(bpf);
	errno = ENOSYS;
	return -1;
}

void
bpf_close(struct bpf *bpf)
{
	if (bpf->bpf_handle != NULL)
		bpf_hurd_free(bpf->bpf_handle);
	free(bpf->bpf_buffer);
	free(bpf);
}
