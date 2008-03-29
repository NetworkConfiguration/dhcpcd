/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
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

#include <asm/types.h> /* Needed for 2.4 kernels */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "common.h"
#include "dhcp.h"
#include "if.h"

/* This netlink stuff is overly compex IMO.
 * The BSD implementation is much cleaner and a lot less code.
 * send_netlink handles the actual transmission so we can work out
 * if there was an error or not. */
#define BUFFERLEN 256
static int
send_netlink(struct nlmsghdr *hdr)
{
	int s;
	pid_t mypid = getpid ();
	struct sockaddr_nl nl;
	struct iovec iov;
	struct msghdr msg;
	static unsigned int seq;
	char *buffer = NULL;
	ssize_t bytes;
	union
	{
		char *buffer;
		struct nlmsghdr *nlm;
	} h;
	int len, l;
	struct nlmsgerr *err;

	if ((s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
		return -1;

	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(s, (struct sockaddr *)&nl, sizeof(nl)) == -1)
		goto eexit;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = hdr;
	iov.iov_len = hdr->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Request a reply */
	hdr->nlmsg_flags |= NLM_F_ACK;
	hdr->nlmsg_seq = ++seq;

	if (sendmsg(s, &msg, 0) == -1)
		goto eexit;

	buffer = xzalloc(sizeof(char) * BUFFERLEN);
	iov.iov_base = buffer;

	for (;;) {
		iov.iov_len = BUFFERLEN;
		bytes = recvmsg(s, &msg, 0);

		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			goto eexit;
		}

		if (bytes == 0) {
			errno = ENODATA;
			goto eexit;
		}

		if (msg.msg_namelen != sizeof(nl)) {
			errno = EBADMSG;
			goto eexit;
		}

		for (h.buffer = buffer; bytes >= (signed) sizeof(*h.nlm); ) {
			len = h.nlm->nlmsg_len;
			l = len - sizeof(*h.nlm);
			err = (struct nlmsgerr *)NLMSG_DATA(h.nlm);

			if (l < 0 || len > bytes) {
				errno = EBADMSG;
				goto eexit;
			}

			/* Ensure it's our message */
			if (nl.nl_pid != 0 ||
			    (pid_t)h.nlm->nlmsg_pid != mypid ||
			    h.nlm->nlmsg_seq != seq)
			{
				/* Next Message */
				bytes -= NLMSG_ALIGN(len);
				h.buffer += NLMSG_ALIGN(len);
				continue;
			}

			/* We get an NLMSG_ERROR back with a code of zero for success */
			if (h.nlm->nlmsg_type != NLMSG_ERROR)
				continue;

			if ((unsigned)l < sizeof(*err)) {
				errno = EBADMSG;
				goto eexit;
			}

			if (err->error == 0) {
				close(s);
				free(buffer);
				return l;
			}

			errno = -err->error;
			goto eexit;
		}
	}

eexit:
	close(s);
	free(buffer);
	return -1;
}

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *)(((ptrdiff_t)(nmsg))+NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int
add_attr_l(struct nlmsghdr *n, unsigned int maxlen, int type,
	   const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

static int
add_attr_32(struct nlmsghdr *n, unsigned int maxlen, int type, uint32_t data)
{
	int len = RTA_LENGTH(sizeof(data));
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		errno = ENOBUFS;
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, sizeof(data));
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

struct nlma
{
	struct nlmsghdr hdr;
	struct ifaddrmsg ifa; 
	char buffer[64];
};

struct nlmr
{
	struct nlmsghdr hdr;
	struct rtmsg rt;
	char buffer[256];
};

int
if_address(const char *ifname,
	   struct in_addr address, struct in_addr netmask,
	   struct in_addr broadcast, int del)
{
	struct nlma *nlm;
	int retval = 0;

	nlm = xzalloc(sizeof(*nlm));
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlm->hdr.nlmsg_flags = NLM_F_REQUEST;
	if (!del)
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	nlm->hdr.nlmsg_type = del ? RTM_DELADDR : RTM_NEWADDR;
	if (!(nlm->ifa.ifa_index = if_nametoindex(ifname))) {
		free(nlm);
		errno = ENODEV;
		return -1;
	}
	nlm->ifa.ifa_family = AF_INET;
	nlm->ifa.ifa_prefixlen = inet_ntocidr(netmask);
	/* This creates the aliased interface */
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LABEL,
		   ifname, strlen(ifname) + 1);
	add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_LOCAL,
		   &address.s_addr, sizeof(address.s_addr));
	if (!del)
		add_attr_l(&nlm->hdr, sizeof(*nlm), IFA_BROADCAST,
			   &broadcast.s_addr, sizeof(broadcast.s_addr));

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
}

int
if_route(const char *ifname,
	 struct in_addr destination, struct in_addr netmask,
	 struct in_addr gateway, int metric, int change, int del)
{
	struct nlmr *nlm;
	unsigned int ifindex;
	int retval = 0;


	if (!(ifindex = if_nametoindex(ifname))) {
		errno = ENODEV;
		return -1;
	}

	nlm = xzalloc(sizeof(*nlm));
	nlm->hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	if (change)
		nlm->hdr.nlmsg_flags = NLM_F_REPLACE;
	else if (!del)
		nlm->hdr.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
	nlm->hdr.nlmsg_flags |= NLM_F_REQUEST;
	nlm->hdr.nlmsg_type = del ? RTM_DELROUTE : RTM_NEWROUTE;
	nlm->rt.rtm_family = AF_INET;
	nlm->rt.rtm_table = RT_TABLE_MAIN;

	if (del)
		nlm->rt.rtm_scope = RT_SCOPE_NOWHERE;
	else {
		nlm->hdr.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		nlm->rt.rtm_protocol = RTPROT_BOOT;
		if (netmask.s_addr == INADDR_BROADCAST ||
		    gateway.s_addr == INADDR_ANY)
			nlm->rt.rtm_scope = RT_SCOPE_LINK;
		else
			nlm->rt.rtm_scope = RT_SCOPE_UNIVERSE;
		nlm->rt.rtm_type = RTN_UNICAST;
	}

	nlm->rt.rtm_dst_len = inet_ntocidr(netmask);
	add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_DST,
		   &destination.s_addr, sizeof(destination.s_addr));
	if (netmask.s_addr != INADDR_BROADCAST &&
	    destination.s_addr != gateway.s_addr)
		add_attr_l(&nlm->hdr, sizeof(*nlm), RTA_GATEWAY,
			   &gateway.s_addr, sizeof(gateway.s_addr));

	add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_OIF, ifindex);
	add_attr_32(&nlm->hdr, sizeof(*nlm), RTA_PRIORITY, metric);

	if (send_netlink(&nlm->hdr) == -1)
		retval = -1;
	free(nlm);
	return retval;
}
