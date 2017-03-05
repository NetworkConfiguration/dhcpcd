/*
 * dhcpcd: BPF arp and bootp functions
 * Copyright (c) 2006-2017 Roy Marples <roy@marples.name>
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

#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#ifdef __linux__
#include <linux/filter.h>
#else
#include <net/bpf.h>
#endif

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "common.h"
#include "arp.h"
#include "dhcp.h"
#include "if.h"

#define	ARP_ADDRS_MAX	3

/* BPF helper macros */
#ifdef __linux__
#define	BPF_L2L			0
#define	BPF_L2I			0
#define	BPF_WHOLEPACKET		0x0fffffff /* work around buggy LPF filters */
#else
#define	BPF_L2L			ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2
#define	BPF_L2I			3
#define	BPF_WHOLEPACKET		~0U
#endif

/* Macros to update the BPF structure */
#define	BPF_SET_STMT(insn, c, v) {				\
	(insn)->code = (c);					\
	(insn)->jt = 0;						\
	(insn)->jf = 0;						\
	(insn)->k = (uint32_t)(v);				\
};

#define	BPF_SET_JUMP(insn, c, v, t, f) {			\
	(insn)->code = (c);					\
	(insn)->jt = (t);					\
	(insn)->jf = (f);					\
	(insn)->k = (uint32_t)(v);				\
};

static unsigned int
bpf_cmp_hwaddr(struct bpf_insn *bpf, size_t bpf_len, size_t off,
    bool equal, uint8_t *hwaddr, size_t hwaddr_len)
{
	struct bpf_insn *bp;
	size_t maclen, nlft, njmps;
	uint32_t mac32;
	uint16_t mac16;
	uint8_t jt, jf;

	/* Calc the number of jumps */
	if ((hwaddr_len / 4) >= 128) {
		errno = EINVAL;
		return 0;
	}
	njmps = (hwaddr_len / 4) * 2; /* 2 instructions per check */
	/* We jump after the 1st check. */
	if (njmps)
		njmps -= 2;
	nlft = hwaddr_len % 4;
	if (nlft) {
		njmps += (nlft / 2) * 2;
		nlft = nlft % 2;
		if (nlft)
			njmps += 2;

	}

	/* Skip to positive finish. */
	njmps++;
	jt = equal ? (uint8_t)njmps : 0;
	jf = equal ? 0 : (uint8_t)njmps;

	bp = bpf;
	for (; hwaddr_len > 0;
	     hwaddr += maclen, hwaddr_len -= maclen, off += maclen)
	{
		if (bpf_len < 3) {
			errno = ENOBUFS;
			return 0;
		}
		bpf_len -= 3;

		if (hwaddr_len >= 4) {
			maclen = sizeof(mac32);
			memcpy(&mac32, hwaddr, maclen);
			BPF_SET_STMT(bp, BPF_LD + BPF_W + BPF_ABS,
			             BPF_L2L + off);
			bp++;
			BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
			             htonl(mac32), jt, jf);
		} else if (hwaddr_len >= 2) {
			maclen = sizeof(mac16);
			memcpy(&mac16, hwaddr, maclen);
			BPF_SET_STMT(bp, BPF_LD + BPF_H + BPF_ABS,
			             BPF_L2L + off);
			bp++;
			BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
			             htons(mac16), jt, jf);
		} else {
			maclen = sizeof(*hwaddr);
			BPF_SET_STMT(bp, BPF_LD + BPF_B + BPF_ABS,
			             BPF_L2L + off);
			bp++;
			BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
			             *hwaddr, jt, jf);
		}
		if (jt)
			jt = (uint8_t)(jt - 2);
		if (jf)
			jf = (uint8_t)(jf - 2);
		bp++;
	}

	/* Last step is always return failure.
	 * Next step is a positive finish. */
	BPF_SET_STMT(bp, BPF_RET + BPF_K, 0);
	bp++;

	return (unsigned int)(bp - bpf);
}

#ifdef ARP
static const struct bpf_insn arp_bpf_filter [] = {
	/* Ensure packet is at least correct size. */
	BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
	BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K,
	         BPF_L2L + sizeof(struct arphdr)
		 + (ETHER_ADDR_LEN * 2)
		 + (sizeof(in_addr_t) * 2), 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#if BPF_L2L > 0
	/* Make sure this is an ARP packet. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         offsetof(struct ether_header, ether_type)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#endif
	/* Make sure this is for IP. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         BPF_L2L + offsetof(struct arphdr, ar_pro)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure this is an ARP REQUEST. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         BPF_L2L + offsetof(struct arphdr, ar_op)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),
	/* or ARP REPLY. */
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure the hardware length matches. */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
	         BPF_L2L + offsetof(struct arphdr, ar_hln)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHER_ADDR_LEN, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure the protocol length matches. */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
	         BPF_L2L + offsetof(struct arphdr, ar_pln)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(in_addr_t), 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Pass back the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, BPF_WHOLEPACKET),
};
#define arp_bpf_filter_len	__arraycount(arp_bpf_filter)
#define arp_bpf_extra		((ARP_ADDRS_MAX * 2) * 2) + 2

int
bpf_arp(struct interface *ifp, int s)
{
	size_t bpf_hw = ((((size_t)ifp->hwlen / 4) + 2) * 2) + 1;
	struct bpf_insn bpf[arp_bpf_filter_len + bpf_hw + arp_bpf_extra];
	struct bpf_insn *bp;
	struct iarp_state *state;

	if (s == -1)
		return 0;
	memcpy(bpf, arp_bpf_filter, sizeof(arp_bpf_filter));
	bp = &bpf[arp_bpf_filter_len];

	/* Ensure it's not from us. */
	bp--;
	bp += bpf_cmp_hwaddr(bp, bpf_hw, sizeof(struct arphdr),
	                     false, ifp->hwaddr, ifp->hwlen);

	state = ARP_STATE(ifp);
	if (TAILQ_FIRST(&state->arp_states)) {
		struct arp_state *astate;
		size_t naddrs;

		/* Match sender protocol address */
		BPF_SET_STMT(bp, BPF_LD + BPF_W + BPF_ABS,
		             BPF_L2L + sizeof(struct arphdr) + ifp->hwlen);
		bp++;
		naddrs = 0;
		TAILQ_FOREACH(astate, &state->arp_states, next) {
			if (++naddrs > ARP_ADDRS_MAX) {
				errno = ENOBUFS;
				logger(ifp->ctx, LOG_ERR, "%s: %m", __func__);
				break;
			}
			BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
			             htonl(astate->addr.s_addr), 0, 1);
			bp++;
			BPF_SET_STMT(bp, BPF_RET + BPF_K, BPF_WHOLEPACKET);
			bp++;
		}

		/* Match target protocol address */
		BPF_SET_STMT(bp, BPF_LD + BPF_W + BPF_ABS,
		             BPF_L2L + sizeof(struct arphdr) + ifp->hwlen);
		bp++;
		naddrs = 0;
		TAILQ_FOREACH(astate, &state->arp_states, next) {
			if (++naddrs > ARP_ADDRS_MAX) {
				/* Already logged error above. */
				break;
			}
			BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
			             htonl(astate->addr.s_addr), 0, 1);
			bp++;
			BPF_SET_STMT(bp, BPF_RET + BPF_K,
			             BPF_WHOLEPACKET);
			bp++;
		}

		/* Return nothing, no protocol address match. */
		BPF_SET_STMT(bp, BPF_RET + BPF_K, 0);
		bp++;
	}

	/* Replace ETHER_ADDR_LEN for Infiniband if needed. */
	if (ifp->hwlen != ETHER_ADDR_LEN) {
		bpf[1].k += (uint32_t)(ifp->hwlen - ETHER_ADDR_LEN) * 2;
		bpf[BPF_L2I + 11].k = ifp->hwlen;
	}

	return if_bpf_attach(s, bpf, (unsigned int)(bp - bpf));
}
#endif

static const struct bpf_insn bootp_bpf_filter[] = {
	/* Ensure packet is at least correct size. */
	BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
	BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K,
	         BPF_L2L + sizeof(struct ip) + sizeof(struct udphdr)
		 + offsetof(struct bootp, vend), 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#if BPF_L2L
	/* Make sure this is an IP packet. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         offsetof(struct ether_header, ether_type)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#endif
	/* Make sure it's a UDP packet. */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
	         BPF_L2L + offsetof(struct bootp_pkt, ip.ip_p)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure this isn't a fragment. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         BPF_L2L + offsetof(struct bootp_pkt, ip.ip_off)),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure it's to the right port. */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
	         BPF_L2L + offsetof(struct bootp_pkt, udp.uh_dport)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTPC, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure it's BOOTREPLY. */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
	         BPF_L2L + offsetof(struct bootp_pkt, bootp.op)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTREPLY, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Pass back the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, BPF_WHOLEPACKET),
};
#define bootp_bpf_filter_len	__arraycount(bootp_bpf_filter)
#define	bootp_bpf_extra		3 + ((BOOTP_CHADDR_LEN / 4) * 3)

int
bpf_bootp(struct interface *ifp, int fd)
{
	const struct dhcp_state *state = D_CSTATE(ifp);
	struct bpf_insn bpf[bootp_bpf_filter_len + bootp_bpf_extra];
	struct bpf_insn *bp;
	unsigned int bpf_len = bootp_bpf_extra;

	if (fd == -1)
		return 0;

	memcpy(bpf, bootp_bpf_filter, sizeof(bootp_bpf_filter));
	bp = &bpf[bootp_bpf_filter_len];

	if (state->state != DHS_BOUND ||
	    ifp->hwlen <= sizeof(((struct bootp *)0)->chaddr))
		bp--;

	if (state->state != DHS_BOUND) {
		/* Make sure the BOOTP packet is for us. */
		BPF_SET_STMT(bp, BPF_LD + BPF_W + BPF_ABS,
		             BPF_L2L + offsetof(struct bootp_pkt, bootp.xid));
		bp++;
		BPF_SET_JUMP(bp, BPF_JMP + BPF_JEQ + BPF_K,
		             state->xid, 1, 0);
		bp++;
		BPF_SET_STMT(bp, BPF_RET + BPF_K, 0);
		bp++;
		bpf_len -= 3;
	}

	if (ifp->hwlen <= sizeof(((struct bootp *)0)->chaddr))
		bp += bpf_cmp_hwaddr(bp, bpf_len,
				offsetof(struct bootp_pkt, bootp.chaddr),
				true, ifp->hwaddr, ifp->hwlen);

	if (state->state != DHS_BOUND ||
	    ifp->hwlen <= sizeof(((struct bootp *)0)->chaddr))
	{
		BPF_SET_STMT(bp, BPF_RET + BPF_K,
		             BPF_WHOLEPACKET);
		bp++;
	}

	return if_bpf_attach(fd, bpf, (unsigned int)(bp - bpf));
}
