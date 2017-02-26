/*
 * dhcpcd - DHCP client daemon
 * Copyright (c) 2006-2017 Roy Marples <roy@marples.name>
 *
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

#ifndef BPF_ETHCOOK
# define BPF_ETHCOOK 0
#endif
#ifndef BPF_WHOLEPACKET
# define BPF_WHOLEPACKET ~0U
#endif

static const struct bpf_insn arp_bpf_filter [] = {
#ifndef BPF_SKIPTYPE
	/* Make sure this is an ARP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#endif
	/* Make sure this is for IP ... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 16 + BPF_ETHCOOK),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure this is an ARP REQUEST... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20 + BPF_ETHCOOK),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),
	/* or ARP REPLY... */
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Pass back the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, BPF_WHOLEPACKET),
};
#define arp_bpf_filter_len __arraycount(arp_bpf_filter)

static const struct bpf_insn bootp_bpf_filter [] = {
#ifndef BPF_SKIPTYPE
	/* Make sure this is an IP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
#endif
	/* Make sure it's a UDP packet... */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23 + BPF_ETHCOOK),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20 + BPF_ETHCOOK),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Get the IP header length... */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14 + BPF_ETHCOOK),
	/* Make sure it's to the right port... */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16 + BPF_ETHCOOK),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTPC, 1, 0),
	BPF_STMT(BPF_RET + BPF_K, 0),
	/* Pass back the whole packet. */
	BPF_STMT(BPF_RET + BPF_K, BPF_WHOLEPACKET),
};
#define bootp_bpf_filter_len __arraycount(bootp_bpf_filter)
