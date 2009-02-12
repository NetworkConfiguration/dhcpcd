/* 
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2009 Roy Marples <roy@marples.name>
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

#ifndef DHCPF_H
#define DHCPF_H

#include "dhcp.h"
#include "if-options.h"
#include "net.h"

#define add_option_mask(var, val) (var[val >> 3] |= 1 << (val & 7))
#define del_option_mask(var, val) (var[val >> 3] &= ~(1 << (val & 7)))
#define has_option_mask(var, val) (var[val >> 3] & (1 << (val & 7)))
int make_option_mask(uint8_t *, const char *, int);
void print_options(void);
char *get_option_string(const struct dhcp_message *, uint8_t);
int get_option_addr(uint32_t *, const struct dhcp_message *, uint8_t);
int get_option_uint32(uint32_t *, const struct dhcp_message *, uint8_t);
int get_option_uint16(uint16_t *, const struct dhcp_message *, uint8_t);
int get_option_uint8(uint8_t *, const struct dhcp_message *, uint8_t);
#define is_bootp(m) (m &&						\
	    !IN_LINKLOCAL(htonl((m)->yiaddr)) &&			\
	    get_option_uint8(NULL, m, DHO_MESSAGETYPE) == -1)
struct rt *get_option_routes(const struct dhcp_message *);
ssize_t configure_env(char **, const char *, const struct dhcp_message *,
    const struct if_options *);

ssize_t make_message(struct dhcp_message **, const struct interface *,
    uint8_t);
int valid_dhcp_packet(unsigned char *);

ssize_t write_lease(const struct interface *, const struct dhcp_message *);
struct dhcp_message *read_lease(const struct interface *);
void get_lease(struct dhcp_lease *, const struct dhcp_message *);
#endif
