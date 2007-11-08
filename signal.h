/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef SIGNALS_H
#define SIGNALS_H

void signal_setup (void);
int signal_fd_set (fd_set *rset, int fd);
int signal_exists (const fd_set *rset);
int signal_read (fd_set *rset);

#endif
