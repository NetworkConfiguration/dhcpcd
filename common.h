/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef COMMON_H
#define COMMON_H

/* string.h pulls in features.h so the below define checks work */
#include <string.h>

/* Only GLIBC doesn't support strlcpy */
#ifdef __GLIBC__
#  if ! defined(__UCLIBC__) && ! defined (__dietlibc__)
size_t strlcpy (char *dst, const char *src, size_t size);
#  endif
#endif

#ifdef __linux__
void srandomdev (void);
#endif

void close_fds (void);
int get_time (struct timeval *tp);
long uptime (void);
void writepid (int fd, pid_t pid);
void *xmalloc (size_t size);
char *xstrdup (const char *str);

#endif
