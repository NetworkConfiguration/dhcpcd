/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef LOGGER_H
#define LOGGER_H

#ifdef __GNUC__
#  define _PRINTF_LIKE(_one, _two)  __attribute__ ((__format__ (__printf__, _one, _two)))
#endif

#include <syslog.h>

int logtolevel (const char *priority);
void setloglevel (int level);
void setlogprefix (const char *prefix);
void logger (int level, const char *fmt, ...) _PRINTF_LIKE (2, 3);

#endif
