/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 2005 - 2006 Roy Marples <uberlord@gentoo.org>
 *
 * dhcpcd is an RFC2131 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef PATHNAMES_H
#define PATHNAMES_H

#define PACKAGE			"dhcpcd"

#define ETCDIR			"/etc"
#define RESOLVFILE		ETCDIR "/resolv.conf"
#define NISFILE			ETCDIR "/yp.conf"
#define NTPFILE			ETCDIR "/ntp.conf"
#define NTPDRIFTFILE		ETCDIR "/ntp.drift"
#define DEFAULT_SCRIPT		ETCDIR "/" PACKAGE ".sh"

#define STATEDIR		"/var"
#define PIDFILE			STATEDIR "/run/" PACKAGE "-%s.pid"

#define CONFIGDIR		STATEDIR "/lib/" PACKAGE
#define INFOFILE		CONFIGDIR "/" PACKAGE "-%s.info"

#define NTPLOGFILE		"/var/log/ntp.log"

#endif
