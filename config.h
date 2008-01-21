/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2008 Roy Marples <roy@marples.name>
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

#ifndef CONFIG_H
#define CONFIG_H

/* You can enable/disable various chunks of optional code here.
 * You would only do this to try and shrink the end binary if dhcpcd
 * was running on a low memory device */

#define ENABLE_ARP
#define ENABLE_NTP
#define ENABLE_NIS
#define ENABLE_INFO
/* Define this to enable some compatability with 1.x and 2.x info files */
/* #define ENABLE_INFO_COMPAT */

/* IPV4LL, aka ZeroConf, aka APIPA, aka RFC 3927.
 * Needs ARP. */
#define ENABLE_IPV4LL

/* We will auto create a DUID_LLT file if it doesn't exist.
 * You can always create your own DUID file that just contains the
 * hex string that represents the DUID.
 * See RFC 3315 for details on this. */
#define ENABLE_DUID

/* resolvconf is framework for multiple interfaces to manage resolv.conf */
#define ENABLE_RESOLVCONF

/* Some systems do not have a working fork.
 * The Makefile will attempt to work it out, but if it fails to feel free to
 * define it here. */
/* #define THERE_IS_NO_FORK */

/* Packname name and pathname definitions. */

#define PACKAGE             "dhcpcd"

#define ETCDIR              "/etc"
#define RESOLVFILE          ETCDIR "/resolv.conf"

#define NISFILE             ETCDIR "/yp.conf"

#define NTPFILE             ETCDIR "/ntp.conf"
#define NTPDRIFTFILE        ETCDIR "/ntp.drift"
#define NTPLOGFILE          "/var/log/ntp.log"

#define OPENNTPFILE         ETCDIR "/ntpd.conf"

#define DEFAULT_SCRIPT      ETCDIR "/" PACKAGE ".sh"

#define STATEDIR            "/var"
#define PIDFILE             STATEDIR "/run/" PACKAGE "-%s.pid"

#ifndef INFODIR
# define INFODIR            "/var/lib/dhcpcd"
#endif
#define INFOFILE            INFODIR "/" PACKAGE "-%s.info"
#define DUIDFILE            INFODIR "/" PACKAGE ".duid"

/* OPENRC is Open Run Control, forked from Gentoo's baselayout package
 * BSDRC is BSD style Run Control
 * SLACKRC is Slackware Run Control
 * SERVICE is RedHat service command
 * SYSV should cover everthing else */
#ifdef ENABLE_OPENRC
# define SERVICE             "OPENRC"
# define NISSERVICE          ETCDIR "/init.d/ypbind"
# define NISRESTARTARGS      "--nodeps", "--quiet", "conditionalrestart"
# define NTPSERVICE          ETCDIR "/init.d/ntpd"
# define NTPRESTARTARGS      "--nodeps", "--quiet", "conditionalrestart"
#endif
#if ENABLE_BSDRC
# define SERVICE             "BSDRC"
# define NISSERVICE          ETCDIR "/rc.d/ypbind"
# define NISRESTARTARGS      "restart"
# define NTPSERVICE          ETCDIR "/rc.d/ntpd"
# define NTPRESTARTARGS      "restart"
#endif
#if ENABLE_SLACKRC
# define SERVICE             "SLACKRC"
# define NISSERVICE          ETCDIR "/rc.d/rc.ypbind"
# define NISRESTARTARGS      "restart"
# define NTPSERVICE          ETCDIR "/rc.d/rc.ntpd"
# define NTPRESTARTARGS      "restart"
#endif
#if ENABLE_SERVICE
# define SERVICE             "SERVICE"
# define NISSERVICE          "service"
# define NISRESTARTARGS      "ypbind", "restart"
# define NTPSERVICE          "service"
# define NTPRESTARTARGS      "ntpd", "restart"
#endif
#if ENABLE_SYSV
# define SERVICE             "SYSV"
# define NISSERVICE          ETCDIR "/init.d/ypbind"
# define NISRESTARTARGS      "restart"
# define NTPSERVICE          ETCDIR "/init.d/ntpd"
# define NTPRESTARTARGS      "restart"
#endif

#ifndef NISSERVICE
# undef ENABLE_NIS
#endif
#ifndef NTPSERVICE
# undef ENABLE_NTP
#endif

#endif
