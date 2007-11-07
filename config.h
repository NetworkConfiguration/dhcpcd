/*
 * dhcpcd - DHCP client daemon
 * Copyright 2006-2007 Roy Marples <roy@marples.name>
 * 
 * Distributed under the terms of the GNU General Public License v2
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
// #define ENABLE_INFO_COMPAT

/* IPV4LL, aka ZeroConf, aka APIPA, aka RFC 3927.
 * Needs ARP. */
#define ENABLE_IPV4LL

/* We will auto create a DUID_LLT file if it doesn't exist.
 * You can always create your own DUID file that just contains the
 * hex string that represents the DUID.
 * See RFC 3315 for details on this. */
#define ENABLE_DUID

/* Some systems do not have a working fork.
 * The Makefile will attempt to work it out, but if it fails to feel free to
 * define it here. */
// #define THERE_IS_NO_FORK

/* Packname name and pathname definitions.
 * NOTE: The service restart commands are Gentoo specific and will
 * probably need to be adapted for your OS. */

#define PACKAGE             "dhcpcd"

#define RESOLVCONF          "/sbin/resolvconf"

#define ETCDIR              "/etc"
#define RESOLVFILE          ETCDIR "/resolv.conf"

#define NISFILE             ETCDIR "/yp.conf"
#define NISSERVICE          ETCDIR "/init.d/ypbind"
#define NISRESTARTARGS      "--nodeps", "--quiet", "conditionalrestart"

#define NTPFILE             ETCDIR "/ntp.conf"
#define NTPDRIFTFILE        ETCDIR "/ntp.drift"
#define NTPLOGFILE          "/var/log/ntp.log"
#define NTPSERVICE          ETCDIR "/init.d/ntpd"
#define NTPRESTARTARGS      "--nodeps", "--quiet", "conditionalrestart"

#define OPENNTPFILE         ETCDIR "/ntpd.conf"
#define OPENNTPSERVICE      ETCDIR "/init.d/ntpd"
#define OPENNTPRESTARTARGS  "--nodeps", "--quiet", "conditionalrestart"

#define DEFAULT_SCRIPT      ETCDIR "/" PACKAGE ".sh"

#define STATEDIR            "/var"
#define PIDFILE             STATEDIR "/run/" PACKAGE "-%s.pid"

#define CONFIGDIR           STATEDIR "/lib/" PACKAGE
#define INFOFILE            CONFIGDIR "/" PACKAGE "-%s.info"

#define DUIDFILE            CONFIGDIR "/" PACKAGE ".duid"

#endif
