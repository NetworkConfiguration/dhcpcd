# System definitions

PICFLAG?=	-fPIC

BINMODE?=	0555
NONBINMODE?=	0444
MANMODE?=	${NONBINMODE}
CONFMODE?=	0644
DBMODE?=	0750

CC?=		cc
ECHO?=		echo
INSTALL?=	install
LINT?=		lint
SED?=		sed
HOST_SH?=	/bin/sh

# This isn't very portable, but I generaly make releases from NetBSD
SHA256?=	sha256
# Force gpg2 to avoid SHA1 signatures from gpg1
PGP?=		gpg2

SCRIPT=		${LIBEXECDIR}/dhcpcd-run-hooks
HOOKDIR=	${LIBEXECDIR}/dhcpcd-hooks

SED_RUNDIR=		-e 's:@RUNDIR@:${RUNDIR}:g'
SED_DBDIR=		-e 's:@DBDIR@:${DBDIR}:g'
SED_LIBDIR=		-e 's:@LIBDIR@:${LIBDIR}:g'
SED_DATADIR=		-e 's:@DATADIR@:${DATADIR}:g'
SED_HOOKDIR=		-e 's:@HOOKDIR@:${HOOKDIR}:g'
SED_SERVICEEXISTS=	-e 's:@SERVICEEXISTS@:${SERVICEEXISTS}:g'
SED_SERVICECMD=		-e 's:@SERVICECMD@:${SERVICECMD}:g'
SED_SERVICESTATUS=	-e 's:@SERVICESTATUS@:${SERVICESTATUS}:g'
SED_STATUSARG=		-e 's:@STATUSARG@:${STATUSARG}:g'
SED_SCRIPT=		-e 's:@SCRIPT@:${SCRIPT}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'
SED_DEFAULT_HOSTNAME=	-e 's:@DEFAULT_HOSTNAME@:${DEFAULT_HOSTNAME}:g'
