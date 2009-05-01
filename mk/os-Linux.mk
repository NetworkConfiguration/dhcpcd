# Setup OS specific variables
# Copyright (c) 2008 Roy Marples <roy@marples.name>

SRC_PF=		lpf.c
SRC_IF=		if-linux.c

CPPFLAGS+=	-D_BSD_SOURCE -D_XOPEN_SOURCE=600
LIBRT=		-lrt

# Nasty hack - see source for why
SRC_IF+=	if-linux-wireless.c
