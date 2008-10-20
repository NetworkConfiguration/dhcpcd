# Generate .depend
# Copyright 2008 Roy Marples <roy@marples.name>

CLEANFILES+=	.depend

.depend: ${SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} > .depend

depend: .depend

# Nasty hack for gmake which does not automatically include .depend
# if it exists, unlike every other make implementation.
INC_DEPEND=$(shell if test -e .depend; then echo .depend; else echo ""; fi)
include ${INC_DEPEND}
