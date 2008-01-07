# This only works for make implementations that always include a .depend if
# it exists. Only GNU make does not do this.

# Copyright 2008 Roy Marples

.depend: ${SCRIPTS} ${SRCS}
	$(CC) $(CFLAGS) -MM ${SRCS} > .depend

depend: .depend

_dependclean:
	rm -f .depend
