# GNU Make does not automagically include .depend
# Luckily it does read GNUmakefile over Makefile so we can work around it

.PHONY:		.depend.depend

include Makefile
-include .depend
