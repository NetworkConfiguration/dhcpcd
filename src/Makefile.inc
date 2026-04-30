check-format:
	find . -iname "*.c" -o -iname "*.h" | \
		xargs -- clang-format --dry-run --Werror

format:
	find . -iname "*.c" -o -iname "*.h" | \
		xargs -- clang-format -i

_lint:
	clang-tidy ${SRCS} -- ${CPPFLAGS} ${CFLAGS} -isystem ${TOP}/vendor

include ${TOP}/Makefile.inc
