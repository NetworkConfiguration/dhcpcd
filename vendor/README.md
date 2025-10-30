This area is for 3rd party software we include directly.
All imports should be made on a branch vendor/NAME (initially orphaned) and
merged into the master branch.

Any local changes we need (ideally none) should be done directly
on the master branch where we handle any fallout.

This makes updating vendor imports easy.

Vendor sources are imported from these locations:
* queue.h     - https://cvsweb.netbsd.org/bsdweb.cgi/src/sys/sys/queue.h
* rbtree.c    - https://cvsweb.netbsd.org/bsdweb.cgi/src/common/lib/libc/gen/rbtree.c
* rbtree.h    - https://cvsweb.netbsd.org/bsdweb.cgi/src/sys/sys/rbtree.h
