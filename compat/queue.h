/* This stub exists to avoid including queue.h in the vendor folder
 * for source imports */
#ifdef BSD
#include <sys/queue.h>
#else
#include "../vendor/queue.h"
#endif
