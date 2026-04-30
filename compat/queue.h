/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2014-2025 Roy Marples <roy@marples.name>
 */

/* This stub exists to avoid including queue.h in the vendor folder
 * for source imports */
#ifdef BSD
#include <sys/queue.h>
#else
#include "../vendor/queue.h"
#endif
