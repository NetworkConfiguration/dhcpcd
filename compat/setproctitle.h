/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SETPROCTITLE_H
#define SETPROCTITLE_H

#ifndef __printflike
#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
#define	__printflike(a, b) __attribute__((format(printf, a, b)))
#else
#define	__printflike(a, b)
#endif
#endif /* !__printflike */

/* WEXITSTATUS is defined in stdlib.h which defines free() */
#ifdef WEXITSTATUS
static inline const char *
getprogname(void)
{
	return "dhcpcd";
}
static inline void
setprogname(char *name)
{
	free(name);
}
#endif

void setproctitle_init(int, char *[], char *[]);
__printflike(1, 2) void setproctitle(const char *, ...);
void setproctitle_fini(void);

#define libbsd_symver_default(alias, symbol, version) \
    extern __typeof(symbol) alias __attribute__((__alias__(#symbol)))

#define libbsd_symver_variant(alias, symbol, version)
#endif
