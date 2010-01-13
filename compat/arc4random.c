/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include <sys/time.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "arc4random.h"

struct arc4_stream {
	uint8_t i;
	uint8_t j;
	uint8_t s[256];
};

static int rs_initialized;
static struct arc4_stream rs;
static int arc4_count;

static void
arc4_init(struct arc4_stream *as)
{
	int n;

	for (n = 0; n < 256; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static void
arc4_addrandom(struct arc4_stream *as, unsigned char *dat, int datlen)
{
	int n;
	uint8_t si;

	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
	as->j = as->i;
}

static uint8_t
arc4_getbyte(struct arc4_stream *as)
{
	uint8_t si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;
	return (as->s[(si + sj) & 0xff]);
}

static uint32_t
arc4_getword(struct arc4_stream *as)
{
	uint32_t val;

	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);
	return val;
}

static void
arc4_stir(struct arc4_stream *as)
{
	int fd;
	struct {
		struct timeval tv;
		unsigned int rnd[(128 - sizeof(struct timeval)) /
			sizeof(unsigned int)];
	}       rdat;
	int n;

	gettimeofday(&rdat.tv, NULL);
	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		n = read(fd, rdat.rnd, sizeof(rdat.rnd));
		close(fd);
	}

	/* fd < 0?  Ah, what the heck. We'll just take
	 * whatever was on the stack... */
	arc4_addrandom(as, (void *) &rdat, sizeof(rdat));

	/*
	 * Throw away the first N words of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.  (N = 256 in our case.)
	 */
	for (n = 0; n < 256 * 4; n++)
		arc4_getbyte(as);
	arc4_count = 1600000;
}

void
arc4random_stir()
{

	if (!rs_initialized) {
		arc4_init(&rs);
		rs_initialized = 1;
	}
	arc4_stir(&rs);
}

void
arc4random_addrandom(unsigned char *dat, int datlen)
{

	if (!rs_initialized)
		arc4random_stir();
	arc4_addrandom(&rs, dat, datlen);
}

uint32_t
arc4random()
{

	arc4_count -= 4;
	if (!rs_initialized || arc4_count <= 0)
		arc4random_stir();
	return arc4_getword(&rs);
}
