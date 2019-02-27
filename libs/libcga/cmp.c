/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/md5.h>

#include "config.h"
#include <applog.h>

#include "cga.h"
#include "cga_local.h"

/**
 * Slower but more general version of cga_cmp. The compiler will
 * not inline this.
 *
 * buf: buffer containing the hash
 * n: number of leftmost bits to compare to zero
 *
 * returns 1 if n leftmost bits are 0, otherwise zero.
 */
#if 0
static int
cga_cmp(uint8_t *buf, int n)
{
	int full = n / 8;
	int part = n % 8;
	uint8_t cmp[MD5_DIGEST_LENGTH], cmpbyte;

	memset(cmp, 0, MD5_DIGEST_LENGTH);

	/* Bulk-compare non-partial bytes */
	if (memcmp(buf, cmp, full) != 0) {
		return (0);
	}

	/* If we don't need to compare a partial byte, it matches */
	if (part == 0) {
		return (1);
	}

	/* else compare partial byte */
	cmpbyte = (1 << part) - 1;
	if ((buf[full] & cmpbyte) == buf[full]) {
		return (1);
	}

	return (0);
}
#endif

int
main()
{
	uint8_t b1[4] = { 0, 0x0f, 0xff, 0xff };
	uint8_t b2[4] = { 0, 0, 0, 0xff };
	uint8_t b3[8] = { 0, 0, 0, 0, 0x0f, 0xff, 0xff, 0xff };
	uint8_t b4[8] = { 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	uint8_t b5[12] = { 0, 0, 0, 0, 0, 0, 0, 0x0f, 0xff, 0xff, 0xff, 0xff };
	uint8_t b6[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff };
	uint8_t b7[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0xff };

	uint8_t bb1[4] = { 0, 0xff, 0xff, 0xff };
	uint8_t bb2[4] = { 0, 0, 0x0f, 0xff };
	uint8_t bb3[8] = { 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
	uint8_t bb4[8] = { 0, 0, 0, 0, 0, 0x0f, 0xff, 0xff };
	uint8_t bb5[12] = { 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t bb6[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0xff, 0xff, 0xff };
	uint8_t bb7[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	printf("b1: %d\n", cga_cmp(b1, 12));
	printf("b2: %d\n", cga_cmp(b2, 24));
	printf("b3: %d\n", cga_cmp(b3, 36));
	printf("b4: %d\n", cga_cmp(b4, 48));
	printf("b5: %d\n", cga_cmp(b5, 60));
	printf("b6: %d\n", cga_cmp(b6, 72));
	printf("b7: %d\n", cga_cmp(b7, 84));

	printf("bb1: %d\n", cga_cmp(bb1, 12));
	printf("bb2: %d\n", cga_cmp(bb2, 24));
	printf("bb3: %d\n", cga_cmp(bb3, 36));
	printf("bb4: %d\n", cga_cmp(bb4, 48));
	printf("bb5: %d\n", cga_cmp(bb5, 60));
	printf("bb6: %d\n", cga_cmp(bb6, 72));
	printf("bb7: %d\n", cga_cmp(bb7, 84));

	return (0);
}
