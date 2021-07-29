/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "geli.h"

void
pkcs5v2_genkey(u_char *key, unsigned key_sz, u_char *salt,
    size_t salt_sz, u_char *passphrase, u_int iterations)
{
#define xor(dst, src, size)	do { for (int i = 0; i < size; i++) dst[i] ^= src[i]; } while (0)
	uint8_t md[SHA512_MDLEN], saltcount[salt_sz + sizeof(uint32_t)];
	uint8_t *counter, *keyp;
	u_int i, bsize, pass_len;
	uint32_t count;
	struct hmac_ctx startpoint, ctx;

	pass_len = strlen((char *)passphrase);
	bzero(key, key_sz);
	bcopy(salt, saltcount, salt_sz);
	counter = saltcount + salt_sz;

	keyp = key;
	for (count = 1; key_sz > 0; count++, key_sz -= bsize, keyp += bsize) {
		bsize = (key_sz < sizeof(md)) ? key_sz : sizeof(md);

		be32enc(counter, count);

		eli_crypt_hmac_init(&startpoint, passphrase, pass_len);
		ctx = startpoint;
		eli_crypt_hmac_update(&ctx, saltcount, sizeof(saltcount));
		eli_crypt_hmac_final(&ctx, md, sizeof(md));
		xor(keyp, md, bsize);

		for(i = 1; i < iterations; i++) {
			ctx = startpoint;
			eli_crypt_hmac_update(&ctx, md, sizeof(md));
			eli_crypt_hmac_final(&ctx, md, sizeof(md));
			xor(keyp, md, bsize);
		}
	}
	explicit_bzero(&startpoint, sizeof(startpoint));
	explicit_bzero(&ctx, sizeof(ctx));
#undef xor
}
