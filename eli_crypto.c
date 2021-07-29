/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005-2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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

int
eli_crypto_cipher(u_int algo, int enc, u_char *data, size_t data_sz,
                  const u_char *key, size_t key_sz)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;
	u_char iv[key_sz];
	int out_sz;

	assert(algo != CRYPTO_AES_XTS);

	switch (algo) {
#ifdef NOT_YET
	case CRYPTO_NULL_CBC:
		type = EVP_enc_null();
		break;
#endif /* TODO: NULL_CBC Support */
	case CRYPTO_AES_CBC:
		switch (key_sz) {
		case 128:
			type = EVP_aes_128_cbc();
			break;
		case 192:
			type = EVP_aes_192_cbc();
			break;
		case 256:
			type = EVP_aes_256_cbc();
			break;
		default:
			return (EINVAL);
		}
		break;
#if NOT_YET
#ifndef OPENSSL_NO_CAMELLIA
	case CRYPTO_CAMELLIA_CBC:
		switch (key_sz) {
		case 128:
			type = EVP_camellia_128_cbc();
			break;
		case 192:
			type = EVP_camellia_192_cbc();
			break;
		case 256:
			type = EVP_camellia_256_cbc();
			break;
		default:
			return (EINVAL);
		}
		break;
#endif
#endif /* TODO: CAMELLIA_CBC Support */
	default:
		return (EINVAL);
	}

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		return ENOMEM;

	EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, enc);
	EVP_CIPHER_CTX_set_key_length(ctx, key_sz / 8);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	explicit_bzero(iv, sizeof iv);
	EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc);

	if (EVP_CipherUpdate(ctx, data, &out_sz, data, data_sz) == 0) {
		EVP_CIPHER_CTX_free(ctx);
		return (EINVAL);
	}
	assert(out_sz == (int)data_sz);

	if (EVP_CipherFinal_ex(ctx, data + out_sz, &out_sz) == 0) {
		EVP_CIPHER_CTX_free(ctx);
		return (EINVAL);
	}
	assert(out_sz == 0);

	EVP_CIPHER_CTX_free(ctx);
	return (0);
}

int
eli_crypt_encrypt(u_int algo, u_char *data, size_t data_sz,
    const u_char *key, size_t key_sz)
{
	/* We prefer AES-CBC for metadata protection. */
	if (algo == CRYPTO_AES_XTS)
		algo = CRYPTO_AES_CBC;

	return eli_crypto_cipher(algo, 1, data, data_sz, key, key_sz);
}

int
eli_crypt_decrypt(u_int algo, u_char *data, size_t data_sz,
    const u_char *key, size_t key_sz)
{
	/* We prefer AES-CBC for metadata protection. */
	if (algo == CRYPTO_AES_XTS)
		algo = CRYPTO_AES_CBC;

	return eli_crypto_cipher(algo, 0, data, data_sz, key, key_sz);
}
