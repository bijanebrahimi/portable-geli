/* Copyright */
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

	/* TODO: PKCS5_PBKDF2_HMAC */
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
	return;
#undef xor
}
