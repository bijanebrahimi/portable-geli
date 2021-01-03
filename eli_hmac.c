/* Copyright */
#include "geli.h"

void
eli_crypt_hmac_init(struct hmac_ctx *ctx, u_char * hkey, size_t hkey_sz)
{
	u_char k_ipad[128], k_opad[128], key[128];

	bzero(key, sizeof(key));
	if (hkey_sz == 0)
		; /* do nothing */
	else if (hkey_sz <= 128)
		bcopy(hkey, key, hkey_sz);
	else {
		/* If hkey is longer than 128 bytes reset it to key = SHA512(hkey). */
		SHA512_CTX lctx;
		SHA512_Init(&lctx);
		SHA512_Update(&lctx, hkey, hkey_sz);
		SHA512_Final(key, &lctx);
	}

	/* XOR key with ipad and opad values. */
	for (int i = 0; i < sizeof(key); i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	explicit_bzero(key, sizeof(key));

	/* Start inner SHA512. */
	SHA512_Init(&ctx->innerctx);
	SHA512_Update(&ctx->innerctx, k_ipad, sizeof(k_ipad));
	explicit_bzero(k_ipad, sizeof(k_ipad));

	/* Start outer SHA512. */
	SHA512_Init(&ctx->outerctx);
	SHA512_Update(&ctx->outerctx, k_opad, sizeof(k_opad));
	explicit_bzero(k_opad, sizeof(k_opad));
}

void
eli_crypt_hmac_update(struct hmac_ctx *ctx, u_char * data, size_t data_sz)
{
	SHA512_Update(&ctx->innerctx, data, data_sz);
}

void
eli_crypt_hmac_final(struct hmac_ctx *ctx, u_char * out, size_t out_sz)
{
	u_char digest[SHA512_MDLEN];

	/* Complete inner hash */
	SHA512_Final(digest, &ctx->innerctx);

	/* Complete outer hash */
	SHA512_Update(&ctx->outerctx, digest, sizeof(digest));
	SHA512_Final(digest, &ctx->outerctx);

	explicit_bzero(ctx, sizeof(*ctx));
	/* out_sz == 0 means "Give me the whole hash!" */
	if (out_sz == 0)
		out_sz = SHA512_MDLEN;
	bcopy(digest, out, out_sz);
	explicit_bzero(digest, sizeof(digest));
}

void
eli_crypt_hmac(u_char * hkey, size_t hkey_sz,
               u_char * data, size_t data_sz,
               u_char * out, size_t out_sz)
{
	/* HMAC(Key, data) = H((k_opad) + H(k_ipad + data))
	 * K = H(Key) if Key > blocksize else Key
	 * k_ipad = K ^ ipad
	 * k_opad = K ^ opad
	 * https://en.wikipedia.org/wiki/HMAC#Definition
	 */
	struct hmac_ctx ctx;

	eli_crypt_hmac_init(&ctx, hkey, hkey_sz);
	eli_crypt_hmac_update(&ctx, data, data_sz);
	eli_crypt_hmac_final(&ctx, out, out_sz);
}

/* Here we generate IV. It is unique for every sector */
void
eli_crypto_ivgen(struct eli_softc *sc, off_t offset, u_char *iv,
    size_t size)
{
	uint8_t off[8];

	if (sc->sc_flags & ELI_FLAG_NATIVE_BYTE_ORDER)
		bcopy(&offset, off, sizeof off);
	else
		le64enc(off, (uint64_t)offset);

	switch (sc->sc_ealgo) {
	case CRYPTO_AES_XTS:
		bcopy(off, iv, sizeof off);
		bzero(iv + sizeof off, size - sizeof off);
		break;
#if 0
	default:
	{
		u_char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX ctx;

		/* Copy precalculated SHA256 context for IV-Key. */
		bcopy(&sc->sc_ivctx, &ctx, sizeof ctx);
		SHA256_Update(&ctx, off, sizeof off);
		SHA256_Final(hash, &ctx);
		bcopy(hash, iv, size < sizeof hash ? size : sizeof hash);
		break;
	}
#endif /* AES-CBC Support */
	}
}
