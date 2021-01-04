/* Copyright */
#include "geli.h"

int
eli_crypto_cipher(u_int algo, int enc, u_char *data, size_t data_sz,
                  const u_char *key, size_t key_sz)
{
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *type;
	u_char iv[key_sz];
	int out_sz;

	assert(algo != CRYPTO_AES_XTS);

	/* Support AES-CBC */
	switch (algo) {
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
			return EINVAL;
		}
		break;
	default:
		return EINVAL;
	}

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, type, NULL, NULL, NULL, enc);
	EVP_CIPHER_CTX_set_key_length(&ctx, key_sz / 8);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	explicit_bzero(iv, sizeof iv);
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, enc);

	if (EVP_CipherUpdate(&ctx, data, &out_sz, data, data_sz) == 0) {
		explicit_bzero(&ctx, sizeof ctx);
		return EINVAL;
	}
	assert(out_sz == (int)data_sz);

	if (EVP_CipherFinal_ex(&ctx, data + out_sz, &out_sz) == 0) {
		explicit_bzero(&ctx, sizeof ctx);
		return EINVAL;
	}
	assert(out_sz == 0);

	explicit_bzero(&ctx, sizeof ctx);
	return 0;
}

int
eli_crypt_encrypt(u_int algo, u_char *data, size_t data_sz, const u_char *key, size_t key_sz)
{
	/* We prefer AES-CBC for metadata protection. */
	if (algo == CRYPTO_AES_XTS)
		algo = CRYPTO_AES_CBC;

	return eli_crypto_cipher(algo, 1, data, data_sz, key, key_sz);
}

int
eli_crypt_decrypt(u_int algo, u_char *data, size_t data_sz, const u_char *key, size_t key_sz)
{
	/* We prefer AES-CBC for metadata protection. */
	if (algo == CRYPTO_AES_XTS)
		algo = CRYPTO_AES_CBC;

	return eli_crypto_cipher(algo, 0, data, data_sz, key, key_sz);
}
