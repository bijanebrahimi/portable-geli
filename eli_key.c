/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005-2011 Pawel Jakub Dawidek <pawel@dawidek.net>
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

static int
eli_mkey_verify(u_char *mkey, u_char *key)
{
	u_char *odhmac;		/* On-disk HMAC. */
	u_char chmac[SHA512_MDLEN];	/* Calculated HMAC. */
	u_char hmkey[SHA512_MDLEN];	/* Key for HMAC. */
	u_char data[] = "\x00";

	/*
	 * The key for HMAC calculations is: hmkey = HMAC_SHA512(Derived-Key, 0)
	 */
	eli_crypt_hmac(key, ELI_USERKEYLEN, data, 1, hmkey, 0);

	odhmac = mkey + ELI_DATAIVKEYLEN;

	/* Calculate HMAC from Data-Key and IV-Key. */
	eli_crypt_hmac(hmkey, sizeof(hmkey), mkey, ELI_DATAIVKEYLEN,
	    chmac, 0);

	explicit_bzero(hmkey, sizeof hmkey);

	/*
	 * Compare calculated HMAC with HMAC from metadata.
	 * If two HMACs are equal, 'key' is correct.
	 */
	return (!strncmp((const char *)odhmac, (const char *)chmac, SHA512_MDLEN));
}

/* Calculate HMAC from Data-Key and IV-Key. */
static void
eli_mkey_hmac(u_char *mkey, u_char *key)
{
	u_char hmkey[SHA512_MDLEN];	/* Key for HMAC. */
	u_char *odhmac;	/* On-disk HMAC. */
	u_char data[] = "\x00";

	/* The key for HMAC calculations is: hmkey = HMAC_SHA512(Derived-Key, 0) */
	eli_crypt_hmac(key, ELI_USERKEYLEN, data, 1, hmkey, 0);

	odhmac = mkey + ELI_DATAIVKEYLEN;
	/* Calculate HMAC from Data-Key and IV-Key. */
	eli_crypt_hmac(hmkey, sizeof(hmkey), mkey, ELI_DATAIVKEYLEN,
	    odhmac, 0);

	explicit_bzero(hmkey, sizeof(hmkey));
}

/*
 * Find and decrypt Master Key encrypted with 'key' at slot 'nkey'.
 * Return 0 on success, > 0 on failure, -1 on bad key.
 */
int
eli_mkey_decrypt(struct eli_metadata *md, u_char *key,
    u_char *mkey, int nkey)
{
	u_char tmpmkey[ELI_MKEYLEN];
	u_char enckey[SHA512_MDLEN];	/* Key for encryption. */
	u_char *mmkey, data[] = "\x01";
	int error;

	if ((nkey < 0) || (nkey > ELI_MKEYLEN))
		return (1);

	if (!(md->md_keys & (1 << nkey)))
		return (-1);

	/* encryption key = HMAC_SHA512(derived-key, 1) */
	eli_crypt_hmac(key, ELI_USERKEYLEN, data, 1, enckey, 0);

	mmkey = md->md_mkeys + (ELI_MKEYLEN * nkey);
	bcopy(mmkey, tmpmkey, ELI_MKEYLEN);

	error = eli_crypt_decrypt(md->md_ealgo, tmpmkey,
	    ELI_MKEYLEN, enckey, md->md_keylen);
	if (error != 0) {
		explicit_bzero(tmpmkey, sizeof(tmpmkey));
		explicit_bzero(enckey, sizeof(enckey));
		return (error);
	}

	if (eli_mkey_verify(tmpmkey, key)) {
		bcopy(tmpmkey, mkey, ELI_DATAIVKEYLEN);
		explicit_bzero(tmpmkey, sizeof(tmpmkey));
		explicit_bzero(enckey, sizeof(enckey));
		return (0);
	}
	explicit_bzero(enckey, sizeof(enckey));
	explicit_bzero(tmpmkey, sizeof(tmpmkey));

	return (-1);
}

int
eli_mkey_decrypt_any(struct eli_metadata *md, u_char *key,
                     u_char *mkey, int *nkeyp)
{
	int error = -1, nkey;

	if (nkeyp != NULL)
		*nkeyp = -1;

	for (nkey = 0; nkey < ELI_MAXMKEYS; nkey++) {
		error = eli_mkey_decrypt(md, key, mkey, nkey);
		if (error == 0) {
			if (nkeyp != NULL)
				*nkeyp = nkey;
			break;
		} else if (error > 0) {
			break;
		}
	}

	return (error);
}

/*
 * Encrypt the Master-Key and calculate HMAC to be able to verify it in the
 * future.
 */
int
eli_mkey_encrypt(uint16_t algo, u_char *key, uint16_t keylen,
    u_char *mkey)
{
	u_char enckey[SHA512_MDLEN];	/* Key for encryption. */
	u_char data[] = "\x01";
	int error;

	/*
	 * To calculate HMAC, the whole key (ELI_USERKEYLEN bytes long) will
	 * be used.
	 */
	eli_mkey_hmac(mkey, key);
	/*
	 * The key for encryption is: enckey = HMAC_SHA512(Derived-Key, 1)
	 */
	eli_crypt_hmac(key, ELI_USERKEYLEN, data, 1, enckey, 0);
	/*
	 * Encrypt the Master-Key and HMAC() result with the given key (this
	 * time only 'keylen' bits from the key are used).
	 */
	error = eli_crypt_encrypt(algo, mkey, ELI_MKEYLEN, enckey, keylen);

	explicit_bzero(enckey, sizeof(enckey));

	return (error);
}

/*
 * When doing encryption only, copy IV key and encryption key.
 * When doing encryption and authentication, copy IV key, generate encryption
 * key and generate authentication key.
 */
void
eli_mkey_propagate(struct eli_softc *sc, u_char *mkey)
{
#ifdef NOT_YET
	u_char data[] = "\x11";
#endif /* TODO: ELI_FLAG_AUTH support */

	/* Remember the Master Key. */
	bcopy(mkey, sc->sc_mkey, sizeof(sc->sc_mkey));

	bcopy(mkey, sc->sc_ivkey, sizeof(sc->sc_ivkey));
	mkey += sizeof(sc->sc_ivkey);

#ifdef NOT_YET
	/* The authentication key is: akey = HMAC_SHA512(Data-Key, 0x11) */
	if ((sc->sc_flags & ELI_FLAG_AUTH) != 0) {
		eli_crypt_hmac(mkey, ELI_MAXKEYLEN, data, 1,
		    sc->sc_akey, 0);
	} else
#endif /* TODO: ELI_FLAG_AUTH support */
	{
		arc4random_buf(sc->sc_akey, sizeof(sc->sc_akey));
	}

	/* Initialize encryption keys. */
	eli_key_init(sc);

	if ((sc->sc_flags & ELI_FLAG_AUTH) != 0) {
		/*
		 * Precalculate SHA256 for HMAC key generation.
		 * This is expensive operation and we can do it only once now or
		 * for every access to sector, so now will be much better.
		 */
		SHA256_Init(&sc->sc_akeyctx);
		SHA256_Update(&sc->sc_akeyctx, sc->sc_akey,
		    sizeof(sc->sc_akey));
	}
	/*
	 * Precalculate SHA256 for IV generation.
	 * This is expensive operation and we can do it only once now or for
	 * every access to sector, so now will be much better.
	 */
	switch (sc->sc_ealgo) {
	case CRYPTO_AES_XTS:
		break;
#ifdef NOT_YET
	default:
		SHA256_Init(&sc->sc_ivctx);
		SHA256_Update(&sc->sc_ivctx, sc->sc_ivkey,
		    sizeof(sc->sc_ivkey));
		break;
#endif /* TODO: AES_CBC Support */
	}
}
