/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011-2019 Pawel Jakub Dawidek <pawel@dawidek.net>
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
eli_key_fill(struct eli_softc *sc, struct eli_key *key, uint64_t keyno)
{
	uint8_t *ekey;
	struct {
		char magic[4];
		uint8_t keyno[8];
	} __attribute__((packed)) hmacdata;

	if ((sc->sc_flags & ELI_FLAG_ENC_IVKEY) != 0)
		ekey = sc->sc_mkey;
	else
		ekey = sc->sc_ekey;

	bcopy("ekey", hmacdata.magic, 4);
	le64enc(hmacdata.keyno, keyno);
	eli_crypt_hmac(ekey, ELI_MAXKEYLEN, (u_char *)&hmacdata,
	    sizeof(hmacdata), key->ek_key, 0);
	key->ek_keyno = keyno;
	key->ek_count = 0;
	key->ek_magic = ELI_KEY_MAGIC;
}

static struct eli_key *
eli_key_allocate(struct eli_softc *sc, uint64_t keyno)
{
	struct eli_key *key;

	/* FIXME: return NULL */
	if ((key = malloc(sizeof(*key))) == NULL)
		errx(1, "failed to allocated key");

	eli_key_fill(sc, key, keyno);

	/*
	* TODO: Support for MP-Safe:
	 * Recheck if the key wasn't added by another thread
	*/
	TAILQ_INSERT_TAIL(&sc->sc_ekeys_queue, key, ek_next);
	sc->sc_ekeys_allocated++;

	return (key);
}

void
eli_key_init(struct eli_softc *sc)
{
	u_char *mkey;
#ifdef NOT_YET
	u_char data[] = "\x10";
#endif /* TODO: add ELI_FLAG_AUTH support */

	/* TODO: Support for MP-Safe */
	mkey = sc->sc_mkey + sizeof(sc->sc_ivkey);
	if ((sc->sc_flags & ELI_FLAG_AUTH) == 0) {
		bcopy(mkey, sc->sc_ekey, sizeof sc->sc_ekey);
	}
#ifdef NOT_YET
	else {
		/* The encryption key is: ekey = HMAC_SHA512(Data-Key, 0x10) */
		eli_crypt_hmac(mkey, ELI_MAXKEYLEN, data, 1,
		    sc->sc_ekey, 0);
	}
#endif /* TODO: add ELI_FLAG_AUTH support */

	if ((sc->sc_flags & ELI_FLAG_SINGLE_KEY) != 0) {
		sc->sc_ekeys_total = 1;
		sc->sc_ekeys_allocated = 0;
	} else {
		off_t mediasize;
		size_t blocksize;

#ifdef NOT_YET
		if ((sc->sc_flags & ELI_FLAG_AUTH) != 0) {
		} else
#endif /* TODO: add ELI_FLAG_AUTH support */
		{
			mediasize = sc->sc_mediasize;
			blocksize = sc->sc_sectorsize;
		}

		sc->sc_ekeys_total =
		    ((mediasize - 1) >> ELI_KEY_SHIFT) / blocksize + 1;
		sc->sc_ekeys_allocated = 0;
		TAILQ_INIT(&sc->sc_ekeys_queue);
		/* TODO: Define maximum number of pre-defined keys */
		{
			uint64_t keyno;
			for (keyno = 0; keyno < sc->sc_ekeys_total; keyno++)
				(void)eli_key_allocate(sc, keyno);
		}
	}
}

/*
 * Select encryption key. If ELI_FLAG_SINGLE_KEY is present we only have one
 * key available for all the data. If the flag is not present select the key
 * based on data offset.
 */
u_char *
eli_key_hold(struct eli_softc *sc, off_t offset, size_t blocksize)
{
	struct eli_key *key;
	uint64_t keyno;

	if ((sc->sc_flags & ELI_FLAG_SINGLE_KEY) != 0)
		return (sc->sc_ekey);

	/* We switch key every 2^ELI_KEY_SHIFT blocks. */
	keyno = (offset >> ELI_KEY_SHIFT) / blocksize;
	assert(keyno < sc->sc_ekeys_total);

	/* TODO: If maximum number of pre-defined keys is defined, search for keyno
	 * if cached, otherwise allocate the key
	 */
	TAILQ_FOREACH(key, &sc->sc_ekeys_queue, ek_next)
		if (key->ek_keyno == keyno)
			break;

	assert(key != NULL);
	assert(key->ek_magic == ELI_KEY_MAGIC);

	return (key->ek_key);
}
