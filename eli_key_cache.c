/* Copyright */
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
	    sizeof hmacdata, key->ek_key, 0);
	key->ek_keyno = keyno;
	key->ek_count = 0;
	key->ek_magic = ELI_KEY_MAGIC;
}

static struct eli_key *
eli_key_allocate(struct eli_softc *sc, uint64_t keyno)
{
	struct eli_key *key;

	if ((key = malloc(sizeof(*key))) == NULL)
		errx(1, "failed to allocated key");

	eli_key_fill(sc, key, keyno);
	TAILQ_INSERT_TAIL(&sc->sc_ekeys_queue, key, ek_next);
	sc->sc_ekeys_allocated++;

	return key;
}

void
eli_key_init(struct eli_softc *sc)
{
	u_char *mkey, data[] = "\x10";

	mkey = sc->sc_mkey + sizeof(sc->sc_ivkey);
	if (sc->sc_flags & ELI_FLAG_AUTH) {
		/* The encryption key is: ekey = HMAC_SHA512(Data-Key, 0x10) */
		eli_crypt_hmac(mkey, ELI_MAXKEYLEN, data, 1,
		    sc->sc_ekey, 0);
	} else {
		bcopy(mkey, sc->sc_ekey, sizeof sc->sc_ekey);
	}

	if (sc->sc_flags & ELI_FLAG_SINGLE_KEY) {
		sc->sc_ekeys_total = 1;
		sc->sc_ekeys_allocated = 0; /* TODO: when to increase? */
	} else {
		off_t mediasize;
		size_t blocksize;

		/* TODO: Check for ELI_FLAG_AUTH */
		mediasize = sc->sc_mediasize;
		blocksize = sc->sc_sectorsize;

		TAILQ_INIT(&sc->sc_ekeys_queue);
		sc->sc_ekeys_total =
		    ((mediasize - 1) >> ELI_KEY_SHIFT) / blocksize + 1;
		sc->sc_ekeys_allocated = 0;

		uint64_t keyno;
		/* TODO: Check if total number os keys are not too much */
		for (keyno = 0; keyno < sc->sc_ekeys_total; keyno++)
			eli_key_allocate(sc, keyno);
	}
}

u_char *
eli_key_hold(struct eli_softc *sc, off_t offset, size_t blocksize)
{
	struct eli_key *key;
	uint64_t keyno;

	/*
	 * Select encryption key. If G_ELI_FLAG_SINGLE_KEY is present we only have one
	 * key available for all the data. If the flag is not present select the key
	 * based on data offset.
	 */
	if (sc->sc_flags & ELI_FLAG_SINGLE_KEY)
		return (sc->sc_ekey);

	/* We switch key every 2^ELI_KEY_SHIFT blocks. */
	keyno = (offset >> ELI_KEY_SHIFT) / blocksize;

	TAILQ_FOREACH(key, &sc->sc_ekeys_queue, ek_next)
		if (key->ek_keyno == keyno)
			break;

	assert(key != NULL);
	return (key->ek_key);
}
