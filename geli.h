/* Copyright */
#ifndef _GELI_H_
#define _GELI_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <endian.h>
#include <fcntl.h>
#include <err.h>
#include <inttypes.h>

#include <sys/errno.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

#include <linux/nbd.h>
#include <linux/fs.h>

#include <bsd/stdlib.h>
#include <bsd/string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "endian.h"

#define	ELI_MAGIC		"GEOM::ELI"

/*
 * Version history:
 * 0 - Initial version number.
 * 1 - Added data authentication support (md_aalgo field and
 *     ELI_FLAG_AUTH flag).
 * 2 - Added ELI_FLAG_READONLY.
 * 3 - Added 'configure' subcommand.
 * 4 - IV is generated from offset converted to little-endian
 *     (the ELI_FLAG_NATIVE_BYTE_ORDER flag will be set for older versions).
 * 5 - Added multiple encrypton keys and AES-XTS support.
 * 6 - Fixed usage of multiple keys for authenticated providers (the
 *     ELI_FLAG_FIRST_KEY flag will be set for older versions).
 * 7 - Encryption keys are now generated from the Data Key and not from the
 *     IV Key (the ELI_FLAG_ENC_IVKEY flag will be set for older versions).
 */
#define	ELI_VERSION_00		0
#define	ELI_VERSION_01		1
#define	ELI_VERSION_02		2
#define	ELI_VERSION_03		3
#define	ELI_VERSION_04		4
#define	ELI_VERSION_05		5
#define	ELI_VERSION_06		6
#define	ELI_VERSION_07		7
#define	ELI_VERSION		ELI_VERSION_07

/* ON DISK FLAGS. */
/* Use random, onetime keys. */
#define	ELI_FLAG_ONETIME		0x00000001
/* Ask for the passphrase from the kernel, before mounting root. */
#define	ELI_FLAG_BOOT			0x00000002
/* Detach on last close, if we were open for writing. */
#define	ELI_FLAG_WO_DETACH		0x00000004
/* Detach on last close. */
#define	ELI_FLAG_RW_DETACH		0x00000008
/* Provide data authentication. */
#define	ELI_FLAG_AUTH			0x00000010
/* Provider is read-only, we should deny all write attempts. */
#define	ELI_FLAG_RO			0x00000020
/* Don't pass through BIO_DELETE requests. */
#define	ELI_FLAG_NODELETE		0x00000040
/* This GELI supports GELIBoot */
#define	ELI_FLAG_GELIBOOT		0x00000080
/* Hide passphrase length in GELIboot. */
#define	ELI_FLAG_GELIDISPLAYPASS	0x00000100
/* RUNTIME FLAGS. */
/* Provider was open for writing. */
#define	ELI_FLAG_WOPEN		0x00010000
/* Destroy device. */
#define	ELI_FLAG_DESTROY		0x00020000
/* Provider uses native byte-order for IV generation. */
#define	ELI_FLAG_NATIVE_BYTE_ORDER	0x00040000
/* Provider uses single encryption key. */
#define	ELI_FLAG_SINGLE_KEY		0x00080000
/* Device suspended. */
#define	ELI_FLAG_SUSPEND		0x00100000
/* Provider uses first encryption key. */
#define	ELI_FLAG_FIRST_KEY		0x00200000
/* Provider uses IV-Key for encryption key generation. */
#define	ELI_FLAG_ENC_IVKEY		0x00400000

#define	SHA512_MDLEN		64
#define	G_ELI_AUTH_SECKEYLEN	SHA256_DIGEST_LENGTH

#define ELI_MAXMKEYS 		2
#define ELI_MAXKEYLEN 		64
#define ELI_USERKEYLEN 		ELI_MAXKEYLEN
#define ELI_DATAKEYLEN 		ELI_MAXKEYLEN
#define	ELI_AUTHKEYLEN		ELI_MAXKEYLEN
#define ELI_IVKEYLEN 		ELI_MAXKEYLEN
#define ELI_SALTLEN 		64
#define ELI_DATAIVKEYLEN	(ELI_DATAKEYLEN + ELI_IVKEYLEN)
#define ELI_MKEYLEN		(ELI_DATAIVKEYLEN + SHA512_MDLEN)
#define	ELI_OVERWRITES		5
#define ELI_KEY_SHIFT 		20

#define CRYPTO_ALGORITHM_MIN    1
#define CRYPTO_DES_CBC          1
#define CRYPTO_3DES_CBC         2
#define CRYPTO_BLF_CBC          3
#define CRYPTO_CAST_CBC         4
#define CRYPTO_SKIPJACK_CBC     5
#define CRYPTO_MD5_HMAC         6
#define CRYPTO_SHA1_HMAC        7
#define CRYPTO_RIPEMD160_HMAC   8
#define CRYPTO_MD5_KPDK         9
#define CRYPTO_SHA1_KPDK        10
#define CRYPTO_RIJNDAEL128_CBC  11 /* 128 bit blocksize */
#define CRYPTO_AES_CBC          11 /* 128 bit blocksize -- the same as above */
#define CRYPTO_ARC4             12
#define CRYPTO_MD5              13
#define CRYPTO_SHA1             14
#define CRYPTO_NULL_HMAC        15
#define CRYPTO_NULL_CBC         16
#define CRYPTO_DEFLATE_COMP     17 /* Deflate compression algorithm */
#define CRYPTO_SHA2_256_HMAC    18
#define CRYPTO_SHA2_384_HMAC    19
#define CRYPTO_SHA2_512_HMAC    20
#define CRYPTO_CAMELLIA_CBC     21
#define CRYPTO_AES_XTS          22
#define CRYPTO_ALGORITHM_MAX    40 /* Keep updated - see below */

#define IVSIZE 			16

struct eli_softc {
	u_int		 sc_version;
	u_int		 sc_crypto;
	uint8_t		 sc_mkey[ELI_DATAIVKEYLEN];
	uint8_t		 sc_ekey[ELI_DATAKEYLEN];
	TAILQ_HEAD(, eli_key) sc_ekeys_queue;
	uint64_t	 sc_ekeys_total;
	uint64_t	 sc_ekeys_allocated;
	u_int		 sc_ealgo;
	u_int		 sc_ekeylen;
	uint8_t		 sc_akey[ELI_AUTHKEYLEN];
	u_int		 sc_aalgo;
	u_int		 sc_akeylen;
	u_int		 sc_alen;
	SHA256_CTX	 sc_akeyctx;
	uint8_t		 sc_ivkey[ELI_IVKEYLEN];
	SHA256_CTX	 sc_ivctx;
	int		 sc_nkey;
	uint32_t	 sc_flags;
	int		 sc_inflight;
	off_t		 sc_mediasize;
	size_t		 sc_sectorsize;
	u_int		 sc_bytes_per_sector;
	u_int		 sc_data_per_sector;
} eli_sc;

#define	ELI_KEY_MAGIC	0xe11341c

struct eli_key {
	/* Key value, must be first in the structure. */
	uint8_t		ek_key[ELI_DATAKEYLEN];
	int		ek_magic;
	uint64_t	ek_keyno;
	int		ek_count;
	/* Keeps keys sorted by most recent use. */
	TAILQ_ENTRY(eli_key) ek_next;
};

/* TODO: turn into named-struct */
struct eli_metadata {
	char		md_magic[16];
	uint32_t	md_version;
	uint32_t	md_flags;
	uint16_t	md_ealgo;
	uint16_t	md_keylen;
	uint16_t	md_aalgo;
	uint64_t	md_provsize;
	uint32_t	md_sectorsize;
	uint8_t		md_keys;
	int32_t		md_iterations;
	uint8_t		md_salt[ELI_SALTLEN];
	uint8_t		md_mkeys[ELI_MAXMKEYS * ELI_MKEYLEN];
	uint8_t		md_hash[MD5_DIGEST_LENGTH];
} __attribute__((packed));

static __inline void
eli_metadata_encode_v0(struct eli_metadata *md, u_char **datap)
{
	u_char *p;

	p = *datap;
	le32enc(p, md->md_flags);	p += sizeof(md->md_flags);
	le16enc(p, md->md_ealgo);	p += sizeof(md->md_ealgo);
	le16enc(p, md->md_keylen);	p += sizeof(md->md_keylen);
	le64enc(p, md->md_provsize);	p += sizeof(md->md_provsize);
	le32enc(p, md->md_sectorsize);	p += sizeof(md->md_sectorsize);
	*p = md->md_keys;		p += sizeof(md->md_keys);
	le32enc(p, md->md_iterations);	p += sizeof(md->md_iterations);
	bcopy(md->md_salt, p, sizeof(md->md_salt)); p += sizeof(md->md_salt);
	bcopy(md->md_mkeys, p, sizeof(md->md_mkeys)); p += sizeof(md->md_mkeys);
	*datap = p;
}

static __inline void
eli_metadata_encode_v1v2v3v4v5v6v7(struct eli_metadata *md, u_char **datap)
{
	u_char *p;

	p = *datap;
	le32enc(p, md->md_flags);	p += sizeof md->md_flags;
	le16enc(p, md->md_ealgo);	p += sizeof md->md_ealgo;
	le16enc(p, md->md_keylen);	p += sizeof md->md_keylen;
	le16enc(p, md->md_aalgo);	p += sizeof md->md_aalgo;
	le64enc(p, md->md_provsize);	p += sizeof md->md_provsize;
	le32enc(p, md->md_sectorsize);	p += sizeof md->md_sectorsize;
	*p = md->md_keys;		p += sizeof md->md_keys;
	le32enc(p, md->md_iterations);	p += sizeof md->md_iterations;
	bcopy(md->md_salt, p, sizeof md->md_salt);	p += sizeof md->md_salt;
	bcopy(md->md_mkeys, p, sizeof md->md_mkeys);	p += sizeof md->md_mkeys;
	*datap = p;
}

static __inline void
eli_metadata_encode(struct eli_metadata *md, u_char *data)
{
	u_char hash[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	u_char *p;

	p = data;
	bcopy(md->md_magic, p, sizeof md->md_magic);	p += sizeof md->md_magic;
	le32enc(p, md->md_version);			p += sizeof md->md_version;
	switch (md->md_version) {
	case ELI_VERSION_00:
		break;
	case ELI_VERSION_01:
	case ELI_VERSION_02:
	case ELI_VERSION_03:
	case ELI_VERSION_04:
	case ELI_VERSION_05:
	case ELI_VERSION_06:
	case ELI_VERSION_07:
		eli_metadata_encode_v1v2v3v4v5v6v7(md, &p);
		break;
	default:
		break;
	}
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, p - data);
	MD5_Final((void *)hash, &ctx);
	bcopy(hash, md->md_hash, sizeof md->md_hash);
	bcopy(md->md_hash, p, sizeof md->md_hash);
}

static __inline int
eli_metadata_decode_v1v2v3v4v5v6v7(u_char *data, struct eli_metadata *md)
{
	u_char hash[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	u_char *p;

	/* Already checked md_magic and md_version */
	p = data + sizeof(md->md_magic) + sizeof(md->md_version);

	md->md_flags = le32dec(p);	p += sizeof md->md_flags;
	md->md_ealgo = le16dec(p);	p += sizeof md->md_ealgo;
	md->md_keylen = le16dec(p);	p += sizeof md->md_keylen;
	md->md_aalgo = le16dec(p);	p += sizeof md->md_aalgo;
	md->md_provsize = le64dec(p);	p += sizeof md->md_provsize;
	md->md_sectorsize = le32dec(p);	p += sizeof md->md_sectorsize;
	md->md_keys = *p;		p += sizeof md->md_keys;
	md->md_iterations = le32dec(p);	p += sizeof md->md_iterations;
	bcopy(p, md->md_salt, sizeof(md->md_salt));	p += sizeof md->md_salt;
	bcopy(p, md->md_mkeys, sizeof md->md_mkeys);	p += sizeof md->md_mkeys;
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, p - data);
	MD5_Final(hash, &ctx);
	bcopy(hash, md->md_hash, sizeof(md->md_hash));

	if (bcmp(md->md_hash, p, sizeof(md->md_hash)) != 0)
		return EINVAL;

	return 0;
}

static __inline int
eli_metadata_decode(u_char *data, struct eli_metadata *md)
{
	int error;

	bcopy(data, md->md_magic, sizeof(md->md_magic));
	if (strcmp(md->md_magic, ELI_MAGIC))
		return EINVAL;
	md->md_version = le32dec(data + sizeof(md->md_magic));
	switch (md->md_version) {
	case ELI_VERSION_00:
		error = EOPNOTSUPP;
		break;
	case ELI_VERSION_01:
	case ELI_VERSION_02:
	case ELI_VERSION_03:
	case ELI_VERSION_04:
	case ELI_VERSION_05:
	case ELI_VERSION_06:
	case ELI_VERSION_07:
		error = eli_metadata_decode_v1v2v3v4v5v6v7(data, md);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static __inline u_int
g_eli_str2ealgo(const char *name)
{
	if (strcasecmp("null", name) == 0)
		return (CRYPTO_NULL_CBC);
	else if (strcasecmp("null-cbc", name) == 0)
		return (CRYPTO_NULL_CBC);
	else if (strcasecmp("aes", name) == 0)
		return (CRYPTO_AES_XTS);
	else if (strcasecmp("aes-cbc", name) == 0)
		return (CRYPTO_AES_CBC);
	else if (strcasecmp("aes-xts", name) == 0)
		return (CRYPTO_AES_XTS);
	else if (strcasecmp("blowfish", name) == 0)
		return (CRYPTO_BLF_CBC);
	else if (strcasecmp("blowfish-cbc", name) == 0)
		return (CRYPTO_BLF_CBC);
	else if (strcasecmp("camellia", name) == 0)
		return (CRYPTO_CAMELLIA_CBC);
	else if (strcasecmp("camellia-cbc", name) == 0)
		return (CRYPTO_CAMELLIA_CBC);
	else if (strcasecmp("3des", name) == 0)
		return (CRYPTO_3DES_CBC);
	else if (strcasecmp("3des-cbc", name) == 0)
		return (CRYPTO_3DES_CBC);
	return (CRYPTO_ALGORITHM_MIN - 1);
}

static __inline const char *
eli_algo2str(uint16_t algo)
{
	switch (algo) {
	case CRYPTO_NULL_CBC:
		return ("NULL");
	case CRYPTO_AES_CBC:
		return ("AES-CBC");
	case CRYPTO_AES_XTS:
		return ("AES-XTS");
	case CRYPTO_BLF_CBC:
		return ("Blowfish-CBC");
	case CRYPTO_CAMELLIA_CBC:
		return ("CAMELLIA-CBC");
	case CRYPTO_3DES_CBC:
		return ("3DES-CBC");
	case CRYPTO_MD5_HMAC:
		return ("HMAC/MD5");
	case CRYPTO_SHA1_HMAC:
		return ("HMAC/SHA1");
	case CRYPTO_RIPEMD160_HMAC:
		return ("HMAC/RIPEMD160");
	case CRYPTO_SHA2_256_HMAC:
		return ("HMAC/SHA256");
	case CRYPTO_SHA2_384_HMAC:
		return ("HMAC/SHA384");
	case CRYPTO_SHA2_512_HMAC:
		return ("HMAC/SHA512");
	}
	return ("unknown");
}

static __inline void
eli_metadata_dump(const struct eli_metadata *md)
{
	u_int i;
	static const char hex[] = "0123456789abcdef";
	char str[sizeof(md->md_mkeys) * 2 + 1];

	printf("     magic: %s\n", md->md_magic);
	printf("   version: %u\n", md->md_version);
	printf("     flags: 0x%x\n", md->md_flags);
	printf("     ealgo: %s (%u)\n", eli_algo2str(md->md_ealgo), md->md_ealgo);
	printf("    keylen: %u\n", md->md_keylen);
	if (md->md_flags & ELI_FLAG_AUTH)
		printf("     aalgo: %s (%u)\n", eli_algo2str(md->md_aalgo), md->md_aalgo);
	printf("  provsize: %ju\n", md->md_provsize);
	printf("sectorsize: %u\n", md->md_sectorsize);
	printf("      keys: 0x%02x\n", md->md_keys);
	printf("iterations: %u\n", md->md_iterations);
	explicit_bzero(str, sizeof(str));
	for (i = 0; i < sizeof(md->md_salt); i++) {
		str[i * 2] = hex[md->md_salt[i] >> 4];
		str[i * 2 + 1] = hex[md->md_salt[i] & 0x0f];
	}
	printf("      Salt: %s\n", str);

	explicit_bzero(str, sizeof(str));
	for (i = 0; i < sizeof(md->md_mkeys); i++) {
		str[i * 2] = hex[md->md_mkeys[i] >> 4];
		str[i * 2 + 1] = hex[md->md_mkeys[i] & 0x0f];
	}
	printf("Master Key: %s\n", str);

	explicit_bzero(str, sizeof(str));
	for (i = 0; i < sizeof(md->md_hash); i++) {
		str [i * 2] = hex[md->md_hash[i] >> 4];
		str [i * 2 + 1] = hex[md->md_hash[i] & 0x0f];
	}
	str[sizeof(md->md_hash) * 2] = '\0';
	printf("  MD5 hash: %s\n", str);
}

static __inline u_int
eli_keylen(u_int algo, u_int keylen)
{
	switch (algo) {
	case CRYPTO_AES_XTS:
		switch (keylen) {
		case 0:
			return 128;
		case 128:
		case 256:
			return keylen;
		default:
			return 0;
		}
	default:
		return 0;
	}
}

static u_int
eli_hashlen(u_int algo)
{
	switch (algo) {
	case CRYPTO_SHA1_HMAC:
		return (20);
	case CRYPTO_RIPEMD160_HMAC:
		return (20);
	case CRYPTO_SHA2_256_HMAC:
		return (32);
	case CRYPTO_SHA2_384_HMAC:
		return (48);
	case CRYPTO_SHA2_512_HMAC:
		return (64);
	}
	return (0);
}

static __inline void
eli_metadata_softc(struct eli_softc *sc, const struct eli_metadata *md,
    u_int sectorsize, off_t mediasize)
{
	sc->sc_version = md->md_version;
	sc->sc_flags = md->md_flags;
	/* Backward compatibility. */
	if (md->md_version < ELI_VERSION_04)
		sc->sc_flags |= ELI_FLAG_NATIVE_BYTE_ORDER;
	if (md->md_version < ELI_VERSION_05)
		sc->sc_flags |= ELI_FLAG_SINGLE_KEY;
	if (md->md_version < ELI_VERSION_06 &&
	    (sc->sc_flags & ELI_FLAG_AUTH) != 0)
		sc->sc_flags |= ELI_FLAG_FIRST_KEY;
	if (md->md_version < ELI_VERSION_07)
		sc->sc_flags |= ELI_FLAG_ENC_IVKEY;
	sc->sc_ealgo = md->md_ealgo;

	if (sc->sc_flags & ELI_FLAG_AUTH) {
		sc->sc_akeylen = sizeof(sc->sc_akey) * 8;
		sc->sc_aalgo = md->md_aalgo;
		sc->sc_alen = eli_hashlen(sc->sc_aalgo);

		sc->sc_data_per_sector = sectorsize - sc->sc_alen;
		/*
		 * Some hash functions (like SHA1 and RIPEMD160) generates hash
		 * which length is not multiple of 128 bits, but we want data
		 * length to be multiple of 128, so we can encrypt without
		 * padding. The line below rounds down data length to multiple
		 * of 128 bits.
		 */
		sc->sc_data_per_sector -= sc->sc_data_per_sector % 16;

		sc->sc_bytes_per_sector =
		    (md->md_sectorsize - 1) / sc->sc_data_per_sector + 1;
		sc->sc_bytes_per_sector *= sectorsize;
	}
	sc->sc_sectorsize = md->md_sectorsize;
	sc->sc_mediasize = mediasize;
	if (!(sc->sc_flags & ELI_FLAG_ONETIME))
		sc->sc_mediasize -= sectorsize;
	if (sc->sc_flags & ELI_FLAG_AUTH) {
		sc->sc_mediasize /= sc->sc_bytes_per_sector;
		sc->sc_mediasize *= sc->sc_sectorsize;
	} else {
		sc->sc_mediasize -= (sc->sc_mediasize % sc->sc_sectorsize);
	}
	sc->sc_ekeylen = md->md_keylen;
}

struct hmac_ctx {
	SHA512_CTX innerctx;
	SHA512_CTX outerctx;
};

int	eli_mkey_decrypt(struct eli_metadata *md, u_char *key, u_char *mkey, int nkey);
int	eli_mkey_decrypt_any(struct eli_metadata *md, u_char *key, u_char *mkey, int *nkeyp);
int	eli_mkey_encrypt(uint16_t algo, u_char *key, uint16_t keylen, u_char *mkey);
void	eli_mkey_propagate(struct eli_softc *sc, u_char *mkey);

void	eli_crypt_hmac_init(struct hmac_ctx *ctx, u_char *hkey, size_t hkey_sz);
void	eli_crypt_hmac_update(struct hmac_ctx *ctx, u_char *data, size_t data_sz);
void	eli_crypt_hmac_final(struct hmac_ctx *ctx, u_char * out, size_t out_sz);
void	eli_crypt_hmac(u_char *hkey, size_t hkey_sz, u_char *data, size_t data_sz, u_char *out, size_t out_sz);
void	eli_crypto_ivgen(struct eli_softc *sc, off_t offset, u_char *iv, size_t size);

void	pkcs5v2_genkey(u_char *key, unsigned key_sz, u_char *salt, size_t salt_sz, u_char *passphrase, u_int iterations);

int	eli_crypto_cipher(u_int algo, int enc, u_char *data, size_t data_sz, const u_char *key, size_t key_sz);
int	eli_crypt_encrypt(u_int algo, u_char *data, size_t data_sz, const u_char *key, size_t key_sz);
int	eli_crypt_decrypt(u_int algo, u_char *data, size_t data_sz, const u_char *key, size_t key_sz);

void	eli_key_fill(struct eli_softc *sc, struct eli_key *key, uint64_t keyno);
void	eli_key_init(struct eli_softc *sc);
u_char *	eli_key_hold(struct eli_softc *sc, off_t offset, size_t blocksize);
#endif /* !_GELI_H_ */
