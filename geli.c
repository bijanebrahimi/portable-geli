/* Copyright */
#include "geli.h"
#include "utils.h"
#include "log.h"

#include <linux/fs.h>	/* ioctl BLKGETSIZE64/BLKSSZGET */

#define NBD_CMD_MASK_COMMAND	0x0000ffff
#define	BUFSIZE			1024

/* Globals */
int verbose;

const char *errmsg;
const char *errstr;
uint8_t retval;

#define ERR(val, msg, str)	do { errmsg = msg; errstr = str; retval = val; } while(0)
#define ERR_SYSCALL(msg)	ERR(errno, msg, strerror(errno))
#define ERR_FAILURE(msg, str)	ERR(EXIT_FAILURE, msg, str)

#define ERR_HANDLE()		do { if (errmsg) { log_err("%s: %s", errmsg, errstr); } } while(0)

/*
 * Passphrase cached during load, in order to be more user-friendly if
 * there are multiple providers using the same passphrase.
 */
static char cached_passphrase[BUFSIZE];

void
sig_handler(int sig)
{
	struct eli_softc *sc = &eli_sc;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:
		break;
	default:
		return;
	}

	/* Close all possible file descriptors */
	close(sc->sc_ifd);
	close(sc->sc_nbd);
	close(sc->sc_pair[0]);
	close(sc->sc_pair[1]);

	explicit_bzero(sc, sizeof *sc);

	exit(0);
}

static void
fetch_env_passphrase(void)
{
	char *env_passphrase;

	if ((env_passphrase = getenv("passphrase")) != NULL) {
		/* Extract passphrase from the environment. */
		strlcpy(cached_passphrase, env_passphrase,
		    sizeof(cached_passphrase));
	}
}

int
eli_read_metadata(int fd, struct eli_metadata *md)
{
	int error, blocksize = 512;
	u_char data[blocksize];

	/* FIXME: look at provider size */
	lseek(fd, -blocksize, SEEK_END);
	error = read_data(fd, data, sizeof data);
	if (error)
		return error;

	error = eli_metadata_decode(data, md);
	if (error)
		return error;

	return 0;
}

struct eli_softc *
eli_create(const struct eli_metadata *md, int fd, int nbd, u_char *mkey, int nkey)
{
	struct eli_softc *sc;
	u_int sectorsize;
	off_t mediasize;

	sc = &eli_sc;

	/* FIXME: get sectorsize and mediasize */
	sectorsize = md->md_sectorsize;
	mediasize = md->md_provsize;
	eli_metadata_softc(sc, md, sectorsize, mediasize);
	sc->sc_nkey = nkey;

	sc->sc_ifd = fd;
	sc->sc_nbd = nbd;

	/* Remember the keys in our softc structure. */
	eli_mkey_propagate(sc, mkey);

	return sc;
}

#if 0
int
g_eli_destroy(struct eli_softc *sc, int force)
{
	/* FIXME: IMPL */
	if (sc == NULL)
		return (ENXIO);

	return 0;
}

static int
eli_destroy_nbd(struct eli_softc *sc)
{
	return (g_eli_destroy(sc, 0));
}
#endif

static void
eli_crypto_run(struct eli_softc *sc, struct nbd_request *req, u_char *buf)
{
	off_t dstoff;
	u_int i, nsec, secsize, cmd;
	u_char *data;
	uint8_t *key, iv[ELI_IVKEYLEN], out[sc->sc_sectorsize];
	size_t key_sz;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *type;

	data = buf;
	secsize = sc->sc_sectorsize;
	nsec = req->len / secsize;
	lseek(sc->sc_ifd, req->from, SEEK_SET);
	cmd = req->type & NBD_CMD_MASK_COMMAND;
	for (i = 0, dstoff = req->from; i < nsec; i++, dstoff += secsize) {
		if (cmd == NBD_CMD_READ)
			read_data(sc->sc_ifd, data, secsize);
		key = eli_key_hold(sc, dstoff, secsize);
		key_sz = sc->sc_ekeylen;
		if (sc->sc_ealgo == CRYPTO_AES_XTS)
			key_sz <<= 1;
		eli_crypto_ivgen(sc, dstoff, iv, sizeof iv);

		/* TODO: cache type in softc struct */
		switch(sc->sc_ealgo) {
		case CRYPTO_AES_XTS:
			switch (sc->sc_ekeylen) {
			case 128:
				type = EVP_aes_128_xts();
				break;
			case 256:
				type = EVP_aes_256_xts();
				break;
			}
			break;
		}

		int out_len, final_out_len;
		if (cmd == NBD_CMD_READ) {
			EVP_DecryptInit(&ctx, type, key, iv);
			EVP_DecryptUpdate(&ctx, data, &out_len, data, secsize);
			EVP_DecryptFinal_ex(&ctx, out + out_len, &final_out_len);
			EVP_CIPHER_CTX_cleanup(&ctx);
		} else {
			EVP_EncryptInit(&ctx, type, key, iv);
			EVP_EncryptUpdate(&ctx, data, &out_len, data, secsize);
			EVP_EncryptFinal_ex(&ctx, out + out_len, &final_out_len);
			EVP_CIPHER_CTX_cleanup(&ctx);
		}
		if (out_len + final_out_len != secsize)
			errx(1, "EVP final_data_len %ld != %d + %d",
			     sizeof data, out_len, final_out_len);
		data += secsize;
	}

	if (cmd == NBD_CMD_WRITE)
		write_data(sc->sc_ifd, buf, req->len);
}

static void
usage(FILE *f, int err, const char *fmt, ...)
{
	if (fmt) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(f, fmt, ap);
		fprintf(f, "\n");
		va_end(ap);
	}

	fprintf(f, "usage: "
	           "geli init [-bdgPRTv] [-a aalgo] [-B backupfile] [-e ealgo]\n"
	           "     [-i iterations] [-J newpassfile] [-K newkeyfile] [-l keylen]\n"
	           "     [-s sectorsize] [-V version] prov\n"
	           "geli attach [-vd] [-j passfile] prov nbd\n"
	           "geli setkey [-v] [-i iterations] [-j passfile] [-J newpassfile] prov\n"
	           "geli backup [-v] prov file\n"
	           "geli restore [-vf] file prov\n"
	           "geli resize [-v] -s oldsize prov\n"
	           "geli version [-v]\n"
	           "geli dump prov[-v]\n");

	exit(err);
}

static int
eli_nbd_create(struct eli_softc *sc)
{
	pid_t pid;
	off_t bytes;
	uint64_t nblocks, blocksize = 512UL;
	u_char *buf;
	const char *errmsg = NULL, *errstr = NULL;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sc->sc_pair) < 0)
		return EINVAL;

	bytes = lseek(sc->sc_ifd, 0, SEEK_END);
	nblocks = (bytes - 512) / blocksize;
	if (nblocks < 0) {
		errmsg = "Cannot get provider media size";
		goto out;
	}

	if (ioctl(sc->sc_nbd, NBD_SET_SIZE, 4096UL) < 0) {
		ERR_SYSCALL("Cannot check provider sector size");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_BLKSIZE, 4096UL) < 0) {
		ERR_SYSCALL("Cannot check provider block size");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_SIZE, (unsigned long)blocksize) < 0) {
		ERR_SYSCALL("Cannot set provider sector size");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_BLKSIZE, blocksize) < 0) {
		ERR_SYSCALL("Cannot set provider block size");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_SIZE_BLOCKS, nblocks) < 0) {
		ERR_SYSCALL("Cannot set provider size");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_CLEAR_SOCK) < 0) {
		ERR_SYSCALL("Cannot clear provider sockets");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_FLAGS, NBD_FLAG_HAS_FLAGS) < 0) {
		ERR_SYSCALL("Cannot set provider server side");
		goto out;
	}
	if (ioctl(sc->sc_nbd, NBD_SET_SOCK, sc->sc_pair[0]) < 0) {
		ERR_SYSCALL("Cannot set provider sockets");
		goto out;
	}

	signal(SIGINT, &sig_handler);
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);

	/* Daemonize */
	if (daemonized) {
		/* FIXME: https://stackoverflow.com/a/17955149 */
		if ((pid = fork()) < 0) {
			ERR_SYSCALL("Cannot fork");
			goto out;
		} else if (pid > 0) {
			exit(0);
		}
	}

	if ((pid = fork()) < 0) {
		ERR_SYSCALL("Cannot fork");
		goto out;
	}

	if(pid > 0) {
		/* Parent */
		close(sc->sc_pair[1]);
		while (1) {
			if (ioctl(sc->sc_nbd, NBD_DO_IT) == 0)
				break;
			if (errno == EINTR)
				continue;
			ERR_SYSCALL("Cannot start NBD device");
			goto out;
		}
		goto out;
	}

	/* Child */
	close(sc->sc_pair[0]);
	close(sc->sc_nbd);

	struct nbd_request request;
	struct nbd_reply reply;

	reply.error = 0;
	reply.magic = htonl(NBD_REPLY_MAGIC);
        while (1) {
		read_data(sc->sc_pair[1], (u_char*) &request, sizeof(request));
		if (request.magic != htonl(NBD_REQUEST_MAGIC))
			goto out;

		request.from = ntohll(request.from);
		request.type = ntohl(request.type);
		request.len = ntohl(request.len);

		memcpy(reply.handle, request.handle, sizeof(reply.handle));
		switch (request.type & NBD_CMD_MASK_COMMAND) {
		case NBD_CMD_DISC:	/* Soft Disconnect */
			reply.error = 0;
			write_data(sc->sc_pair[1], (u_char*)&reply, sizeof(reply));
			break;
		case NBD_CMD_READ:	/* Read */
			if ((buf = malloc(request.len)) == NULL)
				goto out;
			reply.error = 0;
			eli_crypto_run(sc, &request, buf);
			write_data(sc->sc_pair[1], (u_char*)&reply, sizeof(reply));
			write_data(sc->sc_pair[1], buf, request.len);
			free(buf);
			break;
		case NBD_CMD_WRITE:	/* Write */
			if ((buf = malloc(request.len)) == NULL)
				goto out;
			read_data(sc->sc_pair[1], buf, request.len);
			eli_crypto_run(sc, &request, buf);
			reply.error = 0;
			write_data(sc->sc_pair[1], (u_char*)&reply, sizeof(reply));
			free(buf);
			break;
		case NBD_CMD_FLUSH:
		case NBD_CMD_TRIM:
		default:
			reply.error = 0;
		}
	}

out:
	close(sc->sc_pair[0]);
	close(sc->sc_pair[1]);
	close(sc->sc_nbd);
	close(sc->sc_ifd);

	if (ioctl(sc->sc_nbd, NBD_DO_IT) >= 0 || errno == EBADR) {
		// Flush queue and exit
		ioctl(sc->sc_nbd, NBD_CLEAR_QUE);
		ioctl(sc->sc_nbd, NBD_CLEAR_SOCK);
	}

	ERR_HANDLE();
	return retval;
}

static int
eli_genkey_passphrase(struct eli_metadata *md, struct hmac_ctx *ctxp)
{
	char passbuf[BUFSIZE], *ptr;

	passbuf[0] = '\0';

	/* Use cached passphrase if defined. */
	if (strlen(cached_passphrase)) {
		strlcpy(passbuf, cached_passphrase, sizeof passbuf);
		explicit_bzero(cached_passphrase, sizeof cached_passphrase);
	} else {
		ptr = getpass("Enter Password: ");
		if (strlen(ptr) == 0)
			return 1;
		strlcpy(passbuf, ptr, strlen(ptr));
		explicit_bzero(ptr, strlen(ptr));
	}

	/* If md_iterations is equal to 0, user doesn't want PKCS#5v2. */
	if (md->md_iterations == 0) {
		eli_crypt_hmac_update(ctxp, md->md_salt, sizeof md->md_salt);
		eli_crypt_hmac_update(ctxp, (u_char *)passbuf, strlen(passbuf));
	} else {
		u_char dkey[ELI_USERKEYLEN];

		pkcs5v2_genkey(dkey, sizeof dkey, md->md_salt,
		    sizeof md->md_salt, (u_char *)passbuf, md->md_iterations);
		eli_crypt_hmac_update(ctxp, dkey, sizeof dkey);
		explicit_bzero(dkey, sizeof dkey);
	}
	explicit_bzero(passbuf, sizeof(passbuf));

	return (0);
}

static u_char *
eli_genkey(struct eli_metadata *md, unsigned char *key)
{
	struct hmac_ctx ctx;

	eli_crypt_hmac_init(&ctx, NULL, 0);

	if (eli_genkey_passphrase(md, &ctx))
		return (NULL);

	eli_crypt_hmac_final(&ctx, key, 0);

	return (key);
}

static int
eli_metadata_read(char *prov, struct eli_metadata *md)
{
	uint32_t secsize = 512;
	u_char sector[secsize];
	const char *errmsg = NULL, *errstr = NULL;
	int device_fd = -1;

	if ((device_fd = open(prov, O_RDONLY)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

#if 0
	if (ioctl(device_fd, BLKSSZGET, &secsize) < 0) {
		ERR_SYSCALL("Cannot get device information");
		goto out;
	}

	if ((sector = malloc(secsize)) == NULL) {
		ERR_SYSCALL("Cannot allocate memory");
		goto out;
	}
#endif

	lseek(device_fd, -1 * 512, SEEK_END);
	if (read_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot read device");
		goto out;
	}

	if (eli_metadata_decode(sector, md)) {
		ERR_FAILURE("Cannot decode metadata", "Invalid metadata");
		goto out;
	}

out:
	explicit_bzero(&md, sizeof md);
	explicit_bzero(&sector, secsize);

	close(device_fd);

	ERR_HANDLE();
	return retval;
}

static int
eli_init(int argc, char **argv)
{
	int device_fd = -1, passfile_fd = -1;
	char ch;
	struct eli_metadata md;
	char *prov;
	char *ealgo_str = "aes-xts", *iterations_str = NULL, *passfile_str = NULL,
	     *keylen_str = "128", *sectorsize_str = NULL;
	u_char key[ELI_USERKEYLEN];
	u_char sector[512];
	uint16_t ealgo, keylen;
	uint32_t iterations, secsize, val, version = ELI_VERSION;
	uint64_t mediasize;
	const char *errmsg = NULL, *errstr = NULL;

	if (argc < 1)
		usage(stderr, 1, NULL);

	/* fetch passphrase from env */
	fetch_env_passphrase();

	/* User arguments */
	while ((ch = getopt(argc, argv, "e:i:J:l:s:v")) != -1) {
		switch (ch) {
		case 'e':
			ealgo_str = optarg;
			break;
		case 'i':
			iterations_str = optarg;
			break;
		case 'J':
			passfile_str = optarg;
			break;
		case 'l':
			keylen_str = optarg;
			break;
		case 's':
			sectorsize_str = optarg;
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		errmsg = "Invalid arguments";
		goto out;
	}

	prov = argv[0];
	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if ((ealgo = g_eli_str2ealgo(ealgo_str)) < CRYPTO_ALGORITHM_MIN) {
		ERR_FAILURE("Cannot access device", "Unsupported encryption algorithm");
		goto out;
	}

	if (iterations_str == NULL) {
		ERR_FAILURE("Cannot access device", "Iterations are required");
		goto out;
	} else {
		iterations = strtonum(iterations_str, 0, UINT32_MAX, &errstr);
		if (errstr) {
			ERR_FAILURE("Cannot validate iterations", errstr);
			goto out;
		}
	}

	keylen = strtonum(keylen_str, 0, UINT16_MAX, &errstr);
	if (errstr) {
		ERR_FAILURE("Cannot validate key length", errstr);
		goto out;
	} else  if (eli_keylen(ealgo, keylen) == 0) {
		ERR_FAILURE("Cannot validate key length", "Invalid key length");
		goto out;
	}

	if (ioctl(device_fd, BLKSSZGET, &secsize) < 0) {
		ERR_SYSCALL("Cannot get device sector size");
		goto out;
	} else if (ioctl(device_fd, BLKGETSIZE64, &mediasize) < 0) {
		ERR_SYSCALL("Cannot get device media size");
		goto out;
	}

	if (sectorsize_str) {
		/* TODO: secsize should be smaller than pagesize */
		val = strtonum(sectorsize_str, 0, UINT32_MAX, &errstr);
		if (errstr) {
			ERR_FAILURE("Cannot validate sector size", errstr);
			goto out;
		} else if (((val % secsize) != 0) || (val & (val - 1))) {
			ERR_FAILURE("Cannot validate sector size", "Invalid sector size");
			goto out;
		}
		secsize = val;
	}

	/* FIXME: duplicated code */
	if (passfile_str) {
		if (strcmp(passfile_str, "-") == 0)
			passfile_fd = STDIN_FILENO;
		else if ((passfile_fd = open(passfile_str, O_RDONLY)) < 0) {
			ERR_SYSCALL("Cannot open passfile");
			goto out;
		} else  if (read_data(passfile_fd, (u_char *)cached_passphrase, sizeof cached_passphrase)) {
			ERR_SYSCALL("Cannot read passfile");
			goto out;
		}
		if (passfile_fd != STDIN_FILENO)
			close(passfile_fd);
	}

	strlcpy(md.md_magic, ELI_MAGIC, sizeof md.md_magic);
	md.md_version = version;
	md.md_flags = 0x0;
	md.md_ealgo = ealgo;
	md.md_keylen = keylen;
	md.md_aalgo = 0x0;
	md.md_provsize = mediasize;
	md.md_sectorsize = secsize;
	md.md_keys = 0x1;
	md.md_iterations = iterations;
	arc4random_buf(md.md_salt, sizeof md.md_salt);
	arc4random_buf(md.md_mkeys, sizeof md.md_mkeys);

	if (eli_genkey(&md, key) == NULL) {
		ERR_FAILURE("Cannot generate key", "No key components given");
		goto out;
	}

	if (eli_mkey_encrypt(md.md_ealgo, key, md.md_keylen, md.md_mkeys)) {
		ERR_FAILURE("Cannot encrypt Master Key", "Invalid key components");
		goto out;
	}

	/* Convert metadata to on-disk format. */
	eli_metadata_encode(&md, sector);

	lseek(device_fd, -1 * sizeof sector, SEEK_END);
	if (write_data(device_fd, sector, sizeof sector)) {
		ERR_SYSCALL("Cannot store metadata on provider");
		goto out;
	}

out:
	explicit_bzero(&md, sizeof md);
	explicit_bzero(&key, sizeof key);

	close(device_fd);

	ERR_HANDLE();
	return retval;
}

static int
eli_attach(int argc, char **argv)
{
	int error, nkey;
	int passfile_fd = -1, device_fd = -1, nbd_fd = -1;
	char ch, *prov, *nbd, *passfile_str = NULL;
	const char *errmsg = NULL, *errstr = NULL;
	u_char key[ELI_USERKEYLEN], mkey[ELI_DATAIVKEYLEN];
	struct eli_softc *sc;
	struct eli_metadata md;

	/* fetch passphrase from env */
	fetch_env_passphrase();

	/* User arguments */
	while ((ch = getopt(argc, argv, "dvj:")) != -1) {
		switch (ch) {
		case 'd':
			daemonized++;
			break;
		case 'v':
			verbose++;
			break;
		case 'j':
			passfile_str = optarg;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage(stderr, 1, "Invalid arguments");
	prov = argv[0];
	nbd = argv[1];

	/* FIXME: duplicated code */
	if (passfile_str) {
		if (strcmp(passfile_str, "-") == 0)
			passfile_fd = STDIN_FILENO;
		else if ((passfile_fd = open(passfile_str, O_RDONLY)) < 0) {
			ERR_SYSCALL("Cannot open passfile");
			goto out;
		} else  if (read_data(passfile_fd, (u_char *)cached_passphrase, sizeof cached_passphrase)) {
			ERR_SYSCALL("Cannot read from passfile");
			goto out;
		}
		if (passfile_fd != STDIN_FILENO)
			close(passfile_fd);
	}

	/* Opening disk file */
	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open provider");
		goto out;
	}
	if ((nbd_fd = open(nbd, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open nbd device");
		goto out;
	}

	if (eli_read_metadata(device_fd, &md) != 0) {
		ERR_FAILURE("Cannot read metadata", NULL); /* FIXME: */
		goto out;
	}

	/* Validate metadata */
	if (strcmp(md.md_magic, ELI_MAGIC) != 0) {
		ERR_FAILURE("Cannot validate metadata", "Invalid MAGIC");
		goto out;
	} else if (md.md_version != ELI_VERSION) {
		ERR_FAILURE("Cannot validate metadata", "Unsupported version");
		goto out;
	} else if (md.md_keys == 0x00) {
		ERR_FAILURE("Cannot validate metadata", "No valid keys");
		goto out;
	} else if (md.md_iterations == -1) {
		ERR_FAILURE("Cannot validate metadata", "Unsupported keyfile encryption");
		goto out;
	} else if (md.md_ealgo != CRYPTO_AES_XTS) {
		ERR_FAILURE("Cannot validate metadata", "Unsupported encryption algorithm");
		goto out;
	}

	if (eli_genkey(&md, key) == NULL) {
		ERR_FAILURE("Cannot decrypt master key", "No key components given");
		goto out;
	}

	/* Attempt to decrypt master key with human provided key */
	error = eli_mkey_decrypt_any(&md, key, mkey, &nkey);
	explicit_bzero(key, sizeof key);
	if (error) {
		ERR_FAILURE("Cannot decrypt master key", "Invalid key");
		goto out;
	}

	sc = eli_create(&md, device_fd, nbd_fd, mkey, nkey);
	if (sc == NULL)
		exit(1);

	(void)eli_nbd_create(sc);
out:
	explicit_bzero(&md, sizeof md);
	explicit_bzero(mkey, sizeof mkey);

	close(device_fd);
	close(nbd_fd);

	ERR_HANDLE();
	return retval;
}

static int
eli_setkey(int argc, char **argv)
{
	struct eli_metadata md;
	char *prov;
	int error, iterations = -1;
	const char *errmsg = NULL, *errstr = NULL;
	char *passfile_str = NULL, *newpassfile_str = NULL;
	int passfile_fd, newpassfile_fd, keyno = -1;
	u_char key[ELI_USERKEYLEN], mkey[ELI_DATAIVKEYLEN];
	u_char *mkeydst;
	u_char sector[512];
	char ch;
	int device_fd = -1;

	/* User arguments */
	while ((ch = getopt(argc, argv, "vi:j:J:")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
#if 0
		case 'n':
			keyno = strtonum(optarg, 0, ELI_MAXMKEYS - 1, &errstr);
			if (errstr) {
				errmsg = "Invalid keyno";
				goto out;
			}
			break;
#endif
		case 'i':
			iterations = strtonum(optarg, 0, UINT32_MAX, &errstr);
			if (errstr) {
				errmsg = "Invalid iterations";
				goto out;
			}
			break;
		case 'j':
			passfile_str = optarg;
			break;
		case 'J':
			newpassfile_str = optarg;
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (iterations == -1) {
		ERR_FAILURE("Cannot setkey", "Iterations is required");
		goto out;
	}

	if (argc != 1) {
		ERR_FAILURE("Cannot setkey", "Invalid arguments");
		goto out;
	}
	prov = argv[0];

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if (eli_metadata_read(prov, &md))
		goto out;

	/* FIXME: prov should be dettached */
	if (md.md_keys == 0x0) {
		ERR_FAILURE("Cannot validate metadata", "No valid keys");
		goto out;
	}

	/* FIXME: duplicated code */
	if (passfile_str) {
		if (strcmp(passfile_str, "-") == 0)
			passfile_fd = STDIN_FILENO;
		else if ((passfile_fd = open(passfile_str, O_RDONLY)) < 0) {
			ERR_SYSCALL("Cannot open passfile");
			goto out;
		} else  if (read_data(passfile_fd, (u_char *)cached_passphrase, sizeof cached_passphrase)) {
			ERR_SYSCALL("Cannot read passfile");
			goto out;
		}
		if (passfile_fd != STDIN_FILENO)
			close(passfile_fd);
	}

	if (eli_genkey(&md, key) == NULL) {
		ERR_FAILURE("Cannot generate key", "No key components given");
		explicit_bzero(key, sizeof key);
		goto out;
	}

	if (keyno != -1)
		error = eli_mkey_decrypt(&md, key, mkey, keyno);
	else
		error = eli_mkey_decrypt_any(&md, key, mkey, &keyno);

	explicit_bzero(key, sizeof key);
	if (error) {
		ERR_FAILURE("Cannot decrypt master key", "Invalid key");
		goto out;
	}

	if (verbose)
		printf("Decrypted Master Key %u.\n", keyno);

	if (iterations != md.md_iterations)
		md.md_iterations = iterations;

	mkeydst = md.md_mkeys + (keyno * ELI_MKEYLEN);
	md.md_keys |= (1 << keyno);

	bcopy(mkey, mkeydst, sizeof mkey);
	explicit_bzero(mkey, sizeof mkey);

	/* FIXME: duplicated code */
	if (newpassfile_str) {
		if (strcmp(newpassfile_str, "-") == 0)
			newpassfile_fd = STDIN_FILENO;
		else if ((newpassfile_fd = open(newpassfile_str, O_RDONLY)) < 0) {
			ERR_SYSCALL("Cannot open newpassfile key");
			goto out;
		} else  if (read_data(newpassfile_fd, (u_char *)cached_passphrase, sizeof cached_passphrase)) {
			ERR_SYSCALL("Cannot read newpassfile key");
			goto out;
		}
		if (newpassfile_fd != STDIN_FILENO)
			close(passfile_fd);
	}

	/* Generate key for Master Key encryption. */
	if (eli_genkey(&md, key) == NULL) {
		ERR_FAILURE("Cannot generate new key", "No key components given");
		goto out;
	}

	/* Encrypt the Master-Key with the new key. */
	error = eli_mkey_encrypt(md.md_ealgo, key, md.md_keylen, mkeydst);
	explicit_bzero(key, sizeof key);
	if (error) {
		ERR_FAILURE("Cannot decrypt master key", "Invalid key");
		goto out;
	}

	/* Convert metadata to on-disk format. */
	eli_metadata_encode(&md, sector);

	lseek(device_fd, -1 * sizeof sector, SEEK_END);
	if (write_data(device_fd, sector, sizeof sector)) {
		ERR_SYSCALL("Cannot store metadata on provider");
		goto out;
	}

out:
	explicit_bzero(sector, sizeof sector);
	explicit_bzero(key, sizeof key);
	explicit_bzero(&md, sizeof md);

	ERR_HANDLE();
	return retval;
}

static int
eli_backup_create(char *prov, char *file)
{
	uint32_t secsize = 512;
	u_char sector[secsize];
	int device_fd = -1, file_fd = -1;
	const char *errmsg = NULL, *errstr = NULL;

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

#if 0
	if (ioctl(device_fd, BLKSSZGET, &secsize) < 0) {
		ERR_SYSCALL("Cannot get device information");
		goto out;
	}

	if ((sector = malloc(secsize)) == NULL) {
		ERR_SYSCALL("Cannot allocate memory");
		goto out;
	}
#endif

	lseek(device_fd, -1 * 512, SEEK_END);
	if (read_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot read metadata");
		goto out;
	}

	file_fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (file_fd < 0) {
		ERR_SYSCALL("Cannot open backup file");
		goto out;
	}

	if (write_data(file_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot write to backup file");
		goto out;
	}

out:
	close(device_fd);
	close(file_fd);

	explicit_bzero(sector, secsize);

	ERR_HANDLE();
	return retval;
}

static int
eli_backup(int argc, char **argv)
{
	char ch, *file, *prov;

	/* User arguments */
	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage(stderr, 1, NULL);

	prov = argv[0];
	file = argv[1];
	return eli_backup_create(prov, file);
}

static int
eli_restore(int argc, char **argv)
{
	int error, device_fd, force = 0;
	char ch, *file, *prov;
	uint64_t mediasize;
	struct eli_metadata md;

	/* User arguments */
	while ((ch = getopt(argc, argv, "vf")) != -1) {
		switch (ch) {
		case 'f':
			force++;
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage(stderr, 1, NULL);

	file = argv[0];
	prov = argv[1];

	/* Read metadata from the backup file. */
	error = eli_metadata_read(file, &md);
	if (error)
		return error;

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if (ioctl(device_fd, BLKGETSIZE64, &mediasize) < 0) {
		ERR_SYSCALL("Cannot get device information");
		goto out;
	}

	/* Check if the provider size has changed since we did the backup. */
	if (md.md_provsize != mediasize) {
		ERR_FAILURE("Provider size mismatch", "wrong backup file?");
		goto out;
	}

	lseek(device_fd, -512, SEEK_END);
	if (write_data(device_fd, (u_char *)&md, sizeof md)) {
		ERR_SYSCALL("Cannot write metadata to provider");
		goto out;
	}

out:
	close(device_fd);

	ERR_HANDLE();
	return retval;
}

static int
eli_resize(int argc, char **argv)
{
	char ch, *prov, *oldsize_str = NULL;
	uint64_t oldsize, mediasize;
	uint16_t secsize = 512;
	u_char sector[secsize];
	int device_fd;
	struct eli_metadata md;

	/* User arguments */
	while ((ch = getopt(argc, argv, "vs:")) != -1) {
		switch (ch) {
		case 's':
			oldsize_str = optarg;
			break;
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(stderr, 1, NULL);

	if (oldsize_str == NULL)
		usage(stderr, 1, "old size is required");

	oldsize = strtonum(oldsize_str, 2 * secsize, UINT32_MAX, &errstr);
	if (errstr) {
		ERR_FAILURE("Cannot validate oldsize", errstr);
	}

	prov = argv[0];
	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if (ioctl(device_fd, BLKGETSIZE64, &mediasize) < 0) {
		ERR_SYSCALL("Cannot get device information");
		goto out;
	}

	if (oldsize == mediasize) {
		printf("Size hasn't changed");
		goto out;
	}

	lseek(device_fd, oldsize - secsize, SEEK_SET);
	if (read_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot read device");
		goto out;
	}

	if (eli_metadata_decode(sector, &md)) {
		ERR_FAILURE("Cannot decode metadata", "Maybe wrong oldsize?");
		goto out;
	}
	
	md.md_provsize = mediasize;
	/* Write metadata to the provider. */
	eli_metadata_encode(&md, sector);
	lseek(device_fd, -512, SEEK_END);
	if (write_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot write metadata");
		goto out;
	}

	/* Now trash the old metadata. */
	arc4random_buf(sector, secsize);
	lseek(device_fd, oldsize - secsize, SEEK_SET);
	(void)write_data(device_fd, sector, secsize);

out:
	close(device_fd);

	ERR_HANDLE();
	return retval;
}

static int
eli_version(int argc, char **argv)
{
	char ch;

	/* User arguments */
	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(stderr, 1, NULL);

	printf("userland: %u\n", ELI_VERSION);
	return 0;
}

static int
eli_dump(int argc, char **argv)
{
	char ch, *prov;
	struct eli_metadata md;

	/* User arguments */
	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage(stderr, 1, NULL);

	prov = argv[0];
	if (eli_metadata_read(prov, &md))
		return 1;

	printf("Metadata on %s:\n", prov);
	eli_metadata_dump(&md);
	printf("\n");
	return 0;
}

int
main(int argc, char **argv)
{
	char *verb;

	if (argc < 2)
		usage(stderr, 1, NULL);
	argc -= 1;
	argv += 1;
	
	verb = argv[0];
	if (strcmp(verb, "init") == 0)
		return eli_init(argc, argv);
	else if (strcmp(verb, "attach") == 0)
		return eli_attach(argc, argv);
	else if (strcmp(verb, "setkey") == 0)
		return eli_setkey(argc, argv);
	else if (strcmp(verb, "backup") == 0)
		return eli_backup(argc, argv);
	else if (strcmp(verb, "restore") == 0)
		return eli_restore(argc, argv);
	else if (strcmp(verb, "resize") == 0)
		return eli_resize(argc, argv);
	else if (strcmp(verb, "version") == 0)
		return eli_version(argc, argv);
	else if (strcmp(verb, "dump") == 0)
		return eli_dump(argc, argv);

	usage(stderr, 1, "Unknown command");
	return 1;
}
