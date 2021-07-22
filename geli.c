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

#define ERR_HANDLE()		do { if (errmsg) { log_err("%s: %s", errmsg, errstr); errmsg = NULL; errstr = NULL; } } while(0)

/*
 * Passphrase cached during load, in order to be more user-friendly if
 * there are multiple providers using the same passphrase.
 */
static char cached_passphrase[BUFSIZE];

void
sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:
		break;
	default:
		return;
	}

	exit(0);
}

static void
fetch_passphrase(const char *passfile)
{
	int fd;
	char *env_passphrase;

	if (passfile) {
		if (strcmp(passfile, "-") == 0)
			fd = STDIN_FILENO;
		else if ((fd = open(passfile, O_RDONLY)) < 0) {
			ERR_SYSCALL("Cannot open passfile");
			goto out;
		} else  if (read_data(fd, (u_char *)cached_passphrase, sizeof cached_passphrase)) {
			ERR_SYSCALL("Cannot read passfile");
			goto out;
		}
		if (fd != STDIN_FILENO)
			close(fd);
	} else if ((env_passphrase = getenv("passphrase")) != NULL) {
		/* Extract passphrase from the environment variable. */
		strlcpy(cached_passphrase, env_passphrase,
		    sizeof(cached_passphrase));
	}

out:
	ERR_HANDLE();
	return;
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
eli_create(const struct eli_metadata *md, u_char *mkey, int nkey)
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

	/* Remember the keys in our softc structure. */
	eli_mkey_propagate(sc, mkey);

	return sc;
}

void
eli_destroy(struct eli_softc **sc)
{
	if (*sc == NULL)
		return;

	explicit_bzero(*sc, sizeof(struct eli_softc));
	*sc = NULL;

	return;
}

static void
eli_crypto_run(struct eli_softc *sc, int device_fd, struct nbd_request *req, u_char *buf)
{
	off_t dstoff;
	u_int i, nsec, secsize, cmd;
	u_char *data;
	uint8_t *key, iv[ELI_IVKEYLEN], out[sc->sc_sectorsize];
	size_t key_sz;
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *type;

	/* FIXME: write error before return */
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		return;

	data = buf;
	secsize = sc->sc_sectorsize;
	nsec = req->len / secsize;
	lseek(device_fd, req->from, SEEK_SET);
	cmd = req->type & NBD_CMD_MASK_COMMAND;
	for (i = 0, dstoff = req->from; i < nsec; i++, dstoff += secsize) {
		if (cmd == NBD_CMD_READ)
			read_data(device_fd, data, secsize);
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
#if 0
		case CRYPTO_AES_CBC:
			switch (sc->sc_ekeylen) {
			case 128:
				type = EVP_aes_128_cbc();
				break;
			case 192:
				type = EVP_aes_192_cbc();
				break;
			case 256:
				type = EVP_aes_256_cbc();
				break;
			}
			break;
#endif /* AES-CBC Support */
		}

		int out_len, final_out_len;
		if (cmd == NBD_CMD_READ) {
			EVP_DecryptInit(ctx, type, key, iv);
			EVP_DecryptInit(ctx, type, key, iv);
			EVP_DecryptUpdate(ctx, data, &out_len, data, secsize);
			EVP_DecryptFinal_ex(ctx, out + out_len, &final_out_len);
			EVP_CIPHER_CTX_reset(ctx);
		} else {
			EVP_EncryptInit(ctx, type, key, iv);
			EVP_EncryptUpdate(ctx, data, &out_len, data, secsize);
			EVP_EncryptFinal_ex(ctx, out + out_len, &final_out_len);
			EVP_CIPHER_CTX_reset(ctx);
		}
		if (out_len + final_out_len != secsize)
			errx(1, "EVP final_data_len %ld != %d + %d",
			     sizeof data, out_len, final_out_len);
		data += secsize;
	}

	EVP_CIPHER_CTX_free(ctx);

	if (cmd == NBD_CMD_WRITE)
		write_data(device_fd, buf, req->len);
}

static void
usage(const char *fmt, ...)
{
	FILE *fp = fmt ? stderr : stdout;
	va_list ap;

	if (fmt) {
		fprintf(fp, "geli: ");
		va_start(ap, fmt);
		vfprintf(fp, fmt, ap);
		va_end(ap);
		fprintf(fp, "\n");
	}

	fprintf(fp,
	        "usage: geli init [-bgv] [-B backupfile] [-e ealgo] [-i iterations] [-J newpassfile] [-l keylen] prov\n"
	        "       geli label - an alias for 'init'\n"
	        "       geli attach [-vd] [-j passfile] prov nbd\n"
	        "       geli setkey [-v] [-n keyno] [-i iterations] [-j passfile] [-J newpassfile] prov\n"
	        "       geli backup [-v] prov file\n"
	        "       geli restore [-v] file prov\n"
	        "       geli resize [-v] -s oldsize prov\n"
	        "       geli version [-v]\n"
	        "       geli dump prov[-v]\n"
	        "       geli help\n");
}

static int
eli_help()
{
	usage(NULL);
	return 0;
}

static void
eli_nbd_create(struct eli_softc *sc, int device_fd, int nbd_fd, int background)
{
	pid_t pid;
	int pair[2];
	off_t bytes;
	uint64_t nblocks, blocksize = 512UL; /* TODO: set blocksize 4K */

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		ERR_SYSCALL("Cannot create stream sockets");
		goto out;
	}

	bytes = lseek(device_fd, 0, SEEK_END);
	nblocks = (bytes - 512) / blocksize;
	if (nblocks < 0) {
		ERR_FAILURE("Cannot get provider size", "Invalid size");
		goto out;
	}

	if (ioctl(nbd_fd, NBD_SET_SIZE, 4096UL) < 0) {
		ERR_SYSCALL("Cannot set NBD sector size");
		goto out;
	}
	if (ioctl(nbd_fd, NBD_SET_BLKSIZE, 4096UL) < 0) {
		ERR_SYSCALL("Cannot set NBD block size");
		goto out;
	}

	/* Daemonize */
	if (background) {
		/* FIXME: https://stackoverflow.com/a/17955149 */
		if ((pid = fork()) < 0) {
			ERR_SYSCALL("Cannot fork daemon");
			goto out;
		} else if (pid > 0)
			exit(EXIT_SUCCESS);

		if (setsid() < 0) {
			ERR_SYSCALL("Cannot create session");
			goto out;
		}

		/* TODO: install signal handlers */
		if ((pid = fork()) < 0) {
			ERR_SYSCALL("Cannot (second) fork daemon");
			goto out;
		} else if (pid > 0)
			exit(EXIT_SUCCESS);

		(void)chdir("/");

		/* Closing all open files */
		daemonized++;
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* Fork client/server */
	if ((pid = fork()) < 0) {
		ERR_SYSCALL("Cannot fork");
		goto out;
	}

	/* Child: Client side */
	if (pid == 0) {
		eli_destroy(&sc);
		close(device_fd);
		close(pair[1]);

		if (ioctl(nbd_fd, NBD_SET_SIZE, (unsigned long)blocksize) < 0)
			ERR_SYSCALL("Cannot set NBD sector size");
		else if (ioctl(nbd_fd, NBD_SET_BLKSIZE, blocksize) < 0)
			ERR_SYSCALL("Cannot set NBD block size");
		else if (ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, nblocks) < 0)
			ERR_SYSCALL("Cannot set NBD size");
		else if (ioctl(nbd_fd, NBD_CLEAR_SOCK) < 0)
			ERR_SYSCALL("Cannot clear NBD sockets");
		else if (ioctl(nbd_fd, NBD_SET_FLAGS, NBD_FLAG_HAS_FLAGS) < 0)
			ERR_SYSCALL("Cannot set NBD server flag");
		else if (ioctl(nbd_fd, NBD_SET_SOCK, pair[0]) < 0)
			ERR_SYSCALL("Cannot set NBD sockets");
		else if (ioctl(nbd_fd, NBD_DO_IT) < 0)
			ERR_SYSCALL("Cannot start NBD server");

		(void)ioctl(nbd_fd, NBD_CLEAR_QUE);
		(void)ioctl(nbd_fd, NBD_CLEAR_SOCK);

		close(pair[0]);
		close(nbd_fd);

		ERR_HANDLE();
		exit(retval);
	}

	/* Server side*/
	close(nbd_fd);
	close(pair[0]);

	/* FIXME: signal handling */
	//signal(SIGINT, &sig_handler);
	//signal(SIGTERM, &sig_handler);
	//signal(SIGHUP, &sig_handler);

	struct nbd_request request;
	struct nbd_reply reply = {.magic = htonl(NBD_REPLY_MAGIC)};
        while (1) {
		u_char *buf = NULL;

		if (read_data(pair[1], (u_char*) &request, sizeof(request)) < 0) {
			ERR_SYSCALL("Cannot read request");
			goto out;
		}
		if (request.magic != htonl(NBD_REQUEST_MAGIC)) {
			ERR_FAILURE("Cannot validate NBD request", "Invalid magic");
			goto out;
		}

		request.from = ntohll(request.from);
		request.type = ntohl(request.type);
		request.len = ntohl(request.len);

		memcpy(reply.handle, request.handle, sizeof(reply.handle));
		switch (request.type & NBD_CMD_MASK_COMMAND) {
		case NBD_CMD_DISC:	/* Soft Disconnect */
			reply.error = 0;
			write_data(pair[1], (u_char*)&reply, sizeof(reply));
			goto out;
		case NBD_CMD_READ:
			if ((buf = malloc(request.len)) == NULL)
				goto out;
			reply.error = 0;
			eli_crypto_run(sc, device_fd, &request, buf);
			write_data(pair[1], (u_char*)&reply, sizeof(reply));
			write_data(pair[1], buf, request.len);
			free(buf);
			break;
		case NBD_CMD_WRITE:
			if ((buf = malloc(request.len)) == NULL)
				goto out;
			read_data(pair[1], buf, request.len);
			eli_crypto_run(sc, device_fd, &request, buf);
			reply.error = 0;
			write_data(pair[1], (u_char*)&reply, sizeof(reply));
			free(buf);
			break;
		case NBD_CMD_FLUSH:
			fsync(device_fd);
			reply.error = 0;
			write_data(pair[1], (u_char*)&reply, sizeof(reply));
		case NBD_CMD_TRIM:
		default:
			reply.error = htonl(EIO);
			write_data(pair[1], (u_char*)&reply, sizeof(reply));
		}
	}

out:
	close(pair[0]);
	close(pair[1]);

	ERR_HANDLE();
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
		strlcpy(passbuf, ptr, sizeof passbuf);
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
	int device_fd = -1;

	if ((device_fd = open(prov, O_RDONLY)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

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
	close(device_fd);
	explicit_bzero(&md, sizeof md);
	explicit_bzero(&sector, secsize);

	ERR_HANDLE();
	return retval;
}

static int
eli_init(int argc, char **argv)
{
	int device_fd = -1, backup_fd = -1;
	char ch;
	struct eli_metadata md;
	char *prov;
	char *ealgo_str = "aes-xts", *iterations_str = NULL, *passfile_str = NULL,
	     *keylen_str = "128";
	u_char key[ELI_USERKEYLEN];
	u_char sector[512];
	uint16_t ealgo, keylen;
	uint32_t iterations, secsize = 512, flags = 0;
	uint64_t mediasize;
	char *backupfile = NULL;

	if (argc < 1) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

	/* User arguments */
	while ((ch = getopt(argc, argv, "bB:ge:i:J:l:v")) != -1) {
		switch (ch) {
		case 'b':
			flags |= ELI_FLAG_BOOT;
			break;
		case 'B':
			backupfile = optarg;
			break;
		case 'g':
			flags |= ELI_FLAG_GELIBOOT;
			break;
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
#if 0
		case 's':
			sectorsize_str = optarg;
			break;
#endif
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

	prov = argv[0];

	if ((ealgo = g_eli_str2ealgo(ealgo_str)) < CRYPTO_ALGORITHM_MIN) {
		usage("Invalid encryption algorithm %s", ealgo_str);
		exit(EXIT_FAILURE);
	} else if (!eli_ealgo_supprted(ealgo)) {
		usage("unsupported encryption algorithm %s", ealgo_str);
		exit(EXIT_FAILURE);
	}

	if (iterations_str == NULL) {
		usage("Iterations argument is required");
		exit(EXIT_FAILURE);
	} else {
		iterations = strtonum(iterations_str, 0, UINT32_MAX, &errstr);
		if (errstr) {
			usage("Invalid iterations argument: %s", errstr);
			exit(EXIT_FAILURE);
		}
	}

	keylen = strtonum(keylen_str, 0, UINT16_MAX, &errstr);
	if (errstr) {
		usage("Invalid key length: %s", errstr);
		exit(EXIT_FAILURE);
	} else  if (eli_keylen(ealgo, keylen) == 0) {
		usage("Invalid %s key length", ealgo_str);
		exit(EXIT_FAILURE);
	}

#if 0
	if (sectorsize_str) {
		/* TODO: secsize should be smaller than pagesize */
		val = strtonum(sectorsize_str, 0, UINT32_MAX, &errstr);
		if (errstr) {
			usage("Invalid sector size: %s", errstr);
			exit(EXIT_FAILURE);
		} else if (((val % secsize) != 0) || (val & (val - 1))) {
			usage("Invalid sector size: %s", "Should be multiple of 512");
			exit(EXIT_FAILURE);
		}
		secsize = val;
	}
#endif

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if (ioctl(device_fd, BLKSSZGET, &secsize) < 0) {
		ERR_SYSCALL("Cannot get device sector size");
		goto out;
	} else if (secsize != 512) {
		ERR_FAILURE("Cannot initialize device", "Unsuported size");
		goto out;
	} else if (ioctl(device_fd, BLKGETSIZE64, &mediasize) < 0) {
		ERR_SYSCALL("Cannot get device media size");
		goto out;
	}

	fetch_passphrase(passfile_str);

	strlcpy(md.md_magic, ELI_MAGIC, sizeof md.md_magic);
	md.md_version = ELI_VERSION;
	md.md_flags = flags;
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

	if (backupfile) {
		if ((backup_fd = open(backupfile, O_WRONLY | O_TRUNC | O_CREAT, 0600)) < 0) {
			ERR_SYSCALL("Cannot create backupfile");
			goto out;
		}
		if (write_data(backup_fd, sector, sizeof sector)) {
			close(backup_fd);
			ERR_SYSCALL("Cannot store metadata on backupfile");
			goto out;
		}
		close(backup_fd);
	}

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
	int error, nkey, d_flag = 0;
	int device_fd = -1, nbd_fd = -1;
	char ch, *prov, *nbd, *passfile_str = NULL;
	u_char key[ELI_USERKEYLEN], mkey[ELI_DATAIVKEYLEN];
	struct eli_metadata md;

	/* User arguments */
	while ((ch = getopt(argc, argv, "dvj:")) != -1) {
		switch (ch) {
		case 'd':
			d_flag++;
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

	if (argc != 2) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}
	prov = argv[0];
	nbd = argv[1];

	fetch_passphrase(passfile_str);

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
		ERR_FAILURE("Cannot read metadata", "Invalid device"); /* FIXME: */
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
	} else if (!eli_ealgo_supprted(md.md_ealgo)) {
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

	struct eli_softc *sc = eli_create(&md, mkey, nkey);
	eli_nbd_create(sc, device_fd, nbd_fd, d_flag);
	explicit_bzero(sc, sizeof *sc);

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
	int error, iterations = -1, keyno = -1;
	char *passfile_str = NULL, *newpassfile_str = NULL;
	u_char key[ELI_USERKEYLEN], mkey[ELI_DATAIVKEYLEN], *mkeydst;
	u_char sector[512];
	char ch;
	int device_fd = -1;

	/* User arguments */
	while ((ch = getopt(argc, argv, "vi:jn::J:")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		case 'n':
			keyno = strtonum(optarg, 0, ELI_MAXMKEYS - 1, &errstr);
			if (errstr) {
				usage("Invalid keyno: %s", errstr);
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			iterations = strtonum(optarg, 0, UINT32_MAX, &errstr);
			if (errstr) {
				usage("Invalid iterations: %s", errstr);
				exit(EXIT_FAILURE);
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

	if (argc != 1) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}
	prov = argv[0];

	if (iterations < 0) {
		usage("Iterations is required");
		exit(EXIT_FAILURE);
	}

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

	if (eli_metadata_read(prov, &md))
		goto out;

	/* FIXME: prov should be exclusively opened */
	if (md.md_keys == 0x0) {
		ERR_FAILURE("Cannot validate metadata", "No valid keys");
		goto out;
	}

	fetch_passphrase(passfile_str);

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

	fetch_passphrase(newpassfile_str);

	/* Generate key for Master Key encryption. */
	if (eli_genkey(&md, key) == NULL) {
		ERR_FAILURE("Cannot generate new key", "No key components given");
		goto out;
	}

	/* Encrypt the Master-Key with the new key. */
	error = eli_mkey_encrypt(md.md_ealgo, key, md.md_keylen, mkeydst);
	explicit_bzero(key, sizeof key);
	if (error) {
		ERR_FAILURE("Cannot encrypt master key", "Encryption failed");
		goto out;
	}

	/* Convert metadata to on-disk format. */
	eli_metadata_encode(&md, sector);

	lseek(device_fd, -1 * sizeof sector, SEEK_END);
	if (write_data(device_fd, sector, sizeof sector))
		ERR_SYSCALL("Cannot store metadata on provider");

out:
	close(device_fd);

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

	if ((device_fd = open(prov, O_RDWR)) < 0) {
		ERR_SYSCALL("Cannot open device");
		goto out;
	}

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

	if (argc != 2) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

	prov = argv[0];
	file = argv[1];
	return eli_backup_create(prov, file);
}

static int
eli_restore(int argc, char **argv)
{
	int device_fd = -1;
	char ch, *file, *prov;
	uint64_t mediasize;
	struct eli_metadata md;

	/* User arguments */
	while ((ch = getopt(argc, argv, "vf")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

	file = argv[0];
	prov = argv[1];

	/* Read metadata from the backup file. */
	retval = eli_metadata_read(file, &md);
	if (retval)
		goto out;

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

	lseek(device_fd, -1 * 512, SEEK_END);
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

	if (argc != 1) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	} else if (!oldsize_str) {
		usage("Oldsize is required");
		exit(EXIT_FAILURE);
	}

	oldsize = strtonum(oldsize_str, 2 * secsize, UINT32_MAX, &errstr);
	if (errstr) {
		usage("Invalid oldsize (%s)", errstr);
		exit(EXIT_FAILURE);
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
		if (verbose)
			printf("Size hasn't changed\n");
		goto out;
	}

	lseek(device_fd, oldsize - secsize, SEEK_SET);
	if (read_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot read device metadata");
		goto out;
	}

	if (eli_metadata_decode(sector, &md)) {
		ERR_FAILURE("Cannot validate metadata", "Maybe wrong oldsize?");
		goto out;
	}

	md.md_provsize = mediasize;
	eli_metadata_encode(&md, sector);
	lseek(device_fd, -1 * 512, SEEK_END);
	if (write_data(device_fd, sector, secsize)) {
		ERR_SYSCALL("Cannot write metadata");
		goto out;
	}

	arc4random_buf(sector, secsize);
	lseek(device_fd, oldsize - secsize, SEEK_SET);
	if (write_data(device_fd, sector, secsize))
		ERR_SYSCALL("Cannot trash the old metadata");

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

	if (argc != 0) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

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
	if (argc != 1) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

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

	if (argc < 2) {
		usage("Invalid arguments");
		exit(EXIT_FAILURE);
	}

	verb = argv[1];
	argc -= 1;
	argv += 1;
	
	if (strcmp(verb, "init") == 0 || strcmp(verb, "label") == 0)
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
	else if (strcmp(verb, "help") == 0)
		return eli_help();

	usage("Invalid arguments");
	return 1;
}
