
# Portable FreeBSD `geli`
This is portable version FreeBSD [geli(8)][https://www.freebsd.org/cgi/man.cgi?geli]
for GNU/Linux.

Table of Contents:

- [Projects Status](#projects-status)
- [Manual](#manul)
  - [Synapsis](#synapsis)
    - [init](#init)
    - [attach](#attach)
    - [setkey](#setkey)
    - [backup](#backup)
    - [restore](#restore)
    - [resize](#resize)
    - [version](#version)
    - [dump](#dump)
    - [help](#help)
  - [Examples](#examples)


# Projects Status
Right Now only the **AES-XTS** Algorithm with Read/Write is supported.
Support for **AES-CBC**, **PKCS5v2 iterration calculator** and
**Authentication** support is under serious consideration.

This project is presented AS IS. I started to use portable-geli in
production for a few months with no regressions but you should decide
for yourself before relying on it.

# Manual
## Synapsis

```
geli init [-bgv] [-B backupfile] [-e ealgo]
          [-i iterations] [-J newpassfile]
          [-l keylen] prov
geli label - an alias for 'init'
geli attach [-vd] [-j passfile] prov nbd
geli setkey [-v] [-n keyno] [-i iterations]
            [-j passfile] [-J newpassfile] prov
geli backup [-v] prov file
geli restore [-v] file prov
geli resize [-v] -s oldsize prov
geli version [-v]
geli dump prov[-v]
geli help
```

## Description
The first argument	to geli	indicates an action to be performed:

### init
Initialize providers which need to be encrypted.  Multiple providers are
not supported. A unique salt will be randomly generated for provider
to ensure the Master Key for is unique.  Here you can set up the
cryptographic algorithm to use, Data Key length, etc. The last sector
of the providers is used to store metadata. that the metadata can be
recovered with the restore subcommand using the backupfile and backup
action described below.

Additional options include:

- `-b`
Try to decrypt this partition during FreeBSD boot, before the root
partition is mounted. This makes it possible to use an encrypted root
partition for only the FreeBSD

- `-B backupfile`
File name to use for metadata backup. To inhibit backups, you can avoid
this option at command line.

- `-e ealgo`
Encryption algorithm to use. Currently supported algorithm is:
`AES-XTS`. The default and recommended algorithm is `AES-XTS`.

- `-g`
Enable booting from this encrypted root filesystem. Only applicable when
booting the encrypted device using FreeBSD. The FreeBSD boot loader
prompts for the passphrase and loads loader(8) from the encrypted
partition.

- `-i iterations`
Number of iterations to use with PKCS#5v2 when processing User Key
passphrase component. This option is mandatory.

- `-J newpassfile`
Specifies a file which contains the passphrase component of the User Key
(or part of it).  If newpassfile is given as -, standard input will
be used. Only the first line (excluding new-line character) is taken
from the given file. otherwise the environment variable of `passphrase`
will be used.

- `-l keylen`
Data Key length to use with the given crypto graphic algorithm. If the
length is not specified, the selected algorithm uses its default key
length. `AES-XTS` uses 128 and 256 bit keys. The first keylength is
the default.

- `-v`
Enables the verbose mode.

### attach
Attach the given providers. The encrypted Master Keys are loaded from
the metadata and decrypted using the given passphrase and new virtual
block device are created using the specified provider names.

Additional options include:

geli attach [-vd] [-j passfile] prov nbd

- `-d`
If	specified, `geli` daemon will be detached automatically on
success and continue running on background.

- `-j passfile`
Specifies a file which contains the passphrase component of the User Key
(or part       of it). Formore information see the description of the
`-J` option for  the [init](#init) subcommand.

- `-v`
Enables the verbose mode.

### setkey
Install a copy of the Master Key into the selected slot, encrypted
with a new User Key.  If the selected slot is populated, replace the
existing copy.	A provider has one Master Key, which can be stored
in one or both slots, each encrypted with an	independent User Key.
With the [init](#init) subcommand, only key number 0 is  initialized.
The User Key can be changed at any time: for an attached provider,
for    a detached provider, or on the backup file.

Additional options include:

- `-i iterations`
Number of iterations to use with PKCS#5v2.  If 0 is given, PKCS#5v2 will
not be used.

- `-j passfile`
Specifies a file which contains the passphrase component of a current
User Key.

- `-J newpassfile`
Specifies a file which contains	the passphrase component of the
new User Key.

- `-n keyno`
Specifies the index number of the Master Key copy to change (could be
0 or 1).


- `-v`
Enables the verbose mode.


### backup
Backup metadata from the given provider to the given file.

Additional options include:

- `-v`
Enables the verbose mode.

### restore
Restore metadata from the given	file to	the given provider.

Additional options include:

- `-v`
Enables the verbose mode.

### resize
Inform geli that the provider has been resized. The old metadata block
is relocated to the correct position	 at the end of the provider and
the provider size is updated.

Additional options include:

- `-s oldsize`
The	size of	the provider before it was resized.

- `-v`
Enables the verbose mode.

### version
If no arguments are given, the **version** subcommand will print the
version of **geli** userland utility.

- `-v`
Enables the verbose mode.


### dump
Dump metadata stored on the given providers.

- `-v`
Enables the verbose mode.

### Help
Print the short usage help.

## Examples

Initialize the disk using default AES-XTS(128) with custom PKCSv2
iterations:


```sh
$ truncate -s 100m disk.raw
$ losetup /dev/loop1 disk.raw
$ geli init -i 10000 /dev/loop1
Enter Password:

```

Print the GELI metadata:

```sh
$ geli dump /dev/loop1
Metadata on /dev/loop1:
     magic: GEOM::ELI
   version: 7
     flags: 0x0
     ealgo: AES-XTS
    keylen: 128
  provsize: 104857600
sectorsize: 512
      keys: 0x01
iterations: 10000
      Salt: 58d3c4887a8e3558ddcd64b8a2390d75cc101164def18e3a2f6f0e155ab67da109f4169b2df9dafa00899c6170e72a45fcb476424a1d16f6b238f8c74a50384e
Master Key: 07027a69be6aedaa7fbe6110cede8a5590c6ad66d550d8c939a5ba5a4fb6f9e077e647510254506261d827e03210b49f9a6e6ac3573a3e2a2f83960a255cd91364bc57418c5dd0f266b92dad88cea1622e1548d9b570999de6643378a48cb6484ec7ce16139f3a7fc2f11e28524c74e340c9bb63987b8066b00fb75cd26fccb2c9fae68c09d43b0be4e29cbf7d26372b89616841a63ba70f71e3448c59bbc995301e032d05c3b4bf62f68b9144351745566bc92cdc8b9a9fe93603e6ee94b1e900b0b018b76443cc392f032dc398ffa4b7eb743327ccf80988bd15390e70b4d0aad03b61ba67988c385ee67fab707c505abfc31490d95150fc4d146f0c154331b138b513cb549da6e8b3a8cb4134cd698b9b871805a7563daebeb1aa21cb24d5462c32a206f350c24c708025d273bf5171d8737b735f2611cd08ed7074d02571d40f3e6f3f93eb83e972aee4f2a0860a14586bab39fc1b109bbde47ca060f6147bc3bb7eb2b8f40e654c95871bfb3325b3703f12fef6d64fbf907d0a999ab403
  MD5 hash: 8d678a6d0f0eba6d665302cfdd9af252
```

Attaching to the encrypted device. The virtual NBD block device will
presents the unencrypted block device.

```
$ ./geli attach -d /dev/loop1 /dev/nbd1
Enter Password:
```

The decrypted virtual NBD block  device has exactly one sector less
capacity:


```
$ fdisk -l /dev/loop1
Disk /dev/loop1: 100 MiB, 104857600 bytes, 204800 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
$ fdisk -l /dev/nbd1
Disk /dev/nbd1: 100 MiB, 104857088 bytes, 204799 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

Writing to the decrypted BND block device will results to writing
the encrypted device into encrypted block device.

```
$ sudo dd if=/dev/random bs=512 of=/dev/nbd1
```

To detach the virtual block device, simply just kill the geli process.
But ensure all the changes are written back to the encrypted device first.

```
$ sync
$ sudo pkill -f "geli attach /dev/loop1 /dev/nbd1"
```
