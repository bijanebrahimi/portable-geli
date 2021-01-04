.PHONY: aes-xts-128-0.md   \
        aes-xts-128-100.md \
        aes-xts-256-0.md   \
        aes-xts-256-150.md

TESTS	:= $(wildcard *.md)
LOOPBACK:= /dev/loop0
NBD	:= /dev/nbd0
MOUNTDIR:= mnt

all: aes-xts-128-0.md
	../geli version | fgrep 'userland: 7'

aes-xts-128-0.md:
	pwd
	md5sum -c $@.md5
	# Setup
	losetup -d $(LOOPBACK) || true
	losetup $(LOOPBACK) $@
	# Dump
	../geli dump $(LOOPBACK) | fgrep '     magic: GEOM::ELI'
	../geli dump $(LOOPBACK) | fgrep '   version: 7'
	../geli dump $(LOOPBACK) | fgrep '     flags: 0x200'
	../geli dump $(LOOPBACK) | fgrep '     ealgo: AES-XTS'
	../geli dump $(LOOPBACK) | fgrep '    keylen: 128'
	../geli dump $(LOOPBACK) | fgrep '  provsize: 2097152'
	../geli dump $(LOOPBACK) | fgrep 'sectorsize: 512'
	../geli dump $(LOOPBACK) | fgrep '      keys: 0x01'
	../geli dump $(LOOPBACK) | fgrep 'iterations: 0'
	../geli dump $(LOOPBACK) | fgrep '      Salt: ea45d794569eb5c704d0d800a711fb36b3d6f94ab9bc779296add85b564102cd8637141aa6b5d476774257e8eeba52808680214000dc768904c4af5e5e8eb98c'
	../geli dump $(LOOPBACK) | fgrep 'Master Key: 040c978bf3b99dc995f0dea4563534bcf21df6f9dceebc068b64b6f575dd9943af95ff5b90ce5a7ea7b8aa974b39438b75f781518368d85a2f2866696f8291a37e121c7fcae95c8958cb4faf86dea1b3d9772aee9316700c1407c621d1cdaf3e87eb688275a9718ed3ece93ca58a0afaf16afaa8f462c408d77e41b70c3a0182fab9491ba1de38edc24ff8dd1fbec927f4f84eadc1f3e73af77c8b68fbd845e312906e496eb4a9694df2f02be32687a0b95b05841b33bc95f2c68f1af4e4e6256e4c19cebb51edd1047eacdf6421493acea95c8ba309a4b6f9dca3806fb11190d60bde4eeee834aefe295afc44833095edc78b4f730c6d55f2118ebbba5fa66c86f2671b2a05daf1e2a0e1eb301b819ad7e198e4102a4c2a3dc4b6229045a4c8e4a44474a6fa08828d589a48cd569b5f53be0be03b9436f4297a2242861ee432f0ba9a5d94fbcdd4611782be088b6a53b301a4bdd168f9284e72ec1c718f3b52a42a49d1e8d29753b46ace1223a99c7edbca4d1d00583cefe2783f3072f05ae5'
	../geli dump $(LOOPBACK) | fgrep '  MD5 hash: 2e54ee79f7a8e267f04fb180d4eead19'
	# Backup
	../geli backup $(LOOPBACK) $@.backup
	md5sum -c $@.backup.md5
	# Restore
	dd if=/dev/zero bs=512 seek=$$((4096-1)) count=1 of=$(LOOPBACK)
	../geli restore $@.backup $(LOOPBACK)
	sync
	md5sum -c $@.md5
	# setkey (same key)
	../geli setkey -i 0 -j key -J key $(LOOPBACK)
	md5sum -c $@.md5
	# Attach
	#mkdir -p $(MOUNTDIR)
	#../geli attach -d -j key $(LOOPBACK) $(NBD)
	#mount -o ro $(NBD)p1 $(MOUNTDIR)
	#cd $(MOUNTDIR) && md5sum -c md5
	#umount $(MOUNTDIR)
	# Teardown
	rm $@.backup
	losetup -d $(LOOPBACK)
	#pkill -TERM -f "glei attach -d -j key $(LOOPBACK) $(NBD)" || true

aes-xts-128-100.md:
	md5sum -c $@.md5
	# Setup
	losetup -d $(LOOPBACK) || true
	losetup $(LOOPBACK) $@
	# Dump
	../geli dump $(LOOPBACK) | fgrep '     magic: GEOM::ELI'
	../geli dump $(LOOPBACK) | fgrep '   version: 7'
	../geli dump $(LOOPBACK) | fgrep '     flags: 0x200'
	../geli dump $(LOOPBACK) | fgrep '     ealgo: AES-XTS'
	../geli dump $(LOOPBACK) | fgrep '    keylen: 128'
	../geli dump $(LOOPBACK) | fgrep '  provsize: 2097152'
	../geli dump $(LOOPBACK) | fgrep 'sectorsize: 512'
	../geli dump $(LOOPBACK) | fgrep '      keys: 0x01'
	../geli dump $(LOOPBACK) | fgrep 'iterations: 0'
	../geli dump $(LOOPBACK) | fgrep '      Salt: 8ab6b0f0db7191fa4c123825dab1b5cc5d8d97df1278a1f49a2dec4eb48b68e1da8a83038a06ced32d85fa661ee134f3cf5a9d7b0ebff81b3796a8dc26fe8455'
	../geli dump $(LOOPBACK) | fgrep 'Master Key: dc845f91860c377cad7067fe42b1b8a176d58bb47cc3fdf52116717ff692b0297e80dcb527840c8c6455bf718672629ea7e6ffb834b059571cc33d680dc1a986563927d97717862268d39c8e1696b9a98564063b63f05ac38bd7507ce12ad1b902ab504b10946cf1a827ac66cca36eab48a49cdff3ca08ac079012368361b4dfde99d386c94c9c38c208d9a182aa0d246fccb392693d2cb88457fddfcd1b6daf47a4ed804d3d0b98ef8a28ea960a4171e2b9f0f9f93c6a3352270cb338725eb20e53d35fc0a581ee01ae6f1a382ce23c98fdfec930a37407d550aa4ca2101d1688f91433e3925d07289b586f5c65f55b74421eba49739a4282661abfcba77c745133d897113fb0eb5f1e67f059106c7639ffe8f9a9ce0fa4a2fde61a2baf13b53244301d591e1160caaf2a9f361fc484b327a5551b94349d90445593b973438d99713e6f0db8053386e9287d99a72d238db2177a5bc77cdd78bb753d0838654c551667252ccd18b70e39523816b586d5f6ec60dcf0914284487b0a6d3bc50d2b'
	../geli dump $(LOOPBACK) | fgrep '  MD5 hash: 46dc1c29848e51a30f6cd0976449e6fc'
	# Backup
	../geli backup $(LOOPBACK) $@.backup
	md5sum -c $@.backup.md5
	# Restore
	dd if=/dev/zero bs=512 seek=$$((4096-1)) count=1 of=$(LOOPBACK)
	../geli restore $@.backup $(LOOPBACK)
	sync
	md5sum -c $@.md5
	# setkey (same key)
	../geli setkey -i 0 -j key -J key $(LOOPBACK)
	md5sum -c $@.md5
	# Attach
	mkdir -p $(MOUNTDIR)
	../geli attach -d -j key $(LOOPBACK) $(NBD)
	mount -o ro $(NBD)p1 $(MOUNTDIR)
	cd $(MOUNTDIR) && md5sum -c md5
	umount $(MOUNTDIR)
	# Teardown
	#pkill -f "glei attach -d -j key $(LOOPBACK) $(NBD)" || true
	rm $@.backup
	losetup -d $(LOOPBACK)

aes-xts-256-0.md:
	md5sum -c $@.md5
	# Setup
	losetup -d $(LOOPBACK) || true
	losetup $(LOOPBACK) $@
	# Dump
	../geli dump $(LOOPBACK) | fgrep '     magic: GEOM::ELI'
	../geli dump $(LOOPBACK) | fgrep '   version: 7'
	../geli dump $(LOOPBACK) | fgrep '     flags: 0x200'
	../geli dump $(LOOPBACK) | fgrep '     ealgo: AES-XTS'
	../geli dump $(LOOPBACK) | fgrep '    keylen: 256'
	../geli dump $(LOOPBACK) | fgrep '  provsize: 2097152'
	../geli dump $(LOOPBACK) | fgrep 'sectorsize: 512'
	../geli dump $(LOOPBACK) | fgrep '      keys: 0x01'
	../geli dump $(LOOPBACK) | fgrep 'iterations: 0'
	../geli dump $(LOOPBACK) | fgrep '      Salt: 65eeb8a083aca937c77398d00afbd9a5d790ac5763a636da8fd34961bb21fa6d6ee0f89b3a2bbb1fc4e1a19ccc23e1fb3c4103e3a7e7670d2a2973412c2b902e'
	../geli dump $(LOOPBACK) | fgrep 'Master Key: e8e54e54d10a31ea9d56b9c7b30ffca14207448f23fb88b70754b11a8ac939f9f16a7eb5c01aaba57d04ab07ceb27854f2f336e0baa06c98de08ca1ad89f9238cd906c77938622cc9ef3cf21ca98699abd579daa79b1ddd121ae59b16ab9f998833c862e9dea2d93db7a9c9870fb64633d58a3b7d1446046faebf3d9ae18161e72898311b186fd32cc98c953300d831a61dd6f9ced6ff50d60437df71b64990684296c05db31b2f6fecbebfaf28fe988fb111ddbdfcff6a9ac6098d12881b7395321cfe0d312d823f431506f979301bfb41186b3e9de0dc81ee525b0f8f7e17c72a1ee1439db846c5a34b4340fd0cfefb943ec59f049b235ebd239fdf9573c1e0e6589b7c4003901018779181f41341c030dcf611917582cf137de6643dabfb4ea44b29df1884def51e0ddd4f11f43db48bd84a84be9a870f2cfb808d9ab748f9320faa9edf3b5a8e6ebc9ab8c29df9fc649f51242aa67f9310212e39822be8b2da8280915a07b79a04efb19c37df058f9f0c174202c27d0b7f4db91b89771bb'
	../geli dump $(LOOPBACK) | fgrep '  MD5 hash: 99d2da7f96d43b843ef9428fcacc3028'
	# Backup
	../geli backup $(LOOPBACK) $@.backup
	md5sum -c $@.backup.md5
	# Restore
	dd if=/dev/zero bs=512 seek=$$((4096-1)) count=1 of=$(LOOPBACK)
	../geli restore $@.backup $(LOOPBACK)
	sync
	md5sum -c $@.md5
	# setkey (same key)
	../geli setkey -i 0 -j key -J key $(LOOPBACK)
	md5sum -c $@.md5
	# Attach
	mkdir -p $(MOUNTDIR)
	../geli attach -d -j key $(LOOPBACK) $(NBD)
	mount -o ro $(NBD)p1 $(MOUNTDIR)
	cd $(MOUNTDIR) && md5sum -c md5
	umount $(MOUNTDIR)
	# Teardown
	#pkill -f "glei attach -d -j key $(LOOPBACK) $(NBD)" || true
	rm $@.backup
	losetup -d $(LOOPBACK)

aes-xts-256-50.md:
	md5sum -c $@.md5
	# Setup
	losetup -d $(LOOPBACK) || true
	losetup $(LOOPBACK) $@
	# Dump
	../geli dump $(LOOPBACK) | fgrep '     magic: GEOM::ELI'
	../geli dump $(LOOPBACK) | fgrep '   version: 7'
	../geli dump $(LOOPBACK) | fgrep '     flags: 0x200'
	../geli dump $(LOOPBACK) | fgrep '     ealgo: AES-XTS'
	../geli dump $(LOOPBACK) | fgrep '    keylen: 256'
	../geli dump $(LOOPBACK) | fgrep '  provsize: 2097152'
	../geli dump $(LOOPBACK) | fgrep 'sectorsize: 512'
	../geli dump $(LOOPBACK) | fgrep '      keys: 0x01'
	../geli dump $(LOOPBACK) | fgrep 'iterations: 0'
	../geli dump $(LOOPBACK) | fgrep '      Salt: 40e4efcb74c8915e9fea25a4cd68db4ed95ec30ada09d4db4caf4521b70128695b274104a3436df083417e26e6ec9c1f390146c19a434c0b6d8cf1051f78513c'
	../geli dump $(LOOPBACK) | fgrep 'Master Key: 13c9cd306f2a230c37e3eb100c8740e39730f4fd58387d15ae356580f6b678d51411d071f213c2cb4ab94462fa210e93b4866dcf62b6096b4c4e026fa3f310bd9fe733306fb901fe75bfc4acd407e24b60d3d8b5c83b122bd03f28ace8ce30829e27200d378e6375cfd3c3d2ab54e039589253b2be4fa82aadf9db84c4d8354087593a7b475f9fe61199f0ffa6347b1ba292515d1dc704a770fca9c34433ac91d164d1e02f1ce5eccbec163fa625eea9e852cd28099c11195659b17199f466be85e3f45b91b1c2165091f0373d14b5da491df09552337e9112abf4ad8b0c7ead61b38f61649dd4d1c3c423266b5ee849fabcc9f41c433d0ad5c3bbe384c29cf8caae262829fe9080a8984094f72f3253b2ebcc86aaef94f0a2a9b2aab50acfb22eea746d8cb914ff26b6013e1568e0caab85b2e0eafe9b205823e6f60c6740904c727f9fe0e6ce16b40f3c92cab39d5a4206f29a7cc42cc86530330130a976b5183f6ff51c039c79091e0fa223ee772f05adacb9c2b11078e82e16921aa20997'
	../geli dump $(LOOPBACK) | fgrep '  MD5 hash: 6227003a167b9e9f435f95eca2db5590'
	# Backup
	../geli backup $(LOOPBACK) $@.backup
	md5sum -c $@.backup.md5
	# Restore
	dd if=/dev/zero bs=512 seek=$((4096-1)) count=1 of=$(LOOPBACK)
	../geli restore $@.backup $$(LOOPBACK)
	sync
	md5sum -c $@.md5
	# setkey (same key)
	../geli setkey -i 0 -j key -J key $(LOOPBACK)
	md5sum -c $@.md5
	# Attach
	mkdir -p $(MOUNTDIR)
	../geli attach -d -j key $(LOOPBACK) $(NBD)
	mount -o ro $(NBD)p1 $(MOUNTDIR)
	cd $(MOUNTDIR) && md5sum -c md5
	umount $(MOUNTDIR)
	# Teardown
	#pkill -f "glei attach -d -j key $(LOOPBACK) $(NBD)" || true
	rm $@.backup
	losetup -d $(LOOPBACK)

