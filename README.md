# Portable FreeBSD `geli`

## Supported Algorithms
- AES-XTS (128/256 key size)

## Supported Operations
- `dump`
- `init`
- `label`
- `attach`
- `backup`
- `restore`
- `resize`
- `version`

## Unsupported Encryption Algorithms
- AES-CBC
- Camellia-CBC
- NULL

## TODO
- Add support for **Authentication**.
- Add support for `setkey` and `delkey` commands.



```
unit=1
for i in 128 192 256
do
    for j in 0 100
    do	
        sectors=4096 # 2MB
        sector=512
        keylen=${i}
        iter=${j}
        file=aes-cbc-${keylen}-${iter}.md
        truncate -s $(($sectors * $sector)) ${file}
        echo -n password > key
        sudo mdconfig -du ${unit} || true
        sudo mdconfig -u ${unit} -f ${file}
        sudo geli init -e AES-CBC -i 0 -l ${keylen} -J key /dev/md${unit}
        sudo geli attach -j key /dev/md${unit}
        sudo dd if=/dev/zero of=/dev/md${unit}.eli bs=1m
        sudo gpart create -s mbr /dev/md${unit}.eli
        sudo gpart add -t fat32 /dev/md${unit}.eli
        sudo newfs_msdos /dev/md${unit}.elis1
        sudo mount_msdosfs /dev/md${unit}.elis1 /mnt

        sudo dd if=/dev/random bs=512k count=1 of=/mnt/random
        echo "$(md5 -q /mnt/random) random" | sudo tee /mnt/md5

        sudo umount /mnt
        sudo geli detach md${unit}
        sudo mdconfig -du ${unit}
        unit=$((unit+1))
    done
done

eli_mkey_decrypt


u=1
ls *.md | while read f
do
    echo "$(md5 -q $f) $f" > $f.md5

    sudo mdconfig -u ${u} -f $f
    sudo geli dump /dev/md${u} > ${f}.dump
    echo "$(sudo md5 -q $f) $f" > $f.md5
    sudo geli backup /dev/md${u} ${f}.backup
    echo "$(sudo md5 -q $f.backup) $f.backup" > $f.backup.md5
    rm ${f}.backup
    echo -n password > key
    echo -n newpassword > newkey
    cp $f $f.tmp
    sudo geli attach -j key /dev/md${u}
    sudo geli setkey -j key -J newkey /dev/md${u}
    sync
    echo "$(sudo md5 -q $f) $f" > $f.newkey.md5
    sudo geli detach /dev/md${u}
    sudo mdconfig -du ${u}
    mv $f.tmp $f
    u=$((u+1))
done
```
