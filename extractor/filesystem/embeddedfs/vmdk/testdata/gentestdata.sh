#!/usr/bin/env bash

dd if=/dev/zero of=valid.img bs=1M count=256
parted -s --align optimal valid.img --script mklabel gpt
parted -s --align optimal valid.img --script mkpart primary ext4 0% 25%
parted -s --align optimal valid.img --script mkpart primary ntfs 25% 100%
parted -s --align optimal valid.img --script set 2 msftdata on
sudo losetup -fP valid.img
LOOPDEV=$(losetup -j valid.img | cut -d: -f1)
PARTITION1="${LOOPDEV}p1"
PARTITION2="${LOOPDEV}p2"
sudo mkfs.ext4 $PARTITION1
sudo mkfs.vfat -F 32 $PARTITION2
sudo rm -rf /mnt/valid*
sudo mkdir /mnt/valid1
sudo mkdir /mnt/valid2
sudo mount ${PARTITION1} /mnt/valid1
sudo mount ${PARTITION2} /mnt/valid2
openssl genrsa -out private-key.pem 4096
sudo cp private-key.pem /mnt/valid1/private-key1.pem
sudo cp private-key.pem /mnt/valid2/private-key2.pem
sudo umount /mnt/valid1
sudo umount /mnt/valid2
sudo losetup -d ${LOOPDEV}
sudo rm -rf /mnt/valid*
sudo rm -f valid.img
qemu-img convert valid.img -O vmdk valid-fat32-ext.vmdk
rm private-key.pem

echo "Yuvraj Saxena <ysaxenax@gmail.com>" > invalid.vmdk