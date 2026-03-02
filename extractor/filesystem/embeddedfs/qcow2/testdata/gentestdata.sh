#!/usr/bin/env bash

dd if=/dev/zero of=valid.img bs=1M count=256
parted -s --align optimal valid.img --script mklabel gpt
parted -s --align optimal valid.img --script mkpart primary ext4 0% 25%
parted -s --align optimal valid.img --script mkpart primary ntfs 25% 50%
parted -s --align optimal valid.img --script set 2 msftdata on
parted -s --align optimal valid.img --script mkpart primary ntfs 50% 75%
parted -s --align optimal valid.img --script set 3 msftdata on
parted -s --align optimal valid.img --script mkpart primary ntfs 75% 100%
parted -s --align optimal valid.img --script set 3 msftdata on
sudo losetup -fP valid.img
LOOPDEV=$(losetup -j valid.img | cut -d: -f1)
PARTITION1="${LOOPDEV}p1"
PARTITION2="${LOOPDEV}p2"
PARTITION3="${LOOPDEV}p3"
PARTITION4="${LOOPDEV}p4"
sudo mkfs.ext4 $PARTITION1
sudo mkfs.exfat $PARTITION2
sudo mkfs.vfat -F 32 $PARTITION3
sudo mkfs.ntfs $PARTITION4
sudo rm -rf /mnt/valid*
sudo mkdir /mnt/valid1
sudo mkdir /mnt/valid2
sudo mkdir /mnt/valid3
sudo mkdir /mnt/valid4
sudo mount ${PARTITION1} /mnt/valid1
sudo mount ${PARTITION2} /mnt/valid2
sudo mount ${PARTITION3} /mnt/valid3
sudo mount ${PARTITION4} /mnt/valid4
openssl genrsa -out private-key.pem 4096
sudo cp private-key.pem /mnt/valid1/private-key1.pem
sudo cp private-key.pem /mnt/valid2/private-key2.pem
sudo cp private-key.pem /mnt/valid3/private-key3.pem
sudo cp private-key.pem /mnt/valid4/private-key4.pem
sudo umount /mnt/valid1
sudo umount /mnt/valid2
sudo umount /mnt/valid3
sudo umount /mnt/valid4
sudo losetup -d ${LOOPDEV}
sudo rm -rf /mnt/valid*
qemu-img convert valid.img -O qcow2 valid-ext-exfat-fat32-ntfs.qcow2
qemu-img convert --object secret,data="Yuvraj",id=sec0 -f raw valid.img -o encrypt.format=luks,encrypt.key-secret=sec0 -O qcow2 valid-ext-exfat-fat32-ntfs-encrypted-luks.qcow2
qemu-img convert --object secret,data="Yuvraj",id=sec0 -f raw valid.img -o encrypt.format=aes,encrypt.key-secret=sec0 -O qcow2 valid-ext-exfat-fat32-ntfs-encrypted-legacy-aes.qcow2

rm private-key.pem valid.img

echo "Yuvraj Saxena <ysaxenax@gmail.com>" > invalid.qcow2
