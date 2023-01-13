#!/bin/bash

if [ "$#" != 1 ]; then
    echo No kernel image specified
    exit 1
fi

KERNEL=$1

mkdir -p shared
/usr/libexec/virtiofsd --socket-path=.vhostqemu -o source=shared -o cache=always &> /dev/null &

qemu-kvm --nographic -smp 8 -enable-kvm -m 4G -cpu host -drive file=composefs.qcow2,index=0,media=disk,format=qcow2,if=virtio,snapshot=off --kernel $KERNEL --append "root=/dev/vda1 console=ttyS0 ro" -chardev socket,id=char0,path=.vhostqemu -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=sharedfs -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on -numa node,memdev=mem
