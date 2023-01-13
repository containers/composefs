This has some tools to build a (fedora-based) disk image that can be used to boot a custom
kernel and then test composefs inside it using qemu and virtiofs to share files with the host.

To use this, first install the dependencies:

$ dnf install virtiofsd osbuild osbuild-tools

Then build the test image:

$ ./build_image.sh

Then build a kernel with composefs and virtio support build in, and run it like this:

$ ./runkernel.sh /path/to/linux/arch/x86/boot/bzImage

This will give you a VM exposing the directory "shared" in this
directory as /shared in the VM. Log in as "root" or "guest" both with
password "password".
