# s7-1500 software controller loader

This repo implements a small bootloader for the kernel used in Siemens S7-1500 Software Controllers.

The image run inside the VM by the s7-1500 software controller loader contains a multiboot header, but is not actually multiboot compatible. That's why we need this custom loader. For example, the image expects to be executed in 64-bit mode, but multiboot usually starts in protected mode.

`run.sh` can be used to launch a VM.

This is very much work in progress.