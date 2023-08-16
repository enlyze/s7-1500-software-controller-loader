# Copyright 2023 ENLYZE GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Written by Tom Dohrmann for ENLYZE GmbH

# Setup required for GEF. These may be commented out if you don't use GEF.
set architecture i386:x86-64
pi reset_architecture("i386:x86-64")
gef-remote --qemu-user --qemu-binary ./CPU.ELF_C924BFD8_60A0_520A_A2EF_CBE66BEA1F2B.decoded localhost 1234
si
pi gef.arch = __registered_architectures__["i386:x86-64"]()

source page-table-dump.py

# VMMCALL
# hbreak *0x10c06c2f
# hbreak *0x15a91d64
# hbreak *0x15a91eec

# Exception handler
hbreak *0x13e000b0
hbreak *0x1685fa70

# Panic
hbreak *0x15b16ba0
hbreak *0x15b16800
hbreak *0x10c09240
