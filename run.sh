set -e

# Build the bootloader
cargo build --target x86_64-unknown-uefi --release

# Prepare the disk
mkdir -p target/image/EFI/BOOT/
cp target/x86_64-unknown-uefi/release/s7-1500-software-controller-loader.efi target/image/EFI/BOOT/BOOTX64.EFI
cp CPU.ELF_C924BFD8_60A0_520A_A2EF_CBE66BEA1F2B.decoded target/image/CPU.elf

# Prepare options for qemu

OVMF_CODE=/run/libvirt/nix-ovmf/OVMF_CODE.fd
OVMF_VARS=/run/libvirt/nix-ovmf/OVMF_VARS.fd
UEFI_OPTIONS="-drive if=pflash,format=raw,readonly=on,file=$OVMF_CODE -drive if=pflash,format=raw,readonly=on,file=$OVMF_VARS"

# Start a gdbserver on port 1234 and wait for it to attach (halt the VM on start).
# Note that the because the ELF's Class is ELF32, you need to manually switch the architecture
# when attaching with gdb: `set architecture i386:x86-64`
DEBUG_OPTIONS="-s -S"

# Launch the vm
qemu-system-x86_64 $UEFI_OPTIONS -drive file=fat:rw:target/image,format=raw,media=disk -m 4G -serial stdio -enable-kvm $DEBUG_OPTIONS