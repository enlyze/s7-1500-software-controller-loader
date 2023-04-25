#![no_main]
#![no_std]

mod patch;

use core::{arch::asm, fmt::Write, ptr, slice};

use log::info;
use patch::Patcher;
use uefi::{
    prelude::*,
    proto::{
        device_path::DevicePath,
        loaded_image::LoadedImage,
        media::{
            file::{File, FileAttribute, FileInfo, FileMode},
            fs::SimpleFileSystem,
        },
    },
    table::boot::{AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams},
    CStr16,
};
use x86_64::registers::model_specific::{Efer, EferFlags, Msr};
use xmas_elf::{program::Type, ElfFile};

mod logging;
mod panic;

#[entry]
fn main(image: Handle, mut system_table: SystemTable<Boot>) -> Status {
    let res = unsafe { logging::init() };
    let Ok(()) = res else {
        let mut stdout = system_table.stdout();
        let _ = writeln!(stdout, "failed to set logger");
        return Status::ABORTED;
    };

    // The firmware will execute the `VMMCALL` instruction. This instruction
    // requires the `EFER.SVME` bit to be set.
    unsafe {
        Efer::update(|flags| *flags |= EferFlags::SECURE_VIRTUAL_MACHINE_ENABLE);
    }

    let kernel = load_kernel(image, &mut system_table);

    info!("loaded {} bytes", kernel.len());

    info!("exiting boot services");

    let Ok((table, memory_map)) = system_table.exit_boot_services(image, &mut [0; 4096 * 4]) else { return Status::BUFFER_TOO_SMALL; };

    let entry_point = map_kernel(kernel);
    install_hooks();
    info!("jumping to entrypoint entry_point={entry_point:#x}");

    unsafe {
        asm!(
            "jmp {entry_point}",
            entry_point = in(reg) entry_point,
            in("rax") 0x2badb002,
            options(noreturn)
        );
    }
}

/// This function is mostly copied from an older version of rust-osdev/bootloader
fn load_kernel(image: Handle, system_table: &mut SystemTable<Boot>) -> &'static mut [u8] {
    let boot_services = &system_table.boot_services();
    let loaded_image = unsafe {
        boot_services.open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    }
    .expect("Failed to retrieve `LoadedImage` protocol from handle");

    let loaded_image = unsafe { &*loaded_image.interface.get() };

    let device_handle = loaded_image.device();

    let device_path = unsafe {
        boot_services.open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    }
    .expect("Failed to retrieve `DevicePath` protocol from image's device handle");
    let mut device_path = unsafe { &*device_path.interface.get() };

    let fs_handle = boot_services
        .locate_device_path::<SimpleFileSystem>(&mut device_path)
        .expect("boot device is not a simple file system");

    let mut file_system_raw = unsafe {
        boot_services.open_protocol::<SimpleFileSystem>(
            OpenProtocolParams {
                handle: fs_handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::Exclusive,
        )
    }
    .expect("failed to open simple file system protocol");
    let file_system = unsafe { &mut *file_system_raw.interface.get() };

    let mut root = file_system.open_volume().unwrap();
    let mut buf = [0; 14 * 2];
    let filename = CStr16::from_str_with_buf("CPU.elf", &mut buf).unwrap();
    let kernel_file_handle = root
        .open(filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to load kernel (expected file named `CPU.elf`)");
    let mut kernel_file = match kernel_file_handle.into_type().unwrap() {
        uefi::proto::media::file::FileType::Regular(f) => f,
        uefi::proto::media::file::FileType::Dir(_) => panic!(),
    };

    let mut buf = [0; 500];
    let kernel_info: &mut FileInfo = kernel_file.get_info(&mut buf).unwrap();
    let kernel_size = usize::try_from(kernel_info.file_size()).unwrap();

    let kernel_ptr = system_table
        .boot_services()
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            ((kernel_size - 1) / 4096) + 1,
        )
        .expect("failed to allocate memory for kernel") as *mut u8;
    unsafe { ptr::write_bytes(kernel_ptr, 0, kernel_size) };
    let kernel_slice = unsafe { slice::from_raw_parts_mut(kernel_ptr, kernel_size) };
    kernel_file.read(kernel_slice).unwrap();

    kernel_slice
}

fn map_kernel(kernel: &mut [u8]) -> u64 {
    let elf = ElfFile::new(&kernel).expect("failed to parse elf file");

    for ph in elf
        .program_iter()
        .filter(|ph| ph.get_type() == Ok(Type::Load))
    {
        let addr = ph.virtual_addr() as *mut u8;
        let offset = ph.offset() as usize;
        let file_size = ph.file_size() as usize;
        let mem_size = ph.mem_size() as usize;

        info!("loading load segment addr={addr:p} {offset:#x} {file_size:#x} {mem_size:#x}");

        // In UEFI all memory starts out identiy mapped, there's a very good
        // chance, that we can just write to that location without having to
        // map it first.
        unsafe {
            core::ptr::copy(&kernel[offset], addr, file_size);
            core::ptr::write_bytes(addr.add(file_size), 0, mem_size - file_size);
        }
    }

    elf.header.pt2.entry_point()
}

fn install_hooks() {
    let mut patcher = Patcher::new();
    patch_puts(&mut patcher);
    patch_printf(&mut patcher);
    patch_vprintf(&mut patcher);
    patch_put_newline(&mut patcher);

    patch_log_levels();
    patch_memory_table_entries();
}

fn patch_log_levels() {
    // Enable what looks like log levels masks.
    unsafe {
        (0x18d3ea38 as *mut u32).write(!0);
        (0x18d3ea34 as *mut u32).write(!0);
    }
}

/// Reimplement puts. We'll print the string to the first serial port.
fn patch_puts(patcher: &mut Patcher) {
    patcher.set_pc(0x10c072a0);

    // mov    dx,0x3f8
    patcher.place_instruction(&[0x66, 0xba, 0xf8, 0x03]);
    let label = patcher.label();
    // mov    al,BYTE PTR [rdi]
    patcher.place_instruction(&[0x8a, 0x07]);
    // out    dx,al
    patcher.place_instruction(&[0xee]);
    // inc    rdi
    patcher.place_instruction(&[0x48, 0xff, 0xc7]);
    // test   al,al
    patcher.place_instruction(&[0x84, 0xc0]);
    patcher.jne(label);
    // ret
    patcher.place_instruction(&[0xc3]);
}

// Reimplement printf.
fn patch_printf(patcher: &mut Patcher) {
    patcher.set_pc(0x14de4050);
    // push   r9
    patcher.place_instruction(&[0x41, 0x51]);
    // mov    r9,r8
    patcher.place_instruction(&[0x4d, 0x89, 0xc1]);
    // mov    r8,rcx
    patcher.place_instruction(&[0x49, 0x89, 0xc8]);
    // mov    rcx,rdx
    patcher.place_instruction(&[0x48, 0x89, 0xd1]);
    // mov    rdx,rsi
    patcher.place_instruction(&[0x48, 0x89, 0xf2]);
    // mov    rsi,rdi
    patcher.place_instruction(&[0x48, 0x89, 0xfe]);
    // lea    rdi,[rsp-0x1000]
    patcher.place_instruction(&[0x48, 0x8d, 0xbc, 0x24, 0x00, 0xf0, 0xff, 0xff]);
    // call    sprintf
    patcher.call(0x15b2b390);
    // lea    rdi,[rsp-0x1000]
    patcher.place_instruction(&[0x48, 0x8d, 0xbc, 0x24, 0x00, 0xf0, 0xff, 0xff]);
    // call    puts
    patcher.call(0x10c072a0);
    // pop    r9
    patcher.place_instruction(&[0x41, 0x59]);
    // ret
    patcher.place_instruction(&[0xc3]);
}

// Reimplement vprintf.
fn patch_vprintf(patcher: &mut Patcher) {
    // create new callback function.
    let callback = patcher.choose_next_address();
    // mov    rcx,rdx
    patcher.place_instruction(&[0x48, 0x89, 0xd1]);
    // mov    rdx,0x3f8
    patcher.place_instruction(&[0x48, 0xc7, 0xc2, 0xf8, 0x03, 0x00, 0x00]);
    // rep outs dx,BYTE PTR ds:[rsi]
    patcher.place_instruction(&[0xf3, 0x6e]);
    // ret
    patcher.place_instruction(&[0xc3]);

    patcher.set_pc(0x14de4060);
    // mov    rdx,rdi
    patcher.place_instruction(&[0x48, 0x89, 0xfa]);
    // mov    rcx,rsi
    patcher.place_instruction(&[0x48, 0x89, 0xf1]);
    // mov    rdi,callback
    let mut buf = [0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00];
    buf[3..7].copy_from_slice(&u32::try_from(callback).unwrap().to_ne_bytes());
    patcher.place_instruction(&buf);
    // mov    rsi,0x0
    patcher.place_instruction(&[0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00]);
    // call   TD_format
    patcher.call(0x15b34270);
    // ret
    patcher.place_instruction(&[0xc3]);
}

/// Reimplement a function that prints a newline.
fn patch_put_newline(patcher: &mut Patcher) {
    patcher.set_pc(0x10c072b0);

    // mov    dx,0x3f8
    patcher.place_instruction(&[0x66, 0xba, 0xf8, 0x03]);
    // mov    al,0xa
    patcher.place_instruction(&[0xb0, 0x0a]);
    // out    dx,al
    patcher.place_instruction(&[0xee]);
    // ret
    patcher.place_instruction(&[0xc3]);
}

fn patch_memory_table_entries() {
    #[repr(C)]
    struct MemoryTableEntry {
        virt_addr: u32,
        length: u32,
        flags: u32,
    }

    let mut ptr = 0x1000005c as *mut MemoryTableEntry;

    // Add an entry that maps the APIC.
    let apic_base_msr = Msr::new(0x1b);
    let apic_address = unsafe { apic_base_msr.read() } & 0xf_ffff_ffff_f000;
    let apic_address = u32::try_from(apic_address).unwrap();
    unsafe {
        ptr.write(MemoryTableEntry {
            virt_addr: apic_address,
            length: 0x1000,
            flags: 0xff,
        });
        ptr = ptr.add(1);
    }

    // Write the last zero entry.
    unsafe {
        ptr.write(MemoryTableEntry {
            virt_addr: 0,
            length: 0,
            flags: 0,
        });
    }
}
