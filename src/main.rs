#![no_main]
#![no_std]

use core::{arch::asm, fmt::Write, ptr, slice};

use log::info;
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

    let kernel = load_kernel(image, &mut system_table);

    info!("loaded {} bytes", kernel.len());

    info!("exiting boot services");

    let Ok((table, memory_map)) = system_table.exit_boot_services(image, &mut [0; 4096 * 4]) else { return Status::BUFFER_TOO_SMALL; };

    let entry_point = map_kernel(kernel);
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