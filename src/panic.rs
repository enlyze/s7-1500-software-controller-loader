// Copyright 2023 ENLYZE GmbH
// SPDX-License-Identifier: Apache-2.0
//
// Written by Tom Dohrmann for ENLYZE GmbH

use core::panic::PanicInfo;

use log::error;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    error!("{info}");
    loop {}
}
