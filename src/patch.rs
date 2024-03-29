// Copyright 2023 ENLYZE GmbH
// SPDX-License-Identifier: Apache-2.0
//
// Written by Tom Dohrmann for ENLYZE GmbH

//! This module implements helper for live-patching the loaded kernel. This
//! used to reimplement some functions that have disabled (puts, printf, etc).
//!
//! This whole module is wildly unsafe.

pub struct Patcher {
    pc: usize,
    /// A slice of addresses that are unused in the original kernel that we can
    /// use to place our shellcode in.
    /// These addresses point to 15 bytes of unused code (mostly nops).
    available_addresses: &'static [usize],
}

impl Patcher {
    /// Create a new patcher instance. This constructor should only be called
    /// once because it hardcodes the slice of available addresses.
    pub fn new() -> Self {
        Self {
            pc: 0,
            available_addresses: &[
                // 0x10c02a31, 0x10c03f31, 0x10c04571, 0x10c04ba1, 0x10c06471, 0x10c06b81, 0x10c072a1,
                // 0x10c072b1, 0x10c072c1, 0x10c07eb1, 0x10c091c1, 0x10c0fda1, 0x10c12971, 0x10c12eb1,
                // 0x10c14951, 0x10c14c81, 0x10c16231, 0x10c1ab91, 0x10c1aca1, 0x10c1c151, 0x10c1c291,
                // 0x10c1ebb1, 0x10c1f7b1, 0x10c21d31, 0x10c22d91, 0x10c25341, 0x10c28b91, 0x10c28dc1,
                // 0x10c2c821, 0x10c2d581, 0x10c2f2c1, 0x10c2f3c1, 0x10c30b41, 0x10c35971, 0x14401841,
                0x14401931, 0x14403f81, 0x144047c1, 0x14404991, 0x14404a01, 0x14404b31, 0x14406ab1,
                0x14406ba1, 0x14407b41, 0x14407f51, 0x14407f61, 0x14408081, 0x144084e1, 0x14408bb1,
                0x14408bc1, 0x14408c41, 0x14408c51, 0x14408c71, 0x14408c91, 0x14408cf1, 0x14408d21,
                0x14408e01, 0x14408e11, 0x14409c41, 0x1440a0f1, 0x1440a1e1, 0x1440a6c1, 0x1440a711,
                0x1440a721, 0x1440a971, 0x1440a991, 0x1440a9d1, 0x1440aa11, 0x1440af61, 0x1440b6c1,
                0x1440b6d1, 0x1440b6e1, 0x1440b6f1, 0x1440b701, 0x1440b761, 0x1440d371, 0x1440d381,
                0x1440d391, 0x1440d3a1, 0x1440d3b1, 0x1440d3f1, 0x1440d401, 0x1440d411, 0x1440d431,
                0x1440d451, 0x1440e041, 0x1440e641, 0x1440e951, 0x1440f601, 0x1440f611, 0x1440f6c1,
                0x144104b1, 0x14410c21, 0x14411a01, 0x14411a61, 0x14411ac1, 0x14411ad1, 0x14411b21,
                0x14411b41, 0x14411d21, 0x14411e21, 0x14411fe1, 0x14412e01, 0x14412f01, 0x14414301,
                0x144146b1, 0x144171a1, 0x144180a1, 0x14418211, 0x14419351, 0x14419361, 0x14419521,
                0x144195f1, 0x14419611, 0x14419991, 0x1441a0b1, 0x1441a0c1, 0x1441a2b1, 0x1441a581,
                0x1441a591, 0x1441a5a1, 0x1441a981, 0x1441aa51, 0x1441abc1, 0x1441abd1, 0x1441abe1,
                0x1441b0f1, 0x1441b241, 0x1441b251, 0x1441b2d1, 0x1441b361, 0x1441b381, 0x1441b3b1,
                0x1441b941, 0x1441bf51, 0x1441c841, 0x1441c871, 0x1441ccd1, 0x1441df31, 0x1441e091,
                0x1441e0f1, 0x1441e2c1, 0x1441e331, 0x1441e5d1, 0x1441eb51, 0x1441f081, 0x1441f2c1,
                0x14420241, 0x14420861, 0x144208e1, 0x14420a81, 0x14420da1, 0x14420f91, 0x144215f1,
                0x14422341, 0x14424b21, 0x14425541, 0x144256a1, 0x14425831, 0x14425ac1, 0x14426021,
                0x14426481, 0x14426af1, 0x14426b51, 0x14426c01, 0x14426d11, 0x14426ee1, 0x14426f71,
                0x14427f31, 0x14428071, 0x14429571, 0x14429a11, 0x14429e51, 0x1442a0a1, 0x1442a961,
                0x1442b2a1, 0x1442b911, 0x1442b9d1, 0x1442c9f1, 0x1442ca11, 0x1442e001, 0x14431231,
                0x144321d1, 0x14432dd1, 0x144332c1, 0x144334a1, 0x14435191, 0x14435fb1, 0x14436261,
                0x144370f1, 0x14437101, 0x1443f561, 0x1443f571, 0x1443f581, 0x1443f591, 0x1443f5b1,
                0x1443f5c1, 0x1443f5d1, 0x1443f5e1, 0x1443f5f1, 0x1443f601, 0x1443f611, 0x1443fc21,
                0x14448bb1, 0x144491d1, 0x14449831, 0x14449e61, 0x1444ce11, 0x1444cfd1, 0x14452551,
                0x144528a1, 0x144528b1, 0x14453b71, 0x14453b81, 0x144540e1, 0x144550b1, 0x14455711,
                0x14457b91, 0x14457c71, 0x14458131, 0x14458331, 0x14459241, 0x14459a61, 0x1445cf71,
                0x1445d871, 0x1445ecc1, 0x1445f2a1, 0x1445f2e1, 0x1445f7d1, 0x14462121, 0x1446b911,
                0x1446c891, 0x1446c971, 0x1446e3a1, 0x1446e481, 0x1446fd71, 0x14470f21, 0x14472161,
                0x14472241, 0x14475531, 0x14475811, 0x14477001, 0x14477251, 0x14477451, 0x144779a1,
                0x14478ca1, 0x1447a7a1, 0x1447e0b1, 0x1447e0d1, 0x1447e0f1, 0x1447e111, 0x1447e131,
                0x1447e4f1, 0x1447f3e1, 0x1447f631, 0x1447ff01, 0x14480301, 0x14480591, 0x14480811,
                0x14480961, 0x14480971, 0x14480981, 0x144817a1, 0x14482561, 0x14482a41, 0x144830f1,
                0x14483121, 0x14483611, 0x14485361, 0x144856e1, 0x144858a1, 0x14485c51, 0x14485c61,
                0x14486231, 0x14486871, 0x144868f1, 0x14486a41, 0x14486e51, 0x14487581, 0x144877a1,
                0x14487b41, 0x144889c1, 0x14489361, 0x14489bf1, 0x1448d5d1, 0x1448da01, 0x1448da61,
                0x1448db91, 0x1448dc51, 0x1448f451, 0x1448f461, 0x1448f671, 0x144901b1, 0x14490391,
                0x144903b1, 0x14493351, 0x144964f1, 0x14498b41, 0x14498c61, 0x14498cf1, 0x14498db1,
                0x14498dc1, 0x144990e1, 0x144994e1, 0x14499621, 0x14499af1, 0x1449aa11, 0x1449b731,
                0x1449b801, 0x1449c811, 0x1449c911, 0x1449e7a1, 0x144a1f81, 0x144a3da1, 0x144a6151,
                0x144a90f1, 0x144ab951, 0x144abe51, 0x144ac341, 0x144acfe1, 0x144b27c1, 0x144b4681,
                0x144b4b81, 0x144b6a71, 0x144b6ce1, 0x144c2c21, 0x144c6411, 0x144c85b1, 0x144c8a91,
                0x144c8b91, 0x144c8e61, 0x144c95b1, 0x144cad91, 0x144cb411, 0x144cfae1, 0x144d1091,
                0x144da1c1, 0x144e3c71, 0x144e6f71, 0x144eb301, 0x144ed6f1, 0x144ef761, 0x144ef9b1,
                0x144f15b1, 0x144f1bb1, 0x144f3821, 0x144f6081, 0x144f8491, 0x14503e61, 0x14503e91,
                0x14504021, 0x14509121, 0x1450a5f1, 0x1450cd21, 0x1450d271, 0x14510251, 0x14512d51,
                0x145130b1, 0x145130e1, 0x14513251, 0x145149a1, 0x145158f1, 0x14516971, 0x14517fd1,
                0x145181e1, 0x14518311, 0x14518481, 0x145184e1, 0x14518541, 0x1451a2f1, 0x1451acd1,
                0x1451cef1, 0x14521121, 0x14522271, 0x145224d1, 0x14526ad1, 0x14526b11, 0x14526c11,
                0x14526d11, 0x14528351, 0x1452cba1, 0x1452e0e1, 0x1452e591, 0x1452f1c1, 0x145314d1,
                0x1453be11, 0x1453c321, 0x1453d471, 0x14541281, 0x14543ba1, 0x14543c91, 0x14544cd1,
                0x145490b1, 0x14549b31, 0x1454b1a1, 0x1454b991, 0x1454be71, 0x1454c6e1, 0x1454f751,
                0x1454f981, 0x14550541, 0x14550b71, 0x14551da1, 0x14556041, 0x14557771, 0x14557801,
                0x14557891, 0x14558fd1, 0x14559df1, 0x1455b401, 0x1455c831, 0x1455c841, 0x1455da31,
                0x1455da41, 0x1455dc61, 0x1455e931, 0x1455f781, 0x1455f811, 0x1455fde1, 0x1455fe81,
                0x1455fe91, 0x14560061, 0x145600e1, 0x145602e1, 0x14560571, 0x145605e1, 0x14560d41,
                0x14560d51, 0x14560d61, 0x14560e61, 0x14561971, 0x145643a1, 0x145643e1, 0x145643f1,
                0x14564401, 0x14564701, 0x14564d11, 0x14564d81, 0x145653e1, 0x145653f1, 0x14565741,
                0x145657c1, 0x14566f91, 0x145686a1, 0x145686e1, 0x14568771, 0x14568c51, 0x145691a1,
                0x14569631, 0x1456bea1, 0x1456bed1, 0x1456bf21, 0x1456bf31, 0x1456bf41, 0x1456bfc1,
                0x1456c0d1, 0x1456c281, 0x1456c4e1, 0x1456c6b1, 0x1456d171, 0x1456d441, 0x1456d451,
                0x1456d6a1, 0x1456d791, 0x1456dd91, 0x1456f591, 0x1456fbf1, 0x14570811, 0x14571a01,
                0x14571df1, 0x145742b1, 0x14574891, 0x14578451, 0x14578e41, 0x145795a1, 0x1457b0a1,
                0x1457b111, 0x1457b181, 0x1457b1f1, 0x1457b261, 0x1457b2d1, 0x1457b341, 0x1457b3b1,
                0x1457b551, 0x1457b581, 0x1457b851, 0x1457b991, 0x1457b9b1, 0x1457b9f1, 0x1457ba31,
                0x1457bc01, 0x1457bc11, 0x1457cfb1, 0x1457cfc1, 0x1457f0f1, 0x1457f3b1, 0x1457fde1,
                0x1457ff31, 0x14580401, 0x14580661,
            ],
        }
    }

    /// Set the address that should be patched next.
    pub fn set_pc(&mut self, pc: usize) {
        self.pc = pc;
    }

    /// Return a label that can be used in a later jne call.
    pub fn label(&self) -> Label {
        Label(self.pc)
    }

    /// Set pc to some arbitrary free address. This can be used to implement
    /// entirely new functions.
    pub fn choose_next_address(&mut self) -> usize {
        let (next_pc, new_addresses) = self.available_addresses.split_first().unwrap();
        self.pc = *next_pc;
        self.available_addresses = new_addresses;
        self.pc
    }

    /// Place an instruction and a jmp instructions to jump the next slot.
    pub fn place_instruction(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= 10);

        unsafe {
            core::ptr::copy(bytes.as_ptr(), self.pc as _, bytes.len());
        }
        self.pc += bytes.len();

        let (next_pc, new_addresses) = self.available_addresses.split_first().unwrap();

        let diff = i32::try_from((*next_pc as isize).wrapping_sub((self.pc + 5) as isize)).unwrap();
        unsafe {
            (self.pc as *mut u8).write(0xe9);
            ((self.pc + 1) as *mut i32).write(diff);
        }

        self.pc = *next_pc;
        self.available_addresses = new_addresses;
    }

    /// Place a `call` instruction.
    pub fn call(&mut self, addr: usize) {
        let mut buf = [0xe8, 0, 0, 0, 0];
        let diff =
            i32::try_from((addr as isize).wrapping_sub((self.pc + buf.len()) as isize)).unwrap();
        buf[1..].copy_from_slice(&diff.to_ne_bytes());
        self.place_instruction(&buf);
    }

    /// Place a `jne` instruction.
    pub fn jne(&mut self, label: Label) {
        let mut buf = [0x0f, 0x85, 0, 0, 0, 0];
        let diff =
            i32::try_from((label.0 as isize).wrapping_sub((self.pc + buf.len()) as isize)).unwrap();
        buf[2..].copy_from_slice(&diff.to_ne_bytes());
        self.place_instruction(&buf);
    }
}

#[derive(Clone, Copy)]
pub struct Label(usize);
