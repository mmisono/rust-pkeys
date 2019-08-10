use nix::libc::size_t;
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use pkeys::*;
use std::ptr;

pub fn main() {
    const ONE_K: size_t = 1024;
    let pkey = pkey_alloc(0, PkeyAccessRights::PKEY_NONE).unwrap();
    // Allocate memory region with a protection key
    let slice: &mut [u8] = unsafe {
        let mem = mmap(
            ptr::null_mut(),
            ONE_K,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .unwrap();
        pkey_mprotect(
            mem,
            ONE_K,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            pkey,
        )
        .unwrap();
        std::slice::from_raw_parts_mut(mem as *mut u8, ONE_K)
    };

    let rights = pkey_read(pkey);
    println!("pkey = {}", pkey);
    println!("current rights: {:?}", rights);

    // Access OK
    slice[0] = 0xFF;

    pkey_set(pkey, PkeyAccessRights::PKEY_DISABLE_WRITE);
    let rights = pkey_read(pkey);
    println!("update rights: {:?}", rights);

    // Access failed (SEGV)
    slice[0] = 0xFF;

    pkey_free(pkey).unwrap();
}
