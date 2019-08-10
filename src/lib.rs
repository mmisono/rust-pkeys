#![feature(asm)]

use bitflags::bitflags;
use libc::{c_int, c_ulong, c_void, size_t};
use nix::errno::Errno;
use nix::sys::mman::ProtFlags;
use nix::Result;

/// Raw protection keys.
type RawPkey = c_int;

bitflags! {
    /// Access rights covered by the returned protection key.
    pub struct PkeyAccessRights: c_int {
        /// No protection is enforced.
        const PKEY_NONE = 0x0;
        /// Disable all data access to memory.
        const PKEY_DISABLE_ACCESS = 0x1;
        /// Disable write access to memory.
        const PKEY_DISABLE_WRITE = 0x2;
    }
}

/// Allocate a protection key.
pub fn pkey_alloc(flags: c_ulong, access_rights: PkeyAccessRights) -> Result<RawPkey> {
    let res = unsafe { libc::syscall(libc::SYS_pkey_alloc, flags, access_rights.bits()) };
    Errno::result(res as RawPkey)
}

/// Free a protection key.
pub fn pkey_free(pkey: RawPkey) -> Result<()> {
    let res = unsafe { libc::syscall(libc::SYS_pkey_free, pkey) };
    Errno::result(res).map(drop)
}

// almost same test code of nix's mprotect
/// Set protection with a protection key on a region of memory.
///
/// Calls to pkey_mprotect are inherently unsafe, as changes to memory protection can lead to
/// SIGSEGVs.
///
/// ```
/// # use nix::libc::size_t;
/// # use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
/// # use std::ptr;
/// # use pkeys::{pkey_alloc, pkey_free, pkey_mprotect, PkeyAccessRights};
/// const ONE_K: size_t = 1024;
/// let pkey = pkey_alloc(0, PkeyAccessRights::PKEY_NONE).unwrap();
/// let mut slice: &mut [u8] = unsafe {
///     let mem = mmap(ptr::null_mut(), ONE_K, ProtFlags::PROT_NONE,
///                    MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE, -1, 0).unwrap();
///     pkey_mprotect(mem, ONE_K, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE, pkey).unwrap();
///     std::slice::from_raw_parts_mut(mem as *mut u8, ONE_K)
/// };
/// assert_eq!(slice[0], 0x00);
/// slice[0] = 0xFF;
/// assert_eq!(slice[0], 0xFF);
/// pkey_free(pkey).unwrap();
/// ```
pub unsafe fn pkey_mprotect(
    addr: *mut c_void,
    length: size_t,
    prot: ProtFlags,
    pkey: RawPkey,
) -> Result<()> {
    Errno::result(libc::syscall(
        libc::SYS_pkey_mprotect,
        addr,
        length,
        prot.bits(),
        pkey,
    ))
    .map(drop)
}

/// Read protection key rights for user pages
pub fn rdpkru() -> i32 {
    #[allow(unused_assignments)]
    let mut eax: i32 = 0;
    let ecx: i32 = 0;
    unsafe {
        asm!("rdpkru": "={eax}"(eax): "{ecx}"(ecx): "edx": "volatile");
    }
    eax
}

/// Write protection key rights for user pages
pub fn wrpkru(pkru: i32) {
    let eax: i32 = pkru;
    let ecx: i32 = 0;
    let edx: i32 = 0;
    unsafe {
        asm!("wrpkru": : "{eax}"(eax), "{ecx}"(ecx), "{edx}"(edx): : "volatile");
    }
}

/// Set access right of given pkey.
pub fn pkey_set(pkey: RawPkey, access_rights: PkeyAccessRights) {
    let pkru = access_rights.bits() << (2 * pkey as i32);
    wrpkru(pkru);
}

/// Read access right of given pkey.
pub fn pkey_read(pkey: RawPkey) -> PkeyAccessRights {
    let pkru = rdpkru();
    let rights = (pkru >> (2 * pkey as i32)) & 0x3;
    PkeyAccessRights::from_bits(rights).unwrap()
}
