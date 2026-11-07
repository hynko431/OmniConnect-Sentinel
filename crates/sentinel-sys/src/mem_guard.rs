use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{compiler_fence, Ordering};

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn VirtualLock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
    fn VirtualUnlock(lpAddress: *const core::ffi::c_void, dwSize: usize) -> i32;
}

/// Overwrites an arbitrary mutable byte slice with volatile zeroes and a sequential-consistency
/// compiler fence so the compiler cannot elide the wipe before drop.
pub fn zeroize_slice(slice: &mut [u8]) {
    for b in slice.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0u8);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fixed-size sensitive buffer backed by a `Pin<Box<[u8; N]>>` heap allocation so the
/// memory address locked by `VirtualLock` / `mlock` never moves across function returns,
/// and volatile-zeroes all bytes before unlocking on `Drop`.
///
/// Intentionally does NOT implement `Clone` to prevent accidental key duplication in RAM.
pub struct ZeroizingBytes<const N: usize> {
    buf: Pin<Box<[u8; N]>>,
    locked: bool,
}

impl<const N: usize> ZeroizingBytes<N> {
    pub fn new(mut input: [u8; N]) -> Self {
        let boxed = Box::pin(input);
        // Zeroize the caller's stack copy immediately
        zeroize_slice(&mut input);
        let mut s = Self {
            buf: boxed,
            locked: false,
        };
        s.try_lock_pages();
        s
    }

    pub fn zeroed() -> Self {
        Self::new([0u8; N])
    }

    /// Explicit key duplication when a second independent locked buffer is required.
    pub fn duplicate_key(&self) -> Self {
        Self::new(*self.buf)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }

    pub fn is_page_locked(&self) -> bool {
        self.locked
    }

    fn try_lock_pages(&mut self) {
        let ptr = self.buf.as_ptr() as *const core::ffi::c_void;
        #[cfg(windows)]
        unsafe {
            if VirtualLock(ptr, N) != 0 {
                self.locked = true;
            }
        }
        #[cfg(unix)]
        unsafe {
            if libc::mlock(ptr, N) == 0 {
                self.locked = true;
            }
        }
    }

    pub fn zeroize_now(&mut self) {
        zeroize_slice(&mut self.buf[..]);
    }
}

impl<const N: usize> Deref for ZeroizingBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<const N: usize> DerefMut for ZeroizingBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl<const N: usize> Drop for ZeroizingBytes<N> {
    fn drop(&mut self) {
        self.zeroize_now();
        let ptr = self.buf.as_ptr() as *const core::ffi::c_void;
        #[cfg(windows)]
        if self.locked {
            unsafe {
                let _ = VirtualUnlock(ptr, N);
            }
        }
        #[cfg(unix)]
        if self.locked {
            unsafe {
                let _ = libc::munlock(ptr, N);
            }
        }
    }
}

impl<const N: usize> std::fmt::Debug for ZeroizingBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ZeroizingBytes<{}>([REDACTED, locked={}])",
            N, self.locked
        )
    }
}
