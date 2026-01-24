# Rust Secure Memory Template

## Overview

This template provides secure memory allocation patterns for handling sensitive
data with memory locking, guard pages, and secure deallocation.

**Target Use Cases:**

- Cryptographic key storage
- Password buffers
- Sensitive data processing
- Security-critical applications

## Project Structure

```
my-secure-memory/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── allocator.rs
│   ├── protected.rs
│   └── buffer.rs
└── README.md
```

## Cargo.toml

```toml
[package]
name = "my-secure-memory"
version = "0.1.0"
edition = "2021"
rust-version = "1.92.0"

[dependencies]
zeroize = { version = "1.8", features = ["derive"] }
libc = "0.2"
thiserror = "2.0"

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["mman"] }
```

## Core Implementation

### src/protected.rs

```rust
use std::alloc::{alloc, dealloc, Layout};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use zeroize::Zeroize;

#[cfg(unix)]
use nix::sys::mman::{mlock, munlock, mprotect, ProtFlags};

/// Protected memory region that is locked and zeroized
pub struct ProtectedMemory<T> {
    ptr: NonNull<T>,
    layout: Layout,
}

impl<T> ProtectedMemory<T> {
    pub fn new(value: T) -> Result<Self, MemoryError> {
        let layout = Layout::new::<T>();

        unsafe {
            let ptr = alloc(layout) as *mut T;
            if ptr.is_null() {
                return Err(MemoryError::AllocationFailed);
            }

            // Write value
            std::ptr::write(ptr, value);

            // Lock memory to prevent swapping
            #[cfg(unix)]
            {
                let addr = ptr as *mut std::ffi::c_void;
                mlock(addr, layout.size())
                    .map_err(|_| MemoryError::LockFailed)?;
            }

            Ok(Self {
                ptr: NonNull::new_unchecked(ptr),
                layout,
            })
        }
    }
}

impl<T> Deref for ProtectedMemory<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for ProtectedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        unsafe {
            // Zeroize if possible
            let ptr = self.ptr.as_ptr();
            std::ptr::write_bytes(ptr as *mut u8, 0, self.layout.size());

            // Unlock memory
            #[cfg(unix)]
            {
                let addr = ptr as *mut std::ffi::c_void;
                let _ = munlock(addr, self.layout.size());
            }

            // Drop and deallocate
            std::ptr::drop_in_place(ptr);
            dealloc(ptr as *mut u8, self.layout);
        }
    }
}

unsafe impl<T: Send> Send for ProtectedMemory<T> {}
unsafe impl<T: Sync> Sync for ProtectedMemory<T> {}

#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("Memory allocation failed")]
    AllocationFailed,
    #[error("Failed to lock memory")]
    LockFailed,
    #[error("Failed to protect memory")]
    ProtectFailed,
}
```

### src/buffer.rs

```rust
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Secure buffer with capacity management
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureBuffer {
    data: Vec<u8>,
    #[zeroize(skip)]
    capacity: usize,
}

impl SecureBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn with_data(data: Vec<u8>) -> Self {
        let capacity = data.capacity();
        Self { data, capacity }
    }

    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn push(&mut self, byte: u8) {
        if self.data.len() < self.capacity {
            self.data.push(byte);
        }
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        let available = self.capacity - self.data.len();
        let to_add = bytes.len().min(available);
        self.data.extend_from_slice(&bytes[..to_add]);
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
```

## Security Checklist

- [ ] Memory locked against swapping (mlock)
- [ ] Zeroization on drop
- [ ] Guard pages for overflow protection
- [ ] No memory leaks
- [ ] Thread-safe implementation
- [ ] Constant-time comparisons where needed
