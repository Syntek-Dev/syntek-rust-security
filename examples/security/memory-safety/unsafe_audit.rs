//! Unsafe Code Audit Patterns
//!
//! Demonstrates patterns for safe usage of unsafe Rust and audit techniques.

use std::ptr::NonNull;

/// SAFETY DOCUMENTATION PATTERN
///
/// Every unsafe block should document:
/// 1. What invariants must hold
/// 2. Why those invariants are upheld
/// 3. What could go wrong if violated

/// Safe wrapper around raw pointer with documented invariants
pub struct SafeBox<T> {
    ptr: NonNull<T>,
}

impl<T> SafeBox<T> {
    /// Create a new SafeBox
    ///
    /// # Safety Invariants
    /// - `ptr` is always valid and properly aligned
    /// - `ptr` was allocated by Box::into_raw
    /// - Only one SafeBox owns each allocation
    pub fn new(value: T) -> Self {
        let boxed = Box::new(value);
        // SAFETY: Box::into_raw returns a valid, aligned, non-null pointer
        let ptr = unsafe { NonNull::new_unchecked(Box::into_raw(boxed)) };
        Self { ptr }
    }

    pub fn get(&self) -> &T {
        // SAFETY: ptr is valid for the lifetime of SafeBox (invariant 1)
        // and was created from a valid Box (invariant 2)
        unsafe { self.ptr.as_ref() }
    }

    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: We have exclusive access via &mut self,
        // and ptr is valid (invariant 1)
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for SafeBox<T> {
    fn drop(&mut self) {
        // SAFETY: ptr was created from Box::into_raw (invariant 2)
        // and hasn't been freed yet (invariant 3 - single owner)
        unsafe {
            drop(Box::from_raw(self.ptr.as_ptr()));
        }
    }
}

// SAFETY: SafeBox owns its data exclusively, safe to send if T is
unsafe impl<T: Send> Send for SafeBox<T> {}
// SAFETY: SafeBox provides &T access, safe to share if T is Sync
unsafe impl<T: Sync> Sync for SafeBox<T> {}

/// Pattern: Encapsulate unsafe in a safe API
pub mod encapsulated_unsafe {
    /// A simple bump allocator demonstrating safe API over unsafe internals
    pub struct BumpAllocator {
        buffer: Vec<u8>,
        offset: usize,
    }

    impl BumpAllocator {
        pub fn new(capacity: usize) -> Self {
            Self {
                buffer: vec![0; capacity],
                offset: 0,
            }
        }

        /// Allocate space for a value
        /// Returns None if not enough space
        pub fn alloc<T>(&mut self, value: T) -> Option<&mut T> {
            let align = std::mem::align_of::<T>();
            let size = std::mem::size_of::<T>();

            // Align offset
            let aligned_offset = (self.offset + align - 1) & !(align - 1);

            if aligned_offset + size > self.buffer.len() {
                return None;
            }

            // SAFETY:
            // 1. aligned_offset is within buffer bounds (checked above)
            // 2. aligned_offset is properly aligned for T (computed above)
            // 3. We have exclusive access via &mut self
            let ptr = unsafe {
                let ptr = self.buffer.as_mut_ptr().add(aligned_offset) as *mut T;
                std::ptr::write(ptr, value);
                &mut *ptr
            };

            self.offset = aligned_offset + size;
            Some(ptr)
        }

        pub fn reset(&mut self) {
            // Note: This doesn't drop allocated values!
            // Only use with Copy types or types that don't need drop
            self.offset = 0;
        }

        pub fn used(&self) -> usize {
            self.offset
        }
    }
}

/// Pattern: Unsafe trait with safety requirements
///
/// # Safety
/// Implementors must ensure that `as_bytes` returns a valid byte slice
/// that accurately represents the memory layout of Self
pub unsafe trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

// SAFETY: u32 has a defined memory layout (4 bytes, native endian)
unsafe impl AsBytes for u32 {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: u32 is 4 bytes, properly aligned, no padding
        unsafe {
            std::slice::from_raw_parts(self as *const u32 as *const u8, std::mem::size_of::<u32>())
        }
    }
}

/// Pattern: Audit checklist for unsafe code
pub mod audit_checklist {
    /// Common unsafe patterns to audit
    pub fn audit_points() -> Vec<&'static str> {
        vec![
            "1. Raw pointer dereference: Is pointer valid? Aligned? Non-null?",
            "2. Calling unsafe function: Are all preconditions met?",
            "3. Accessing mutable static: Is there data race potential?",
            "4. Implementing unsafe trait: Are all invariants upheld?",
            "5. FFI calls: Are types compatible? Is memory ownership clear?",
            "6. Union field access: Is the correct variant being accessed?",
            "7. Inline assembly: Are all constraints correct?",
            "8. Transmute: Are types compatible in size and alignment?",
        ]
    }

    /// Questions to ask for each unsafe block
    pub fn safety_questions() -> Vec<&'static str> {
        vec![
            "What invariants must hold for this to be safe?",
            "How do we know these invariants hold?",
            "What happens if the invariants are violated?",
            "Is there a safe alternative?",
            "Is the unsafe scope minimized?",
            "Is the safety documented in a SAFETY comment?",
        ]
    }
}

/// Pattern: Prefer safe abstractions
pub mod safe_alternatives {
    /// Instead of raw pointers, use references
    pub fn use_references(data: &mut [i32]) {
        for item in data.iter_mut() {
            *item *= 2;
        }
    }

    /// Instead of manual memory management, use Vec/Box
    pub fn use_collections() -> Vec<i32> {
        let mut v = Vec::with_capacity(100);
        v.extend(0..100);
        v
    }

    /// Instead of transmute, use safe conversions
    pub fn safe_conversion(bytes: [u8; 4]) -> u32 {
        u32::from_ne_bytes(bytes)
    }

    /// Instead of raw slice creation, use safe methods
    pub fn safe_slice(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
        data.get(start..start.checked_add(len)?)
    }
}

/// Demonstrate MIRI-detectable issues (for testing)
#[cfg(miri)]
pub mod miri_tests {
    // These would be caught by MIRI
    // DO NOT use in production - for demonstration only

    pub fn _use_after_free_example() {
        // MIRI would catch this
        let ptr: *const i32;
        {
            let x = 42;
            ptr = &x;
        }
        // unsafe { println!("{}", *ptr); } // UB: use after free
    }

    pub fn _data_race_example() {
        // MIRI would catch concurrent mutation
        // static mut COUNTER: i32 = 0;
        // Multiple threads modifying COUNTER would be UB
    }
}

fn main() {
    println!("=== Unsafe Code Audit Patterns ===\n");

    // SafeBox demonstration
    println!("--- SafeBox (Safe Wrapper) ---");
    let mut boxed = SafeBox::new(42);
    println!("Value: {}", boxed.get());
    *boxed.get_mut() = 100;
    println!("Modified: {}", boxed.get());

    // Bump allocator
    println!("\n--- Encapsulated Unsafe (Bump Allocator) ---");
    use encapsulated_unsafe::BumpAllocator;
    let mut alloc = BumpAllocator::new(1024);

    let a = alloc.alloc(42i32).unwrap();
    let b = alloc.alloc(3.14f64).unwrap();
    println!("Allocated i32: {}", a);
    println!("Allocated f64: {}", b);
    println!("Used: {} bytes", alloc.used());

    // AsBytes trait
    println!("\n--- Unsafe Trait (AsBytes) ---");
    let num: u32 = 0x12345678;
    let bytes = num.as_bytes();
    println!("u32 as bytes: {:02x?}", bytes);

    // Audit checklist
    println!("\n--- Audit Checklist ---");
    for point in audit_checklist::audit_points() {
        println!("  {}", point);
    }

    // Safety questions
    println!("\n--- Safety Questions ---");
    for question in audit_checklist::safety_questions() {
        println!("  - {}", question);
    }

    // Safe alternatives
    println!("\n--- Safe Alternatives ---");
    let mut data = vec![1, 2, 3, 4, 5];
    safe_alternatives::use_references(&mut data);
    println!("After doubling: {:?}", data);

    let bytes = [0x78, 0x56, 0x34, 0x12];
    let num = safe_alternatives::safe_conversion(bytes);
    println!("Converted: 0x{:08x}", num);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_box() {
        let mut b = SafeBox::new(String::from("hello"));
        assert_eq!(b.get(), "hello");
        b.get_mut().push_str(" world");
        assert_eq!(b.get(), "hello world");
    }

    #[test]
    fn test_bump_allocator() {
        use encapsulated_unsafe::BumpAllocator;
        let mut alloc = BumpAllocator::new(256);

        let a = alloc.alloc(1u8).unwrap();
        let b = alloc.alloc(2u32).unwrap();
        let c = alloc.alloc(3u64).unwrap();

        assert_eq!(*a, 1);
        assert_eq!(*b, 2);
        assert_eq!(*c, 3);
    }

    #[test]
    fn test_bump_allocator_overflow() {
        use encapsulated_unsafe::BumpAllocator;
        let mut alloc = BumpAllocator::new(4);

        assert!(alloc.alloc(1u32).is_some());
        assert!(alloc.alloc(2u32).is_none()); // No space
    }

    #[test]
    fn test_as_bytes() {
        let num: u32 = 0x01020304;
        let bytes = num.as_bytes();

        // Endianness-aware check
        if cfg!(target_endian = "little") {
            assert_eq!(bytes, &[0x04, 0x03, 0x02, 0x01]);
        } else {
            assert_eq!(bytes, &[0x01, 0x02, 0x03, 0x04]);
        }
    }

    #[test]
    fn test_safe_slice() {
        let data = [1, 2, 3, 4, 5];

        assert_eq!(
            safe_alternatives::safe_slice(&data, 1, 2),
            Some(&[2, 3][..])
        );
        assert_eq!(safe_alternatives::safe_slice(&data, 4, 2), None); // Out of bounds
        assert_eq!(safe_alternatives::safe_slice(&data, usize::MAX, 1), None); // Overflow
    }
}
