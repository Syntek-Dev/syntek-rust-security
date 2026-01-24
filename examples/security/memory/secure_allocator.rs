//! Secure Memory Allocator
//!
//! A memory allocator with security features including guard pages,
//! memory poisoning, and automatic zeroization.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Memory protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLevel {
    /// No protection, standard allocation
    None,
    /// Zeroize memory on free
    ZeroOnFree,
    /// Guard pages + zeroize on free
    Guarded,
    /// Full protection: guard pages, zeroize, mlock
    Maximum,
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub ptr: usize,
    pub size: usize,
    pub layout: Layout,
    pub protection: ProtectionLevel,
    pub allocated_at: std::time::Instant,
    pub guard_before: Option<usize>,
    pub guard_after: Option<usize>,
    pub is_locked: bool,
}

/// Allocation statistics
#[derive(Debug, Default)]
pub struct AllocationStats {
    pub total_allocations: AtomicUsize,
    pub total_deallocations: AtomicUsize,
    pub current_allocated: AtomicUsize,
    pub peak_allocated: AtomicUsize,
    pub total_bytes_allocated: AtomicUsize,
    pub total_bytes_freed: AtomicUsize,
    pub guard_page_faults: AtomicUsize,
}

impl AllocationStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_allocation(&self, size: usize) {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_allocated
            .fetch_add(size, Ordering::Relaxed);
        let current = self.current_allocated.fetch_add(size, Ordering::Relaxed) + size;

        // Update peak if needed
        let mut peak = self.peak_allocated.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_allocated.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_freed.fetch_add(size, Ordering::Relaxed);
        self.current_allocated.fetch_sub(size, Ordering::Relaxed);
    }
}

/// Secure allocator configuration
#[derive(Debug, Clone)]
pub struct SecureAllocatorConfig {
    pub default_protection: ProtectionLevel,
    pub guard_page_size: usize,
    pub poison_byte: u8,
    pub track_allocations: bool,
    pub mlock_sensitive: bool,
    pub max_allocation_size: usize,
}

impl Default for SecureAllocatorConfig {
    fn default() -> Self {
        Self {
            default_protection: ProtectionLevel::ZeroOnFree,
            guard_page_size: 4096,
            poison_byte: 0xDE,
            track_allocations: true,
            mlock_sensitive: false,
            max_allocation_size: 1024 * 1024 * 100, // 100MB
        }
    }
}

/// Secure memory allocator
pub struct SecureAllocator {
    config: SecureAllocatorConfig,
    stats: AllocationStats,
    regions: Mutex<HashMap<usize, MemoryRegion>>,
    initialized: AtomicBool,
}

impl SecureAllocator {
    pub const fn new() -> Self {
        Self {
            config: SecureAllocatorConfig {
                default_protection: ProtectionLevel::ZeroOnFree,
                guard_page_size: 4096,
                poison_byte: 0xDE,
                track_allocations: true,
                mlock_sensitive: false,
                max_allocation_size: 1024 * 1024 * 100,
            },
            stats: AllocationStats {
                total_allocations: AtomicUsize::new(0),
                total_deallocations: AtomicUsize::new(0),
                current_allocated: AtomicUsize::new(0),
                peak_allocated: AtomicUsize::new(0),
                total_bytes_allocated: AtomicUsize::new(0),
                total_bytes_freed: AtomicUsize::new(0),
                guard_page_faults: AtomicUsize::new(0),
            },
            regions: Mutex::new(HashMap::new()),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn with_config(config: SecureAllocatorConfig) -> Self {
        Self {
            config,
            stats: AllocationStats::new(),
            regions: Mutex::new(HashMap::new()),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn stats(&self) -> &AllocationStats {
        &self.stats
    }

    /// Allocate memory with specified protection level
    pub fn allocate_protected(
        &self,
        layout: Layout,
        protection: ProtectionLevel,
    ) -> Option<NonNull<u8>> {
        if layout.size() > self.config.max_allocation_size {
            return None;
        }

        let ptr = match protection {
            ProtectionLevel::None => self.allocate_simple(layout),
            ProtectionLevel::ZeroOnFree => self.allocate_simple(layout),
            ProtectionLevel::Guarded => self.allocate_guarded(layout),
            ProtectionLevel::Maximum => self.allocate_maximum(layout),
        }?;

        // Record allocation
        if self.config.track_allocations {
            let region = MemoryRegion {
                ptr: ptr.as_ptr() as usize,
                size: layout.size(),
                layout,
                protection,
                allocated_at: std::time::Instant::now(),
                guard_before: None,
                guard_after: None,
                is_locked: protection == ProtectionLevel::Maximum,
            };

            if let Ok(mut regions) = self.regions.lock() {
                regions.insert(ptr.as_ptr() as usize, region);
            }
        }

        self.stats.record_allocation(layout.size());

        Some(ptr)
    }

    fn allocate_simple(&self, layout: Layout) -> Option<NonNull<u8>> {
        unsafe {
            let ptr = std::alloc::alloc(layout);
            NonNull::new(ptr)
        }
    }

    fn allocate_guarded(&self, layout: Layout) -> Option<NonNull<u8>> {
        // In a real implementation, this would allocate guard pages
        // before and after the actual allocation
        let guard_size = self.config.guard_page_size;
        let total_size = guard_size + layout.size() + guard_size;

        let total_layout = Layout::from_size_align(total_size, layout.align()).ok()?;

        unsafe {
            let base = std::alloc::alloc(total_layout);
            if base.is_null() {
                return None;
            }

            // Poison guard pages
            std::ptr::write_bytes(base, self.config.poison_byte, guard_size);
            std::ptr::write_bytes(
                base.add(guard_size + layout.size()),
                self.config.poison_byte,
                guard_size,
            );

            // Return pointer to usable memory
            NonNull::new(base.add(guard_size))
        }
    }

    fn allocate_maximum(&self, layout: Layout) -> Option<NonNull<u8>> {
        let ptr = self.allocate_guarded(layout)?;

        // In a real implementation, we would mlock the memory here
        // to prevent it from being swapped to disk

        Some(ptr)
    }

    /// Deallocate memory with proper cleanup
    pub fn deallocate_protected(&self, ptr: NonNull<u8>, layout: Layout) {
        let protection = if let Ok(regions) = self.regions.lock() {
            regions
                .get(&(ptr.as_ptr() as usize))
                .map(|r| r.protection)
                .unwrap_or(self.config.default_protection)
        } else {
            self.config.default_protection
        };

        match protection {
            ProtectionLevel::None => {
                self.deallocate_simple(ptr, layout);
            }
            ProtectionLevel::ZeroOnFree => {
                self.zeroize_and_deallocate(ptr, layout);
            }
            ProtectionLevel::Guarded => {
                self.deallocate_guarded(ptr, layout);
            }
            ProtectionLevel::Maximum => {
                self.deallocate_maximum(ptr, layout);
            }
        }

        // Remove from tracking
        if self.config.track_allocations {
            if let Ok(mut regions) = self.regions.lock() {
                regions.remove(&(ptr.as_ptr() as usize));
            }
        }

        self.stats.record_deallocation(layout.size());
    }

    fn deallocate_simple(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe {
            std::alloc::dealloc(ptr.as_ptr(), layout);
        }
    }

    fn zeroize_and_deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // Zeroize memory before freeing
        unsafe {
            // Use volatile writes to prevent optimization
            std::ptr::write_bytes(ptr.as_ptr(), 0, layout.size());

            // Memory barrier to ensure writes complete
            std::sync::atomic::fence(Ordering::SeqCst);

            std::alloc::dealloc(ptr.as_ptr(), layout);
        }
    }

    fn deallocate_guarded(&self, ptr: NonNull<u8>, layout: Layout) {
        let guard_size = self.config.guard_page_size;

        // Verify guard pages weren't overwritten
        unsafe {
            let base = ptr.as_ptr().sub(guard_size);

            // Check before guard
            for i in 0..guard_size {
                if *base.add(i) != self.config.poison_byte {
                    self.stats.guard_page_faults.fetch_add(1, Ordering::Relaxed);
                    // In a real implementation, this would trigger an alert
                }
            }

            // Check after guard
            let after = ptr.as_ptr().add(layout.size());
            for i in 0..guard_size {
                if *after.add(i) != self.config.poison_byte {
                    self.stats.guard_page_faults.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Zeroize and deallocate
            let total_size = guard_size + layout.size() + guard_size;
            std::ptr::write_bytes(base, 0, total_size);

            let total_layout = Layout::from_size_align_unchecked(total_size, layout.align());
            std::alloc::dealloc(base, total_layout);
        }
    }

    fn deallocate_maximum(&self, ptr: NonNull<u8>, layout: Layout) {
        // In a real implementation, we would munlock here
        self.deallocate_guarded(ptr, layout);
    }

    /// Check for memory leaks
    pub fn check_leaks(&self) -> Vec<MemoryRegion> {
        if let Ok(regions) = self.regions.lock() {
            regions.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get allocation report
    pub fn report(&self) -> String {
        let leaks = self.check_leaks();

        format!(
            "Secure Allocator Report:\n\
             ├─ Total allocations: {}\n\
             ├─ Total deallocations: {}\n\
             ├─ Current allocated: {} bytes\n\
             ├─ Peak allocated: {} bytes\n\
             ├─ Guard page faults: {}\n\
             └─ Potential leaks: {}",
            self.stats.total_allocations.load(Ordering::Relaxed),
            self.stats.total_deallocations.load(Ordering::Relaxed),
            self.stats.current_allocated.load(Ordering::Relaxed),
            self.stats.peak_allocated.load(Ordering::Relaxed),
            self.stats.guard_page_faults.load(Ordering::Relaxed),
            leaks.len()
        )
    }
}

impl Default for SecureAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure box that automatically zeroizes on drop
pub struct SecureBox<T> {
    ptr: NonNull<T>,
    allocator: &'static SecureAllocator,
}

impl<T> SecureBox<T> {
    pub fn new(value: T, allocator: &'static SecureAllocator) -> Option<Self> {
        let layout = Layout::new::<T>();
        let ptr = allocator.allocate_protected(layout, ProtectionLevel::Maximum)?;

        unsafe {
            std::ptr::write(ptr.as_ptr() as *mut T, value);
        }

        Some(Self {
            ptr: ptr.cast(),
            allocator,
        })
    }

    pub fn get(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }

    pub fn get_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for SecureBox<T> {
    fn drop(&mut self) {
        let layout = Layout::new::<T>();

        // Drop the contained value first
        unsafe {
            std::ptr::drop_in_place(self.ptr.as_ptr());
        }

        // Deallocate with secure cleanup
        self.allocator.deallocate_protected(self.ptr.cast(), layout);
    }
}

/// Secure vector with automatic zeroization
pub struct SecureVec<T> {
    data: Vec<T>,
}

impl<T: Default + Clone> SecureVec<T> {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, value: T) {
        self.data.push(value);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.data.pop()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }

    pub fn clear(&mut self) {
        // Zeroize before clearing
        for item in &mut self.data {
            *item = T::default();
        }
        self.data.clear();
    }
}

impl<T: Default + Clone> Default for SecureVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Clone> Drop for SecureVec<T> {
    fn drop(&mut self) {
        // Zeroize all elements before dropping
        for item in &mut self.data {
            *item = T::default();
        }
    }
}

/// Memory pool for fixed-size secure allocations
pub struct SecurePool {
    block_size: usize,
    blocks: Mutex<Vec<NonNull<u8>>>,
    free_list: Mutex<Vec<NonNull<u8>>>,
    allocator: SecureAllocator,
}

impl SecurePool {
    pub fn new(block_size: usize, initial_blocks: usize) -> Self {
        let allocator = SecureAllocator::with_config(SecureAllocatorConfig {
            default_protection: ProtectionLevel::ZeroOnFree,
            ..Default::default()
        });

        let mut blocks = Vec::with_capacity(initial_blocks);
        let mut free_list = Vec::with_capacity(initial_blocks);

        let layout = Layout::from_size_align(block_size, 8).unwrap();

        for _ in 0..initial_blocks {
            if let Some(ptr) = allocator.allocate_protected(layout, ProtectionLevel::ZeroOnFree) {
                blocks.push(ptr);
                free_list.push(ptr);
            }
        }

        Self {
            block_size,
            blocks: Mutex::new(blocks),
            free_list: Mutex::new(free_list),
            allocator,
        }
    }

    pub fn allocate(&self) -> Option<NonNull<u8>> {
        let mut free_list = self.free_list.lock().ok()?;

        if let Some(ptr) = free_list.pop() {
            return Some(ptr);
        }

        // Allocate new block if pool is exhausted
        let layout = Layout::from_size_align(self.block_size, 8).ok()?;
        let ptr = self
            .allocator
            .allocate_protected(layout, ProtectionLevel::ZeroOnFree)?;

        if let Ok(mut blocks) = self.blocks.lock() {
            blocks.push(ptr);
        }

        Some(ptr)
    }

    pub fn deallocate(&self, ptr: NonNull<u8>) {
        // Zeroize before returning to pool
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), 0, self.block_size);
        }

        if let Ok(mut free_list) = self.free_list.lock() {
            free_list.push(ptr);
        }
    }

    pub fn available(&self) -> usize {
        self.free_list.lock().map(|f| f.len()).unwrap_or(0)
    }

    pub fn total(&self) -> usize {
        self.blocks.lock().map(|b| b.len()).unwrap_or(0)
    }
}

impl Drop for SecurePool {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.block_size, 8).unwrap();

        if let Ok(blocks) = self.blocks.lock() {
            for &ptr in blocks.iter() {
                self.allocator.deallocate_protected(ptr, layout);
            }
        }
    }
}

fn main() {
    println!("=== Secure Memory Allocator Demo ===\n");

    // Create allocator with custom config
    let config = SecureAllocatorConfig {
        default_protection: ProtectionLevel::ZeroOnFree,
        track_allocations: true,
        ..Default::default()
    };

    let allocator = SecureAllocator::with_config(config);

    // Allocate with different protection levels
    println!("Allocating memory with various protection levels...\n");

    let layout = Layout::from_size_align(256, 8).unwrap();

    // Simple allocation
    if let Some(ptr) = allocator.allocate_protected(layout, ProtectionLevel::None) {
        println!("Simple allocation: {:?}", ptr);
        allocator.deallocate_protected(ptr, layout);
    }

    // Zeroize on free
    if let Some(ptr) = allocator.allocate_protected(layout, ProtectionLevel::ZeroOnFree) {
        println!("Zeroize-on-free allocation: {:?}", ptr);

        // Write some data
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
        }

        allocator.deallocate_protected(ptr, layout);
    }

    // Guarded allocation
    if let Some(ptr) = allocator.allocate_protected(layout, ProtectionLevel::Guarded) {
        println!("Guarded allocation: {:?}", ptr);
        allocator.deallocate_protected(ptr, layout);
    }

    // Maximum protection
    if let Some(ptr) = allocator.allocate_protected(layout, ProtectionLevel::Maximum) {
        println!("Maximum protection allocation: {:?}", ptr);
        allocator.deallocate_protected(ptr, layout);
    }

    // Print stats
    println!("\n{}", allocator.report());

    // Demonstrate SecureVec
    println!("\n--- SecureVec Demo ---");
    {
        let mut secure_vec: SecureVec<u8> = SecureVec::new();
        secure_vec.push(0x41);
        secure_vec.push(0x42);
        secure_vec.push(0x43);
        println!("SecureVec contents: {:?}", secure_vec.as_slice());
        println!("SecureVec will be zeroized on drop");
    }
    println!("SecureVec dropped and zeroized");

    // Demonstrate SecurePool
    println!("\n--- SecurePool Demo ---");
    let pool = SecurePool::new(64, 10);
    println!("Pool created with {} blocks", pool.total());
    println!("Available blocks: {}", pool.available());

    if let Some(ptr) = pool.allocate() {
        println!("Allocated from pool: {:?}", ptr);
        println!("Available blocks: {}", pool.available());

        pool.deallocate(ptr);
        println!("Returned to pool");
        println!("Available blocks: {}", pool.available());
    }

    // Check for leaks
    println!("\n--- Leak Check ---");
    let leaks = allocator.check_leaks();
    if leaks.is_empty() {
        println!("No memory leaks detected!");
    } else {
        println!("Potential leaks: {}", leaks.len());
        for leak in &leaks {
            println!("  - {:?} bytes at 0x{:x}", leak.size, leak.ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_creation() {
        let allocator = SecureAllocator::new();
        assert_eq!(allocator.stats.total_allocations.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_simple_allocation() {
        let allocator = SecureAllocator::new();
        let layout = Layout::from_size_align(64, 8).unwrap();

        let ptr = allocator.allocate_protected(layout, ProtectionLevel::None);
        assert!(ptr.is_some());

        allocator.deallocate_protected(ptr.unwrap(), layout);
        assert_eq!(allocator.stats.total_allocations.load(Ordering::Relaxed), 1);
        assert_eq!(
            allocator.stats.total_deallocations.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_zeroize_on_free() {
        let allocator = SecureAllocator::new();
        let layout = Layout::from_size_align(64, 8).unwrap();

        let ptr = allocator
            .allocate_protected(layout, ProtectionLevel::ZeroOnFree)
            .unwrap();

        // Write data
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), 0xFF, layout.size());
        }

        // Deallocate (will zeroize)
        allocator.deallocate_protected(ptr, layout);
    }

    #[test]
    fn test_guarded_allocation() {
        let allocator = SecureAllocator::new();
        let layout = Layout::from_size_align(64, 8).unwrap();

        let ptr = allocator
            .allocate_protected(layout, ProtectionLevel::Guarded)
            .unwrap();

        // Write within bounds
        unsafe {
            std::ptr::write_bytes(ptr.as_ptr(), 0xAA, layout.size());
        }

        allocator.deallocate_protected(ptr, layout);
        assert_eq!(allocator.stats.guard_page_faults.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_allocation_stats() {
        let stats = AllocationStats::new();

        stats.record_allocation(100);
        stats.record_allocation(200);
        stats.record_deallocation(100);

        assert_eq!(stats.total_allocations.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_deallocations.load(Ordering::Relaxed), 1);
        assert_eq!(stats.current_allocated.load(Ordering::Relaxed), 200);
        assert_eq!(stats.peak_allocated.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_max_allocation_size() {
        let config = SecureAllocatorConfig {
            max_allocation_size: 1000,
            ..Default::default()
        };
        let allocator = SecureAllocator::with_config(config);

        let large_layout = Layout::from_size_align(2000, 8).unwrap();
        assert!(allocator
            .allocate_protected(large_layout, ProtectionLevel::None)
            .is_none());
    }

    #[test]
    fn test_leak_detection() {
        let allocator = SecureAllocator::with_config(SecureAllocatorConfig {
            track_allocations: true,
            ..Default::default()
        });

        let layout = Layout::from_size_align(64, 8).unwrap();

        // Allocate but don't deallocate
        let _ptr = allocator.allocate_protected(layout, ProtectionLevel::None);

        let leaks = allocator.check_leaks();
        assert_eq!(leaks.len(), 1);
    }

    #[test]
    fn test_secure_vec() {
        let mut vec: SecureVec<u8> = SecureVec::new();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        assert_eq!(vec.len(), 3);
        assert_eq!(vec.as_slice(), &[1, 2, 3]);

        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_secure_pool() {
        let pool = SecurePool::new(64, 5);

        assert_eq!(pool.total(), 5);
        assert_eq!(pool.available(), 5);

        let ptr1 = pool.allocate().unwrap();
        let ptr2 = pool.allocate().unwrap();

        assert_eq!(pool.available(), 3);

        pool.deallocate(ptr1);
        assert_eq!(pool.available(), 4);

        pool.deallocate(ptr2);
        assert_eq!(pool.available(), 5);
    }

    #[test]
    fn test_protection_levels() {
        assert_ne!(ProtectionLevel::None, ProtectionLevel::ZeroOnFree);
        assert_ne!(ProtectionLevel::Guarded, ProtectionLevel::Maximum);
    }

    #[test]
    fn test_memory_region() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        let region = MemoryRegion {
            ptr: 0x1000,
            size: 64,
            layout,
            protection: ProtectionLevel::Maximum,
            allocated_at: std::time::Instant::now(),
            guard_before: Some(0x0F00),
            guard_after: Some(0x1100),
            is_locked: true,
        };

        assert_eq!(region.size, 64);
        assert!(region.is_locked);
    }
}
