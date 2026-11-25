//! Probes that `base` wipes the storage it owns: a dropped secret's slot reads zero, and a freed buffer is
//! inspected by the global allocator before it returns to the system. Copies and moves are not tracked.
#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::mem::{MaybeUninit, size_of};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use base::{Secret, SecretBytes, b64url_decode, b64url_encode};

    // the size of block inspected as it is freed, the blocks seen, and their non-zero bytes
    static WATCH: AtomicUsize = AtomicUsize::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    static DIRTY: AtomicUsize = AtomicUsize::new(0);

    struct Inspect;

    unsafe impl GlobalAlloc for Inspect {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if layout.size() == WATCH.load(SeqCst) {
                let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                DIRTY.fetch_add(block.iter().filter(|&&b| b != 0).count(), SeqCst);
                SEEN.fetch_add(1, SeqCst);
            }
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }

    #[global_allocator]
    static INSPECT: Inspect = Inspect;

    // (blocks of `size` freed, their non-zero bytes) while `f` runs; one test, so no other test allocates meanwhile
    fn freed(size: usize, f: impl FnOnce()) -> (usize, usize) {
        SEEN.store(0, SeqCst);
        DIRTY.store(0, SeqCst);
        WATCH.store(size, SeqCst);
        f();
        WATCH.store(0, SeqCst);
        (SEEN.load(SeqCst), DIRTY.load(SeqCst))
    }

    #[test]
    fn owned_storage_is_wiped() {
        let mut slot = MaybeUninit::<Secret<32>>::uninit();
        assert_eq!(size_of::<Secret<32>>(), 32);
        slot.write(Secret::new([0xaa; 32]));
        unsafe { slot.assume_init_drop() };
        let left = unsafe { std::ptr::read_volatile(slot.as_ptr().cast::<[u8; 32]>()) };
        assert_eq!(left, [0; 32], "a dropped Secret's slot is zero");

        let secret = SecretBytes::new(vec![0xaa; 8192]);
        assert_eq!(freed(8192, || drop(secret)), (1, 0), "a dropped SecretBytes buffer is zero when freed");

        // a text whose every symbol but the last decodes, so the buffer holds 5,997 bytes when the last is refused
        let mut text = b64url_encode(&[0xaa; 6000]);
        text.pop();
        text.push('+');
        let mut outcome = None;
        let seen = freed(text.len(), || outcome = Some(b64url_decode(&text).is_err()));
        assert_eq!(outcome, Some(true), "the text is refused");
        assert_eq!(seen, (1, 0), "a refused text's decode buffer is zero when freed");
    }
}
