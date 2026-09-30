//! v52.0.0 (CIRISPersist#958) — **I294: the signing form does not clone the
//! envelope.** A counting global allocator (this test binary only) measures
//! the bytes `canonicalize_envelope_for_signing` allocates for a 1 MiB
//! envelope built like Edge's chunk rows (a 262,144-entry integer array),
//! against the pre-#958 clone-then-remove. The clone of a tree of 262k
//! numbers is the cost #958 removes; the JCS writer's own per-member work is
//! paid by both paths, so the witness asserts the SAVING is the clone.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn measured<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.load(Ordering::Relaxed);
    let out = f();
    (out, ALLOCATED.load(Ordering::Relaxed) - before)
}

#[test]
fn i294_the_signing_form_does_not_clone_the_envelope() {
    let chunk: Vec<serde_json::Value> = (0..262_144u32)
        .map(|i| serde_json::json!(i % 256))
        .collect();
    let envelope = serde_json::json!({
        "kind": "chunk",
        "seq": 7,
        "bytes": chunk,
        "signature": "c2lnbmF0dXJl",
        "signature_pqc": "cHFj",
    });
    let (new, new_bytes) =
        measured(|| ciris_persist::prelude::canonicalize_envelope_for_signing(&envelope).unwrap());
    let (old, old_bytes) = measured(|| {
        let mut v = envelope.clone();
        let o = v.as_object_mut().unwrap();
        o.remove("signature");
        o.remove("signature_pqc");
        ciris_persist::prelude::ceg_produce_canonicalize(&v).unwrap()
    });
    assert_eq!(new, old, "I294: the same bytes");
    let (_copy, clone_bytes) = measured(|| envelope.clone());
    eprintln!(
        "MEASURED #958 signing form over a 262,144-entry array: {new_bytes} bytes allocated \
         (clone-then-remove: {old_bytes}; the clone alone: {clone_bytes}); output {} bytes",
        new.len()
    );
    // The JCS writer's own per-member work is paid either way; what #958
    // removes is the clone. At least 90% of the clone's bytes must be gone.
    assert!(
        new_bytes + clone_bytes * 9 / 10 <= old_bytes,
        "I294: the signing form allocated {new_bytes} bytes against clone-then-remove's \
         {old_bytes}, a saving smaller than the clone ({clone_bytes}) — it is still copying the \
         envelope (#958)"
    );
}
