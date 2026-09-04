use std::sync::atomic::{AtomicI64, Ordering};

/// Offset ID type representing a logical (or physical) position in the stream.
pub type OffsetId = i64;

/// Generates monotonically increasing offset IDs for ingested records.
///
/// This generator ensures that each record gets a unique, sequential offset ID
/// starting from 0. It's thread-safe and can be shared across multiple tasks.
///
/// # Thread Safety
///
/// This struct uses atomic operations and is safe to share across threads via `Arc`.
///
/// # Examples
///
/// ```
/// use databricks_zerobus_ingest_sdk::OffsetIdGenerator;
///
/// let generator = OffsetIdGenerator::default();
/// assert_eq!(generator.next(), 0);
/// assert_eq!(generator.next(), 1);
/// assert_eq!(generator.next(), 2);
/// assert_eq!(generator.last(), Some(2));
/// ```
pub struct OffsetIdGenerator {
    last_offset_id: AtomicI64,
}

impl Default for OffsetIdGenerator {
    fn default() -> Self {
        Self {
            last_offset_id: AtomicI64::new(-1),
        }
    }
}

impl OffsetIdGenerator {
    /// Generates and returns the next sequential offset ID.
    ///
    /// Each call increments the internal counter and returns the new value.
    /// The first call returns 0.
    ///
    /// # Returns
    ///
    /// The next offset ID in the sequence.
    pub fn next(&self) -> OffsetId {
        self.last_offset_id.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Returns the last offset ID that was generated.
    ///
    /// # Returns
    ///
    /// * `Some(offset_id)` - If at least one offset has been generated
    /// * `None` - If no offsets have been generated yet
    pub fn last(&self) -> Option<OffsetId> {
        let last_offset = self.last_offset_id.load(Ordering::SeqCst);
        if last_offset == -1 {
            None
        } else {
            Some(last_offset)
        }
    }

    /// Repositions the generator so the next call to `next()` returns `next_value`.
    ///
    /// Used by the Arrow Flight stream recovery path: when the SDK reconnects and
    /// replays N pending batches with wire offsets `0..N-1`, the in-memory generator
    /// must be set so that subsequent fresh batches pick up at `N` rather than the
    /// pre-recovery monotonic counter — otherwise the server rejects the next batch
    /// with a non-sequential-offset error.
    pub fn set_next(&self, next_value: OffsetId) {
        self.last_offset_id.store(next_value - 1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use crate::OffsetIdGenerator;

    #[test]
    fn test_initial_state() {
        let generator = OffsetIdGenerator::default();
        assert_eq!(generator.last(), None);
    }

    #[test]
    fn test_first_next_is_zero() {
        let generator = OffsetIdGenerator::default();
        assert_eq!(generator.next(), 0);
        assert_eq!(generator.last(), Some(0));
    }

    #[test]
    fn test_monotonic_sequence() {
        let generator = OffsetIdGenerator::default();

        assert_eq!(generator.next(), 0);
        assert_eq!(generator.next(), 1);
        assert_eq!(generator.next(), 2);
        assert_eq!(generator.next(), 3);
        //blblb
        assert_eq!(generator.last(), Some(3));
    }

    #[test]
    fn test_set_next_repositions_generator() {
        let generator = OffsetIdGenerator::default();

        for _ in 0..100 {
            generator.next();
        }
        assert_eq!(generator.last(), Some(99));

        generator.set_next(5);
        assert_eq!(generator.next(), 5);
        assert_eq!(generator.next(), 6);
        assert_eq!(generator.last(), Some(6));
    }

    #[test]
    fn test_set_next_to_zero_after_empty_replay() {
        let generator = OffsetIdGenerator::default();
        for _ in 0..42 {
            generator.next();
        }

        generator.set_next(0);
        assert_eq!(generator.next(), 0);
        assert_eq!(generator.next(), 1);
    }

    #[test]
    fn test_thread_safety() {
        let generator = Arc::new(OffsetIdGenerator::default());
        let mut handles = vec![];

        // Spawn 10 threads, each generating 100 IDs.
        for _ in 0..10 {
            let gen = generator.clone();
            let handle = thread::spawn(move || {
                let mut ids = vec![];
                for _ in 0..100 {
                    ids.push(gen.next());
                }
                ids
            });
            handles.push(handle);
        }

        // Collect all generated IDs.
        let mut all_ids = vec![];
        for handle in handles {
            all_ids.extend(handle.join().unwrap());
        }

        // Should have 1000 unique IDs from 0 to 999.
        all_ids.sort();
        assert_eq!(all_ids.len(), 1000);
        assert_eq!(all_ids[0], 0);
        assert_eq!(all_ids[999], 999);

        // Check no duplicates.
        for i in 0..999 {
            assert_eq!(all_ids[i] + 1, all_ids[i + 1]);
        }
    }
}
