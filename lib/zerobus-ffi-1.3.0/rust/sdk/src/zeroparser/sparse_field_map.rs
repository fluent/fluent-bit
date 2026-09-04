//! A sparse array-backed map optimized for protobuf field numbers.
//!
//! Uses a dynamically-sized inline array for fast lookup of field numbers,
//! with a HashMap fallback for larger field numbers.

use std::collections::HashMap;

/// Maximum capacity for inline field number storage.
/// Field numbers >= this threshold always fall back to HashMap lookup.
pub const MAX_INLINE_CAPACITY: usize = 128;

/// Provides O(1) lookup for common field numbers using a sparse array,
/// with HashMap fallback for larger field numbers.
#[derive(Debug)]
pub struct SparseFieldMap<V> {
    /// Sparse array indexed by field number. Size is min(max_field_num + 1, MAX_INLINE_CAPACITY).
    inline: Box<[Option<V>]>,
    /// For field numbers >= inline.len().
    overflow: HashMap<i32, V>,
}

impl<V> SparseFieldMap<V> {
    /// Creates a new `SparseFieldMap` with inline capacity based on max field number.
    /// Uses `min(max_field_num + 1, MAX_INLINE_CAPACITY)` slots in the inline array.
    #[inline(always)]
    pub fn new(max_field_num: i32) -> Self {
        let inline_size = ((max_field_num + 1) as usize).min(MAX_INLINE_CAPACITY);
        Self {
            inline: (0..inline_size)
                .map(|_| None)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            overflow: HashMap::new(),
        }
    }

    /// Inserts a value at the given field number.
    ///
    /// If the field number already had a value, it is returned.
    #[inline(always)]
    pub fn insert(&mut self, field_num: i32, value: V) -> Option<V> {
        let idx = field_num as usize;
        if idx < self.inline.len() {
            self.inline[idx].replace(value)
        } else {
            self.overflow.insert(field_num, value)
        }
    }

    /// Returns a reference to the value at the given field number.
    #[inline(always)]
    pub fn get(&self, field_num: i32) -> Option<&V> {
        let idx = field_num as usize;
        if idx < self.inline.len() {
            self.inline[idx].as_ref()
        } else {
            self.overflow.get(&field_num)
        }
    }
}
