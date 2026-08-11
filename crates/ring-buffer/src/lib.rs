// SPDX-License-Identifier: Apache-2.0
#![deny(unsafe_code)]
//! A copy-in/copy-out ring buffer.
//!
//! Rust 2024 migration of [`src/ring_buffer.h`](../../src/ring_buffer.h).
//! Same API surface (`tryPush` -> [`RingBuffer::try_push`], `tryPop` ->
//! [`RingBuffer::try_pop`], `availableRead`/`availableWrite`/`capacity`/
//! `reset`), same capacity rounding (the smallest power of two >= the
//! requested size), same success/failure semantics: a push or pop does
//! nothing (and returns `false`) unless the whole slice fits.
//!
//! Deliberate, documented differences from the C++:
//!
//! * The C++ header is SPSC-safe across threads (cache-line-padded atomics).
//!   The only caller in this repository (the `airplay-send` demo) feeds and
//!   drains the ring from the same `poll()` loop, so the Rust version is a
//!   plain `&mut` ring with no synchronization. Cross-thread use must be
//!   coordinated by the caller (e.g. behind a `Mutex`). Revisit if a
//!   multithreaded host appears.
//! * `T` must be `Copy` (the C++ required trivially copyable, which is the
//!   same concept expressed by the Rust type system).
//! * `requested_size == 0` yields a capacity-0 ring where every non-empty
//!   push/pop fails (the C++ `nextPow2(0)` produces the same result by
//!   wraparound; the Rust version states it explicitly).
//!
//! ```
//! use ring_buffer::RingBuffer;
//! let mut r = RingBuffer::<i16>::new(8);
//! assert_eq!(r.capacity(), 8);
//! assert!(r.try_push(&[1, 2, 3]));
//! assert!(!r.try_push(&[9; 6]));          // only 5 slots left
//! let mut out = [0i16; 3];
//! assert!(r.try_pop(&mut out));
//! assert_eq!(out, [1, 2, 3]);
//! ```

/// Smallest power of two >= `v`; `0` maps to `0` (C++ wraparound parity).
fn next_pow2(v: usize) -> usize {
    if v == 0 {
        return 0;
    }
    1usize << (usize::BITS - (v - 1).leading_zeros())
}

/// A power-of-two-capacity ring buffer of copyable items.
pub struct RingBuffer<T: Copy> {
    mask: usize,
    // INVARIANT: exactly the slots holding items in [read, write) circular
    // order are `Some`; all others are `None`. Slots are only ever read
    // after they were written (any attempt otherwise fails the `false`
    // guard below before touching a slot), which is what makes the
    // `expect`s inside [`RingBuffer::try_pop`] impossible to hit.
    buffer: Vec<Option<T>>,
    read: usize,
    write: usize,
}

impl<T: Copy> RingBuffer<T> {
    /// Allocate a ring with capacity = smallest power of two >=
    /// `requested_size` (0 -> capacity 0).
    pub fn new(requested_size: usize) -> Self {
        let capacity = next_pow2(requested_size);
        RingBuffer {
            mask: capacity.wrapping_sub(1),
            buffer: vec![None; capacity],
            read: 0,
            write: 0,
        }
    }

    /// Push `data` in whole, wrapping around the buffer, or return `false`
    /// (and push nothing) if it does not fit. Mirrors C++ `tryPush`.
    pub fn try_push(&mut self, data: &[T]) -> bool {
        if data.len() > self.capacity() - (self.write - self.read) {
            return false;
        }
        let pos = self.write & self.mask;
        let first = data.len().min(self.capacity() - pos);
        for (i, item) in data[..first].iter().enumerate() {
            self.buffer[pos + i] = Some(*item);
        }
        for (i, item) in data[first..].iter().enumerate() {
            self.buffer[i] = Some(*item);
        }
        self.write += data.len();
        true
    }

    /// Pop up to `data.len()` items into `data`, wrapping around the
    /// buffer, or return `false` (and pop nothing) if fewer are available.
    /// Mirrors C++ `tryPop`; note that an empty slice pops successfully
    /// even when the ring is empty (exactly like the C++).
    pub fn try_pop(&mut self, data: &mut [T]) -> bool {
        if data.len() > self.write - self.read {
            return false;
        }
        let pos = self.read & self.mask;
        let first = data.len().min(self.capacity() - pos);
        // INVARIANT guarantees these slots are `Some` — data.len() items
        // were verified to be available above, and availability means the
        // slots are within the written window.
        for (i, slot) in data[..first].iter_mut().enumerate() {
            *slot = self.buffer[pos + i]
                .take()
                .expect("ring invariant: written slot");
        }
        for (i, slot) in data[first..].iter_mut().enumerate() {
            *slot = self.buffer[i].take().expect("ring invariant: written slot");
        }
        self.read += data.len();
        true
    }

    /// Items currently stored (C++ `availableRead`).
    pub fn available_read(&self) -> usize {
        self.write - self.read
    }

    /// Free slots (C++ `availableWrite`).
    pub fn available_write(&self) -> usize {
        self.capacity() - self.available_read()
    }

    /// Buffer capacity (C++ `capacity()`).
    pub fn capacity(&self) -> usize {
        self.mask.wrapping_add(1)
    }

    /// Drop everything (C++ `reset`).
    pub fn reset(&mut self) {
        self.read = 0;
        self.write = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_rounds_up_to_pow2() {
        for (requested, expected) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 4),
            (5, 8),
            (8, 8),
            (9, 16),
        ] {
            assert_eq!(RingBuffer::<i16>::new(requested).capacity(), expected);
        }
    }

    #[test]
    fn zero_capacity_ring_rejects_everything_nonempty() {
        let mut r = RingBuffer::<i16>::new(0);
        assert_eq!(r.capacity(), 0);
        assert!(!r.try_push(&[1]));
        assert!(!r.try_pop(&mut [0i16; 1]));
        // Empty operations succeed (C++ parity).
        assert!(r.try_push(&[]));
        assert!(r.try_pop(&mut []));
    }

    #[test]
    fn push_pop_roundtrip_without_wraparound() {
        let mut r = RingBuffer::<i16>::new(8);
        assert!(r.try_push(&[1, 2, 3, 4]));
        assert_eq!(r.available_read(), 4);
        assert_eq!(r.available_write(), 4);
        assert!(!r.try_push(&[5, 6, 7, 8, 9])); // 5 > 4
        let mut out = [0i16; 2];
        assert!(r.try_pop(&mut out));
        assert_eq!(out, [1, 2]);
        assert!(r.try_push(&[5, 6]));
        assert_eq!(r.available_read(), 4);
    }

    #[test]
    fn wraps_around_the_buffer() {
        let mut r = RingBuffer::<i16>::new(8);
        // Fill completely.
        assert!(r.try_push(&[1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(!r.try_push(&[9]));
        // Drain 6, then push 6 -> write wraps past the end.
        let mut out = [0i16; 6];
        assert!(r.try_pop(&mut out));
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);
        assert!(r.try_push(&[9, 10, 11, 12, 13, 14]));
        // Full wrap-around read.
        let mut out2 = [0i16; 8];
        assert!(r.try_pop(&mut out2));
        assert_eq!(out2, [7, 8, 9, 10, 11, 12, 13, 14]);
    }

    #[test]
    fn pop_fails_when_insufficient_data() {
        let mut r = RingBuffer::<i16>::new(8);
        r.try_push(&[1, 2, 3]);
        let mut out = [0i16; 4];
        assert!(!r.try_pop(&mut out));
        assert_eq!(out, [0, 0, 0, 0]); // untouched
        assert_eq!(r.available_read(), 3);
    }

    #[test]
    fn push_pop_partial_chunks_keep_order() {
        let mut r = RingBuffer::<i16>::new(8);
        r.try_push(&[10, 11, 12, 13, 14]);
        let mut out = [0i16; 2];
        r.try_pop(&mut out);
        r.try_pop(&mut out);
        assert_eq!(out, [12, 13]);
        r.try_push(&[20, 21, 22]);
        assert_eq!(r.available_read(), 4); // [14, 20, 21, 22]
        assert_eq!(r.available_write(), 4);
    }

    #[test]
    fn reset_clears_contents() {
        let mut r = RingBuffer::<i16>::new(8);
        r.try_push(&[7, 8]);
        r.reset();
        assert_eq!(r.available_read(), 0);
        assert_eq!(r.available_write(), 8);
        assert!(!r.try_pop(&mut [0i16; 1]));
        r.try_push(&[9]);
        let mut out = [0i16; 1];
        assert!(r.try_pop(&mut out));
        assert_eq!(out, [9]);
    }

    #[test]
    fn empty_slice_ops_succeed_like_cpp() {
        let mut r = RingBuffer::<i16>::new(8);
        assert!(r.try_push(&[]));
        assert!(r.try_pop(&mut []));
        assert_eq!(r.available_read(), 0);
    }

    #[test]
    fn model_check_against_vecdeque() {
        // Randomized differential test against std::collections::VecDeque,
        // the reference FIFO model: every push/pop sequence must agree.
        use std::collections::VecDeque;
        let mut r = RingBuffer::<i16>::new(16);
        let mut model: VecDeque<i16> = VecDeque::new();
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..50_000 {
            match next() % 4 {
                0 => {
                    // Push a random chunk (reject if it would overflow).
                    let n = (next() % 8) as usize;
                    if model.len() + n > r.capacity() {
                        assert!(!r.try_push(&[7; 8][..n]));
                    } else {
                        let data: Vec<i16> = (0..n).map(|_| (next() % 1000) as i16).collect();
                        assert!(r.try_push(&data));
                        for v in data {
                            model.push_back(v);
                        }
                    }
                }
                1 => {
                    let n = (next() % 8) as usize;
                    let mut out = [0i16; 8];
                    let r_ok = r.try_pop(&mut out[..n]);
                    let m_ok = model.len() >= n;
                    assert_eq!(r_ok, m_ok);
                    if m_ok {
                        for &v in &out[..n] {
                            assert_eq!(model.pop_front(), Some(v));
                        }
                    }
                }
                2 => assert_eq!(r.available_read(), model.len()),
                3 => {
                    r.reset();
                    model.clear();
                    assert_eq!(r.available_read(), 0);
                }
                _ => unreachable!(),
            }
        }
        // Drain fully at the end (exercises the wrap-around paths).
        while !model.is_empty() {
            let n = 3.min(model.len());
            let mut out = [0i16; 3];
            assert!(r.try_pop(&mut out[..n]));
            for &v in &out[..n] {
                assert_eq!(model.pop_front(), Some(v));
            }
        }
        assert_eq!(r.available_read(), 0);
    }
}
