// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Single-producer, single-consumer receive ring.
//!
//! The mailbox calls the driver in hard-IRQ context with its receive spinlock
//! held, so the producer can neither sleep nor allocate. The consumer is a
//! single work item, which the workqueue never runs concurrently with itself.

use core::cell::UnsafeCell;
use kernel::soc::apple::mailbox::Message;
use kernel::sync::atomic::{Acquire, Atomic, Relaxed, Release};

const LEN: u32 = 64;
const MASK: u32 = LEN - 1;
kernel::static_assert!(LEN.is_power_of_two());

pub(crate) struct RxRing {
    slots: [UnsafeCell<Message>; LEN as usize],
    head: Atomic<u32>,
    tail: Atomic<u32>,
    dropped: Atomic<u32>,
}

// SAFETY: a slot is owned by exactly one side at a time, handed over by the
// release/acquire pairs on `head` and `tail`. There is one producer (the
// mailbox IRQ handler, serialised by the mailbox's receive lock) and one
// consumer (the receive work item).
unsafe impl Sync for RxRing {}
// SAFETY: `Message` is plain data.
unsafe impl Send for RxRing {}

impl RxRing {
    pub(crate) fn new() -> Self {
        RxRing {
            slots: core::array::from_fn(|_| UnsafeCell::new(Message { msg0: 0, msg1: 0 })),
            head: Atomic::new(0),
            tail: Atomic::new(0),
            dropped: Atomic::new(0),
        }
    }

    /// Producer side. Returns false, and counts the drop, if the ring is full.
    pub(crate) fn push(&self, msg: Message) -> bool {
        let head = self.head.load(Relaxed);
        let tail = self.tail.load(Acquire);
        if head.wrapping_sub(tail) >= LEN {
            self.dropped.fetch_add(1, Relaxed);
            return false;
        }
        // SAFETY: slot `head` is not yet published, so the consumer cannot be
        // reading it, and there is only one producer.
        unsafe { self.slots[(head & MASK) as usize].get().write(msg) };
        self.head.store(head.wrapping_add(1), Release);
        true
    }

    /// Consumer side.
    pub(crate) fn pop(&self) -> Option<Message> {
        let tail = self.tail.load(Relaxed);
        let head = self.head.load(Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: `head` is past `tail`, so the producer has finished writing
        // this slot and will not reuse it until `tail` is published.
        let msg = unsafe { self.slots[(tail & MASK) as usize].get().read() };
        self.tail.store(tail.wrapping_add(1), Release);
        Some(msg)
    }

    /// Takes the number of messages dropped since the last call.
    pub(crate) fn take_dropped(&self) -> u32 {
        self.dropped.xchg(0, Relaxed)
    }
}
