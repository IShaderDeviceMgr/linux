// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Events for the userspace client, and the xART requests it has taken but
//! not yet answered.
//!
//! A request the client took but never answered (it crashed or was
//! restarted) goes back to the front of the queue when the device is closed:
//! the SEP is still waiting for that answer and will not ask again.

use crate::xarm;
use kernel::prelude::*;

/// Queue bound. xART requests are serialised by the SEP in practice, so this
/// only fills up if nobody is reading; endpoint events are dropped first.
const MAX_QUEUED: usize = 64;

/// Pushes `ev`, handing it back if memory runs out (`KVec::push` would drop
/// it).
fn push_keep(v: &mut KVec<Event>, ev: Event) -> core::result::Result<(), Event> {
    if v.reserve(1, GFP_KERNEL).is_err() {
        return Err(ev);
    }
    v.push_within_capacity(ev).map_err(|e| e.0)
}

pub(crate) enum Event {
    /// `flags`: `APPLE_SEP_XART_F_*`.
    Xart {
        req: xarm::Req,
        payload: KVec<u8>,
        flags: u8,
    },
    Endpoint {
        ep: u8,
        name: [u8; 4],
    },
}

pub(crate) struct Events {
    queue: KVec<Event>,
    inflight: KVec<Event>,
    dropped: u32,
}

impl Events {
    pub(crate) fn new() -> Self {
        Events {
            queue: KVec::new(),
            inflight: KVec::new(),
            dropped: 0,
        }
    }

    /// Queues an event. An xART request is refused (returned to the caller,
    /// which then fails it to the SEP) rather than dropped silently.
    pub(crate) fn push(&mut self, ev: Event) -> core::result::Result<(), Event> {
        if self.queue.len() >= MAX_QUEUED {
            if let Some(i) = self
                .queue
                .iter()
                .position(|e| matches!(e, Event::Endpoint { .. }))
            {
                let _ = self.queue.remove(i);
                self.dropped = self.dropped.saturating_add(1);
            } else {
                return Err(ev);
            }
        }
        push_keep(&mut self.queue, ev)
    }

    /// Takes the oldest event. The caller records a delivered xART request
    /// with [`Events::track`].
    pub(crate) fn pop(&mut self) -> Option<Event> {
        if self.queue.is_empty() {
            return None;
        }
        self.queue.remove(0).ok()
    }

    /// Puts an event back at the front (delivery to the client failed).
    pub(crate) fn push_front(&mut self, ev: Event) {
        if self.queue.reserve(1, GFP_KERNEL).is_ok() {
            let _ = self.queue.insert_within_capacity(0, ev);
        }
    }

    /// Records a delivered xART request as awaiting its reply. On failure the
    /// event is handed back.
    pub(crate) fn track(&mut self, ev: Event) -> core::result::Result<(), Event> {
        push_keep(&mut self.inflight, ev)
    }

    pub(crate) fn is_inflight(&self, tag: u8) -> bool {
        self.inflight
            .iter()
            .any(|e| matches!(e, Event::Xart { req, .. } if req.tag == tag))
    }

    /// Removes the in-flight request with `tag`; false if there is none.
    pub(crate) fn complete(&mut self, tag: u8) -> bool {
        let pos = self
            .inflight
            .iter()
            .position(|e| matches!(e, Event::Xart { req, .. } if req.tag == tag));
        match pos {
            Some(i) => self.inflight.remove(i).is_ok(),
            None => false,
        }
    }

    /// Puts every unanswered request back at the front, oldest first.
    pub(crate) fn requeue_inflight(&mut self) -> usize {
        let n = self.inflight.len();
        if n == 0 {
            return 0;
        }
        if self.queue.reserve(n, GFP_KERNEL).is_err() {
            return 0;
        }
        let mut i = 0;
        while let Some(ev) = self.inflight.pop() {
            // Popping reverses the order; inserting each at the front
            // restores it.
            let _ = self.queue.insert_within_capacity(0, ev);
            i += 1;
        }
        i
    }

    pub(crate) fn take_dropped(&mut self) -> u32 {
        core::mem::take(&mut self.dropped)
    }
}
