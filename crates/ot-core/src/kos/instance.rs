//! Domain separation for KOS instances that share one global `delta`.

use std::fmt;

/// A domain separator for one KOS extension instance.
///
/// KOS15 is analysed as a *single* extension per global correlation `delta`.
/// Running several instances under one `delta` steps outside that analysis: if
/// two instances ever derive the same extension columns, the sender's keys
/// become related by `delta` at every column where the receiver's choice bits
/// differ, and the instances are no longer independent.
///
/// Every instance sharing a `delta` must therefore carry a distinct
/// `InstanceId`, and the two parties of one instance must carry the *same* id.
/// Ids are matched by value, not by construction order.
///
/// [`InstanceId::SOLO`] is the id for a `delta` used by exactly one instance.
/// It reproduces stock KOS byte for byte, so a solo instance stays wire
/// compatible with an implementation that predates this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(u64);

impl InstanceId {
    /// The id for a `delta` driven by exactly one instance.
    ///
    /// Deliberately not [`Default`]: sharing a `delta` between instances that
    /// both defaulted is precisely the mistake this type exists to prevent.
    pub const SOLO: Self = Self(0);

    /// Creates an id.
    ///
    /// # Arguments
    ///
    /// * `id` - Distinct across every instance sharing one `delta`, and equal
    ///   between the sender and receiver of the same instance.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying value.
    pub const fn to_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Hands out distinct [`InstanceId`]s for one global `delta`.
///
/// Both parties allocate from their own `InstanceIds` and must request ids in
/// the same order, so that instance *n* on one side faces instance *n* on the
/// other. Where a fixed wiring is clearer, name the ids with
/// [`InstanceId::new`] instead.
#[derive(Debug, Clone, Default)]
pub struct InstanceIds {
    next: u64,
}

impl InstanceIds {
    /// Creates an allocator, starting at [`InstanceId::SOLO`].
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Returns an id that no earlier call returned.
    ///
    /// # Panics
    ///
    /// If more than `u64::MAX` ids are requested, rather than wrapping onto an
    /// id already in use.
    pub fn allocate(&mut self) -> InstanceId {
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .expect("KOS instance ids exhausted for this delta");
        InstanceId(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_never_repeats() {
        let mut ids = InstanceIds::new();
        let issued: Vec<_> = (0..8).map(|_| ids.allocate()).collect();
        assert_eq!(issued[0], InstanceId::SOLO);
        for (i, id) in issued.iter().enumerate() {
            assert!(!issued[..i].contains(id), "id {id} was issued twice");
        }
    }
}
