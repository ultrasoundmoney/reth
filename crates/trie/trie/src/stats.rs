use reth_primitives_traits::FastInstant as Instant;
use std::{cell::Cell, time::Duration};

/// Trie stats.
#[derive(Clone, Copy, Debug)]
pub struct TrieStats {
    duration: Duration,
    branches_added: u64,
    leaves_added: u64,
}

impl TrieStats {
    /// Duration for root calculation.
    pub const fn duration(&self) -> Duration {
        self.duration
    }

    /// Number of leaves added to the hash builder during the calculation.
    pub const fn leaves_added(&self) -> u64 {
        self.leaves_added
    }

    /// Number of branches added to the hash builder during the calculation.
    pub const fn branches_added(&self) -> u64 {
        self.branches_added
    }
}

/// Trie metrics tracker.
#[derive(Debug)]
pub struct TrieTracker {
    started_at: Instant,
    branches_added: u64,
    leaves_added: u64,
}

impl Default for TrieTracker {
    fn default() -> Self {
        Self { started_at: Instant::now(), branches_added: 0, leaves_added: 0 }
    }
}

impl TrieTracker {
    /// Increment the number of branches added to the hash builder during the calculation.
    pub const fn inc_branch(&mut self) {
        self.branches_added += 1;
    }

    /// Increment the number of leaves added to the hash builder during the calculation.
    pub const fn inc_leaf(&mut self) {
        self.leaves_added += 1;
    }

    /// Called when root calculation is finished to return trie statistics.
    pub fn finish(self) -> TrieStats {
        TrieStats {
            duration: self.started_at.elapsed(),
            branches_added: self.branches_added,
            leaves_added: self.leaves_added,
        }
    }
}

thread_local! {
    static STATE_ROOT_COUNTERS: Cell<Option<StateRootCounters>> = const { Cell::new(None) };
}

/// Where the work of serial [`StateRoot`](crate::StateRoot) calculations went, collected only
/// inside [`collect_state_root_counters`].
///
/// Counters accumulate over every calculation on the collecting thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateRootCounters {
    /// Keys in the account prefix sets handed to the walker.
    pub account_prefix_set_len: u64,
    /// Storage tries in the storage prefix sets handed to the walker.
    pub storage_prefix_sets: u64,
    /// Account leaves the walker emitted, each of which gets its storage root computed.
    pub account_leaves: u64,
    /// Account leaves outside the account prefix set: unchanged siblings of changed accounts.
    pub untouched_account_leaves: u64,
    /// Storage roots computed for account leaves without a storage prefix set.
    pub storage_roots_without_changes: u64,
    /// Storage roots computed for account leaves with a storage prefix set.
    pub storage_roots_with_changes: u64,
    /// Time spent in storage roots of account leaves without a storage prefix set.
    pub storage_roots_without_changes_duration: Duration,
    /// Time spent in storage roots of account leaves with a storage prefix set.
    pub storage_roots_with_changes_duration: Duration,
    /// Stored account trie branch hashes reused by the hash builder.
    pub account_branches: u64,
    /// Stored storage trie branch hashes reused by the hash builder.
    pub storage_branches: u64,
    /// Storage slots fed to the hash builder.
    pub storage_slots: u64,
    /// Time spent in the state root calculations.
    pub duration: Duration,
    /// Whether an overlay had to revert the database to an older anchor.
    pub reverts_required: bool,
}

impl StateRootCounters {
    pub(crate) fn add(&mut self, other: &Self) {
        self.account_prefix_set_len += other.account_prefix_set_len;
        self.storage_prefix_sets += other.storage_prefix_sets;
        self.account_leaves += other.account_leaves;
        self.untouched_account_leaves += other.untouched_account_leaves;
        self.storage_roots_without_changes += other.storage_roots_without_changes;
        self.storage_roots_with_changes += other.storage_roots_with_changes;
        self.storage_roots_without_changes_duration += other.storage_roots_without_changes_duration;
        self.storage_roots_with_changes_duration += other.storage_roots_with_changes_duration;
        self.account_branches += other.account_branches;
        self.storage_branches += other.storage_branches;
        self.storage_slots += other.storage_slots;
        self.duration += other.duration;
        self.reverts_required |= other.reverts_required;
    }
}

/// Runs `f` and returns the [`StateRootCounters`] of the state root work it did on this thread.
pub fn collect_state_root_counters<R>(f: impl FnOnce() -> R) -> (R, StateRootCounters) {
    struct Restore(Option<StateRootCounters>);

    impl Drop for Restore {
        fn drop(&mut self) {
            STATE_ROOT_COUNTERS.set(self.0.take());
        }
    }

    let restore = Restore(STATE_ROOT_COUNTERS.replace(Some(StateRootCounters::default())));
    let result = f();
    let counters = STATE_ROOT_COUNTERS.get().unwrap_or_default();
    drop(restore);

    (result, counters)
}

/// Returns `true` inside [`collect_state_root_counters`].
pub fn is_collecting_state_root_counters() -> bool {
    STATE_ROOT_COUNTERS.get().is_some()
}

/// Updates the counters of the enclosing [`collect_state_root_counters`], if any.
pub fn record_state_root_counters(f: impl FnOnce(&mut StateRootCounters)) {
    if let Some(mut counters) = STATE_ROOT_COUNTERS.get() {
        f(&mut counters);
        STATE_ROOT_COUNTERS.set(Some(counters));
    }
}
