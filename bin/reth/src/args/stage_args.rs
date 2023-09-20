//! Shared arguments related to stages

/// Represents a certain stage of the pipeline.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, clap::ValueEnum)]
#[allow(missing_docs)]
pub enum StageEnum {
    Headers,
    Bodies,
    Senders,
    Execution,
    AccountHashing,
    StorageHashing,
    Hashing,
    Merkle,
    TxLookup,
    AccountHistory,
    StorageHistory,
    TotalDifficulty,
}
