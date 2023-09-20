/// Result alias for `Error`
pub type Result<T> = std::result::Result<T, Error>;

/// Core error variants possible when interacting with the blockchain
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    Execution(#[from] crate::executor::BlockExecutionError),

    #[error(transparent)]
    Consensus(#[from] crate::consensus::ConsensusError),

    #[error(transparent)]
    Database(#[from] crate::db::DatabaseError),

    #[error(transparent)]
    Provider(#[from] crate::provider::ProviderError),

    #[error(transparent)]
    Network(#[from] reth_network_api::NetworkError),

    #[error(transparent)]
    Canonical(#[from] crate::blockchain_tree::error::CanonicalError),

    #[error("{0}")]
    Custom(std::string::String),
}
