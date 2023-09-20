use reth_primitives::EIP4844_TX_TYPE_ID;

/// Guarantees max transactions for one sender, compatible with geth/erigon
pub const TXPOOL_MAX_ACCOUNT_SLOTS_PER_SENDER: usize = 16;

/// The default maximum allowed number of transactions in the given subpool.
pub const TXPOOL_SUBPOOL_MAX_TXS_DEFAULT: usize = 10_000;

/// The default maximum allowed size of the given subpool.
pub const TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT: usize = 20;

/// Default price bump (in %) for the transaction pool underpriced check.
pub const DEFAULT_PRICE_BUMP: u128 = 10;

/// Replace blob price bump (in %) for the transaction pool underpriced check.
///
/// This enforces that a blob transaction requires a 100% price bump to be replaced
pub const REPLACE_BLOB_PRICE_BUMP: u128 = 100;

/// Configuration options for the Transaction pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Max number of transaction in the pending sub-pool
    pub pending_limit: SubPoolLimit,
    /// Max number of transaction in the basefee sub-pool
    pub basefee_limit: SubPoolLimit,
    /// Max number of transaction in the queued sub-pool
    pub queued_limit: SubPoolLimit,
    /// Max number of executable transaction slots guaranteed per account
    pub max_account_slots: usize,
    /// Price bump (in %) for the transaction pool underpriced check.
    pub price_bumps: PriceBumpConfig,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pending_limit: Default::default(),
            basefee_limit: Default::default(),
            queued_limit: Default::default(),
            max_account_slots: TXPOOL_MAX_ACCOUNT_SLOTS_PER_SENDER,
            price_bumps: Default::default(),
        }
    }
}

/// Size limits for a sub-pool.
#[derive(Debug, Clone)]
pub struct SubPoolLimit {
    /// Maximum amount of transaction in the pool.
    pub max_txs: usize,
    /// Maximum combined size (in bytes) of transactions in the pool.
    pub max_size: usize,
}

impl SubPoolLimit {
    /// Returns whether the size or amount constraint is violated.
    #[inline]
    pub fn is_exceeded(&self, txs: usize, size: usize) -> bool {
        self.max_txs < txs || self.max_size < size
    }
}

impl Default for SubPoolLimit {
    fn default() -> Self {
        // either 10k transactions or 20MB
        Self {
            max_txs: TXPOOL_SUBPOOL_MAX_TXS_DEFAULT,
            max_size: TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT * 1024 * 1024,
        }
    }
}

/// Price bump config (in %) for the transaction pool underpriced check.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PriceBumpConfig {
    /// Default price bump (in %) for the transaction pool underpriced check.
    pub default_price_bump: u128,
    /// Replace blob price bump (in %) for the transaction pool underpriced check.
    pub replace_blob_tx_price_bump: u128,
}

impl PriceBumpConfig {
    /// Returns the price bump required to replace the given transaction type.
    #[inline]
    pub(crate) fn price_bump(&self, tx_type: u8) -> u128 {
        if tx_type == EIP4844_TX_TYPE_ID {
            return self.replace_blob_tx_price_bump
        }
        self.default_price_bump
    }
}

impl Default for PriceBumpConfig {
    fn default() -> Self {
        Self {
            default_price_bump: DEFAULT_PRICE_BUMP,
            replace_blob_tx_price_bump: REPLACE_BLOB_PRICE_BUMP,
        }
    }
}
