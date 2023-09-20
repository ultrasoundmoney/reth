//! Transaction pool arguments

use clap::Args;
use reth_transaction_pool::{
    PoolConfig, PriceBumpConfig, SubPoolLimit, DEFAULT_PRICE_BUMP, REPLACE_BLOB_PRICE_BUMP,
    TXPOOL_MAX_ACCOUNT_SLOTS_PER_SENDER, TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT,
    TXPOOL_SUBPOOL_MAX_TXS_DEFAULT,
};

/// Parameters for debugging purposes
#[derive(Debug, Args, PartialEq, Default)]
pub struct TxPoolArgs {
    /// Max number of transaction in the pending sub-pool.
    #[arg(long = "txpool.pending_max_count", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_TXS_DEFAULT)]
    pub pending_max_count: usize,
    /// Max size of the pending sub-pool in megabytes.
    #[arg(long = "txpool.pending_max_size", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT)]
    pub pending_max_size: usize,

    /// Max number of transaction in the basefee sub-pool
    #[arg(long = "txpool.basefee_max_count", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_TXS_DEFAULT)]
    pub basefee_max_count: usize,
    /// Max size of the basefee sub-pool in megabytes.
    #[arg(long = "txpool.basefee_max_size", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT)]
    pub basefee_max_size: usize,

    /// Max number of transaction in the queued sub-pool
    #[arg(long = "txpool.queued_max_count", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_TXS_DEFAULT)]
    pub queued_max_count: usize,
    /// Max size of the queued sub-pool in megabytes.
    #[arg(long = "txpool.queued_max_size", help_heading = "TxPool", default_value_t = TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT)]
    pub queued_max_size: usize,

    /// Max number of executable transaction slots guaranteed per account
    #[arg(long = "txpool.max_account_slots", help_heading = "TxPool", default_value_t = TXPOOL_MAX_ACCOUNT_SLOTS_PER_SENDER)]
    pub max_account_slots: usize,

    /// Price bump (in %) for the transaction pool underpriced check.
    #[arg(long = "txpool.pricebump", help_heading = "TxPool", default_value_t = DEFAULT_PRICE_BUMP)]
    pub price_bump: u128,

    /// Price bump percentage to replace an already existing blob transaction
    #[arg(long = "blobpool.pricebump", help_heading = "TxPool", default_value_t = REPLACE_BLOB_PRICE_BUMP)]
    pub blob_transaction_price_bump: u128,
}

impl TxPoolArgs {
    /// Returns transaction pool configuration.
    pub fn pool_config(&self) -> PoolConfig {
        PoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: self.pending_max_count,
                max_size: self.pending_max_size * 1024 * 1024,
            },
            basefee_limit: SubPoolLimit {
                max_txs: self.basefee_max_count,
                max_size: self.basefee_max_size * 1024 * 1024,
            },
            queued_limit: SubPoolLimit {
                max_txs: self.queued_max_count,
                max_size: self.queued_max_size * 1024 * 1024,
            },
            max_account_slots: self.max_account_slots,
            price_bumps: PriceBumpConfig {
                default_price_bump: self.price_bump,
                replace_blob_tx_price_bump: self.blob_transaction_price_bump,
            },
        }
    }
}
