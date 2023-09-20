use async_trait::async_trait;
use reth_primitives::{
    BlockHash, BlockNumber, Header, InvalidTransactionError, SealedBlock, SealedHeader, H256, U256,
};
use std::fmt::Debug;

/// Re-export fork choice state
pub use reth_rpc_types::engine::ForkchoiceState;

/// Consensus is a protocol that chooses canonical chain.
#[async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait Consensus: Debug + Send + Sync {
    /// Validate if header is correct and follows consensus specification.
    ///
    /// This is called on standalone header to check if all hashes are correct.
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError>;

    /// Validate that the header information regarding parent are correct.
    /// This checks the block number, timestamp, basefee and gas limit increment.
    ///
    /// This is called before properties that are not in the header itself (like total difficulty)
    /// have been computed.
    ///
    /// **This should not be called for the genesis block**.
    ///
    /// Note: Validating header against its parent does not include other Consensus validations.
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError>;

    /// Validates the given headers
    ///
    /// This ensures that the first header is valid on its own and all subsequent headers are valid
    /// on its own and valid against its parent.
    ///
    /// Note: this expects that the headers are in natural order (ascending block number)
    fn validate_header_range(&self, headers: &[SealedHeader]) -> Result<(), ConsensusError> {
        if headers.is_empty() {
            return Ok(())
        }
        let first = headers.first().expect("checked empty");
        self.validate_header(first)?;
        let mut parent = first;
        for child in headers.iter().skip(1) {
            self.validate_header(child)?;
            self.validate_header_against_parent(child, parent)?;
            parent = child;
        }

        Ok(())
    }

    /// Validate if the header is correct and follows the consensus specification, including
    /// computed properties (like total difficulty).
    ///
    /// Some consensus engines may want to do additional checks here.
    ///
    /// Note: validating headers with TD does not include other Consensus validation.
    fn validate_header_with_total_difficulty(
        &self,
        header: &Header,
        total_difficulty: U256,
    ) -> Result<(), ConsensusError>;

    /// Validate a block disregarding world state, i.e. things that can be checked before sender
    /// recovery and execution.
    ///
    /// See the Yellow Paper sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and
    /// 11.1 "Ommer Validation".
    ///
    /// **This should not be called for the genesis block**.
    ///
    /// Note: validating blocks does not include other validations of the Consensus
    fn validate_block(&self, block: &SealedBlock) -> Result<(), ConsensusError>;
}

/// Consensus Errors
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusError {
    #[error("Block used gas ({gas_used}) is greater than gas limit ({gas_limit}).")]
    HeaderGasUsedExceedsGasLimit { gas_used: u64, gas_limit: u64 },
    #[error("Block ommer hash ({got:?}) is different from expected: ({expected:?})")]
    BodyOmmersHashDiff { got: H256, expected: H256 },
    #[error("Block state root ({got:?}) is different from expected: ({expected:?})")]
    BodyStateRootDiff { got: H256, expected: H256 },
    #[error("Block transaction root ({got:?}) is different from expected ({expected:?})")]
    BodyTransactionRootDiff { got: H256, expected: H256 },
    #[error("Block withdrawals root ({got:?}) is different from expected ({expected:?})")]
    BodyWithdrawalsRootDiff { got: H256, expected: H256 },
    #[error("Block with [hash:{hash:?},number: {number}] is already known.")]
    BlockKnown { hash: BlockHash, number: BlockNumber },
    #[error("Block parent [hash:{hash:?}] is not known.")]
    ParentUnknown { hash: BlockHash },
    #[error(
        "Block number {block_number} does not match parent block number {parent_block_number}"
    )]
    ParentBlockNumberMismatch { parent_block_number: BlockNumber, block_number: BlockNumber },
    #[error(
        "Parent hash {got_parent_hash:?} does not match the expected {expected_parent_hash:?}"
    )]
    ParentHashMismatch { expected_parent_hash: H256, got_parent_hash: H256 },
    #[error(
        "Block timestamp {timestamp} is in the past compared to the parent timestamp {parent_timestamp}."
    )]
    TimestampIsInPast { parent_timestamp: u64, timestamp: u64 },
    #[error("Block timestamp {timestamp} is in the future compared to our clock time {present_timestamp}.")]
    TimestampIsInFuture { timestamp: u64, present_timestamp: u64 },
    #[error("Child gas_limit {child_gas_limit} max increase is {parent_gas_limit}/1024.")]
    GasLimitInvalidIncrease { parent_gas_limit: u64, child_gas_limit: u64 },
    #[error("Child gas_limit {child_gas_limit} max decrease is {parent_gas_limit}/1024.")]
    GasLimitInvalidDecrease { parent_gas_limit: u64, child_gas_limit: u64 },
    #[error("Base fee missing.")]
    BaseFeeMissing,
    #[error("Block base fee ({got}) is different than expected: ({expected}).")]
    BaseFeeDiff { expected: u64, got: u64 },
    #[error("Transaction signer recovery error.")]
    TransactionSignerRecoveryError,
    #[error("Extra data {len} exceeds max length: ")]
    ExtraDataExceedsMax { len: usize },
    #[error("Difficulty after merge is not zero")]
    TheMergeDifficultyIsNotZero,
    #[error("Nonce after merge is not zero")]
    TheMergeNonceIsNotZero,
    #[error("Ommer root after merge is not empty")]
    TheMergeOmmerRootIsNotEmpty,
    #[error("Missing withdrawals root")]
    WithdrawalsRootMissing,
    #[error("Unexpected withdrawals root")]
    WithdrawalsRootUnexpected,
    #[error("Withdrawal index #{got} is invalid. Expected: #{expected}.")]
    WithdrawalIndexInvalid { got: u64, expected: u64 },
    #[error("Missing withdrawals")]
    BodyWithdrawalsMissing,
    #[error("Missing blob gas used")]
    BlobGasUsedMissing,
    #[error("Unexpected blob gas used")]
    BlobGasUsedUnexpected,
    #[error("Missing excess blob gas")]
    ExcessBlobGasMissing,
    #[error("Unexpected excess blob gas")]
    ExcessBlobGasUnexpected,
    #[error("Missing parent beacon block root")]
    ParentBeaconBlockRootMissing,
    #[error("Unexpected parent beacon block root")]
    ParentBeaconBlockRootUnexpected,
    #[error("Blob gas used {blob_gas_used} exceeds maximum allowance {max_blob_gas_per_block}")]
    BlobGasUsedExceedsMaxBlobGasPerBlock { blob_gas_used: u64, max_blob_gas_per_block: u64 },
    #[error(
        "Blob gas used {blob_gas_used} is not a multiple of blob gas per blob {blob_gas_per_blob}"
    )]
    BlobGasUsedNotMultipleOfBlobGasPerBlob { blob_gas_used: u64, blob_gas_per_blob: u64 },
    #[error("Blob gas used in the header {header_blob_gas_used} does not match the expected blob gas used {expected_blob_gas_used}")]
    BlobGasUsedDiff { header_blob_gas_used: u64, expected_blob_gas_used: u64 },
    #[error("Invalid excess blob gas. Expected: {expected}, got: {got}. Parent excess blob gas: {parent_excess_blob_gas}, parent blob gas used: {parent_blob_gas_used}.")]
    ExcessBlobGasDiff {
        expected: u64,
        got: u64,
        parent_excess_blob_gas: u64,
        parent_blob_gas_used: u64,
    },
    /// Error for a transaction that violates consensus.
    #[error(transparent)]
    InvalidTransaction(#[from] InvalidTransactionError),
}
