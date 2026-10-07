//! API for block submission validation.

use alloy_primitives::{Address, Bloom, Bytes, B256};
use alloy_rpc_types_beacon::relay::{
    BuilderBlockValidationRequest, BuilderBlockValidationRequestV2, SignedBidSubmissionV3,
    SignedBidSubmissionV4, SignedBidSubmissionV5, SignedBidSubmissionV6,
};
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

// Ultra Sound custom types to support per request transaction filtering

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs, clippy::upper_case_acronyms)]
pub enum TransactionFilter {
    #[default]
    None,
    OFAC,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BuilderBlockValidationRequestV3 {
    /// The request to be validated.
    #[serde(flatten)]
    pub request: SignedBidSubmissionV3,
    /// The registered gas limit for the validation request.
    #[serde_as(as = "DisplayFromStr")]
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    pub transaction_filter: TransactionFilter,
}

/// A Request to validate a [`SignedBidSubmissionV4`]
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BuilderBlockValidationRequestV4 {
    /// The request to be validated.
    #[serde(flatten)]
    pub request: SignedBidSubmissionV4,
    /// The registered gas limit for the validation request.
    #[serde_as(as = "DisplayFromStr")]
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    #[serde(default)]
    pub transaction_filter: TransactionFilter,
}

/// A Request to validate a [`SignedBidSubmissionV5`]
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BuilderBlockValidationRequestV5 {
    /// The request to be validated.
    #[serde(flatten)]
    pub request: SignedBidSubmissionV5,
    /// The registered gas limit for the validation request.
    #[serde_as(as = "DisplayFromStr")]
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    #[serde(default)]
    pub transaction_filter: TransactionFilter,
}

/// A Request to validate a [`SignedBidSubmissionV6`]
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BuilderBlockValidationRequestV6 {
    /// The request to be validated.
    #[serde(flatten)]
    pub request: SignedBidSubmissionV6,
    /// The registered gas limit for the validation request.
    #[serde_as(as = "DisplayFromStr")]
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    #[serde(default)]
    pub transaction_filter: TransactionFilter,
}

/// A V6 submission whose last transaction is the placeholder payment, plus the account the relay
/// pays the replacement from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct AdjustmentDataRequest {
    #[serde(flatten)]
    pub request: BuilderBlockValidationRequestV6,
    pub fee_payer: Address,
}

/// The proofs a relay needs to swap the placeholder payment of a submitted block: account proofs
/// over the post-state, the placeholder's transaction and receipt proofs, and the roots they
/// verify against. Field names follow the relay's adjustment data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct AdjustmentData {
    pub state_root: B256,
    pub receipts_root: B256,
    pub el_transactions_root: B256,
    pub el_withdrawals_root: B256,
    pub builder_address: Address,
    pub builder_proof: Vec<Bytes>,
    pub fee_recipient_address: Address,
    pub fee_recipient_proof: Vec<Bytes>,
    pub fee_payer_address: Address,
    pub fee_payer_proof: Vec<Bytes>,
    pub el_placeholder_transaction_proof: Vec<Bytes>,
    pub el_placeholder_receipt_proof: Vec<Bytes>,
    /// Logs bloom of the receipts ahead of the placeholder.
    pub pre_payment_logs_bloom: Bloom,
    pub placeholder_gas_used: u64,
}

/// Block validation rpc interface.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "flashbots"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "flashbots"))]
pub trait BlockSubmissionValidationApi {
    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV1")]
    async fn validate_builder_submission_v1(
        &self,
        request: BuilderBlockValidationRequest,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV2")]
    async fn validate_builder_submission_v2(
        &self,
        request: BuilderBlockValidationRequestV2,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV3")]
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV4")]
    async fn validate_builder_submission_v4(
        &self,
        request: BuilderBlockValidationRequestV4,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV5")]
    async fn validate_builder_submission_v5(
        &self,
        request: BuilderBlockValidationRequestV5,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// A Request to validate a block submission.
    #[method(name = "validateBuilderSubmissionV6")]
    async fn validate_builder_submission_v6(
        &self,
        request: BuilderBlockValidationRequestV6,
    ) -> jsonrpsee::core::RpcResult<()>;

    /// Validates a V6 submission like `validateBuilderSubmissionV6` and returns the proofs the
    /// relay needs to adjust its placeholder payment.
    // devnet tooling: lets a builder without state of its own produce adjustable submissions.
    #[method(name = "getAdjustmentData")]
    async fn get_adjustment_data(
        &self,
        request: AdjustmentDataRequest,
    ) -> jsonrpsee::core::RpcResult<AdjustmentData>;
}
