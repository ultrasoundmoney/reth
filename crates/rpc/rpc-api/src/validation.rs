//! API for block submission validation.

use alloy_primitives::Address;
use alloy_rpc_types_beacon::relay::{
    BuilderBlockValidationRequest, BuilderBlockValidationRequestV2,
    BuilderBlockValidationRequestV3, BuilderBlockValidationRequestV4,
    BuilderBlockValidationRequestV5, BuilderBlockValidationRequestV6,
};
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

/// The payment check the relay requests for a builder submission.
///
/// Gloas settles trustless bids from builder stake on the CL, so which in-payload payment
/// (if any) must be verified depends on the auction mode the relay ran for the bid.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PaymentCheck {
    /// Pre-gloas proposer payment: balance-delta primary, last-tx fallback.
    #[default]
    Proposer,
    /// No in-payload payment expected: the proposer is paid from builder stake (partially
    /// mediated).
    Skip,
    /// The payload's last transaction must pay `recipient` exactly the bid value (fully
    /// mediated: the relay fronts the proposer payment from its own stake).
    LastTxStrict {
        /// The wallet that must receive the payment.
        recipient: Address,
    },
}

/// [`BuilderBlockValidationRequestV6`] extended with the ultra sound payment-check mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UltraSoundBuilderBlockValidationRequestV6 {
    /// The upstream validation request.
    #[serde(flatten)]
    pub base: BuilderBlockValidationRequestV6,
    /// Which payment check to run for this submission.
    #[serde(default)]
    pub payment_check: PaymentCheck,
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
        request: UltraSoundBuilderBlockValidationRequestV6,
    ) -> jsonrpsee::core::RpcResult<()>;
}
