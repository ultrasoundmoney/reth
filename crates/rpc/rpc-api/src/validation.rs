//! API for block submission validation.

use alloy_rpc_types_beacon::relay::{
    BuilderBlockValidationRequest, BuilderBlockValidationRequestV2,
    BuilderBlockValidationRequestV3, BuilderBlockValidationRequestV4,
    BuilderBlockValidationRequestV5, BuilderBlockValidationRequestV6,
};
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

/// [`BuilderBlockValidationRequestV6`] extended with reth specific validation options.
///
/// The options are flattened next to the upstream request and default, so a request that carries
/// none of them behaves exactly like [`BuilderBlockValidationRequestV6`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderBlockValidationRequestV6Ext {
    /// The request to be validated.
    #[serde(flatten)]
    pub request: BuilderBlockValidationRequestV6,
    /// Skip the check that the proposer was paid inside the execution payload.
    ///
    /// A trustless ePBS (gloas) bid settles the proposer payment from the builder's stake on the
    /// consensus layer, so the execution payload contains no payment to the bid's
    /// `proposer_fee_recipient` and the payment check would reject an otherwise valid block.
    /// Every other submission leaves this at `false` and is checked as before.
    #[serde(default)]
    pub skip_payment_check: bool,
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
        request: BuilderBlockValidationRequestV6Ext,
    ) -> jsonrpsee::core::RpcResult<()>;
}
