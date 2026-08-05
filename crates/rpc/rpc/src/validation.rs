use alloy_consensus::{
    BlobTransactionValidationError, BlockHeader, EnvKzgSettings, Transaction, TxReceipt,
};
use alloy_eip7928::{bal::DecodedBal, compute_block_access_list_hash};
use alloy_eips::eip7685::RequestsOrHash;
use alloy_primitives::{address, b256, map::AddressSet, Address, B256, U256};
use alloy_rpc_types_beacon::relay::{
    BidTrace, BuilderBlockValidationRequest, BuilderBlockValidationRequestV2,
};
use alloy_rpc_types_engine::{
    BlobsBundleV1, BlobsBundleV2, CancunPayloadFields, ExecutionData, ExecutionPayload,
    ExecutionPayloadSidecar, PraguePayloadFields,
};
use async_trait::async_trait;
use core::fmt;
use jsonrpsee::core::RpcResult;
use jsonrpsee_types::error::ErrorObject;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_consensus::{Consensus, FullConsensus};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_engine_primitives::PayloadValidator;
use reth_errors::{BlockExecutionError, ConsensusError, ProviderError};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_execution_types::BlockExecutionOutput;
use reth_metrics::{
    metrics,
    metrics::{gauge, Gauge},
    Metrics,
};
use reth_node_api::{NewPayloadError, PayloadTypes};
use reth_primitives_traits::{
    BlockBody, GotExpected, NodePrimitives, RecoveredBlock, SealedBlock, SealedHeaderFor,
};
use reth_revm::{cached::CachedReads, database::StateProviderDatabase};
use reth_rpc_api::{
    BlockSubmissionValidationApiServer, BuilderBlockValidationRequestV3,
    BuilderBlockValidationRequestV4, BuilderBlockValidationRequestV5,
    BuilderBlockValidationRequestV6, TransactionFilter,
};
use reth_rpc_server_types::result::{internal_rpc_err, invalid_params_rpc_err};
use reth_storage_api::{BlockReaderIdExt, HashedPostStateProvider, StateProviderFactory};
use reth_tasks::Runtime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use tokio::sync::{oneshot, RwLock};
use tracing::warn;

const DEFAULT_PAYMENT_FORWARDER: Address = address!("0xFEEEEEE44046c3f61a8CC081E0918eF0de0a7ffC");

const PAYMENT_FORWARDER_VAR: &str = "PAYMENT_FORWARDER_ADDRESS";

/// <https://github.com/gattaca-com/helix/pull/466>. Overridable per chain; the code hash is
/// not, so a wrong address fails closed.
pub(crate) static PAYMENT_FORWARDER: LazyLock<Address> =
    LazyLock::new(|| match std::env::var(PAYMENT_FORWARDER_VAR) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{PAYMENT_FORWARDER_VAR} is not a valid address: {value}")),
        Err(_) => DEFAULT_PAYMENT_FORWARDER,
    });

/// `[4-byte timestamp][20-byte recipient]`
const PAYMENT_FORWARDER_CALLDATA_LEN: usize = 24;

/// A value call to a codeless address succeeds and keeps the value, so without this a payment
/// would validate on a chain lacking the forwarder while the recipient received nothing.
const PAYMENT_FORWARDER_CODE_HASH: B256 =
    b256!("0xd9f5db49d3c0a174c39701485406cd78d01dd27f73b7ef7b883e5f69d8103220");

/// Trailing bytes are inert: the contract reads one calldata word and forwards nothing. Shorter
/// input would zero-pad the recipient and burn the value, so it is rejected.
fn payment_forwarder_recipient(input: &[u8]) -> Option<Address> {
    (input.len() >= PAYMENT_FORWARDER_CALLDATA_LEN)
        .then(|| Address::from_slice(&input[4..PAYMENT_FORWARDER_CALLDATA_LEN]))
}

/// The type that implements the `validation` rpc namespace trait
#[derive(Clone, Debug, derive_more::Deref)]
pub struct ValidationApi<Provider, E: ConfigureEvm, T: PayloadTypes> {
    #[deref]
    inner: Arc<ValidationApiInner<Provider, E, T>>,
}

impl<Provider, E, T> ValidationApi<Provider, E, T>
where
    E: ConfigureEvm,
    T: PayloadTypes,
{
    /// Create a new instance of the [`ValidationApi`]
    pub fn new(
        provider: Provider,
        consensus: Arc<dyn FullConsensus<E::Primitives>>,
        evm_config: E,
        config: ValidationApiConfig,
        task_spawner: Runtime,
        payload_validator: Arc<
            dyn PayloadValidator<T, Block = <E::Primitives as NodePrimitives>::Block>,
        >,
    ) -> Self {
        let ValidationApiConfig { disallow, validation_window } = config;

        let metrics = ValidationMetrics::default();
        record_disallow_metrics(&metrics, &disallow);

        let inner = Arc::new(ValidationApiInner {
            provider,
            consensus,
            payload_validator,
            evm_config,
            disallow: parking_lot::RwLock::new(Arc::new(disallow)),
            validation_window,
            cached_state: Default::default(),
            task_spawner,
            metrics,
        });

        Self { inner }
    }

    /// Replaces the disallow list (e.g. from a periodic refresh) and re-emits its metrics.
    pub fn update_disallow(&self, disallow: AddressSet) {
        record_disallow_metrics(&self.metrics, &disallow);
        *self.disallow.write() = Arc::new(disallow);
    }

    /// Returns the cached reads for the given head hash.
    async fn cached_reads(&self, head: B256) -> CachedReads {
        let cache = self.inner.cached_state.read().await;
        if cache.0 == head {
            cache.1.clone()
        } else {
            Default::default()
        }
    }

    /// Updates the cached state for the given head hash.
    async fn update_cached_reads(&self, head: B256, cached_state: CachedReads) {
        let mut cache = self.inner.cached_state.write().await;
        if cache.0 == head {
            cache.1.extend(cached_state);
        } else {
            *cache = (head, cached_state)
        }
    }
}

impl<Provider, E, T> ValidationApi<Provider, E, T>
where
    Provider: BlockReaderIdExt<Header = <E::Primitives as NodePrimitives>::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + StateProviderFactory
        + 'static,
    E: ConfigureEvm + 'static,
    T: PayloadTypes<ExecutionData = ExecutionData>,
{
    /// Validates the given block and a [`BidTrace`] against it.
    pub async fn validate_message_against_block(
        &self,
        block: RecoveredBlock<<E::Primitives as NodePrimitives>::Block>,
        message: BidTrace,
        registered_gas_limit: u64,
        transaction_filter: TransactionFilter,
        decoded_bal: Option<DecodedBal>,
    ) -> Result<(), ValidationApiError> {
        self.validate_message_against_header(block.sealed_header(), &message)?;

        self.consensus.validate_header(block.sealed_header())?;
        self.consensus.validate_block_pre_execution(block.sealed_block())?;

        let disallow =
            (transaction_filter == TransactionFilter::OFAC).then(|| self.disallow.read().clone());

        if let Some(disallow) = &disallow {
            if disallow.contains(&block.beneficiary()) {
                return Err(ValidationApiError::Blacklist(block.beneficiary()))
            }
            if disallow.contains(&message.proposer_fee_recipient) {
                return Err(ValidationApiError::Blacklist(message.proposer_fee_recipient))
            }
            for (sender, tx) in block.senders_iter().zip(block.body().transactions()) {
                if disallow.contains(sender) {
                    return Err(ValidationApiError::Blacklist(*sender))
                }
                if let Some(to) = tx.to() &&
                    disallow.contains(&to)
                {
                    return Err(ValidationApiError::Blacklist(to))
                }
            }
        }

        let latest_header =
            self.provider.latest_header()?.ok_or_else(|| ValidationApiError::MissingLatestBlock)?;

        let parent_header = if block.parent_hash() == latest_header.hash() {
            latest_header
        } else {
            // parent is not the latest header so we need to fetch it and ensure it's not too old
            let parent_header = self
                .provider
                .sealed_header_by_hash(block.parent_hash())?
                .ok_or_else(|| ValidationApiError::MissingParentBlock)?;

            if latest_header.number().saturating_sub(parent_header.number()) >
                self.validation_window
            {
                return Err(ValidationApiError::BlockTooOld)
            }
            parent_header
        };

        self.consensus.validate_header_against_parent(block.sealed_header(), &parent_header)?;
        parent_header.validate_gas_limit(registered_gas_limit, block.gas_limit()).map_err(
            |err| {
                ValidationApiError::GasLimitMismatch(GotExpected {
                    got: err.got,
                    expected: err.expected,
                })
            },
        )?;

        // Ensure the submitted block access list does not exceed the block gas limit (EIP-7928)
        if let Some(decoded_bal) = decoded_bal {
            decoded_bal
                .as_bal()
                .validate_gas_limit(block.gas_limit())
                .map_err(ConsensusError::from)?;
        }

        let parent_header_hash = parent_header.hash();
        let state_provider = self.provider.state_by_block_hash(parent_header_hash)?;

        let mut request_cache = self.cached_reads(parent_header_hash).await;

        let (output, block_access_list_hash) = {
            let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));
            let mut executor = self.evm_config.batch_executor(cached_db);

            let result = executor.execute_one(&block)?;

            // The executor rebuilds the block access list whenever the block header contains a
            // BAL hash. Comparing the rebuilt hash against the header post execution also
            // commits to the submitted access list, because the header's BAL hash is derived
            // from the submitted bytes.
            let block_access_list_hash =
                executor.take_bal().map(|bal| compute_block_access_list_hash(&bal));

            let mut state = executor.into_state();
            if let Some(disallow) = &disallow {
                // Check whether the submission interacted with any blacklisted account by
                // scanning the `State`'s cache that records everything read from database
                // during execution.
                for account in state.cache.accounts.keys() {
                    if disallow.contains(account) {
                        return Err(ValidationApiError::Blacklist(*account))
                    }
                }
            }

            (BlockExecutionOutput { state: state.take_bundle(), result }, block_access_list_hash)
        };

        // update the cached reads
        self.update_cached_reads(parent_header_hash, request_cache).await;

        self.consensus.validate_block_post_execution(
            &block,
            &output,
            None,
            block_access_list_hash,
        )?;

        self.ensure_payment(&block, &output, &message)?;

        let hashed_state = state_provider.hashed_post_state(&output.state)?;
        let state_root = state_provider.state_root(hashed_state)?;

        if state_root != block.header().state_root() {
            return Err(ConsensusError::BodyStateRootDiff(
                GotExpected { got: state_root, expected: block.header().state_root() }.into(),
            )
            .into())
        }

        Ok(())
    }

    /// Ensures that fields of [`BidTrace`] match the fields of the [`SealedHeaderFor`].
    fn validate_message_against_header(
        &self,
        header: &SealedHeaderFor<E::Primitives>,
        message: &BidTrace,
    ) -> Result<(), ValidationApiError> {
        if header.hash() != message.block_hash {
            Err(ValidationApiError::BlockHashMismatch(GotExpected {
                got: message.block_hash,
                expected: header.hash(),
            }))
        } else if header.parent_hash() != message.parent_hash {
            Err(ValidationApiError::ParentHashMismatch(GotExpected {
                got: message.parent_hash,
                expected: header.parent_hash(),
            }))
        } else if header.gas_limit() != message.gas_limit {
            Err(ValidationApiError::GasLimitMismatch(GotExpected {
                got: message.gas_limit,
                expected: header.gas_limit(),
            }))
        } else if header.gas_used() != message.gas_used {
            Err(ValidationApiError::GasUsedMismatch(GotExpected {
                got: message.gas_used,
                expected: header.gas_used(),
            }))
        } else {
            Ok(())
        }
    }

    /// Ensures that the proposer has received [`BidTrace::value`] for this block.
    ///
    /// Firstly attempts to verify the payment by checking the state changes, otherwise falls back
    /// to checking the latest block transaction.
    fn ensure_payment(
        &self,
        block: &SealedBlock<<E::Primitives as NodePrimitives>::Block>,
        output: &BlockExecutionOutput<<E::Primitives as NodePrimitives>::Receipt>,
        message: &BidTrace,
    ) -> Result<(), ValidationApiError> {
        // A zero-value bid promises the proposer nothing, so the payload owes nothing.
        if message.value.is_zero() {
            return Ok(())
        }

        let (mut balance_before, balance_after) = if let Some(acc) =
            output.state.state.get(&message.proposer_fee_recipient)
        {
            let balance_before = acc.original_info.as_ref().map(|i| i.balance).unwrap_or_default();
            let balance_after = acc.info.as_ref().map(|i| i.balance).unwrap_or_default();

            (balance_before, balance_after)
        } else {
            // account might have balance but considering it zero is fine as long as we know
            // that balance have not changed
            (U256::ZERO, U256::ZERO)
        };

        if let Some(withdrawals) = block.body().withdrawals() {
            for withdrawal in withdrawals {
                if withdrawal.address == message.proposer_fee_recipient {
                    balance_before += withdrawal.amount_wei();
                }
            }
        }

        if balance_after >= balance_before.saturating_add(message.value) {
            return Ok(())
        }

        let (receipt, tx) = output
            .receipts
            .last()
            .zip(block.body().transactions().last())
            .ok_or(ValidationApiError::ProposerPayment)?;

        if !receipt.status() {
            return Err(ValidationApiError::ProposerPayment)
        }

        let paid_directly =
            tx.to() == Some(message.proposer_fee_recipient) && tx.input().is_empty();
        let paid_via_forwarder = tx.to() == Some(*PAYMENT_FORWARDER) &&
            payment_forwarder_recipient(tx.input()) == Some(message.proposer_fee_recipient) &&
            output.state.state.get(&*PAYMENT_FORWARDER).is_some_and(|account| {
                account
                    .info
                    .as_ref()
                    .is_some_and(|info| info.code_hash == PAYMENT_FORWARDER_CODE_HASH)
            });

        if !paid_directly && !paid_via_forwarder {
            return Err(ValidationApiError::ProposerPayment)
        }

        if tx.value() != message.value {
            return Err(ValidationApiError::ProposerPayment)
        }

        if let Some(block_base_fee) = block.header().base_fee_per_gas() &&
            tx.effective_tip_per_gas(block_base_fee).unwrap_or_default() != 0
        {
            return Err(ValidationApiError::ProposerPayment)
        }

        Ok(())
    }

    /// Validates the given [`BlobsBundleV1`] and returns versioned hashes for blobs.
    pub fn validate_blobs_bundle(
        &self,
        blobs_bundle: BlobsBundleV1,
    ) -> Result<Vec<B256>, ValidationApiError> {
        let versioned_hashes = blobs_bundle.versioned_hashes();
        let sidecar =
            blobs_bundle.try_into_sidecar().map_err(|_| ValidationApiError::InvalidBlobsBundle)?;

        sidecar.validate(&versioned_hashes, EnvKzgSettings::default().get())?;
        Ok(versioned_hashes)
    }

    /// Validates the given [`BlobsBundleV2`] and returns versioned hashes for blobs.
    pub fn validate_blobs_bundle_v2(
        &self,
        blobs_bundle: BlobsBundleV2,
    ) -> Result<Vec<B256>, ValidationApiError> {
        let versioned_hashes = blobs_bundle.versioned_hashes();
        let sidecar =
            blobs_bundle.try_into_sidecar().map_err(|_| ValidationApiError::InvalidBlobsBundle)?;

        sidecar.validate(&versioned_hashes, EnvKzgSettings::default().get())?;
        Ok(versioned_hashes)
    }

    /// Core logic for validating the builder submission v3
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> Result<(), ValidationApiError> {
        let block = self.payload_validator.ensure_well_formed_payload(ExecutionData {
            payload: ExecutionPayload::V3(request.request.execution_payload),
            sidecar: ExecutionPayloadSidecar::v3(CancunPayloadFields {
                parent_beacon_block_root: request.parent_beacon_block_root,
                versioned_hashes: self.validate_blobs_bundle(request.request.blobs_bundle)?,
            }),
        })?;

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            request.transaction_filter,
            None,
        )
        .await
    }

    /// Core logic for validating the builder submission v4
    async fn validate_builder_submission_v4(
        &self,
        request: BuilderBlockValidationRequestV4,
    ) -> Result<(), ValidationApiError> {
        let block = self.payload_validator.ensure_well_formed_payload(ExecutionData {
            payload: ExecutionPayload::V3(request.request.execution_payload),
            sidecar: ExecutionPayloadSidecar::v4(
                CancunPayloadFields {
                    parent_beacon_block_root: request.parent_beacon_block_root,
                    versioned_hashes: self.validate_blobs_bundle(request.request.blobs_bundle)?,
                },
                PraguePayloadFields {
                    requests: RequestsOrHash::Requests(
                        request.request.execution_requests.to_requests(),
                    ),
                },
            ),
        })?;

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            request.transaction_filter,
            None,
        )
        .await
    }

    /// Core logic for validating the builder submission v5
    async fn validate_builder_submission_v5(
        &self,
        request: BuilderBlockValidationRequestV5,
    ) -> Result<(), ValidationApiError> {
        let payload = ExecutionPayload::V3(request.request.execution_payload);
        validate_message_against_payload(&request.request.message, &payload)?;

        let block = self.payload_validator.ensure_well_formed_payload(ExecutionData {
            payload,
            sidecar: ExecutionPayloadSidecar::v4(
                CancunPayloadFields {
                    parent_beacon_block_root: request.parent_beacon_block_root,
                    versioned_hashes: self
                        .validate_blobs_bundle_v2(request.request.blobs_bundle)?,
                },
                PraguePayloadFields {
                    requests: RequestsOrHash::Requests(
                        request.request.execution_requests.to_requests(),
                    ),
                },
            ),
        })?;

        // Check block size as per EIP-7934 (only applies when Osaka hardfork is active)
        let chain_spec = self.provider.chain_spec();
        if chain_spec.is_osaka_active_at_timestamp(block.timestamp()) {
            let rlp_length = block.rlp_length();
            if rlp_length > MAX_RLP_BLOCK_SIZE {
                return Err(ValidationApiError::Consensus(ConsensusError::BlockTooLarge {
                    rlp_length,
                    max_rlp_length: MAX_RLP_BLOCK_SIZE,
                }));
            }
        }

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            request.transaction_filter,
            None,
        )
        .await
    }

    /// Core logic for validating the builder submission v6
    async fn validate_builder_submission_v6(
        &self,
        request: BuilderBlockValidationRequestV6,
    ) -> Result<(), ValidationApiError> {
        let payload = ExecutionPayload::V4(request.request.execution_payload);
        validate_message_against_payload(&request.request.message, &payload)?;

        let decoded_bal =
            DecodedBal::from_rlp_bytes(payload.as_v4().unwrap().block_access_list.clone())
                .map_err(ValidationApiError::InvalidBlockAccessList)?;

        let block = self.payload_validator.ensure_well_formed_payload(ExecutionData {
            payload,
            sidecar: ExecutionPayloadSidecar::v4(
                CancunPayloadFields {
                    parent_beacon_block_root: request.parent_beacon_block_root,
                    versioned_hashes: self
                        .validate_blobs_bundle_v2(request.request.blobs_bundle)?,
                },
                PraguePayloadFields {
                    requests: RequestsOrHash::Requests(
                        request.request.execution_requests.to_requests(),
                    ),
                },
            ),
        })?;

        let chain_spec = self.provider.chain_spec();
        if chain_spec.is_osaka_active_at_timestamp(block.timestamp()) {
            let rlp_length = block.rlp_length();
            if rlp_length > MAX_RLP_BLOCK_SIZE {
                return Err(ValidationApiError::Consensus(ConsensusError::BlockTooLarge {
                    rlp_length,
                    max_rlp_length: MAX_RLP_BLOCK_SIZE,
                }));
            }
        }

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            request.transaction_filter,
            Some(decoded_bal),
        )
        .await
    }
}

#[async_trait]
impl<Provider, E, T> BlockSubmissionValidationApiServer for ValidationApi<Provider, E, T>
where
    Provider: BlockReaderIdExt<Header = <E::Primitives as NodePrimitives>::BlockHeader>
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + StateProviderFactory
        + Clone
        + 'static,
    E: ConfigureEvm + 'static,
    T: PayloadTypes<ExecutionData = ExecutionData>,
{
    async fn validate_builder_submission_v1(
        &self,
        _request: BuilderBlockValidationRequest,
    ) -> RpcResult<()> {
        warn!(target: "rpc::flashbots", "Method `flashbots_validateBuilderSubmissionV1` is not supported");
        Err(internal_rpc_err("unimplemented"))
    }

    async fn validate_builder_submission_v2(
        &self,
        _request: BuilderBlockValidationRequestV2,
    ) -> RpcResult<()> {
        warn!(target: "rpc::flashbots", "Method `flashbots_validateBuilderSubmissionV2` is not supported");
        Err(internal_rpc_err("unimplemented"))
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v3(
        &self,
        request: BuilderBlockValidationRequestV3,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking_task(async move {
            let result = Self::validate_builder_submission_v3(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        });

        rx.await.map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v4(
        &self,
        request: BuilderBlockValidationRequestV4,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking_task(async move {
            let result = Self::validate_builder_submission_v4(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        });

        rx.await.map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v5(
        &self,
        request: BuilderBlockValidationRequestV5,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking_task(async move {
            let result = Self::validate_builder_submission_v5(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        });

        rx.await.map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }

    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v6(
        &self,
        request: BuilderBlockValidationRequestV6,
    ) -> RpcResult<()> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        self.task_spawner.spawn_blocking_task(async move {
            let result = Self::validate_builder_submission_v6(&this, request)
                .await
                .map_err(ErrorObject::from);
            let _ = tx.send(result);
        });

        rx.await.map_err(|_| internal_rpc_err("Internal blocking task error"))?
    }
}

pub struct ValidationApiInner<Provider, E: ConfigureEvm, T: PayloadTypes> {
    /// The provider that can interact with the chain.
    provider: Provider,
    /// Consensus implementation.
    consensus: Arc<dyn FullConsensus<E::Primitives>>,
    /// Execution payload validator.
    payload_validator:
        Arc<dyn PayloadValidator<T, Block = <E::Primitives as NodePrimitives>::Block>>,
    /// Block executor factory.
    evm_config: E,
    /// Disallowed addresses, swappable so a periodic refresh can update them without a restart.
    disallow: parking_lot::RwLock<Arc<AddressSet>>,
    /// The maximum block distance - parent to latest - allowed for validation
    validation_window: u64,
    /// Cached state reads to avoid redundant disk I/O across multiple validation attempts
    /// targeting the same state. Stores a tuple of (`block_hash`, `cached_reads`) for the
    /// latest head block state. Uses async `RwLock` to safely handle concurrent validation
    /// requests.
    cached_state: RwLock<(B256, CachedReads)>,
    /// Task spawner for blocking operations
    task_spawner: Runtime,
    /// Validation metrics
    metrics: ValidationMetrics,
}

/// Ensures that the raw execution payload fields match the corresponding [`BidTrace`] fields.
fn validate_message_against_payload(
    message: &BidTrace,
    payload: &ExecutionPayload,
) -> Result<(), ValidationApiError> {
    let payload = payload.as_v1();

    if payload.block_hash != message.block_hash {
        Err(ValidationApiError::BlockHashMismatch(GotExpected {
            got: message.block_hash,
            expected: payload.block_hash,
        }))
    } else if payload.parent_hash != message.parent_hash {
        Err(ValidationApiError::ParentHashMismatch(GotExpected {
            got: message.parent_hash,
            expected: payload.parent_hash,
        }))
    } else if payload.gas_limit != message.gas_limit {
        Err(ValidationApiError::GasLimitMismatch(GotExpected {
            got: message.gas_limit,
            expected: payload.gas_limit,
        }))
    } else if payload.gas_used != message.gas_used {
        Err(ValidationApiError::GasUsedMismatch(GotExpected {
            got: message.gas_used,
            expected: payload.gas_used,
        }))
    } else {
        Ok(())
    }
}

/// Calculates a deterministic hash of the blocklist for change detection.
///
/// This function sorts addresses to ensure deterministic output regardless of
/// insertion order, then computes a SHA256 hash of the concatenated addresses.
fn hash_disallow_list(disallow: &AddressSet) -> String {
    let mut sorted: Vec<_> = disallow.iter().collect();
    sorted.sort_unstable(); // sort for deterministic hashing

    let mut hasher = Sha256::new();
    for addr in sorted {
        hasher.update(addr.as_slice());
    }

    format!("{:x}", hasher.finalize())
}

/// Sets the disallow-list size and hash gauges from the given set.
fn record_disallow_metrics(metrics: &ValidationMetrics, disallow: &AddressSet) {
    metrics.disallow_size.set(disallow.len() as f64);

    let disallow_hash = hash_disallow_list(disallow);
    let hash_gauge = gauge!("builder_validation_disallow_hash", "hash" => disallow_hash);
    hash_gauge.set(1.0);
}

impl<Provider, E: ConfigureEvm, T: PayloadTypes> fmt::Debug for ValidationApiInner<Provider, E, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationApiInner").finish_non_exhaustive()
    }
}

/// Configuration for validation API.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidationApiConfig {
    /// Disallowed addresses.
    pub disallow: AddressSet,
    /// The maximum block distance - parent to latest - allowed for validation
    pub validation_window: u64,
}

impl ValidationApiConfig {
    /// Default validation blocks window of 3 blocks
    pub const DEFAULT_VALIDATION_WINDOW: u64 = 3;
}

impl Default for ValidationApiConfig {
    fn default() -> Self {
        Self { disallow: Default::default(), validation_window: Self::DEFAULT_VALIDATION_WINDOW }
    }
}

/// Errors thrown by the validation API.
#[derive(Debug, thiserror::Error)]
pub enum ValidationApiError {
    #[error("block gas limit mismatch: {_0}")]
    GasLimitMismatch(GotExpected<u64>),
    #[error("block gas used mismatch: {_0}")]
    GasUsedMismatch(GotExpected<u64>),
    #[error("block parent hash mismatch: {_0}")]
    ParentHashMismatch(GotExpected<B256>),
    #[error("block hash mismatch: {_0}")]
    BlockHashMismatch(GotExpected<B256>),
    #[error("missing latest block in database")]
    MissingLatestBlock,
    #[error("parent block not found")]
    MissingParentBlock,
    #[error("block is too old, outside validation window")]
    BlockTooOld,
    #[error("could not verify proposer payment")]
    ProposerPayment,
    #[error("invalid blobs bundle")]
    InvalidBlobsBundle,
    #[error("invalid block access list: {_0}")]
    InvalidBlockAccessList(alloy_rlp::Error),
    #[error("block accesses blacklisted address: {_0}")]
    Blacklist(Address),
    #[error(transparent)]
    Blob(#[from] BlobTransactionValidationError),
    #[error(transparent)]
    Consensus(#[from] ConsensusError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Execution(#[from] BlockExecutionError),
    #[error(transparent)]
    Payload(#[from] NewPayloadError),
}

impl From<ValidationApiError> for ErrorObject<'static> {
    fn from(error: ValidationApiError) -> Self {
        match error {
            ValidationApiError::GasLimitMismatch(_) |
            ValidationApiError::GasUsedMismatch(_) |
            ValidationApiError::ParentHashMismatch(_) |
            ValidationApiError::BlockHashMismatch(_) |
            ValidationApiError::Blacklist(_) |
            ValidationApiError::ProposerPayment |
            ValidationApiError::InvalidBlobsBundle |
            ValidationApiError::InvalidBlockAccessList(_) |
            ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

            ValidationApiError::Consensus(
                error @ (ConsensusError::BlockAccessListCostMoreThanGasLimit(_) |
                ConsensusError::BlockAccessListHashMismatch(_)),
            ) => invalid_params_rpc_err(error.to_string()),
            ValidationApiError::MissingLatestBlock |
            ValidationApiError::MissingParentBlock |
            ValidationApiError::BlockTooOld |
            ValidationApiError::Consensus(_) |
            ValidationApiError::Provider(_) => internal_rpc_err(error.to_string()),
            ValidationApiError::Execution(err) => match err {
                error @ BlockExecutionError::Validation(_) => {
                    invalid_params_rpc_err(error.to_string())
                }
                error @ BlockExecutionError::Internal(_) => internal_rpc_err(error.to_string()),
            },
            ValidationApiError::Payload(err) => match err {
                error @ NewPayloadError::Eth(_) => invalid_params_rpc_err(error.to_string()),
                error @ NewPayloadError::Other(_) => internal_rpc_err(error.to_string()),
            },
        }
    }
}

/// Metrics for the validation endpoint.
#[derive(Metrics)]
#[metrics(scope = "builder.validation")]
pub(crate) struct ValidationMetrics {
    /// The number of entries configured in the builder validation disallow list.
    pub(crate) disallow_size: Gauge,
}

#[cfg(test)]
mod tests {
    use super::{
        hash_disallow_list, payment_forwarder_recipient, validate_message_against_payload,
        AddressSet, BuilderBlockValidationRequestV6, TransactionFilter, ValidationApi,
        ValidationApiConfig, ValidationApiError, DEFAULT_PAYMENT_FORWARDER, PAYMENT_FORWARDER,
        PAYMENT_FORWARDER_CALLDATA_LEN, PAYMENT_FORWARDER_CODE_HASH,
    };
    use alloy_consensus::{BlockHeader, Header};
    use alloy_eips::{
        eip7002::WithdrawalRequest,
        eip8282::{BuilderDepositRequest, BuilderExitRequest},
    };
    use alloy_primitives::{address, b256, hex, keccak256, Address, Bytes, FixedBytes, B256, U256};
    use alloy_rpc_types_beacon::{
        relay::{BidTrace, SignedBidSubmissionV6},
        requests::ExecutionRequestsV5,
    };
    use alloy_rpc_types_engine::{
        ExecutionData, ExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2,
        ExecutionPayloadV3, ExecutionPayloadV4,
    };
    use reth_consensus::noop::NoopConsensus;
    use reth_engine_primitives::PayloadValidator;
    use reth_ethereum_engine_primitives::EthPayloadTypes;
    use reth_ethereum_primitives::Block;
    use reth_evm_ethereum::EthEvmConfig;
    use reth_execution_types::BlockExecutionOutput;
    use reth_node_api::NewPayloadError;
    use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
    use reth_provider::test_utils::MockEthProvider;
    use reth_revm::db::{states::bundle_state::BundleState, AccountStatus, BundleAccount};
    use reth_tasks::Runtime;
    use revm::state::AccountInfo;
    use std::sync::Arc;

    fn test_execution_payload() -> ExecutionPayload {
        ExecutionPayload::V1(ExecutionPayloadV1 {
            parent_hash: B256::repeat_byte(0x11),
            fee_recipient: Address::ZERO,
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            prev_randao: B256::ZERO,
            block_number: 1,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: B256::repeat_byte(0x22),
            transactions: Default::default(),
        })
    }

    fn matching_bid_trace(payload: &ExecutionPayload) -> BidTrace {
        let payload = payload.as_v1();
        BidTrace {
            parent_hash: payload.parent_hash,
            block_hash: payload.block_hash,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_message_against_payload_block_hash_mismatch() {
        let payload = test_execution_payload();
        let mut message = matching_bid_trace(&payload);
        message.block_hash = B256::repeat_byte(0x33);

        let err = validate_message_against_payload(&message, &payload).unwrap_err();
        let ValidationApiError::BlockHashMismatch(mismatch) = err else {
            panic!("unexpected error: {err}")
        };
        assert_eq!(mismatch.got, message.block_hash);
        assert_eq!(mismatch.expected, payload.block_hash());
    }

    #[test]
    fn test_validate_message_against_payload_parent_hash_mismatch() {
        let payload = test_execution_payload();
        let mut message = matching_bid_trace(&payload);
        message.parent_hash = B256::repeat_byte(0x33);

        let err = validate_message_against_payload(&message, &payload).unwrap_err();
        let ValidationApiError::ParentHashMismatch(mismatch) = err else {
            panic!("unexpected error: {err}")
        };
        assert_eq!(mismatch.got, message.parent_hash);
        assert_eq!(mismatch.expected, payload.parent_hash());
    }

    #[test]
    fn test_validate_message_against_payload_gas_limit_mismatch() {
        let payload = test_execution_payload();
        let mut message = matching_bid_trace(&payload);
        message.gas_limit += 1;

        let err = validate_message_against_payload(&message, &payload).unwrap_err();
        let ValidationApiError::GasLimitMismatch(mismatch) = err else {
            panic!("unexpected error: {err}")
        };
        assert_eq!(mismatch.got, message.gas_limit);
        assert_eq!(mismatch.expected, payload.gas_limit());
    }

    #[test]
    fn test_validate_message_against_payload_gas_used_mismatch() {
        let payload = test_execution_payload();
        let mut message = matching_bid_trace(&payload);
        message.gas_used += 1;

        let err = validate_message_against_payload(&message, &payload).unwrap_err();
        let ValidationApiError::GasUsedMismatch(mismatch) = err else {
            panic!("unexpected error: {err}")
        };
        assert_eq!(mismatch.got, message.gas_used);
        assert_eq!(mismatch.expected, payload.as_v1().gas_used);
    }

    fn test_v6_request() -> BuilderBlockValidationRequestV6 {
        let ExecutionPayload::V1(payload_v1) = test_execution_payload() else { unreachable!() };

        BuilderBlockValidationRequestV6 {
            request: SignedBidSubmissionV6 {
                message: BidTrace::default(),
                execution_payload: ExecutionPayloadV4 {
                    payload_inner: ExecutionPayloadV3 {
                        payload_inner: ExecutionPayloadV2 {
                            payload_inner: payload_v1,
                            withdrawals: Vec::new(),
                        },
                        blob_gas_used: 0,
                        excess_blob_gas: 0,
                    },
                    block_access_list: Bytes::from_static(&[0xaa, 0xbb]),
                    slot_number: 6,
                },
                blobs_bundle: Default::default(),
                execution_requests: ExecutionRequestsV5::default(),
                signature: Default::default(),
            },
            registered_gas_limit: 30_000_000,
            parent_beacon_block_root: B256::ZERO,
            transaction_filter: TransactionFilter::None,
        }
    }

    /// EIP-8282 builder deposit requests observed on glamsterdam devnet-8 (relay registry
    /// topups), reconstructed from the builder deposit predeploy logs of the named blocks.
    /// The expected hashes are the blocks' on-chain `requestsHash` header fields, so this
    /// proves the typed representation reproduces the EIP-7685 commitment for real gloas-era
    /// blocks carrying builder requests.
    #[test]
    fn test_devnet8_builder_deposit_requests_hash() {
        let pubkey = FixedBytes::from(hex!(
            "a44d606ec070d7252f1fdbff753ae5913615f0d323b93dd403ad99d2706b4bcfd96d258a4327538acb6282e1ae7397ed"
        ));
        let withdrawal_credentials =
            b256!("b00000000000000000000000a4449f1cfb6476994842c346fad9ec7cd15380bd");

        let cases = [
            // block 210258
            (
                91_000_000_000u64,
                hex!(
                    "95a3bb94fbf447868213462857b574bb840f4299b4e603c3016f9a86b23086395d43d13be362c1e9179c82d28415e0eb044300f5f2d1c90ddf446eea31e279de0c9d3163a7fef26742e4c0952a03306319d2a87bd0cbd7c1100ca0e6ee5e747a"
                ),
                b256!("1c85a255985080d1ee0ae90ed6e4825ab75e64b316783684ea83c1d9709cf6af"),
            ),
            // block 216118
            (
                500_000_000_000u64,
                hex!(
                    "ae171b037a065264d90d2eee298f54a2e13465b18b171457fc4e2714fd8b687415c8eae08e4750f0829a03277523ff730a1198df2b4272062fafaa024f7a106794f21534754919f0ea8f3811dec78d951198da3badf9f853563b46cf2c83b6a3"
                ),
                b256!("79b08a123c1a895a75b0dd2edf13667ff1a71c442baa729040363a408afa1b15"),
            ),
        ];

        for (amount, signature, expected_requests_hash) in cases {
            let requests = ExecutionRequestsV5 {
                builder_deposits: vec![BuilderDepositRequest {
                    pubkey,
                    withdrawal_credentials,
                    amount,
                    signature: FixedBytes::from(signature),
                }],
                ..Default::default()
            };

            assert_eq!(requests.to_requests().requests_hash(), expected_requests_hash);
        }
    }

    /// Builder pubkey of the relay's devnet-8 registry entry, reused by the builder-exit cases
    /// below so they exercise realistically shaped (not repeat-byte) inputs.
    fn devnet8_builder_pubkey() -> FixedBytes<48> {
        FixedBytes::from(hex!(
            "a44d606ec070d7252f1fdbff753ae5913615f0d323b93dd403ad99d2706b4bcfd96d258a4327538acb6282e1ae7397ed"
        ))
    }

    /// Withdrawal address embedded in the relay's `0xb0…` builder withdrawal credentials, which
    /// is also the address that would submit a builder exit for that entry.
    fn devnet8_builder_source_address() -> Address {
        address!("0xa4449f1cfb6476994842c346fad9ec7cd15380bd")
    }

    fn devnet8_builder_deposits() -> Vec<BuilderDepositRequest> {
        let withdrawal_credentials =
            b256!("b00000000000000000000000a4449f1cfb6476994842c346fad9ec7cd15380bd");

        vec![
            BuilderDepositRequest {
                pubkey: devnet8_builder_pubkey(),
                withdrawal_credentials,
                amount: 91_000_000_000,
                signature: FixedBytes::from(hex!(
                    "95a3bb94fbf447868213462857b574bb840f4299b4e603c3016f9a86b23086395d43d13be362c1e9179c82d28415e0eb044300f5f2d1c90ddf446eea31e279de0c9d3163a7fef26742e4c0952a03306319d2a87bd0cbd7c1100ca0e6ee5e747a"
                )),
            },
            BuilderDepositRequest {
                pubkey: FixedBytes::repeat_byte(0xb0),
                withdrawal_credentials,
                amount: 500_000_000_000,
                signature: FixedBytes::from(hex!(
                    "ae171b037a065264d90d2eee298f54a2e13465b18b171457fc4e2714fd8b687415c8eae08e4750f0829a03277523ff730a1198df2b4272062fafaa024f7a106794f21534754919f0ea8f3811dec78d951198da3badf9f853563b46cf2c83b6a3"
                )),
            },
        ]
    }

    /// No devnet block has carried a builder exit (`0x04`) yet, so the expected commitments here
    /// come from an independent reimplementation of the EIP-7685 hash (SSZ fixed-size container
    /// concatenation, then `sha256(concat(sha256(type || data)))` over non-empty requests only)
    /// that was first checked against the two real on-chain hashes asserted in
    /// [`test_devnet8_builder_deposit_requests_hash`]. Exercising exits this way still pins the
    /// `0x04` type byte, the 68-byte `source_address ++ pubkey` layout and the list ordering.
    #[test]
    fn test_builder_exit_requests_hash() {
        let requests = ExecutionRequestsV5 {
            builder_exits: vec![BuilderExitRequest {
                source_address: devnet8_builder_source_address(),
                pubkey: devnet8_builder_pubkey(),
            }],
            ..Default::default()
        };

        assert_eq!(
            requests.to_requests().requests_hash(),
            b256!("f9799dae8c2b40782f525d1d7bd54da6a31515e6f056945153513f660b8009ca")
        );
    }

    /// A block carrying Electra and gloas request types together: the `0x03`/`0x04` builder
    /// requests must be committed alongside the Electra ones, in ascending type order, without
    /// disturbing them.
    #[test]
    fn test_mixed_electra_and_builder_requests_hash() {
        let withdrawals = vec![WithdrawalRequest {
            source_address: devnet8_builder_source_address(),
            validator_pubkey: devnet8_builder_pubkey(),
            amount: 0,
        }];
        let builder_exits = vec![
            BuilderExitRequest {
                source_address: devnet8_builder_source_address(),
                pubkey: devnet8_builder_pubkey(),
            },
            BuilderExitRequest {
                source_address: devnet8_builder_source_address(),
                pubkey: FixedBytes::repeat_byte(0xb0),
            },
        ];

        let requests = ExecutionRequestsV5 {
            withdrawals: withdrawals.clone(),
            builder_deposits: devnet8_builder_deposits(),
            builder_exits: builder_exits.clone(),
            ..Default::default()
        };

        assert_eq!(
            requests.to_requests().requests_hash(),
            b256!("0ea2b4ddd21d4cbca90bb0391e65120cab2d5b5fd093e84357362bdab9df2fe5")
        );

        // Request order inside a list is committed to, so a reordered exit list must not
        // reproduce the same commitment.
        let reordered = ExecutionRequestsV5 {
            withdrawals,
            builder_deposits: devnet8_builder_deposits(),
            builder_exits: builder_exits.into_iter().rev().collect(),
            ..Default::default()
        };

        assert_eq!(
            reordered.to_requests().requests_hash(),
            b256!("7a80e960aba502bd450ee7381cd5bf42a178b6098beb54ed9a1e95cce5a9d2b2")
        );
    }

    /// The `execution_requests` object on the RPC body is the surface a relay actually posts, so
    /// the builder lists must survive JSON as well as SSZ -- and an Electra-shaped body (no
    /// builder keys at all) must still parse, which is what keeps V6 callers working.
    #[test]
    fn test_v6_body_carries_builder_requests_over_json() {
        let mut request = test_v6_request();
        request.request.execution_requests = ExecutionRequestsV5 {
            builder_deposits: devnet8_builder_deposits(),
            builder_exits: vec![BuilderExitRequest {
                source_address: devnet8_builder_source_address(),
                pubkey: devnet8_builder_pubkey(),
            }],
            ..Default::default()
        };

        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json["execution_requests"]["builder_deposits"].as_array().unwrap().len(), 2);
        assert_eq!(json["execution_requests"]["builder_exits"].as_array().unwrap().len(), 1);

        let parsed: BuilderBlockValidationRequestV6 = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(parsed, request);

        let mut electra_shaped = json;
        electra_shaped["execution_requests"] =
            serde_json::json!({ "deposits": [], "withdrawals": [], "consolidations": [] });

        let parsed: BuilderBlockValidationRequestV6 =
            serde_json::from_value(electra_shaped).unwrap();
        assert!(parsed.request.execution_requests.builder_deposits.is_empty());
        assert!(parsed.request.execution_requests.builder_exits.is_empty());
    }

    /// The opaque EIP-7685 wire form a relay forwards is what the node decodes back into typed
    /// requests, so a mixed gloas block must survive that round trip unchanged.
    #[test]
    fn test_mixed_builder_requests_round_trip_through_wire_form() {
        let requests = ExecutionRequestsV5 {
            builder_deposits: devnet8_builder_deposits(),
            builder_exits: vec![BuilderExitRequest {
                source_address: devnet8_builder_source_address(),
                pubkey: devnet8_builder_pubkey(),
            }],
            ..Default::default()
        };

        let decoded = ExecutionRequestsV5::try_from(&requests.to_requests()).unwrap();

        assert_eq!(decoded, requests);
    }

    /// 4-byte big-endian timestamp followed by the 20-byte recipient.
    fn forwarder_calldata(recipient: Address, timestamp: u32) -> Vec<u8> {
        let mut input = timestamp.to_be_bytes().to_vec();
        input.extend_from_slice(recipient.as_slice());
        input
    }

    #[test]
    fn payment_forwarder_defaults_to_the_canonical_deployment() {
        assert_eq!(*PAYMENT_FORWARDER, DEFAULT_PAYMENT_FORWARDER);
    }

    /// If this stops matching, the contract changed and its address changed with it.
    #[test]
    fn payment_forwarder_code_hash_matches_the_deployed_runtime() {
        let runtime = alloy_primitives::hex!("5f358060e01c4218600f5760401cff5b5f5ffd00");

        assert_eq!(keccak256(runtime), PAYMENT_FORWARDER_CODE_HASH);
    }

    #[test]
    fn payment_forwarder_recipient_reads_the_encoded_address() {
        let recipient = Address::from([7u8; 20]);
        let input = forwarder_calldata(recipient, 1_760_000_000);

        assert_eq!(input.len(), PAYMENT_FORWARDER_CALLDATA_LEN);
        assert_eq!(payment_forwarder_recipient(&input), Some(recipient));
    }

    #[test]
    fn payment_forwarder_recipient_rejects_short_calldata() {
        let recipient = Address::from([7u8; 20]);

        for len in 0..PAYMENT_FORWARDER_CALLDATA_LEN {
            let mut input = forwarder_calldata(recipient, 1_760_000_000);
            input.truncate(len);

            assert_eq!(payment_forwarder_recipient(&input), None, "accepted {len} bytes");
        }
    }

    #[test]
    fn payment_forwarder_recipient_ignores_trailing_calldata() {
        let recipient = Address::from([7u8; 20]);

        for extra in 1..=64usize {
            let mut input = forwarder_calldata(recipient, 1_760_000_000);
            input.extend(std::iter::repeat_n(0xABu8, extra));

            assert_eq!(
                payment_forwarder_recipient(&input),
                Some(recipient),
                "misparsed with {extra} trailing bytes"
            );
        }
    }

    #[test]
    fn payment_forwarder_recipient_ignores_the_timestamp_value() {
        let recipient = Address::from([7u8; 20]);

        for timestamp in [0u32, 1, 1_760_000_000, u32::MAX] {
            assert_eq!(
                payment_forwarder_recipient(&forwarder_calldata(recipient, timestamp)),
                Some(recipient)
            );
        }
    }

    #[test]
    fn test_hash_disallow_list_deterministic() {
        let mut addresses = AddressSet::default();
        addresses.insert(Address::from([1u8; 20]));
        addresses.insert(Address::from([2u8; 20]));

        let hash1 = hash_disallow_list(&addresses);
        let hash2 = hash_disallow_list(&addresses);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_disallow_list_different_content() {
        let mut addresses1 = AddressSet::default();
        addresses1.insert(Address::from([1u8; 20]));

        let mut addresses2 = AddressSet::default();
        addresses2.insert(Address::from([2u8; 20]));

        let hash1 = hash_disallow_list(&addresses1);
        let hash2 = hash_disallow_list(&addresses2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_disallow_list_order_independent() {
        let mut addresses1 = AddressSet::default();
        addresses1.insert(Address::from([1u8; 20]));
        addresses1.insert(Address::from([2u8; 20]));

        let mut addresses2 = AddressSet::default();
        addresses2.insert(Address::from([2u8; 20])); // Different insertion order
        addresses2.insert(Address::from([1u8; 20]));

        let hash1 = hash_disallow_list(&addresses1);
        let hash2 = hash_disallow_list(&addresses2);

        assert_eq!(hash1, hash2);
    }

    #[test]
    //ensures parity with rbuilder hashing https://github.com/flashbots/rbuilder/blob/962c8444cdd490a216beda22c7eec164db9fc3ac/crates/rbuilder/src/live_builder/block_list_provider.rs#L248
    fn test_disallow_list_hash_rbuilder_parity() {
        let json = r#"["0x05E0b5B40B7b66098C2161A5EE11C5740A3A7C45","0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1","0x03893a7c7463AE47D46bc7f091665f1893656003","0x04DBA1194ee10112fE6C3207C0687DEf0e78baCf"]"#;
        let blocklist: Vec<Address> = serde_json::from_str(json).unwrap();
        let blocklist: AddressSet = blocklist.into_iter().collect();
        let expected_hash = "ee14e9d115e182f61871a5a385ab2f32ecf434f3b17bdbacc71044810d89e608";
        let hash = hash_disallow_list(&blocklist);
        assert_eq!(expected_hash, hash);
    }

    /// Only [`ValidationApi::validate_message_against_block`] is exercised below, which never
    /// converts a payload.
    #[derive(Debug)]
    struct UnusedPayloadValidator;

    impl PayloadValidator<EthPayloadTypes> for UnusedPayloadValidator {
        type Block = Block;

        fn convert_payload_to_block(
            &self,
            _payload: ExecutionData,
        ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
            unimplemented!()
        }
    }

    fn test_validation_api(
        provider: MockEthProvider,
    ) -> ValidationApi<MockEthProvider, EthEvmConfig, EthPayloadTypes> {
        ValidationApi::new(
            provider,
            NoopConsensus::arc(),
            EthEvmConfig::mainnet(),
            ValidationApiConfig::default(),
            Runtime::test(),
            Arc::new(UnusedPayloadValidator),
        )
    }

    /// A submission whose payload pays the proposer nothing, like a trustless ePBS bid: there the
    /// payment settles from the builder's stake on the consensus layer.
    fn payment_free_submission() -> (MockEthProvider, RecoveredBlock<Block>, BidTrace) {
        let provider = MockEthProvider::default();

        let parent = Header { gas_limit: 30_000_000, ..Default::default() };
        let parent = SealedHeader::seal_slow(parent);
        provider.add_block(
            parent.hash(),
            Block { header: parent.clone_header(), body: Default::default() },
        );

        let header = Header {
            parent_hash: parent.hash(),
            number: parent.number() + 1,
            gas_limit: parent.gas_limit(),
            timestamp: parent.timestamp() + 12,
            ..Default::default()
        };
        let block = SealedBlock::seal_slow(Block { header, body: Default::default() })
            .try_recover()
            .unwrap();
        provider.state_roots.lock().push(block.state_root());

        let message = BidTrace {
            parent_hash: block.parent_hash(),
            block_hash: block.hash(),
            gas_limit: block.gas_limit(),
            gas_used: block.gas_used(),
            proposer_fee_recipient: Address::repeat_byte(0x42),
            value: U256::from(1_000_000_000_000_000_000u64),
            ..Default::default()
        };

        (provider, block, message)
    }

    #[tokio::test]
    async fn test_payment_check_runs_for_a_nonzero_bid() {
        let (provider, block, message) = payment_free_submission();
        let registered_gas_limit = block.gas_limit();

        let err = test_validation_api(provider)
            .validate_message_against_block(
                block,
                message,
                registered_gas_limit,
                TransactionFilter::None,
                None,
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationApiError::ProposerPayment), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_zero_value_bid_skips_the_payment_check() {
        let (provider, block, mut message) = payment_free_submission();
        let registered_gas_limit = block.gas_limit();
        message.value = U256::ZERO;

        test_validation_api(provider)
            .validate_message_against_block(
                block,
                message,
                registered_gas_limit,
                TransactionFilter::None,
                None,
            )
            .await
            .unwrap();
    }

    /// A zero-value bid promises the proposer nothing, so there is nothing to verify. The
    /// balance-delta branch already lets one through whenever the fee recipient's balance does
    /// not fall -- but a fee recipient that merely sends a transaction of its own in the same
    /// block ends it poorer, drops through to the last-transaction fallback and is rejected.
    #[test]
    fn test_zero_value_bid_is_accepted_when_the_fee_recipient_spends() {
        let (provider, block, mut message) = payment_free_submission();
        message.value = U256::ZERO;

        let output = BlockExecutionOutput {
            result: Default::default(),
            state: fee_recipient_spent(message.proposer_fee_recipient),
        };

        test_validation_api(provider)
            .ensure_payment(block.sealed_block(), &output, &message)
            .unwrap();
    }

    /// Execution state for a block in which `address` ended up poorer than it started.
    fn fee_recipient_spent(address: Address) -> BundleState {
        let balance =
            |wei: u64| Some(AccountInfo { balance: U256::from(wei), ..Default::default() });

        let mut state = BundleState::default();
        state.state.insert(
            address,
            BundleAccount {
                original_info: balance(1_000),
                info: balance(999),
                storage: Default::default(),
                status: AccountStatus::Changed,
            },
        );
        state
    }
}
