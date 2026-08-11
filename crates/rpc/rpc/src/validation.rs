use alloy_consensus::{
    BlobTransactionValidationError, BlockHeader, EnvKzgSettings, Transaction, TxReceipt,
};
use alloy_eips::{eip4844::kzg_to_versioned_hash, eip7685::RequestsOrHash};
use alloy_primitives::map::AddressSet;
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
    constants::GAS_LIMIT_BOUND_DIVISOR, BlockBody, GotExpected, NodePrimitives, RecoveredBlock,
    SealedBlock, SealedHeaderFor,
};
use reth_revm::{cached::CachedReads, database::StateProviderDatabase};
use reth_rpc_api::{
    BlockSubmissionValidationApiServer, BuilderBlockValidationRequestV3,
    BuilderBlockValidationRequestV4, BuilderBlockValidationRequestV5, TransactionFilter,
};
use reth_rpc_server_types::result::{internal_rpc_err, invalid_params_rpc_err};
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use reth_tasks::Runtime;
use revm_primitives::{address, b256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use tokio::sync::{oneshot, RwLock};
use tracing::warn;

/// <https://github.com/gattaca-com/helix/pull/466>.
const DEFAULT_PAYMENT_FORWARDERS: [(Address, B256); 1] = [(
    address!("0xFEEEEEE44046c3f61a8CC081E0918eF0de0a7ffC"),
    b256!("0xd9f5db49d3c0a174c39701485406cd78d01dd27f73b7ef7b883e5f69d8103220"),
)];

const PAYMENT_FORWARDERS_VAR: &str = "PAYMENT_FORWARDERS";

/// Accepted forwarders, as comma-separated `address:code_hash` pairs.
///
/// A list rather than one entry so a redeployment can be accepted alongside the old contract,
/// instead of needing a flag day where one of the two is rejected.
///
/// The code hash is part of the entry and never inferred from the chain: a value call to a
/// codeless address succeeds and keeps the value, so an address on its own would validate a
/// payment the recipient never received.
pub(crate) static PAYMENT_FORWARDERS: LazyLock<HashMap<Address, B256>> =
    LazyLock::new(|| match std::env::var(PAYMENT_FORWARDERS_VAR) {
        Ok(value) => parse_payment_forwarders(&value)
            .unwrap_or_else(|error| panic!("{PAYMENT_FORWARDERS_VAR} is invalid: {error}")),
        Err(_) => DEFAULT_PAYMENT_FORWARDERS.into_iter().collect(),
    });

/// Rejects an empty list: disabling forwarder payments is not a configuration we want to reach
/// by accident, and a typo that parsed to nothing would silently demote every builder using one.
fn parse_payment_forwarders(value: &str) -> Result<HashMap<Address, B256>, String> {
    let forwarders = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (address, code_hash) = entry
                .split_once(':')
                .ok_or_else(|| format!("expected `address:code_hash`, got `{entry}`"))?;

            Ok((
                address
                    .trim()
                    .parse::<Address>()
                    .map_err(|_| format!("invalid address `{address}`"))?,
                code_hash
                    .trim()
                    .parse::<B256>()
                    .map_err(|_| format!("invalid code hash `{code_hash}`"))?,
            ))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;

    if forwarders.is_empty() {
        return Err("no forwarders configured".to_string());
    }

    Ok(forwarders)
}

/// `[4-byte timestamp][20-byte recipient]`
const PAYMENT_FORWARDER_CALLDATA_LEN: usize = 24;

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
    ) -> Result<(), ValidationApiError> {
        self.validate_message_against_header(block.sealed_header(), &message)?;

        self.consensus.validate_header(block.sealed_header())?;
        self.consensus.validate_block_pre_execution(block.sealed_block())?;

        let disallow =
            (transaction_filter == TransactionFilter::OFAC).then(|| self.disallow.read().clone());

        if let Some(disallow) = &disallow {
            if disallow.contains(&block.beneficiary()) {
                return Err(ValidationApiError::Blacklist(block.beneficiary()));
            }
            if disallow.contains(&message.proposer_fee_recipient) {
                return Err(ValidationApiError::Blacklist(message.proposer_fee_recipient));
            }
            for (sender, tx) in block.senders_iter().zip(block.body().transactions()) {
                if disallow.contains(sender) {
                    return Err(ValidationApiError::Blacklist(*sender));
                }
                if let Some(to) = tx.to() &&
                    disallow.contains(&to)
                {
                    return Err(ValidationApiError::Blacklist(to));
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
                return Err(ValidationApiError::BlockTooOld);
            }
            parent_header
        };

        self.consensus.validate_header_against_parent(block.sealed_header(), &parent_header)?;
        self.validate_gas_limit(registered_gas_limit, &parent_header, block.sealed_header())?;
        let parent_header_hash = parent_header.hash();
        let state_provider = self.provider.state_by_block_hash(parent_header_hash)?;

        let mut request_cache = self.cached_reads(parent_header_hash).await;

        let cached_db = request_cache.as_db_mut(StateProviderDatabase::new(&state_provider));
        let executor = self.evm_config.batch_executor(cached_db);

        let mut accessed_blacklisted = None;
        let output = executor.execute_with_state_closure(&block, |state| {
            if let Some(disallow) = &disallow {
                // Check whether the submission interacted with any blacklisted account by scanning
                // the `State`'s cache that records everything read from database during execution.
                for account in state.cache.accounts.keys() {
                    if disallow.contains(account) {
                        accessed_blacklisted = Some(*account);
                    }
                }
            }
        })?;

        if let Some(account) = accessed_blacklisted {
            return Err(ValidationApiError::Blacklist(account));
        }

        // update the cached reads
        self.update_cached_reads(parent_header_hash, request_cache).await;

        self.consensus.validate_block_post_execution(&block, &output, None)?;

        self.ensure_payment(&block, &output, &message)?;

        let state_root =
            state_provider.state_root(state_provider.hashed_post_state(&output.state))?;

        if state_root != block.header().state_root() {
            return Err(ConsensusError::BodyStateRootDiff(
                GotExpected { got: state_root, expected: block.header().state_root() }.into(),
            )
            .into());
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

    /// Ensures that the chosen gas limit is the closest possible value for the validator's
    /// registered gas limit.
    ///
    /// Ref: <https://github.com/flashbots/builder/blob/a742641e24df68bc2fc476199b012b0abce40ffe/core/blockchain.go#L2474-L2477>
    fn validate_gas_limit(
        &self,
        registered_gas_limit: u64,
        parent_header: &SealedHeaderFor<E::Primitives>,
        header: &SealedHeaderFor<E::Primitives>,
    ) -> Result<(), ValidationApiError> {
        let max_gas_limit =
            parent_header.gas_limit() + parent_header.gas_limit() / GAS_LIMIT_BOUND_DIVISOR - 1;
        let min_gas_limit =
            parent_header.gas_limit() - parent_header.gas_limit() / GAS_LIMIT_BOUND_DIVISOR + 1;

        let best_gas_limit =
            std::cmp::max(min_gas_limit, std::cmp::min(max_gas_limit, registered_gas_limit));

        if best_gas_limit != header.gas_limit() {
            return Err(ValidationApiError::GasLimitMismatch(GotExpected {
                got: header.gas_limit(),
                expected: best_gas_limit,
            }));
        }

        Ok(())
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
            return Ok(());
        }

        let (receipt, tx) = output
            .receipts
            .last()
            .zip(block.body().transactions().last())
            .ok_or(ValidationApiError::ProposerPayment)?;

        if !receipt.status() {
            return Err(ValidationApiError::ProposerPayment);
        }

        let paid_directly =
            tx.to() == Some(message.proposer_fee_recipient) && tx.input().is_empty();
        let paid_via_forwarder = tx.to().is_some_and(|to| {
            PAYMENT_FORWARDERS.get(&to).is_some_and(|code_hash| {
                payment_forwarder_recipient(tx.input()) == Some(message.proposer_fee_recipient) &&
                    output.state.state.get(&to).is_some_and(|account| {
                        account.info.as_ref().is_some_and(|info| info.code_hash == *code_hash)
                    })
            })
        });

        if !paid_directly && !paid_via_forwarder {
            return Err(ValidationApiError::ProposerPayment);
        }

        if tx.value() != message.value {
            return Err(ValidationApiError::ProposerPayment);
        }

        if let Some(block_base_fee) = block.header().base_fee_per_gas() &&
            tx.effective_tip_per_gas(block_base_fee).unwrap_or_default() != 0
        {
            return Err(ValidationApiError::ProposerPayment);
        }

        Ok(())
    }

    /// Validates the given [`BlobsBundleV1`] and returns versioned hashes for blobs.
    pub fn validate_blobs_bundle(
        &self,
        mut blobs_bundle: BlobsBundleV1,
    ) -> Result<Vec<B256>, ValidationApiError> {
        if blobs_bundle.commitments.len() != blobs_bundle.proofs.len() ||
            blobs_bundle.commitments.len() != blobs_bundle.blobs.len()
        {
            return Err(ValidationApiError::InvalidBlobsBundle);
        }

        let versioned_hashes = blobs_bundle
            .commitments
            .iter()
            .map(|c| kzg_to_versioned_hash(c.as_slice()))
            .collect::<Vec<_>>();

        let sidecar = blobs_bundle.pop_sidecar(blobs_bundle.blobs.len());

        sidecar.validate(&versioned_hashes, EnvKzgSettings::default().get())?;

        Ok(versioned_hashes)
    }
    /// Validates the given [`BlobsBundleV1`] and returns versioned hashes for blobs.
    pub fn validate_blobs_bundle_v2(
        &self,
        blobs_bundle: BlobsBundleV2,
    ) -> Result<Vec<B256>, ValidationApiError> {
        let versioned_hashes = blobs_bundle
            .commitments
            .iter()
            .map(|c| kzg_to_versioned_hash(c.as_slice()))
            .collect::<Vec<_>>();

        blobs_bundle
            .try_into_sidecar()
            .map_err(|_| ValidationApiError::InvalidBlobsBundle)?
            .validate(&versioned_hashes, EnvKzgSettings::default().get())?;

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
        )
        .await
    }

    /// Core logic for validating the builder submission v5
    async fn validate_builder_submission_v5(
        &self,
        request: BuilderBlockValidationRequestV5,
    ) -> Result<(), ValidationApiError> {
        let block = self.payload_validator.ensure_well_formed_payload(ExecutionData {
            payload: ExecutionPayload::V3(request.request.execution_payload),
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
        if chain_spec.is_osaka_active_at_timestamp(block.timestamp()) &&
            block.rlp_length() > MAX_RLP_BLOCK_SIZE
        {
            return Err(ValidationApiError::Consensus(ConsensusError::BlockTooLarge {
                rlp_length: block.rlp_length(),
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        self.validate_message_against_block(
            block,
            request.request.message,
            request.registered_gas_limit,
            request.transaction_filter,
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
            ValidationApiError::Blob(_) => invalid_params_rpc_err(error.to_string()),

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
        hash_disallow_list, parse_payment_forwarders, payment_forwarder_recipient, AddressSet,
        DEFAULT_PAYMENT_FORWARDERS, PAYMENT_FORWARDERS, PAYMENT_FORWARDER_CALLDATA_LEN,
    };
    use alloy_primitives::keccak256;
    use revm_primitives::{Address, B256};
    use std::collections::HashMap;

    /// 4-byte big-endian timestamp followed by the 20-byte recipient.
    fn forwarder_calldata(recipient: Address, timestamp: u32) -> Vec<u8> {
        let mut input = timestamp.to_be_bytes().to_vec();
        input.extend_from_slice(recipient.as_slice());
        input
    }

    #[test]
    fn payment_forwarders_default_to_the_canonical_deployment() {
        let expected: HashMap<Address, B256> = DEFAULT_PAYMENT_FORWARDERS.into_iter().collect();

        assert_eq!(*PAYMENT_FORWARDERS, expected);
    }

    /// If this stops matching, the contract changed and its address changed with it.
    #[test]
    fn payment_forwarder_code_hash_matches_the_deployed_runtime() {
        let runtime = alloy_primitives::hex!("5f358060e01c4218600f5760401cff5b5f5ffd00");
        let (_, code_hash) = DEFAULT_PAYMENT_FORWARDERS[0];

        assert_eq!(keccak256(runtime), code_hash);
    }

    /// The migration case: both deployments accepted at once, each pinned to its own code hash.
    #[test]
    fn parse_payment_forwarders_reads_several_pairs() {
        let old = Address::from([1u8; 20]);
        let new = Address::from([2u8; 20]);
        let old_hash = B256::from([3u8; 32]);
        let new_hash = B256::from([4u8; 32]);

        let parsed =
            parse_payment_forwarders(&format!(" {old}:{old_hash} , {new}:{new_hash} ")).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get(&old), Some(&old_hash));
        assert_eq!(parsed.get(&new), Some(&new_hash));
    }

    /// A typo must not silently parse to a list that accepts nothing - that would demote every
    /// builder paying through a forwarder.
    #[test]
    fn parse_payment_forwarders_rejects_malformed_input() {
        let address = Address::from([1u8; 20]);
        let hash = B256::from([3u8; 32]);

        for input in [
            String::new(),
            "  ,  ".to_string(),
            format!("{address}"),
            format!("{address}:"),
            format!(":{hash}"),
            format!("{address}:0xnothex"),
            format!("notanaddress:{hash}"),
        ] {
            assert!(parse_payment_forwarders(&input).is_err(), "accepted `{input}`");
        }
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
}
