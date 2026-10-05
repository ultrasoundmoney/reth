//! SSZ transport for the builder block validation API.
//!
//! The relay reaches validation through prio-load-balancer, which queues request bodies as
//! opaque bytes. Taking the submission SSZ-encoded skips the JSON encoding and decoding of
//! multi-megabyte payloads on both ends; validation itself runs through the same
//! [`BlockSubmissionValidationApiServer`] handler as the JSON-RPC method.

use alloy_primitives::B256;
use alloy_rpc_types_beacon::relay::{SignedBidSubmissionV5, SignedBidSubmissionV6};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming,
    header::{HeaderValue, CONTENT_TYPE},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use reth_rpc_api::{
    servers::BlockSubmissionValidationApiServer, BuilderBlockValidationRequestV5,
    BuilderBlockValidationRequestV6, TransactionFilter,
};
use reth_tracing::tracing::{debug, warn};
use ssz::Decode;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpListener;

/// Keeps a persistent accept error, e.g. running out of file descriptors, from spinning a core
/// that validation needs.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The request body. The union selector carries the request version, so a new version needs no
/// change in prio-load-balancer, which routes on the content type alone.
#[derive(Debug, ssz_derive::Encode, ssz_derive::Decode)]
#[ssz(enum_behaviour = "union")]
pub enum SszValidationRequest {
    /// The request of `flashbots_validateBuilderSubmissionV5`.
    V5(SszValidationRequestV5),
    /// The request of `flashbots_validateBuilderSubmissionV6`.
    V6(SszValidationRequestV6),
}

/// [`BuilderBlockValidationRequestV5`] with the transaction filter as a byte: 0 is none, 1 is
/// OFAC.
#[derive(Debug, ssz_derive::Encode, ssz_derive::Decode)]
pub struct SszValidationRequestV5 {
    /// The registered gas limit for the validation request.
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    /// The transaction filter to apply.
    pub transaction_filter: u8,
    /// The submission to validate.
    pub request: SignedBidSubmissionV5,
}

impl SszValidationRequestV5 {
    fn into_validation_request(self) -> Result<BuilderBlockValidationRequestV5, String> {
        Ok(BuilderBlockValidationRequestV5 {
            request: self.request,
            registered_gas_limit: self.registered_gas_limit,
            parent_beacon_block_root: self.parent_beacon_block_root,
            transaction_filter: decode_transaction_filter(self.transaction_filter)?,
        })
    }
}

/// [`BuilderBlockValidationRequestV6`] with the transaction filter as a byte: 0 is none, 1 is
/// OFAC.
#[derive(Debug, ssz_derive::Encode, ssz_derive::Decode)]
pub struct SszValidationRequestV6 {
    /// The registered gas limit for the validation request.
    pub registered_gas_limit: u64,
    /// The parent beacon block root for the validation request.
    pub parent_beacon_block_root: B256,
    /// The transaction filter to apply.
    pub transaction_filter: u8,
    /// The submission to validate.
    pub request: SignedBidSubmissionV6,
}

impl SszValidationRequestV6 {
    fn into_validation_request(self) -> Result<BuilderBlockValidationRequestV6, String> {
        Ok(BuilderBlockValidationRequestV6 {
            request: self.request,
            registered_gas_limit: self.registered_gas_limit,
            parent_beacon_block_root: self.parent_beacon_block_root,
            transaction_filter: decode_transaction_filter(self.transaction_filter)?,
        })
    }
}

fn decode_transaction_filter(byte: u8) -> Result<TransactionFilter, String> {
    match byte {
        0 => Ok(TransactionFilter::None),
        1 => Ok(TransactionFilter::OFAC),
        other => Err(format!("unknown transaction filter {other}")),
    }
}

/// A decoded request, ready for the handler of its version.
#[derive(Debug)]
enum ValidationRequest {
    V5(BuilderBlockValidationRequestV5),
    V6(BuilderBlockValidationRequestV6),
}

/// Serves [`SszValidationRequest`]s on `listener` until the node shuts down.
///
/// Every validated request gets a 200 with a JSON-RPC-shaped body carrying the same result or
/// error as the JSON-RPC method, whether the block is valid or not. prio-load-balancer takes any
/// status of 400 or above as a node failure and retries it on another node, so that status is
/// kept for bodies that never reach validation: those are relay bugs, not a verdict on the
/// builder's block.
pub async fn serve<Api>(listener: TcpListener, api: Api, max_request_size: usize)
where
    Api: BlockSubmissionValidationApiServer + Clone,
{
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                warn!(target: "rpc::flashbots", %error, "failed to accept ssz validation connection");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue
            }
        };

        let api = api.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| handle(api.clone(), max_request_size, request));

            if let Err(error) =
                http1::Builder::new().serve_connection(TokioIo::new(stream), service).await
            {
                debug!(target: "rpc::flashbots", %error, "ssz validation connection failed");
            }
        });
    }
}

async fn handle<Api>(
    api: Api,
    max_request_size: usize,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible>
where
    Api: BlockSubmissionValidationApiServer,
{
    if request.method() != Method::POST {
        return Ok(text_response(StatusCode::METHOD_NOT_ALLOWED, "expected POST".to_string()))
    }

    let body = match Limited::new(request.into_body(), max_request_size).collect().await {
        Ok(body) => body.to_bytes(),
        Err(error) => return Ok(text_response(StatusCode::BAD_REQUEST, error.to_string())),
    };

    let request = match decode_request(&body) {
        Ok(request) => request,
        Err(error) => return Ok(text_response(StatusCode::BAD_REQUEST, error)),
    };

    let result = match request {
        ValidationRequest::V5(request) => api.validate_builder_submission_v5(request).await,
        ValidationRequest::V6(request) => api.validate_builder_submission_v6(request).await,
    };

    let body = match result {
        Ok(()) => serde_json::json!({ "jsonrpc": "2.0", "id": null, "result": null }),
        Err(error) => serde_json::json!({ "jsonrpc": "2.0", "id": null, "error": error }),
    };

    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}

fn decode_request(body: &[u8]) -> Result<ValidationRequest, String> {
    match SszValidationRequest::from_ssz_bytes(body)
        .map_err(|error| format!("invalid ssz validation request: {error:?}"))?
    {
        SszValidationRequest::V5(request) => {
            request.into_validation_request().map(ValidationRequest::V5)
        }
        SszValidationRequest::V6(request) => {
            request.into_validation_request().map(ValidationRequest::V6)
        }
    }
}

fn text_response(status: StatusCode, message: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(message)));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::{
        decode_request, SszValidationRequest, SszValidationRequestV5, SszValidationRequestV6,
        ValidationRequest,
    };
    use alloy_eips::eip8282::{BuilderDepositRequest, BuilderExitRequest};
    use alloy_primitives::{Address, Bloom, Bytes, FixedBytes, B256, U256};
    use alloy_rpc_types_beacon::{
        relay::{BidTrace, SignedBidSubmissionV5, SignedBidSubmissionV6},
        requests::ExecutionRequestsV5,
    };
    use alloy_rpc_types_engine::{
        BlobsBundleV2, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
        ExecutionPayloadV4,
    };
    use reth_rpc_api::{BuilderBlockValidationRequestV6, TransactionFilter};
    use ssz::Encode;

    fn test_submission() -> SignedBidSubmissionV5 {
        SignedBidSubmissionV5 {
            message: BidTrace { slot: 7, gas_limit: 30_000_000, ..Default::default() },
            execution_payload: ExecutionPayloadV3 {
                payload_inner: ExecutionPayloadV2 {
                    payload_inner: ExecutionPayloadV1 {
                        parent_hash: B256::repeat_byte(0x01),
                        fee_recipient: Address::repeat_byte(0x02),
                        state_root: B256::repeat_byte(0x03),
                        receipts_root: B256::repeat_byte(0x04),
                        logs_bloom: Bloom::default(),
                        prev_randao: B256::repeat_byte(0x05),
                        block_number: 1,
                        gas_limit: 30_000_000,
                        gas_used: 21_000,
                        timestamp: 12,
                        extra_data: Bytes::from_static(b"ultra sound"),
                        base_fee_per_gas: U256::from(7),
                        block_hash: B256::repeat_byte(0x06),
                        transactions: vec![Bytes::from_static(&[0x02, 0xf8, 0x6f])],
                    },
                    withdrawals: Vec::new(),
                },
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            blobs_bundle: Default::default(),
            execution_requests: Default::default(),
            signature: Default::default(),
        }
    }

    fn test_submission_v6() -> SignedBidSubmissionV6 {
        let v5 = test_submission();

        SignedBidSubmissionV6 {
            message: BidTrace { value: U256::from(7_000_000_000u64), ..v5.message },
            execution_payload: ExecutionPayloadV4 {
                payload_inner: ExecutionPayloadV3 {
                    blob_gas_used: 131_072,
                    ..v5.execution_payload
                },
                block_access_list: Bytes::from_static(&[0xc0]),
                slot_number: 7,
            },
            blobs_bundle: BlobsBundleV2::default(),
            execution_requests: ExecutionRequestsV5 {
                builder_deposits: vec![BuilderDepositRequest {
                    pubkey: FixedBytes::repeat_byte(0x33),
                    withdrawal_credentials: B256::repeat_byte(0x44),
                    amount: 32_000_000_000,
                    signature: FixedBytes::repeat_byte(0x55),
                }],
                builder_exits: vec![BuilderExitRequest {
                    source_address: Address::repeat_byte(0x66),
                    pubkey: FixedBytes::repeat_byte(0x77),
                }],
                ..Default::default()
            },
            signature: FixedBytes::repeat_byte(0x88),
        }
    }

    fn encode_v6(transaction_filter: u8) -> Vec<u8> {
        SszValidationRequest::V6(SszValidationRequestV6 {
            registered_gas_limit: 36_000_000,
            parent_beacon_block_root: B256::repeat_byte(0xaa),
            transaction_filter,
            request: test_submission_v6(),
        })
        .as_ssz_bytes()
    }

    /// The relay encodes this layout on its own, so a change here is a wire break.
    #[test]
    fn test_wire_layout_is_pinned() {
        let submission = test_submission();
        let encoded = SszValidationRequest::V5(SszValidationRequestV5 {
            registered_gas_limit: 36_000_000,
            parent_beacon_block_root: B256::repeat_byte(0xaa),
            transaction_filter: 1,
            request: submission.clone(),
        })
        .as_ssz_bytes();

        // union selector
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1..9], 36_000_000u64.to_le_bytes());
        assert_eq!(encoded[9..41], [0xaa; 32]);
        assert_eq!(encoded[41], 1);
        // offset of the submission: 8 + 32 + 1 + 4 bytes of fixed fields
        assert_eq!(encoded[42..46], 45u32.to_le_bytes());
        assert_eq!(encoded[46..], submission.as_ssz_bytes());
    }

    /// Same fixed fields as V5 behind selector 1. The relay encodes this layout on its own, so a
    /// change here is a wire break.
    #[test]
    fn test_v6_wire_layout_is_pinned() {
        let encoded = encode_v6(1);

        // union selector
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1..9], 36_000_000u64.to_le_bytes());
        assert_eq!(encoded[9..41], [0xaa; 32]);
        assert_eq!(encoded[41], 1);
        assert_eq!(encoded[42..46], 45u32.to_le_bytes());

        let submission = &encoded[46..];
        assert_eq!(submission, test_submission_v6().as_ssz_bytes());

        // 236 bytes of bid trace, three offsets, then the 96 byte signature
        assert_eq!(submission[236..240], 344u32.to_le_bytes());
        assert_eq!(submission[248..344], [0x88; 96]);
    }

    /// The SSZ request must reach the V6 handler as exactly what the JSON-RPC method decodes.
    #[test]
    fn test_v6_decodes_like_the_json_request() {
        let json = serde_json::to_string(&BuilderBlockValidationRequestV6 {
            request: test_submission_v6(),
            registered_gas_limit: 36_000_000,
            parent_beacon_block_root: B256::repeat_byte(0xaa),
            transaction_filter: TransactionFilter::OFAC,
        })
        .unwrap();
        let from_json: BuilderBlockValidationRequestV6 = serde_json::from_str(&json).unwrap();

        let ValidationRequest::V6(from_ssz) = decode_request(&encode_v6(1)).unwrap() else {
            panic!("expected a v6 request")
        };

        assert_eq!(from_ssz, from_json);
    }

    #[test]
    fn test_rejects_unknown_selector_and_filter() {
        let mut unknown_selector = encode_v6(0);
        unknown_selector[0] = 2;
        assert!(decode_request(&unknown_selector).is_err());

        assert!(decode_request(&encode_v6(2)).is_err());
    }
}
