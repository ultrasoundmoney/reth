#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxzy/reth/issues/"
)]
#![warn(missing_debug_implementations, missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Reth RPC implementation
//!
//! Provides the implementation of all RPC interfaces.
//!
//!
//! ## Note on blocking behaviour
//!
//! All async RPC handlers must non-blocking, see also [What is blocking](https://ryhl.io/blog/async-what-is-blocking/).
//!
//! A lot of the RPC are using a mix of async and direct calls to the database, which are blocking
//! and can reduce overall performance of all concurrent requests handled via the jsonrpsee server.
//!
//! To avoid this, all blocking or CPU intensive handlers must be spawned to a separate task. See
//! the [EthApi] handler implementations for examples. The rpc-api traits make no use of the
//! available jsonrpsee `blocking` attribute to give implementors more freedom because the
//! `blocking` attribute and async handlers are mutually exclusive. However, as mentioned above, a
//! lot of handlers make use of async functions, caching for example, but are also using blocking
//! disk-io, hence these calls are spawned as futures to a blocking task manually.

mod admin;
mod debug;
mod engine;
pub mod eth;
mod layers;
mod net;
mod otterscan;
mod reth;
mod rpc;
mod trace;
pub mod tracing_call;
mod txpool;
mod validation;
mod web3;

pub use admin::AdminApi;
pub use debug::DebugApi;
pub use engine::{EngineApi, EngineEthApi};
pub use eth::{EthApi, EthApiSpec, EthFilter, EthPubSub, EthSubscriptionIdProvider};
pub use layers::{AuthLayer, AuthValidator, Claims, JwtAuthValidator, JwtError, JwtSecret};
pub use net::NetApi;
pub use otterscan::OtterscanApi;
pub use reth::RethApi;
pub use rpc::RPCApi;
pub use trace::TraceApi;
pub use tracing_call::{TracingCallGuard, TracingCallPool};
pub use txpool::TxPoolApi;
pub use validation::ValidationApi;
pub use web3::Web3Api;

pub(crate) mod result;
