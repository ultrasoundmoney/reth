use crate::{
    Address, BlockHash, BlockNumber, Header, SealedHeader, TransactionSigned, Withdrawal, H256, U64,
};
use fixed_hash::rustc_hex::FromHexError;
use reth_codecs::derive_arbitrary;
use reth_rlp::{Decodable, DecodeError, Encodable, RlpDecodable, RlpEncodable};
use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, fmt::Formatter, num::ParseIntError, ops::Deref, str::FromStr};

/// Ethereum full block.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
#[derive_arbitrary(rlp, 25)]
#[rlp(trailing)]
pub struct Block {
    /// Block header.
    pub header: Header,
    /// Transactions in this block.
    pub body: Vec<TransactionSigned>,
    /// Ommers/uncles header.
    pub ommers: Vec<Header>,
    /// Block withdrawals.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl Block {
    /// Create SealedBLock that will create all header hashes.
    pub fn seal_slow(self) -> SealedBlock {
        SealedBlock {
            header: self.header.seal_slow(),
            body: self.body,
            ommers: self.ommers,
            withdrawals: self.withdrawals,
        }
    }

    /// Seal the block with a known hash.
    ///
    /// WARNING: This method does not perform validation whether the hash is correct.
    pub fn seal(self, hash: H256) -> SealedBlock {
        SealedBlock {
            header: self.header.seal(hash),
            body: self.body,
            ommers: self.ommers,
            withdrawals: self.withdrawals,
        }
    }

    /// Transform into a [`BlockWithSenders`].
    pub fn with_senders(self, senders: Vec<Address>) -> BlockWithSenders {
        assert_eq!(self.body.len(), senders.len(), "Unequal number of senders");

        BlockWithSenders { block: self, senders }
    }

    /// Calculates a heuristic for the in-memory size of the [Block].
    #[inline]
    pub fn size(&self) -> usize {
        self.header.size() +
            // take into account capacity
            self.body.iter().map(TransactionSigned::size).sum::<usize>() + self.body.capacity() * std::mem::size_of::<TransactionSigned>() +
            self.ommers.iter().map(Header::size).sum::<usize>() + self.ommers.capacity() * std::mem::size_of::<Header>() +
            self.withdrawals.as_ref().map(|w| w.iter().map(Withdrawal::size).sum::<usize>() + w.capacity() * std::mem::size_of::<Withdrawal>()).unwrap_or(std::mem::size_of::<Option<Vec<Withdrawal>>>())
    }
}

impl Deref for Block {
    type Target = Header;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

/// Sealed block with senders recovered from transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockWithSenders {
    /// Block
    pub block: Block,
    /// List of senders that match the transactions in the block
    pub senders: Vec<Address>,
}

impl BlockWithSenders {
    /// New block with senders. Return none if len of tx and senders does not match
    pub fn new(block: Block, senders: Vec<Address>) -> Option<Self> {
        (!block.body.len() != senders.len()).then_some(Self { block, senders })
    }

    /// Split Structure to its components
    pub fn into_components(self) -> (Block, Vec<Address>) {
        (self.block, self.senders)
    }
}

impl Deref for BlockWithSenders {
    type Target = Block;
    fn deref(&self) -> &Self::Target {
        &self.block
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::ops::DerefMut for BlockWithSenders {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.block
    }
}

/// Sealed Ethereum full block.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
#[derive_arbitrary(rlp, 10)]
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
#[rlp(trailing)]
pub struct SealedBlock {
    /// Locked block header.
    pub header: SealedHeader,
    /// Transactions with signatures.
    pub body: Vec<TransactionSigned>,
    /// Ommer/uncle headers
    pub ommers: Vec<Header>,
    /// Block withdrawals.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl SealedBlock {
    /// Create a new sealed block instance using the sealed header and block body.
    pub fn new(header: SealedHeader, body: BlockBody) -> Self {
        let BlockBody { transactions, ommers, withdrawals } = body;
        Self { header, body: transactions, ommers, withdrawals }
    }

    /// Header hash.
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }

    /// Splits the sealed block into underlying components
    pub fn split(self) -> (SealedHeader, Vec<TransactionSigned>, Vec<Header>) {
        (self.header, self.body, self.ommers)
    }

    /// Splits the [BlockBody] and [SealedHeader] into separate components
    pub fn split_header_body(self) -> (SealedHeader, BlockBody) {
        (
            self.header,
            BlockBody {
                transactions: self.body,
                ommers: self.ommers,
                withdrawals: self.withdrawals,
            },
        )
    }

    /// Returns only the blob transactions, if any, from the block body.
    pub fn blob_transactions(&self) -> Vec<&TransactionSigned> {
        self.body.iter().filter(|tx| tx.is_eip4844()).collect()
    }

    /// Expensive operation that recovers transaction signer. See [SealedBlockWithSenders].
    pub fn senders(&self) -> Option<Vec<Address>> {
        TransactionSigned::recover_signers(&self.body, self.body.len())
    }

    /// Seal sealed block with recovered transaction senders.
    pub fn seal_with_senders(self) -> Option<SealedBlockWithSenders> {
        self.try_seal_with_senders().ok()
    }

    /// Seal sealed block with recovered transaction senders.
    pub fn try_seal_with_senders(self) -> Result<SealedBlockWithSenders, Self> {
        match self.senders() {
            Some(senders) => Ok(SealedBlockWithSenders { block: self, senders }),
            None => Err(self),
        }
    }

    /// Unseal the block
    pub fn unseal(self) -> Block {
        Block {
            header: self.header.unseal(),
            body: self.body,
            ommers: self.ommers,
            withdrawals: self.withdrawals,
        }
    }

    /// Calculates a heuristic for the in-memory size of the [SealedBlock].
    #[inline]
    pub fn size(&self) -> usize {
        self.header.size() +
            // take into account capacity
            self.body.iter().map(TransactionSigned::size).sum::<usize>() + self.body.capacity() * std::mem::size_of::<TransactionSigned>() +
            self.ommers.iter().map(Header::size).sum::<usize>() + self.ommers.capacity() * std::mem::size_of::<Header>() +
            self.withdrawals.as_ref().map(|w| w.iter().map(Withdrawal::size).sum::<usize>() + w.capacity() * std::mem::size_of::<Withdrawal>()).unwrap_or(std::mem::size_of::<Option<Vec<Withdrawal>>>())
    }
}

impl From<SealedBlock> for Block {
    fn from(block: SealedBlock) -> Self {
        block.unseal()
    }
}

impl Deref for SealedBlock {
    type Target = SealedHeader;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::ops::DerefMut for SealedBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
}

/// Sealed block with senders recovered from transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SealedBlockWithSenders {
    /// Sealed block
    pub block: SealedBlock,
    /// List of senders that match transactions from block.
    pub senders: Vec<Address>,
}

impl SealedBlockWithSenders {
    /// New sealed block with sender. Return none if len of tx and senders does not match
    pub fn new(block: SealedBlock, senders: Vec<Address>) -> Option<Self> {
        (!block.body.len() != senders.len()).then_some(Self { block, senders })
    }

    /// Split Structure to its components
    pub fn into_components(self) -> (SealedBlock, Vec<Address>) {
        (self.block, self.senders)
    }
}

impl Deref for SealedBlockWithSenders {
    type Target = SealedBlock;
    fn deref(&self) -> &Self::Target {
        &self.block
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::ops::DerefMut for SealedBlockWithSenders {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.block
    }
}

/// Either a block hash _or_ a block number
#[derive_arbitrary(rlp)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockHashOrNumber {
    /// A block hash
    Hash(H256),
    /// A block number
    Number(u64),
}

// === impl BlockHashOrNumber ===

impl BlockHashOrNumber {
    /// Returns the block number if it is a [`BlockHashOrNumber::Number`].
    #[inline]
    pub fn as_number(self) -> Option<u64> {
        match self {
            BlockHashOrNumber::Hash(_) => None,
            BlockHashOrNumber::Number(num) => Some(num),
        }
    }
}

impl From<H256> for BlockHashOrNumber {
    fn from(value: H256) -> Self {
        BlockHashOrNumber::Hash(value)
    }
}

impl From<u64> for BlockHashOrNumber {
    fn from(value: u64) -> Self {
        BlockHashOrNumber::Number(value)
    }
}

/// Allows for RLP encoding of either a block hash or block number
impl Encodable for BlockHashOrNumber {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        match self {
            Self::Hash(block_hash) => block_hash.encode(out),
            Self::Number(block_number) => block_number.encode(out),
        }
    }
    fn length(&self) -> usize {
        match self {
            Self::Hash(block_hash) => block_hash.length(),
            Self::Number(block_number) => block_number.length(),
        }
    }
}

/// Allows for RLP decoding of a block hash or block number
impl Decodable for BlockHashOrNumber {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        let header: u8 = *buf.first().ok_or(DecodeError::InputTooShort)?;
        // if the byte string is exactly 32 bytes, decode it into a Hash
        // 0xa0 = 0x80 (start of string) + 0x20 (32, length of string)
        if header == 0xa0 {
            // strip the first byte, parsing the rest of the string.
            // If the rest of the string fails to decode into 32 bytes, we'll bubble up the
            // decoding error.
            let hash = H256::decode(buf)?;
            Ok(Self::Hash(hash))
        } else {
            // a block number when encoded as bytes ranges from 0 to any number of bytes - we're
            // going to accept numbers which fit in less than 64 bytes.
            // Any data larger than this which is not caught by the Hash decoding should error and
            // is considered an invalid block number.
            Ok(Self::Number(u64::decode(buf)?))
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Failed to parse `{input}` as integer: {pares_int_error} or as hex: {hex_error}")]
pub struct ParseBlockHashOrNumberError {
    input: String,
    pares_int_error: ParseIntError,
    hex_error: FromHexError,
}

impl FromStr for BlockHashOrNumber {
    type Err = ParseBlockHashOrNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match u64::from_str(s) {
            Ok(val) => Ok(val.into()),
            Err(pares_int_error) => match H256::from_str(s) {
                Ok(val) => Ok(val.into()),
                Err(hex_error) => Err(ParseBlockHashOrNumberError {
                    input: s.to_string(),
                    pares_int_error,
                    hex_error,
                }),
            },
        }
    }
}

/// A Block Identifier
/// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1898.md>
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockId {
    /// A block hash and an optional bool that defines if it's canonical
    Hash(RpcBlockHash),
    /// A block number
    Number(BlockNumberOrTag),
}

// === impl BlockId ===

impl BlockId {
    /// Returns the block hash if it is [BlockId::Hash]
    pub fn as_block_hash(&self) -> Option<H256> {
        match self {
            BlockId::Hash(hash) => Some(hash.block_hash),
            BlockId::Number(_) => None,
        }
    }

    /// Returns true if this is [BlockNumberOrTag::Latest]
    pub fn is_latest(&self) -> bool {
        matches!(self, BlockId::Number(BlockNumberOrTag::Latest))
    }

    /// Returns true if this is [BlockNumberOrTag::Pending]
    pub fn is_pending(&self) -> bool {
        matches!(self, BlockId::Number(BlockNumberOrTag::Pending))
    }
}

impl From<u64> for BlockId {
    fn from(num: u64) -> Self {
        BlockNumberOrTag::Number(num).into()
    }
}

impl From<BlockNumberOrTag> for BlockId {
    fn from(num: BlockNumberOrTag) -> Self {
        BlockId::Number(num)
    }
}

impl From<H256> for BlockId {
    fn from(block_hash: H256) -> Self {
        BlockId::Hash(RpcBlockHash { block_hash, require_canonical: None })
    }
}

impl From<(H256, Option<bool>)> for BlockId {
    fn from(hash_can: (H256, Option<bool>)) -> Self {
        BlockId::Hash(RpcBlockHash { block_hash: hash_can.0, require_canonical: hash_can.1 })
    }
}

impl From<RpcBlockHash> for BlockId {
    fn from(hash_can: RpcBlockHash) -> Self {
        BlockId::Hash(hash_can)
    }
}

impl From<BlockHashOrNumber> for BlockId {
    fn from(value: BlockHashOrNumber) -> Self {
        match value {
            BlockHashOrNumber::Hash(hash) => H256::from(hash.0).into(),
            BlockHashOrNumber::Number(number) => number.into(),
        }
    }
}

impl Serialize for BlockId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            BlockId::Hash(RpcBlockHash { ref block_hash, ref require_canonical }) => {
                let mut s = serializer.serialize_struct("BlockIdEip1898", 1)?;
                s.serialize_field("blockHash", block_hash)?;
                if let Some(require_canonical) = require_canonical {
                    s.serialize_field("requireCanonical", require_canonical)?;
                }
                s.end()
            }
            BlockId::Number(ref num) => num.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for BlockId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlockIdVisitor;

        impl<'de> Visitor<'de> for BlockIdVisitor {
            type Value = BlockId;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("Block identifier following EIP-1898")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Since there is no way to clearly distinguish between a DATA parameter and a QUANTITY parameter. A str is therefor deserialized into a Block Number: <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1898.md>
                // However, since the hex string should be a QUANTITY, we can safely assume that if the len is 66 bytes, it is in fact a hash, ref <https://github.com/ethereum/go-ethereum/blob/ee530c0d5aa70d2c00ab5691a89ab431b73f8165/rpc/types.go#L184-L184>
                if v.len() == 66 {
                    Ok(BlockId::Hash(v.parse::<H256>().map_err(serde::de::Error::custom)?.into()))
                } else {
                    // quantity hex string or tag
                    Ok(BlockId::Number(v.parse().map_err(serde::de::Error::custom)?))
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut number = None;
                let mut block_hash = None;
                let mut require_canonical = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "blockNumber" => {
                            if number.is_some() || block_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("blockNumber"))
                            }
                            if require_canonical.is_some() {
                                return Err(serde::de::Error::custom(
                                    "Non-valid require_canonical field",
                                ))
                            }
                            number = Some(map.next_value::<BlockNumberOrTag>()?)
                        }
                        "blockHash" => {
                            if number.is_some() || block_hash.is_some() {
                                return Err(serde::de::Error::duplicate_field("blockHash"))
                            }

                            block_hash = Some(map.next_value::<H256>()?);
                        }
                        "requireCanonical" => {
                            if number.is_some() || require_canonical.is_some() {
                                return Err(serde::de::Error::duplicate_field("requireCanonical"))
                            }

                            require_canonical = Some(map.next_value::<bool>()?)
                        }
                        key => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["blockNumber", "blockHash", "requireCanonical"],
                            ))
                        }
                    }
                }

                if let Some(number) = number {
                    Ok(BlockId::Number(number))
                } else if let Some(block_hash) = block_hash {
                    Ok(BlockId::Hash(RpcBlockHash { block_hash, require_canonical }))
                } else {
                    Err(serde::de::Error::custom(
                        "Expected `blockNumber` or `blockHash` with `requireCanonical` optionally",
                    ))
                }
            }
        }

        deserializer.deserialize_any(BlockIdVisitor)
    }
}

/// A block Number (or tag - "latest", "earliest", "pending")
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum BlockNumberOrTag {
    /// Latest block
    #[default]
    Latest,
    /// Finalized block accepted as canonical
    Finalized,
    /// Safe head block
    Safe,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number from canon chain
    Number(u64),
}

impl BlockNumberOrTag {
    /// Returns the numeric block number if explicitly set
    pub fn as_number(&self) -> Option<u64> {
        match *self {
            BlockNumberOrTag::Number(num) => Some(num),
            _ => None,
        }
    }

    /// Returns `true` if a numeric block number is set
    pub fn is_number(&self) -> bool {
        matches!(self, BlockNumberOrTag::Number(_))
    }

    /// Returns `true` if it's "latest"
    pub fn is_latest(&self) -> bool {
        matches!(self, BlockNumberOrTag::Latest)
    }

    /// Returns `true` if it's "finalized"
    pub fn is_finalized(&self) -> bool {
        matches!(self, BlockNumberOrTag::Finalized)
    }

    /// Returns `true` if it's "safe"
    pub fn is_safe(&self) -> bool {
        matches!(self, BlockNumberOrTag::Safe)
    }

    /// Returns `true` if it's "pending"
    pub fn is_pending(&self) -> bool {
        matches!(self, BlockNumberOrTag::Pending)
    }

    /// Returns `true` if it's "earliest"
    pub fn is_earliest(&self) -> bool {
        matches!(self, BlockNumberOrTag::Earliest)
    }
}

impl From<u64> for BlockNumberOrTag {
    fn from(num: u64) -> Self {
        BlockNumberOrTag::Number(num)
    }
}

impl From<U64> for BlockNumberOrTag {
    fn from(num: U64) -> Self {
        num.as_u64().into()
    }
}

impl Serialize for BlockNumberOrTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            BlockNumberOrTag::Number(ref x) => serializer.serialize_str(&format!("0x{x:x}")),
            BlockNumberOrTag::Latest => serializer.serialize_str("latest"),
            BlockNumberOrTag::Finalized => serializer.serialize_str("finalized"),
            BlockNumberOrTag::Safe => serializer.serialize_str("safe"),
            BlockNumberOrTag::Earliest => serializer.serialize_str("earliest"),
            BlockNumberOrTag::Pending => serializer.serialize_str("pending"),
        }
    }
}

impl<'de> Deserialize<'de> for BlockNumberOrTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.to_lowercase();
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for BlockNumberOrTag {
    type Err = ParseBlockNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let block = match s {
            "latest" => Self::Latest,
            "finalized" => Self::Finalized,
            "safe" => Self::Safe,
            "earliest" => Self::Earliest,
            "pending" => Self::Pending,
            _number => {
                if let Some(hex_val) = s.strip_prefix("0x") {
                    let number = u64::from_str_radix(hex_val, 16);
                    BlockNumberOrTag::Number(number?)
                } else {
                    return Err(HexStringMissingPrefixError::default().into())
                }
            }
        };
        Ok(block)
    }
}

impl fmt::Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockNumberOrTag::Number(ref x) => format!("0x{x:x}").fmt(f),
            BlockNumberOrTag::Latest => f.write_str("latest"),
            BlockNumberOrTag::Finalized => f.write_str("finalized"),
            BlockNumberOrTag::Safe => f.write_str("safe"),
            BlockNumberOrTag::Earliest => f.write_str("earliest"),
            BlockNumberOrTag::Pending => f.write_str("pending"),
        }
    }
}

/// Error variants when parsing a [BlockNumberOrTag]
#[derive(Debug, thiserror::Error)]
pub enum ParseBlockNumberError {
    /// Failed to parse hex value
    #[error(transparent)]
    ParseIntErr(#[from] ParseIntError),
    /// Block numbers should be 0x-prefixed
    #[error(transparent)]
    MissingPrefix(#[from] HexStringMissingPrefixError),
}

/// Thrown when a 0x-prefixed hex string was expected
#[derive(Debug, Default, thiserror::Error)]
#[non_exhaustive]
#[error("hex string without 0x prefix")]
pub struct HexStringMissingPrefixError;

/// A block hash which may have
/// a boolean requireCanonical field.
/// If false, an RPC call should raise if a block
/// matching the hash is not found.
/// If true, an RPC call should additionaly raise if
/// the block is not in the canonical chain.
/// <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1898.md#specification>
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RpcBlockHash {
    /// A block hash
    pub block_hash: H256,
    /// Whether the block must be a canonical block
    pub require_canonical: Option<bool>,
}

impl RpcBlockHash {
    pub fn from_hash(block_hash: H256, require_canonical: Option<bool>) -> Self {
        RpcBlockHash { block_hash, require_canonical }
    }
}

impl From<H256> for RpcBlockHash {
    fn from(value: H256) -> Self {
        Self::from_hash(value, None)
    }
}

impl From<RpcBlockHash> for H256 {
    fn from(value: RpcBlockHash) -> Self {
        value.block_hash
    }
}

impl AsRef<H256> for RpcBlockHash {
    fn as_ref(&self) -> &H256 {
        &self.block_hash
    }
}

/// Block number and hash.
#[derive(Clone, Copy, Hash, Default, PartialEq, Eq)]
pub struct BlockNumHash {
    /// Block number
    pub number: BlockNumber,
    /// Block hash
    pub hash: BlockHash,
}

/// Block number and hash of the forked block.
pub type ForkBlock = BlockNumHash;

impl std::fmt::Debug for BlockNumHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("").field(&self.number).field(&self.hash).finish()
    }
}

impl BlockNumHash {
    /// Creates a new `BlockNumHash` from a block number and hash.
    pub fn new(number: BlockNumber, hash: BlockHash) -> Self {
        Self { number, hash }
    }

    /// Consumes `Self` and returns [`BlockNumber`], [`BlockHash`]
    pub fn into_components(self) -> (BlockNumber, BlockHash) {
        (self.number, self.hash)
    }

    /// Returns whether or not the block matches the given [BlockHashOrNumber].
    pub fn matches_block_or_num(&self, block: &BlockHashOrNumber) -> bool {
        match block {
            BlockHashOrNumber::Hash(hash) => self.hash == *hash,
            BlockHashOrNumber::Number(number) => self.number == *number,
        }
    }
}

impl From<(BlockNumber, BlockHash)> for BlockNumHash {
    fn from(val: (BlockNumber, BlockHash)) -> Self {
        BlockNumHash { number: val.0, hash: val.1 }
    }
}

impl From<(BlockHash, BlockNumber)> for BlockNumHash {
    fn from(val: (BlockHash, BlockNumber)) -> Self {
        BlockNumHash { hash: val.0, number: val.1 }
    }
}

/// A response to `GetBlockBodies`, containing bodies if any bodies were found.
///
/// Withdrawals can be optionally included at the end of the RLP encoded message.
#[derive_arbitrary(rlp, 10)]
#[derive(
    Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
#[rlp(trailing)]
pub struct BlockBody {
    /// Transactions in the block
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "proptest::collection::vec(proptest::arbitrary::any::<TransactionSigned>(), 0..=100)"
        )
    )]
    pub transactions: Vec<TransactionSigned>,
    /// Uncle headers for the given block
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "proptest::collection::vec(proptest::arbitrary::any::<Header>(), 0..=2)"
        )
    )]
    pub ommers: Vec<Header>,
    /// Withdrawals in the block.
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "proptest::option::of(proptest::collection::vec(proptest::arbitrary::any::<Withdrawal>(), 0..=16))"
        )
    )]
    pub withdrawals: Option<Vec<Withdrawal>>,
}

impl BlockBody {
    /// Create a [`Block`] from the body and its header.
    pub fn create_block(&self, header: Header) -> Block {
        Block {
            header,
            body: self.transactions.clone(),
            ommers: self.ommers.clone(),
            withdrawals: self.withdrawals.clone(),
        }
    }

    /// Calculate the transaction root for the block body.
    pub fn calculate_tx_root(&self) -> H256 {
        crate::proofs::calculate_transaction_root(&self.transactions)
    }

    /// Calculate the ommers root for the block body.
    pub fn calculate_ommers_root(&self) -> H256 {
        crate::proofs::calculate_ommers_root(&self.ommers)
    }

    /// Calculate the withdrawals root for the block body, if withdrawals exist. If there are no
    /// withdrawals, this will return `None`.
    pub fn calculate_withdrawals_root(&self) -> Option<H256> {
        self.withdrawals.as_ref().map(|w| crate::proofs::calculate_withdrawals_root(w))
    }

    /// Calculate all roots (transaction, ommers, withdrawals) for the block body.
    pub fn calculate_roots(&self) -> BlockBodyRoots {
        BlockBodyRoots {
            tx_root: self.calculate_tx_root(),
            ommers_hash: self.calculate_ommers_root(),
            withdrawals_root: self.calculate_withdrawals_root(),
        }
    }

    /// Calculates a heuristic for the in-memory size of the [BlockBody].
    #[inline]
    pub fn size(&self) -> usize {
        self.transactions.iter().map(TransactionSigned::size).sum::<usize>() +
            self.transactions.capacity() * std::mem::size_of::<TransactionSigned>() +
            self.ommers.iter().map(Header::size).sum::<usize>() +
            self.ommers.capacity() * std::mem::size_of::<Header>() +
            self.withdrawals
                .as_ref()
                .map(|w| {
                    w.iter().map(Withdrawal::size).sum::<usize>() +
                        w.capacity() * std::mem::size_of::<Withdrawal>()
                })
                .unwrap_or(std::mem::size_of::<Option<Vec<Withdrawal>>>())
    }
}

/// A struct that represents roots associated with a block body. This can be used to correlate
/// block body responses with headers.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, Hash)]
pub struct BlockBodyRoots {
    /// The transaction root for the block body.
    pub tx_root: H256,
    /// The ommers hash for the block body.
    pub ommers_hash: H256,
    /// The withdrawals root for the block body, if withdrawals exist.
    pub withdrawals_root: Option<H256>,
}

#[cfg(test)]
mod test {
    use super::{BlockId, BlockNumberOrTag::*, *};

    /// Check parsing according to EIP-1898.
    #[test]
    fn can_parse_blockid_u64() {
        let num = serde_json::json!(
            {"blockNumber": "0xaf"}
        );

        let id = serde_json::from_value::<BlockId>(num);
        assert_eq!(id.unwrap(), BlockId::from(175));
    }
    #[test]
    fn can_parse_block_hash() {
        let block_hash =
            H256::from_str("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap();
        let block_hash_json = serde_json::json!(
            { "blockHash": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}
        );
        let id = serde_json::from_value::<BlockId>(block_hash_json).unwrap();
        assert_eq!(id, BlockId::from(block_hash,));
    }
    #[test]
    fn can_parse_block_hash_with_canonical() {
        let block_hash =
            H256::from_str("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap();
        let block_id = BlockId::Hash(RpcBlockHash::from_hash(block_hash, Some(true)));
        let block_hash_json = serde_json::json!(
            { "blockHash": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "requireCanonical": true }
        );
        let id = serde_json::from_value::<BlockId>(block_hash_json).unwrap();
        assert_eq!(id, block_id)
    }
    #[test]
    fn can_parse_blockid_tags() {
        let tags =
            [("latest", Latest), ("finalized", Finalized), ("safe", Safe), ("pending", Pending)];
        for (value, tag) in tags {
            let num = serde_json::json!({ "blockNumber": value });
            let id = serde_json::from_value::<BlockId>(num);
            assert_eq!(id.unwrap(), BlockId::from(tag))
        }
    }
    #[test]
    fn repeated_keys_is_err() {
        let num = serde_json::json!({"blockNumber": 1, "requireCanonical": true, "requireCanonical": false});
        assert!(serde_json::from_value::<BlockId>(num).is_err());
        let num =
            serde_json::json!({"blockNumber": 1, "requireCanonical": true, "blockNumber": 23});
        assert!(serde_json::from_value::<BlockId>(num).is_err());
    }
    /// Serde tests
    #[test]
    fn serde_blockid_tags() {
        let block_ids = [Latest, Finalized, Safe, Pending].map(BlockId::from);
        for block_id in &block_ids {
            let serialized = serde_json::to_string(&block_id).unwrap();
            let deserialized: BlockId = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, *block_id)
        }
    }

    #[test]
    fn serde_blockid_number() {
        let block_id = BlockId::from(100u64);
        let serialized = serde_json::to_string(&block_id).unwrap();
        let deserialized: BlockId = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, block_id)
    }

    #[test]
    fn serde_blockid_hash() {
        let block_id = BlockId::from(H256::default());
        let serialized = serde_json::to_string(&block_id).unwrap();
        let deserialized: BlockId = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, block_id)
    }

    #[test]
    fn serde_blockid_hash_from_str() {
        let val = "\"0x898753d8fdd8d92c1907ca21e68c7970abd290c647a202091181deec3f30a0b2\"";
        let block_hash: H256 = serde_json::from_str(val).unwrap();
        let block_id: BlockId = serde_json::from_str(val).unwrap();
        assert_eq!(block_id, BlockId::Hash(block_hash.into()));
    }

    #[test]
    fn serde_rpc_payload_block_tag() {
        let payload = r#"{"method":"eth_call","params":[{"to":"0xebe8efa441b9302a0d7eaecc277c09d20d684540","data":"0x45848dfc"},"latest"],"id":1,"jsonrpc":"2.0"}"#;
        let value: serde_json::Value = serde_json::from_str(payload).unwrap();
        let block_id_param = value.pointer("/params/1").unwrap();
        let block_id: BlockId = serde_json::from_value::<BlockId>(block_id_param.clone()).unwrap();
        assert_eq!(BlockId::Number(BlockNumberOrTag::Latest), block_id);
    }
    #[test]
    fn serde_rpc_payload_block_object() {
        let example_payload = r#"{"method":"eth_call","params":[{"to":"0xebe8efa441b9302a0d7eaecc277c09d20d684540","data":"0x45848dfc"},{"blockHash": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}],"id":1,"jsonrpc":"2.0"}"#;
        let value: serde_json::Value = serde_json::from_str(example_payload).unwrap();
        let block_id_param = value.pointer("/params/1").unwrap().to_string();
        let block_id: BlockId = serde_json::from_str::<BlockId>(&block_id_param).unwrap();
        let hash =
            H256::from_str("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap();
        assert_eq!(BlockId::from(hash), block_id);
        let serialized = serde_json::to_string(&BlockId::from(hash)).unwrap();
        assert_eq!("{\"blockHash\":\"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\"}", serialized)
    }
    #[test]
    fn serde_rpc_payload_block_number() {
        let example_payload = r#"{"method":"eth_call","params":[{"to":"0xebe8efa441b9302a0d7eaecc277c09d20d684540","data":"0x45848dfc"},{"blockNumber": "0x0"}],"id":1,"jsonrpc":"2.0"}"#;
        let value: serde_json::Value = serde_json::from_str(example_payload).unwrap();
        let block_id_param = value.pointer("/params/1").unwrap().to_string();
        let block_id: BlockId = serde_json::from_str::<BlockId>(&block_id_param).unwrap();
        assert_eq!(BlockId::from(0u64), block_id);
        let serialized = serde_json::to_string(&BlockId::from(0u64)).unwrap();
        assert_eq!("\"0x0\"", serialized)
    }
    #[test]
    #[should_panic]
    fn serde_rpc_payload_block_number_duplicate_key() {
        let payload = r#"{"blockNumber": "0x132", "blockNumber": "0x133"}"#;
        let parsed_block_id = serde_json::from_str::<BlockId>(payload);
        parsed_block_id.unwrap();
    }
    #[test]
    fn serde_rpc_payload_block_hash() {
        let payload = r#"{"blockHash": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}"#;
        let parsed = serde_json::from_str::<BlockId>(payload).unwrap();
        let expected = BlockId::from(
            H256::from_str("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap(),
        );
        assert_eq!(parsed, expected);
    }

    #[test]
    fn encode_decode_raw_block() {
        let block = "0xf90288f90218a0fe21bb173f43067a9f90cfc59bbb6830a7a2929b5de4a61f372a9db28e87f9aea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a061effbbcca94f0d3e02e5bd22e986ad57142acabf0cb3d129a6ad8d0f8752e94a0d911c25e97e27898680d242b7780b6faef30995c355a2d5de92e6b9a7212ad3aa0056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008003834c4b408252081e80a00000000000000000000000000000000000000000000000000000000000000000880000000000000000842806be9da056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421f869f86702842806be9e82520894658bdf435d810c91414ec09147daa6db624063798203e880820a95a040ce7918eeb045ebf8c8b1887ca139d076bda00fa828a07881d442a72626c42da0156576a68e456e295e4c9cf67cf9f53151f329438916e0f24fc69d6bbb7fbacfc0c0";
        let bytes = hex::decode(&block[2..]).unwrap();
        let bytes_buf = &mut bytes.as_ref();
        let block = Block::decode(bytes_buf).unwrap();
        let mut encoded_buf = Vec::new();
        block.encode(&mut encoded_buf);
        assert_eq!(bytes, encoded_buf);
    }

    #[test]
    fn serde_blocknumber_non_0xprefix() {
        let s = "\"2\"";
        let err = serde_json::from_str::<BlockNumberOrTag>(s).unwrap_err();
        assert_eq!(err.to_string(), HexStringMissingPrefixError::default().to_string());
    }
}
