//! Reth block execution/validation configuration and constants

use reth_primitives::{ChainSpec, Hardfork, Head};

/// Returns the spec id at the given timestamp.
///
/// Note: This is only intended to be used after the merge, when hardforks are activated by
/// timestamp.
pub fn revm_spec_by_timestamp_after_merge(
    chain_spec: &ChainSpec,
    timestamp: u64,
) -> revm::primitives::SpecId {
    if chain_spec.is_fork_active_at_timestamp(Hardfork::Shanghai, timestamp) {
        revm::primitives::SHANGHAI
    } else {
        revm::primitives::MERGE
    }
}

/// return revm_spec from spec configuration.
pub fn revm_spec(chain_spec: &ChainSpec, block: Head) -> revm::primitives::SpecId {
    if chain_spec.fork(Hardfork::Cancun).active_at_head(&block) {
        revm::primitives::CANCUN
    } else if chain_spec.fork(Hardfork::Shanghai).active_at_head(&block) {
        revm::primitives::SHANGHAI
    } else if chain_spec.fork(Hardfork::Paris).active_at_head(&block) {
        revm::primitives::MERGE
    } else if chain_spec.fork(Hardfork::London).active_at_head(&block) {
        revm::primitives::LONDON
    } else if chain_spec.fork(Hardfork::Berlin).active_at_head(&block) {
        revm::primitives::BERLIN
    } else if chain_spec.fork(Hardfork::Istanbul).active_at_head(&block) {
        revm::primitives::ISTANBUL
    } else if chain_spec.fork(Hardfork::Petersburg).active_at_head(&block) {
        revm::primitives::PETERSBURG
    } else if chain_spec.fork(Hardfork::Byzantium).active_at_head(&block) {
        revm::primitives::BYZANTIUM
    } else if chain_spec.fork(Hardfork::SpuriousDragon).active_at_head(&block) {
        revm::primitives::SPURIOUS_DRAGON
    } else if chain_spec.fork(Hardfork::Tangerine).active_at_head(&block) {
        revm::primitives::TANGERINE
    } else if chain_spec.fork(Hardfork::Homestead).active_at_head(&block) {
        revm::primitives::HOMESTEAD
    } else if chain_spec.fork(Hardfork::Frontier).active_at_head(&block) {
        revm::primitives::FRONTIER
    } else {
        panic!(
            "invalid hardfork chainspec: expected at least one hardfork, got {:?}",
            chain_spec.hardforks
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::config::revm_spec;
    use reth_primitives::{ChainSpecBuilder, Head, MAINNET, U256};
    #[test]
    fn test_to_revm_spec() {
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().paris_activated().build(), Head::default()),
            revm::primitives::MERGE
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().london_activated().build(), Head::default()),
            revm::primitives::LONDON
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().berlin_activated().build(), Head::default()),
            revm::primitives::BERLIN
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().istanbul_activated().build(), Head::default()),
            revm::primitives::ISTANBUL
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().petersburg_activated().build(), Head::default()),
            revm::primitives::PETERSBURG
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().byzantium_activated().build(), Head::default()),
            revm::primitives::BYZANTIUM
        );
        assert_eq!(
            revm_spec(
                &ChainSpecBuilder::mainnet().spurious_dragon_activated().build(),
                Head::default()
            ),
            revm::primitives::SPURIOUS_DRAGON
        );
        assert_eq!(
            revm_spec(
                &ChainSpecBuilder::mainnet().tangerine_whistle_activated().build(),
                Head::default()
            ),
            revm::primitives::TANGERINE
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().homestead_activated().build(), Head::default()),
            revm::primitives::HOMESTEAD
        );
        assert_eq!(
            revm_spec(&ChainSpecBuilder::mainnet().frontier_activated().build(), Head::default()),
            revm::primitives::FRONTIER
        );
    }

    #[test]
    fn test_eth_spec() {
        assert_eq!(
            revm_spec(
                &MAINNET,
                Head {
                    total_difficulty: U256::from(58_750_000_000_000_000_000_010_u128),
                    difficulty: U256::from(10_u128),
                    ..Default::default()
                }
            ),
            revm::primitives::MERGE
        );
        // TTD trumps the block number
        assert_eq!(
            revm_spec(
                &MAINNET,
                Head {
                    number: 15537394 - 10,
                    total_difficulty: U256::from(58_750_000_000_000_000_000_010_u128),
                    difficulty: U256::from(10_u128),
                    ..Default::default()
                }
            ),
            revm::primitives::MERGE
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 15537394 - 10, ..Default::default() }),
            revm::primitives::LONDON
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 12244000 + 10, ..Default::default() }),
            revm::primitives::BERLIN
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 12244000 - 10, ..Default::default() }),
            revm::primitives::ISTANBUL
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 7280000 + 10, ..Default::default() }),
            revm::primitives::PETERSBURG
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 7280000 - 10, ..Default::default() }),
            revm::primitives::BYZANTIUM
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 2675000 + 10, ..Default::default() }),
            revm::primitives::SPURIOUS_DRAGON
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 2675000 - 10, ..Default::default() }),
            revm::primitives::TANGERINE
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 1150000 + 10, ..Default::default() }),
            revm::primitives::HOMESTEAD
        );
        assert_eq!(
            revm_spec(&MAINNET, Head { number: 1150000 - 10, ..Default::default() }),
            revm::primitives::FRONTIER
        );
    }
}
