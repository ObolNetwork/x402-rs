//! Alloy bindings for the deployed `AuthCaptureEscrow` contract
//! (base/commerce-payments v1.0.0) — the escrow behind the x402
//! `auth-capture` scheme — plus the payer-agnostic nonce derivation.
//!
//! Canonical CREATE2 deployment addresses live in
//! [`crate::v2_eip155_auth_capture::constants`].

#![allow(missing_docs)]

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::{SolStruct, SolValue, sol};

use crate::v2_eip155_auth_capture::constants::AUTH_CAPTURE_ESCROW_ADDRESS;

sol! {
    /// Mirrors `AuthCaptureEscrow.PaymentInfo` byte-for-byte; the derived
    /// EIP-712 typehash must match the contract's `PAYMENT_INFO_TYPEHASH`.
    #[derive(Debug)]
    struct PaymentInfo {
        address operator;
        address payer;
        address receiver;
        address token;
        uint120 maxAmount;
        uint48 preApprovalExpiry;
        uint48 authorizationExpiry;
        uint48 refundExpiry;
        uint16 minFeeBps;
        uint16 maxFeeBps;
        address feeReceiver;
        uint256 salt;
    }

    contract AuthCaptureEscrow {
        function charge(
            PaymentInfo calldata paymentInfo,
            uint256 amount,
            address tokenCollector,
            bytes calldata collectorData,
            uint16 feeBps,
            address feeReceiver
        ) external;

        function getHash(PaymentInfo calldata paymentInfo) public view returns (bytes32);

        error InvalidSender(address sender, address expected);
        error ZeroAmount();
        error AmountOverflow(uint256 amount, uint256 limit);
        error ExceedsMaxAmount(uint256 amount, uint256 maxAmount);
        error AfterPreApprovalExpiry(uint48 timestamp, uint48 expiry);
        error InvalidExpiries(uint48 preApproval, uint48 authorization, uint48 refund);
        error FeeBpsOverflow(uint16 feeBps);
        error InvalidFeeBpsRange(uint16 minFeeBps, uint16 maxFeeBps);
        error FeeBpsOutOfRange(uint16 feeBps, uint16 minFeeBps, uint16 maxFeeBps);
        error ZeroFeeReceiver();
        error InvalidFeeReceiver(address attempted, address expected);
        error InvalidCollectorForOperation();
        error TokenCollectionFailed();
        error PaymentAlreadyCollected(bytes32 paymentInfoHash);
        error AfterAuthorizationExpiry(uint48 timestamp, uint48 expiry);
        error InsufficientAuthorization(bytes32 paymentInfoHash, uint256 authorizedAmount, uint256 requestedAmount);
        error ZeroAuthorization(bytes32 paymentInfoHash);
    }
}

/// Payer-agnostic nonce derivation (spec: "Nonce Derivation"):
///
/// ```text
/// paymentInfoHash = keccak256(abi.encode(PAYMENT_INFO_TYPEHASH, paymentInfoWithZeroPayer))
/// nonce           = keccak256(abi.encode(chainId, AUTH_CAPTURE_ESCROW_ADDRESS, paymentInfoHash))
/// ```
///
/// Equals the deployed contract's `getHash()` for the same struct with
/// `payer = address(0)` — the golden-vector oracle for this function.
pub fn payer_agnostic_nonce(chain_id: u64, info: &PaymentInfo) -> B256 {
    let zeroed = PaymentInfo {
        payer: Address::ZERO,
        ..info.clone()
    };
    let struct_hash = zeroed.eip712_hash_struct();
    keccak256(
        (
            U256::from(chain_id),
            AUTH_CAPTURE_ESCROW_ADDRESS,
            struct_hash,
        )
            .abi_encode(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use alloy_sol_types::SolStruct;

    #[test]
    fn payment_info_typehash_matches_contract() {
        // Must equal AuthCaptureEscrow.PAYMENT_INFO_TYPEHASH (keccak of the
        // canonical typestring).
        let expected = keccak256(
            "PaymentInfo(address operator,address payer,address receiver,address token,uint120 maxAmount,uint48 preApprovalExpiry,uint48 authorizationExpiry,uint48 refundExpiry,uint16 minFeeBps,uint16 maxFeeBps,address feeReceiver,uint256 salt)"
                .as_bytes(),
        );
        assert_eq!(PaymentInfo::eip712_type_hash(&sample()), expected);
    }

    fn sample() -> PaymentInfo {
        PaymentInfo {
            operator: address!("4444444444444444444444444444444444444444"),
            payer: address!("1111111111111111111111111111111111111111"),
            receiver: address!("3333333333333333333333333333333333333333"),
            token: address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
            maxAmount: alloy_primitives::aliases::U120::from(1500u64),
            preApprovalExpiry: alloy_primitives::aliases::U48::from(1_800_000_000u64),
            authorizationExpiry: alloy_primitives::aliases::U48::from(1_800_000_600u64),
            refundExpiry: alloy_primitives::aliases::U48::from(1_800_001_200u64),
            minFeeBps: 2000,
            maxFeeBps: 2000,
            feeReceiver: address!("5555555555555555555555555555555555555555"),
            salt: U256::from(0xabcu64),
        }
    }

    /// Golden vector captured from the deployed Base Sepolia escrow via
    /// `eth_call getHash(sample with payer=0)`, independently reproduced with
    /// viem (`encodeAbiParameters` + `keccak256`, the same primitives the
    /// upstream TypeScript client uses) — so the assertion pins
    /// `alloy_sol_types` against both the live contract and viem byte-for-byte.
    #[test]
    fn payer_agnostic_nonce_matches_deployed_escrow() {
        let nonce = payer_agnostic_nonce(84532, &sample());
        assert_eq!(
            nonce.to_string(),
            "0xcad3fb0ec55cb75e58df69311ba1d530447f64e0798e57e842987c2fbdb4f02f",
        );
    }
}
