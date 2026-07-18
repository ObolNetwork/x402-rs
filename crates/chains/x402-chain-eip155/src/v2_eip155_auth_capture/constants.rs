//! Canonical addresses and protocol bounds for the `auth-capture` EVM scheme.
//!
//! These mirror `typescript/packages/mechanisms/evm/src/auth-capture/constants.ts`
//! exactly. The `AuthCaptureEscrow` and its token collectors come from
//! base/commerce-payments v1.0.0 (audited) and are deployed via CREATE2 at the
//! same addresses across every supported EVM chain — universal constants, not
//! configurable per merchant.

use alloy_primitives::{Address, address};

/// Scheme identifier for the auth-capture payment scheme.
pub const AUTH_CAPTURE_SCHEME: &str = "auth-capture";

/// Deployed address of the `AuthCaptureEscrow` singleton.
pub const AUTH_CAPTURE_ESCROW_ADDRESS: Address =
    address!("0xBdEA0D1bcC5966192B070Fdf62aB4EF5b4420cff");

/// Deployed address of the ERC-3009 token collector
/// (pulls funds via `receiveWithAuthorization`).
pub const EIP3009_TOKEN_COLLECTOR_ADDRESS: Address =
    address!("0x0E3dF9510de65469C4518D7843919c0b8C7A7757");

/// Deployed address of the Permit2 token collector
/// (unused until the Permit2 path ships).
pub const PERMIT2_TOKEN_COLLECTOR_ADDRESS: Address =
    address!("0x992476B9Ee81d52a5BdA0622C333938D0Af0aB26");

/// Clock-skew guard applied to deadline checks, matching the spec's `now + 6s`.
pub const DEADLINE_SKEW_SECS: u64 = 6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_addresses_match_spec() {
        // Sanity checks that the canonical addresses literally match the spec.
        // These are referenced by the deployed contracts and must be identical
        // across every EVM chain — drift would break interop with every other
        // auth-capture implementation.
        assert_eq!(
            format!("{:#x}", AUTH_CAPTURE_ESCROW_ADDRESS),
            "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff"
        );
        assert_eq!(
            format!("{:#x}", EIP3009_TOKEN_COLLECTOR_ADDRESS),
            "0x0e3df9510de65469c4518d7843919c0b8c7a7757"
        );
        assert_eq!(
            format!("{:#x}", PERMIT2_TOKEN_COLLECTOR_ADDRESS),
            "0x992476b9ee81d52a5bda0622c333938d0af0ab26"
        );
    }
}
