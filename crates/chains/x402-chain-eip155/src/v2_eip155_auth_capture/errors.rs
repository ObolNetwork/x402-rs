//! Error code constants for the `auth-capture` EVM scheme.
//!
//! Mirrors the error tables in
//! `specs/schemes/auth-capture/scheme_auth_capture_evm.md`. Unlike
//! batch-settlement, auth-capture uses flat (unprefixed) codes; the exact
//! string values are part of the wire format and shared across
//! implementations.

#![allow(missing_docs)]

// --- Verification errors (spec "Verification Errors" table) -----------------

pub const ERR_INVALID_PAYLOAD_FORMAT: &str = "invalid_payload_format";
pub const ERR_NETWORK_MISMATCH: &str = "network_mismatch";
pub const ERR_INVALID_AUTH_CAPTURE_EXTRA: &str = "invalid_auth_capture_extra";
pub const ERR_UNSUPPORTED_ASSET_TRANSFER_METHOD: &str = "unsupported_asset_transfer_method";
pub const ERR_CAPTURE_DEADLINE_EXPIRED: &str = "capture_deadline_expired";
pub const ERR_INVALID_DEADLINE_ORDERING: &str = "invalid_deadline_ordering";
pub const ERR_AUTHORIZATION_EXPIRED: &str = "authorization_expired";
pub const ERR_AUTHORIZATION_NOT_YET_VALID: &str = "authorization_not_yet_valid";
pub const ERR_INVALID_AUTH_CAPTURE_SIGNATURE: &str = "invalid_auth_capture_signature";
pub const ERR_AMOUNT_MISMATCH: &str = "amount_mismatch";
pub const ERR_TOKEN_COLLECTOR_MISMATCH: &str = "token_collector_mismatch";
pub const ERR_NONCE_MISMATCH: &str = "nonce_mismatch";
pub const ERR_INSUFFICIENT_BALANCE: &str = "insufficient_balance";
pub const ERR_SIMULATION_FAILED: &str = "simulation_failed";

// --- Codes shared with the spec's typed-simulation-revert table -------------

pub const ERR_INVALID_CAPTURE_AUTHORIZER: &str = "invalid_capture_authorizer";
pub const ERR_ZERO_FEE_RECEIVER: &str = "zero_fee_receiver";

// --- Settlement errors (spec "Settlement Errors" table) ---------------------

pub const ERR_TRANSACTION_REVERTED: &str = "transaction_reverted";

// --- Implementation-scope codes (not in the spec tables) --------------------

/// This port settles exclusively via single-shot `charge()`; requirements with
/// `autoCapture` unset or `false` request the two-phase `authorize()` /
/// `capture()` flow, which is out of scope for the baseline port.
pub const ERR_TWO_PHASE_NOT_SUPPORTED: &str = "auth_capture_two_phase_not_supported";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_unique() {
        // Every code is part of the wire format; duplicates would make
        // failures indistinguishable to clients matching on the code.
        let codes = [
            ERR_INVALID_PAYLOAD_FORMAT,
            ERR_NETWORK_MISMATCH,
            ERR_INVALID_AUTH_CAPTURE_EXTRA,
            ERR_UNSUPPORTED_ASSET_TRANSFER_METHOD,
            ERR_CAPTURE_DEADLINE_EXPIRED,
            ERR_INVALID_DEADLINE_ORDERING,
            ERR_AUTHORIZATION_EXPIRED,
            ERR_AUTHORIZATION_NOT_YET_VALID,
            ERR_INVALID_AUTH_CAPTURE_SIGNATURE,
            ERR_AMOUNT_MISMATCH,
            ERR_TOKEN_COLLECTOR_MISMATCH,
            ERR_NONCE_MISMATCH,
            ERR_INSUFFICIENT_BALANCE,
            ERR_SIMULATION_FAILED,
            ERR_INVALID_CAPTURE_AUTHORIZER,
            ERR_ZERO_FEE_RECEIVER,
            ERR_TRANSACTION_REVERTED,
            ERR_TWO_PHASE_NOT_SUPPORTED,
        ];
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }
}
