//! V2 EIP-155 `auth-capture` payment scheme implementation.
//!
//! `auth-capture` escrows a single client-signed payment in the audited
//! base/commerce-payments `AuthCaptureEscrow` contract, which enforces
//! client-signed fee bounds and splits `feeBps` to `feeRecipient` at capture
//! time — the canonical x402 native-fee mechanism. One client signature covers
//! the payment and the fee split; no second authorization is needed.
//!
//! See `docs/specs/schemes/auth-capture/scheme_auth_capture_evm.md` (mirrored
//! from the upstream `x402-foundation/x402` repo) for the full spec.
//!
//! # Module Layout
//!
//! - [`constants`]   — canonical contract addresses + protocol bounds
//! - [`errors`]      — wire-format error code constants
//! - [`types`]       — wire types (requirements extra, authorization, payload)
//! - [`facilitator`] — verify / settle / supported dispatcher (gated behind
//!   the `facilitator` feature)
//!
//! # Scope
//!
//! The baseline port implements the EIP-3009 + single-shot `charge()`
//! (`extra.autoCapture == true`) path with EOA signatures (ERC-2098 compact
//! accepted). Permit2 payloads, the two-phase `authorize()`/`capture()` flow,
//! and EIP-1271/6492 smart-wallet signatures are rejected with stable error
//! codes until implemented.
//!
//! # Scheme Identifier
//!
//! The blueprint registers itself as `v2-eip155-auth-capture`.

pub mod constants;
pub mod errors;
pub mod types;

pub use types::{
    AuthCaptureAuthorization, AuthCapturePayload, AuthCapturePaymentRequirementsExtra,
    AuthCaptureScheme, PaymentPayload, PaymentRequirements, SettleRequest, VerifyRequest,
};

#[cfg(feature = "facilitator")]
pub mod facilitator;
#[cfg(feature = "facilitator")]
pub use facilitator::V2Eip155AuthCaptureFacilitator;

use x402_types::scheme::X402SchemeId;

/// Scheme identifier blueprint for `v2-eip155-auth-capture`.
///
/// This unit struct is the public entry point for registering the scheme with
/// a [`x402_types::scheme::SchemeBlueprints`] registry. The facilitator-side
/// implementation lives in [`facilitator`] (gated behind the `facilitator`
/// feature).
pub struct V2Eip155AuthCapture;

impl X402SchemeId for V2Eip155AuthCapture {
    fn namespace(&self) -> &str {
        "eip155"
    }

    fn scheme(&self) -> &str {
        AuthCaptureScheme.as_ref()
    }
}
