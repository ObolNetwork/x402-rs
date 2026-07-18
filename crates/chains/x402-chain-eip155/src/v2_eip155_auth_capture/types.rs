//! Wire format types for the V2 EIP-155 `auth-capture` payment scheme.
//!
//! Mirrors `specs/schemes/auth-capture/scheme_auth_capture_evm.md` and the
//! TypeScript client in
//! `typescript/packages/mechanisms/evm/src/auth-capture/types.ts`.
//!
//! Scope: the EIP-3009 + `charge()` (auto-capture) path. Permit2 payloads and
//! the two-phase `authorize()`/`capture()` flow are recognized on the wire but
//! rejected with stable error codes until implemented.

use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};
use x402_types::lit_str;
use x402_types::proto::v2;

use crate::chain::ChecksummedAddress;
use crate::v2_eip155_batch_settlement::types::{AssetTransferMethod, U256String};

lit_str!(AuthCaptureScheme, "auth-capture");

/// V2 `PaymentRequirements` for auth-capture payments.
pub type PaymentRequirements = v2::PaymentRequirements<
    AuthCaptureScheme,
    U256String,
    ChecksummedAddress,
    AuthCapturePaymentRequirementsExtra,
>;

/// V2 `PaymentPayload` enveloping an auth-capture payload.
pub type PaymentPayload = v2::PaymentPayload<PaymentRequirements, AuthCapturePayload>;

/// V2 `VerifyRequest` for auth-capture payments.
pub type VerifyRequest = v2::VerifyRequest<PaymentPayload, PaymentRequirements>;

/// V2 `SettleRequest` for auth-capture payments (same shape as verify).
pub type SettleRequest = VerifyRequest;

/// `PaymentRequirements.extra` for auth-capture payments.
///
/// Wire field names are spec-level; the on-chain `PaymentInfo` mapping is:
/// `captureAuthorizer` → `operator`, `captureDeadline` → `authorizationExpiry`,
/// `refundDeadline` → `refundExpiry`, `feeRecipient` → `feeReceiver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthCapturePaymentRequirementsExtra {
    /// EIP-712 token-domain name (ERC-3009 signing only).
    pub name: String,
    /// EIP-712 token-domain version.
    pub version: String,
    /// Address authorized to authorize/capture/void/refund/charge.
    pub capture_authorizer: ChecksummedAddress,
    /// Absolute Unix seconds — capture must occur before this (`authorizationExpiry`).
    pub capture_deadline: u64,
    /// Absolute Unix seconds — refunds allowed until this (`refundExpiry`).
    pub refund_deadline: u64,
    /// Fee recipient (`PaymentInfo.feeReceiver`).
    pub fee_recipient: ChecksummedAddress,
    /// Minimum fee in basis points.
    pub min_fee_bps: u16,
    /// Maximum fee in basis points.
    pub max_fee_bps: u16,
    /// `true` → single-shot `charge()`. `false`/absent → two-phase `authorize()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_capture: Option<bool>,
    /// Which token collector to use. Default `eip3009`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_transfer_method: Option<AssetTransferMethod>,
}

/// ERC-3009 `ReceiveWithAuthorization` fields carried in the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthCaptureAuthorization {
    /// Payer address (signature must recover to this).
    pub from: ChecksummedAddress,
    /// Must equal the canonical `EIP3009_TOKEN_COLLECTOR_ADDRESS`.
    pub to: ChecksummedAddress,
    /// Must equal `requirements.amount`.
    pub value: U256String,
    /// `0` — the token collector hardcodes the lower bound.
    pub valid_after: U256String,
    /// `now + maxTimeoutSeconds`; doubles as `PaymentInfo.preApprovalExpiry`.
    pub valid_before: U256String,
    /// The payer-agnostic `PaymentInfo` hash (see nonce derivation).
    pub nonce: B256,
}

/// Auth-capture EIP-3009 payment payload: authorization + signature + salt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthCapturePayload {
    /// The ERC-3009 authorization fields.
    pub authorization: AuthCaptureAuthorization,
    /// 65-byte ECDSA (or ERC-2098 compact / EIP-1271 envelope) signature.
    pub signature: Bytes,
    /// Fresh client-generated entropy (`PaymentInfo.salt`).
    pub salt: B256,
}
