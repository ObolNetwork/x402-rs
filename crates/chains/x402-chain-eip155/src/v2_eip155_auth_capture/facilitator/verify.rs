//! Verification for the auth-capture scheme.
//!
//! Implements the spec's "Verification Logic" steps for the EIP-3009 +
//! `charge()` path. The pure checks (steps 2–12, including ECDSA signature
//! recovery) live in [`verify_charge`] so they can be exercised offline; the
//! async [`verify`] dispatcher adds the onchain balance check and a `charge()`
//! simulation (step 13).

use alloy_primitives::{
    Address, U256,
    aliases::{U48, U120},
};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolStruct, eip712_domain};
use x402_types::proto::v2;

use super::abi::{PaymentInfo, payer_agnostic_nonce};
use super::settle::charge_calldata;
use crate::v2_eip155_auth_capture::constants::{
    AUTH_CAPTURE_ESCROW_ADDRESS, DEADLINE_SKEW_SECS, EIP3009_TOKEN_COLLECTOR_ADDRESS,
};
use crate::v2_eip155_auth_capture::errors as err;
use crate::v2_eip155_auth_capture::types::{PaymentPayload, PaymentRequirements};
use crate::v2_eip155_batch_settlement::facilitator::abi::{IERC20View, ReceiveWithAuthorization};
use crate::v2_eip155_batch_settlement::facilitator::voucher::recover_ecdsa_and_match;
use crate::v2_eip155_batch_settlement::types::AssetTransferMethod;

/// Everything settlement needs, produced by a successful verification.
#[derive(Debug)]
pub struct VerifiedCharge {
    /// The reconstructed onchain `PaymentInfo` struct.
    pub payment_info: PaymentInfo,
    /// Recovered payer address (the ERC-3009 `from`).
    pub payer: Address,
    /// Charge amount (`requirements.amount`, range-checked to `uint120`).
    pub amount: U256,
}

/// Current Unix time in seconds.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// Top-level dispatcher: offline checks, then balance read, then a `charge()`
/// simulation from the operator address.
pub async fn verify<P>(
    provider: &P,
    chain_id: u64,
    facilitator_signers: &[String],
    payment_payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> v2::VerifyResponse
where
    P: Provider,
{
    let payer = payment_payload.payload.authorization.from.to_string();
    let charge = match verify_charge(
        chain_id,
        unix_now(),
        facilitator_signers,
        payment_payload,
        requirements,
    ) {
        Ok(charge) => charge,
        Err(reason) => return v2::VerifyResponse::invalid(Some(payer), reason.to_string()),
    };

    // Spec check: payer balance covers the charge. An RPC read failure is
    // indistinguishable from "could not complete the onchain leg", so it
    // surfaces as `simulation_failed` rather than a false balance verdict.
    let token: Address = requirements.asset.into();
    let erc20 = IERC20View::new(token, provider);
    match erc20.balanceOf(charge.payer).call().await {
        Ok(balance) if balance >= charge.amount => {}
        Ok(_) => {
            return v2::VerifyResponse::invalid(Some(payer), err::ERR_INSUFFICIENT_BALANCE.into());
        }
        Err(_) => {
            return v2::VerifyResponse::invalid(Some(payer), err::ERR_SIMULATION_FAILED.into());
        }
    }

    // Spec step 13: simulate `charge()` from the operator address. Catches
    // everything the static checks cannot see (payment already collected,
    // token-level transfer restrictions, …).
    let calldata = charge_calldata(&charge, &payment_payload.payload.signature, requirements);
    let request = TransactionRequest::default()
        .from(charge.payment_info.operator)
        .to(AUTH_CAPTURE_ESCROW_ADDRESS)
        .input(calldata.into());
    if provider.call(request).await.is_err() {
        return v2::VerifyResponse::invalid(Some(payer), err::ERR_SIMULATION_FAILED.into());
    }

    v2::VerifyResponse::valid(payer)
}

/// Offline verification (spec "Verification Logic" steps 2–12).
///
/// Pure with respect to the chain: takes the clock and the facilitator's
/// signer set as inputs so conformance tests can drive it without an RPC
/// provider. On success returns the reconstructed [`VerifiedCharge`] that
/// settlement encodes into the `charge()` call.
pub fn verify_charge(
    chain_id: u64,
    now: u64,
    facilitator_signers: &[String],
    payment_payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<VerifiedCharge, &'static str> {
    // Steps 2–3: scheme equality is enforced by the typed wire format;
    // networks must agree with each other and with the connected chain.
    if payment_payload.accepted.network != requirements.network {
        return Err(err::ERR_NETWORK_MISMATCH);
    }
    if requirements.network.to_string() != format!("eip155:{chain_id}") {
        return Err(err::ERR_NETWORK_MISMATCH);
    }

    // Steps 4–5: extra validation + method routing. Required extra fields are
    // enforced by deserialization; Permit2 is recognized but out of scope for
    // the baseline port, as is the two-phase `authorize()` flow.
    let extra = &requirements.extra;
    match extra.asset_transfer_method {
        None | Some(AssetTransferMethod::Eip3009) => {}
        Some(AssetTransferMethod::Permit2) => {
            return Err(err::ERR_UNSUPPORTED_ASSET_TRANSFER_METHOD);
        }
    }
    if extra.auto_capture != Some(true) {
        return Err(err::ERR_TWO_PHASE_NOT_SUPPORTED);
    }
    if extra.min_fee_bps > extra.max_fee_bps || extra.max_fee_bps > 10_000 {
        return Err(err::ERR_INVALID_AUTH_CAPTURE_EXTRA);
    }
    let fee_recipient: Address = extra.fee_recipient.into();
    if extra.max_fee_bps > 0 && fee_recipient == Address::ZERO {
        return Err(err::ERR_ZERO_FEE_RECEIVER);
    }

    // The escrow gates `charge()` on `msg.sender == PaymentInfo.operator`, so
    // the advertised captureAuthorizer must be one of our own signers.
    let operator: Address = extra.capture_authorizer.into();
    let operator_is_ours = facilitator_signers
        .iter()
        .any(|signer| signer.parse::<Address>() == Ok(operator));
    if !operator_is_ours {
        return Err(err::ERR_INVALID_CAPTURE_AUTHORIZER);
    }

    // Step 6: deadline ordering.
    if extra.capture_deadline <= now + DEADLINE_SKEW_SECS {
        return Err(err::ERR_CAPTURE_DEADLINE_EXPIRED);
    }
    if extra.refund_deadline < extra.capture_deadline {
        return Err(err::ERR_INVALID_DEADLINE_ORDERING);
    }
    let auth = &payment_payload.payload.authorization;
    let valid_after = auth.valid_after.0;
    let valid_before = auth.valid_before.0;
    if valid_before > U256::from(extra.capture_deadline) {
        return Err(err::ERR_INVALID_DEADLINE_ORDERING);
    }

    // Step 7: time window.
    if valid_before <= U256::from(now + DEADLINE_SKEW_SECS) {
        return Err(err::ERR_AUTHORIZATION_EXPIRED);
    }
    if valid_after > U256::from(now) {
        return Err(err::ERR_AUTHORIZATION_NOT_YET_VALID);
    }

    // Step 8: collector match.
    let collector: Address = auth.to.into();
    if collector != EIP3009_TOKEN_COLLECTOR_ADDRESS {
        return Err(err::ERR_TOKEN_COLLECTOR_MISMATCH);
    }

    // Step 11: amount match + `uint120` range check.
    if auth.value != requirements.amount {
        return Err(err::ERR_AMOUNT_MISMATCH);
    }
    let amount: U256 = requirements.amount.0;
    if amount.bit_len() > 120 {
        return Err(err::ERR_AMOUNT_MISMATCH);
    }
    let limbs = amount.as_limbs();
    let max_amount = U120::from_limbs([limbs[0], limbs[1]]);

    // Step 12: reconstruct `PaymentInfo` and match the wire nonce against the
    // payer-agnostic hash. This transitively pins receiver, token, deadlines,
    // fee bounds, and feeRecipient to what the payer signed, so those need no
    // field-by-field checks.
    let payer: Address = auth.from.into();
    let token: Address = requirements.asset.into();
    let payment_info = PaymentInfo {
        operator,
        payer,
        receiver: requirements.pay_to.into(),
        token,
        maxAmount: max_amount,
        preApprovalExpiry: U48::from(valid_before),
        authorizationExpiry: U48::from(extra.capture_deadline),
        refundExpiry: U48::from(extra.refund_deadline),
        minFeeBps: extra.min_fee_bps,
        maxFeeBps: extra.max_fee_bps,
        feeReceiver: fee_recipient,
        salt: payment_payload.payload.salt.into(),
    };
    if payer_agnostic_nonce(chain_id, &payment_info) != auth.nonce {
        return Err(err::ERR_NONCE_MISMATCH);
    }

    // Step 10: recover the ERC-3009 signature over the token-domain EIP-712
    // digest; the signer must be the payer. EOA signatures only (ERC-2098
    // compact accepted) — EIP-1271/6492 smart-wallet envelopes are out of
    // scope for the baseline port.
    let receive_auth = ReceiveWithAuthorization {
        from: payer,
        to: collector,
        value: auth.value.0,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce: auth.nonce,
    };
    let domain = eip712_domain! {
        name: extra.name.clone(),
        version: extra.version.clone(),
        chain_id: chain_id,
        verifying_contract: token,
    };
    let digest = receive_auth.eip712_signing_hash(&domain);
    recover_ecdsa_and_match(&payment_payload.payload.signature, &digest, payer)
        .map_err(|_| err::ERR_INVALID_AUTH_CAPTURE_SIGNATURE)?;

    Ok(VerifiedCharge {
        payment_info,
        payer,
        amount,
    })
}
