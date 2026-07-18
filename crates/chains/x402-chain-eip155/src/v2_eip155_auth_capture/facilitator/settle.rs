//! Settlement for the auth-capture scheme.
//!
//! Re-verifies the payload offline (spec "Settlement Logic" step 1 — catches
//! expired or invalid payloads before spending gas), then submits a single
//! `charge()` transaction: the escrow pulls the payment through the ERC-3009
//! token collector, pays `feeBps` to `feeRecipient`, and forwards the
//! remainder to the receiver, atomically. The transaction-send path performs
//! gas estimation, which simulates the call — a doomed `charge()` fails there
//! rather than onchain.

use alloy_primitives::Bytes;
use alloy_provider::Provider;
use alloy_sol_types::SolCall;
use x402_types::chain::ChainProviderOps;
use x402_types::proto::v2;

use super::abi::AuthCaptureEscrow;
use super::verify::{VerifiedCharge, unix_now, verify_charge};
use crate::chain::{Eip155MetaTransactionProvider, MetaTransaction, MetaTransactionSendError};
use crate::v2_eip155_auth_capture::constants::{
    AUTH_CAPTURE_ESCROW_ADDRESS, EIP3009_TOKEN_COLLECTOR_ADDRESS,
};
use crate::v2_eip155_auth_capture::errors as err;
use crate::v2_eip155_auth_capture::types::{PaymentPayload, PaymentRequirements};

/// Encodes the `charge()` call for a verified payment.
///
/// `collectorData` is the raw ERC-3009 signature; the charged fee is
/// `extra.maxFeeBps` (with `minFeeBps == maxFeeBps` for fixed-fee servers,
/// this is exactly the agreed fee).
pub(crate) fn charge_calldata(
    charge: &VerifiedCharge,
    signature: &Bytes,
    requirements: &PaymentRequirements,
) -> Vec<u8> {
    AuthCaptureEscrow::chargeCall {
        paymentInfo: charge.payment_info.clone(),
        amount: charge.amount,
        tokenCollector: EIP3009_TOKEN_COLLECTOR_ADDRESS,
        collectorData: signature.clone(),
        feeBps: requirements.extra.max_fee_bps,
        feeReceiver: requirements.extra.fee_recipient.into(),
    }
    .abi_encode()
}

/// Executes settlement: offline re-verification, then `charge()` onchain.
pub async fn settle<P>(
    provider: &P,
    chain_id: u64,
    payment_payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> v2::SettleResponse
where
    P: Eip155MetaTransactionProvider + ChainProviderOps,
    P::Inner: Provider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = requirements.network.to_string();
    let signers = provider.signer_addresses();
    let charge = match verify_charge(
        chain_id,
        unix_now(),
        &signers,
        payment_payload,
        requirements,
    ) {
        Ok(charge) => charge,
        Err(reason) => {
            return v2::SettleResponse::Error {
                reason: reason.to_string(),
                network,
            };
        }
    };

    let calldata = charge_calldata(&charge, &payment_payload.payload.signature, requirements);
    match provider
        .send_transaction(MetaTransaction::new(
            AUTH_CAPTURE_ESCROW_ADDRESS,
            calldata.into(),
        ))
        .await
    {
        Ok(receipt) if receipt.status() => v2::SettleResponse::Success {
            payer: charge.payer.to_string(),
            transaction: receipt.transaction_hash.to_string(),
            network,
        },
        Ok(receipt) => v2::SettleResponse::Error {
            reason: format!(
                "{} (tx {})",
                err::ERR_TRANSACTION_REVERTED,
                receipt.transaction_hash
            ),
            network,
        },
        Err(e) => {
            let send_error: MetaTransactionSendError = e.into();
            v2::SettleResponse::Error {
                reason: format!("{}: {}", err::ERR_TRANSACTION_REVERTED, send_error),
                network,
            }
        }
    }
}
