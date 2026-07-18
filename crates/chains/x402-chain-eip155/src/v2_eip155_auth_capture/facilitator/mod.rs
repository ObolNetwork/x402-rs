//! Facilitator-side implementation of the V2 EIP-155 `auth-capture` scheme.
//!
//! The facilitator implements three operations:
//!
//! - [`X402SchemeFacilitator::verify`]    — validate an auth-capture payload
//!   without committing onchain: offline checks (deadlines, collector, amount,
//!   nonce reconstruction, ERC-3009 signature recovery), payer balance read,
//!   and a `charge()` simulation.
//! - [`X402SchemeFacilitator::settle`]    — re-verify offline, then submit a
//!   single `charge()` transaction. The escrow collects the payment, pays
//!   `feeBps` to `feeRecipient`, and forwards the remainder to the receiver
//!   atomically.
//! - [`X402SchemeFacilitator::supported`] — advertise the scheme and the
//!   facilitator's transaction signer as `extra.captureAuthorizer`, so
//!   resource servers can build requirements the facilitator can settle.
//!
//! Configuration: none. The escrow gates `charge()` on
//! `msg.sender == PaymentInfo.operator`, so the capture authorizer is always
//! the facilitator's own transaction signer; any JSON config supplied at
//! registration is ignored.

pub mod abi;
pub mod settle;
pub mod verify;

pub use verify::{VerifiedCharge, verify_charge};

use alloy_provider::Provider;
use std::collections::HashMap;
use x402_types::chain::ChainProviderOps;
use x402_types::proto;
use x402_types::proto::v2;
use x402_types::scheme::{
    X402SchemeFacilitator, X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError,
};

use crate::V2Eip155AuthCapture;
use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_auth_capture::constants::AUTH_CAPTURE_SCHEME;
use crate::v2_eip155_auth_capture::types as wire;

impl<P> X402SchemeFacilitatorBuilder<P> for V2Eip155AuthCapture
where
    P: Eip155MetaTransactionProvider + ChainProviderOps + Send + Sync + 'static,
    P::Inner: Provider,
    P::Error: Into<MetaTransactionSendError>,
{
    fn build(
        &self,
        provider: P,
        _config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        Ok(Box::new(V2Eip155AuthCaptureFacilitator::new(provider)))
    }
}

/// Facilitator implementation for V2 EIP-155 `auth-capture`.
///
/// Decoupled from any single provider implementation — accepts anything that
/// implements [`Eip155MetaTransactionProvider`] + [`ChainProviderOps`], so it
/// can be exercised with a mock provider in tests.
pub struct V2Eip155AuthCaptureFacilitator<P> {
    provider: P,
}

impl<P> V2Eip155AuthCaptureFacilitator<P> {
    /// Constructs a facilitator directly.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

#[async_trait::async_trait]
impl<P> X402SchemeFacilitator for V2Eip155AuthCaptureFacilitator<P>
where
    P: Eip155MetaTransactionProvider + ChainProviderOps + Send + Sync,
    P::Inner: Provider,
    P::Error: Into<MetaTransactionSendError>,
{
    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, X402SchemeFacilitatorError> {
        let typed: wire::VerifyRequest = wire::VerifyRequest::try_from(request)?;
        let chain_id = self.provider.chain().inner();
        let signers = self.provider.signer_addresses();
        let response = verify::verify(
            self.provider.inner(),
            chain_id,
            &signers,
            &typed.payment_payload,
            &typed.payment_requirements,
        )
        .await;
        Ok(response.into())
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, X402SchemeFacilitatorError> {
        let typed: wire::SettleRequest = wire::SettleRequest::try_from(request)?;
        let chain_id = self.provider.chain().inner();
        let response = settle::settle(
            &self.provider,
            chain_id,
            &typed.payment_payload,
            &typed.payment_requirements,
        )
        .await;
        Ok(response.into())
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, X402SchemeFacilitatorError> {
        let chain_id = self.provider.chain_id();
        // Resource servers must set `extra.captureAuthorizer` to an address
        // the facilitator can transact as; advertise the first signer.
        let extra = self
            .provider
            .signer_addresses()
            .first()
            .map(|signer| serde_json::json!({ "captureAuthorizer": signer }));
        let kinds = vec![proto::SupportedPaymentKind {
            x402_version: v2::X402Version2.into(),
            scheme: AUTH_CAPTURE_SCHEME.to_string(),
            network: chain_id.clone().into(),
            extra,
        }];
        let mut signers = HashMap::with_capacity(1);
        signers.insert(chain_id, self.provider.signer_addresses());
        Ok(proto::SupportedResponse {
            kinds,
            extensions: Vec::new(),
            signers,
        })
    }
}
