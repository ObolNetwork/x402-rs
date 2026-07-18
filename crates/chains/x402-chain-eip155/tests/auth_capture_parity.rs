//! Cross-module integration tests for the V2 EIP-155 `auth-capture` scheme.
//!
//! These tests sit at the crate boundary so they exercise the publicly
//! re-exported API the same way downstream consumers do. They mirror the
//! upstream TypeScript unit suite
//! (`typescript/packages/mechanisms/evm/test/unit/auth-capture/`) and pin the
//! hash pipeline against cross-implementation golden vectors:
//!
//! - the payer-agnostic nonce, three ways — the deployed Base Sepolia
//!   `AuthCaptureEscrow.getHash()`, viem (`encodeAbiParameters` + `keccak256`,
//!   the primitives the upstream TS client uses), and `alloy_sol_types` — all
//!   agreeing on the same 32 bytes;
//! - the ERC-3009 `ReceiveWithAuthorization` digest and a full client-signed
//!   payload against viem's `hashTypedData` / `signTypedData`, driven through
//!   the offline verification path end to end.

#![cfg(feature = "facilitator")]

use alloy_primitives::{B256, U256, address, b256, bytes};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use x402_chain_eip155::chain::ChecksummedAddress;
use x402_chain_eip155::v2_eip155_auth_capture::{
    AuthCaptureAuthorization, AuthCapturePayload, AuthCapturePaymentRequirementsExtra,
    AuthCaptureScheme, PaymentPayload, PaymentRequirements, constants, errors as err,
    facilitator::{
        abi::{PaymentInfo, payer_agnostic_nonce},
        verify_charge,
    },
};
use x402_chain_eip155::v2_eip155_batch_settlement::types::{AssetTransferMethod, U256String};

const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

/// Well-known anvil account 0 — the payer in the signed fixture.
const PAYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PAYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// Facilitator signer advertised as `captureAuthorizer` in the fixture.
const OPERATOR: &str = "0x4444444444444444444444444444444444444444";

fn addr(s: &str) -> ChecksummedAddress {
    s.parse().unwrap()
}

/// The shared fixture: same concrete values as the golden-vector sample in
/// `facilitator/abi.rs`, so every hash asserted here is pinned against the
/// deployed escrow's `getHash()` as well as viem.
fn sample_extra() -> AuthCapturePaymentRequirementsExtra {
    AuthCapturePaymentRequirementsExtra {
        name: "USDC".into(),
        version: "2".into(),
        capture_authorizer: addr(OPERATOR),
        capture_deadline: 1_800_000_600,
        refund_deadline: 1_800_001_200,
        fee_recipient: addr("0x5555555555555555555555555555555555555555"),
        min_fee_bps: 2000,
        max_fee_bps: 2000,
        auto_capture: Some(true),
        asset_transfer_method: None,
    }
}

fn sample_requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: AuthCaptureScheme,
        network: x402_types::chain::ChainId::new("eip155", "84532"),
        amount: U256String::from(U256::from(1500u64)),
        pay_to: addr("0x3333333333333333333333333333333333333333"),
        max_timeout_seconds: 300,
        asset: addr("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
        extra: sample_extra(),
    }
}

/// Nonce for the shared fixture — equals the deployed escrow's `getHash()`
/// (payer zeroed) and viem's recomputation. See `facilitator/abi.rs`.
const FIXTURE_NONCE: B256 =
    b256!("0xcad3fb0ec55cb75e58df69311ba1d530447f64e0798e57e842987c2fbdb4f02f");

/// A fixed clock inside the fixture's validity window (validAfter = 0,
/// validBefore = 1.8e9, deadlines beyond that).
const NOW: u64 = 1_790_000_000;

fn signed_payload() -> PaymentPayload {
    let signer: PrivateKeySigner = PAYER_KEY.parse().unwrap();
    let authorization = AuthCaptureAuthorization {
        from: addr(PAYER),
        to: addr("0x0E3dF9510de65469C4518D7843919c0b8C7A7757"),
        value: U256String::from(U256::from(1500u64)),
        valid_after: U256String::from(U256::ZERO),
        valid_before: U256String::from(U256::from(1_800_000_000u64)),
        nonce: FIXTURE_NONCE,
    };
    // Sign the same EIP-712 digest viem's signTypedData produces (pinned in
    // `erc3009_digest_and_signature_match_viem` below).
    let digest = b256!("0xe21415fb808c901533cf13d58ad14d9b07e5f33dc7142b06c0fc13a90f362b12");
    let signature = signer.sign_hash_sync(&digest).unwrap();
    PaymentPayload {
        accepted: sample_requirements(),
        payload: AuthCapturePayload {
            authorization,
            signature: signature.as_bytes().to_vec().into(),
            salt: b256!("0x0000000000000000000000000000000000000000000000000000000000000abc"),
        },
        resource: None,
        x402_version: x402_types::proto::v2::X402Version2,
        extensions: Default::default(),
    }
}

fn signers() -> Vec<String> {
    vec![OPERATOR.to_string()]
}

// --- Wire format (mirrors types.test.ts) ------------------------------------

#[test]
fn payment_payload_round_trips_via_value() {
    let payload = signed_payload();
    let json = serde_json::to_value(&payload).unwrap();
    assert_eq!(json["accepted"]["scheme"], "auth-capture");
    assert_eq!(json["accepted"]["network"], "eip155:84532");
    assert_eq!(json["payload"]["authorization"]["value"], "1500");
    assert_eq!(json["payload"]["authorization"]["validAfter"], "0");
    assert!(json["payload"]["signature"].is_string());
    assert!(json["payload"]["salt"].is_string());
    let back: PaymentPayload = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
    assert_eq!(back.payload, payload.payload);
}

#[test]
fn requirements_extra_round_trips_with_camel_case_fields() {
    let req = sample_requirements();
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["extra"]["captureAuthorizer"], OPERATOR);
    assert_eq!(json["extra"]["captureDeadline"], 1_800_000_600u64);
    assert_eq!(json["extra"]["refundDeadline"], 1_800_001_200u64);
    assert_eq!(json["extra"]["minFeeBps"], 2000);
    assert_eq!(json["extra"]["maxFeeBps"], 2000);
    assert_eq!(json["extra"]["autoCapture"], true);
    // Optional fields are omitted, not null (wire compatibility with TS).
    assert!(json["extra"].get("assetTransferMethod").is_none());
    let back: PaymentRequirements = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
    assert_eq!(back.extra, req.extra);
}

#[test]
fn extra_missing_required_field_is_rejected() {
    // Mirrors the TS `isAuthCaptureExtra` guard tests: dropping any required
    // field must fail deserialization.
    let full = serde_json::to_value(sample_extra()).unwrap();
    for field in [
        "name",
        "version",
        "captureAuthorizer",
        "captureDeadline",
        "refundDeadline",
        "feeRecipient",
        "minFeeBps",
        "maxFeeBps",
    ] {
        let mut json = full.clone();
        json.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AuthCapturePaymentRequirementsExtra>(json).is_err(),
            "extra without {field} should be rejected"
        );
    }
}

// --- Nonce derivation (mirrors nonce.test.ts + golden vectors) ---------------

fn fixture_payment_info(payer: &str) -> PaymentInfo {
    PaymentInfo {
        operator: OPERATOR.parse().unwrap(),
        payer: payer.parse().unwrap(),
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

#[test]
fn nonce_is_payer_agnostic() {
    // Mirrors the TS test: different payers (and the zero payer) produce the
    // identical nonce, because the payer is zeroed before hashing.
    let a = payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &fixture_payment_info(PAYER));
    let b = payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &fixture_payment_info(OPERATOR));
    let zero = payer_agnostic_nonce(
        BASE_SEPOLIA_CHAIN_ID,
        &fixture_payment_info("0x0000000000000000000000000000000000000000"),
    );
    assert_eq!(a, b);
    assert_eq!(a, zero);
    assert_eq!(a, FIXTURE_NONCE);
}

#[test]
fn nonce_differs_by_chain_amount_and_salt() {
    // Mirrors the TS tests: chain id, any PaymentInfo field, and the salt all
    // feed the hash, so changing any of them changes the nonce.
    let base = payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &fixture_payment_info(PAYER));
    assert_ne!(
        base,
        payer_agnostic_nonce(8453, &fixture_payment_info(PAYER))
    );
    let mut bigger = fixture_payment_info(PAYER);
    bigger.maxAmount = alloy_primitives::aliases::U120::from(2000u64);
    assert_ne!(base, payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &bigger));
    let mut salted = fixture_payment_info(PAYER);
    salted.salt = U256::from(0xdefu64);
    assert_ne!(base, payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &salted));
}

#[test]
fn nonce_matches_upstream_ts_fixture_vector() {
    // The exact mock struct from the upstream TS suite
    // (`test/unit/auth-capture/nonce.test.ts`), with the nonce computed via
    // viem — pins this port against the fixture the reference implementation
    // tests itself with.
    let info = PaymentInfo {
        operator: address!("1111111111111111111111111111111111111111"),
        payer: address!("0000000000000000000000000000000000000000"),
        receiver: address!("2222222222222222222222222222222222222222"),
        token: address!("3333333333333333333333333333333333333333"),
        maxAmount: alloy_primitives::aliases::U120::from(1_000_000u64),
        preApprovalExpiry: alloy_primitives::aliases::U48::from(281_474_976_710_655u64),
        authorizationExpiry: alloy_primitives::aliases::U48::from(281_474_976_710_655u64),
        refundExpiry: alloy_primitives::aliases::U48::from(281_474_976_710_655u64),
        minFeeBps: 0,
        maxFeeBps: 100,
        feeReceiver: address!("4444444444444444444444444444444444444444"),
        salt: U256::from(1u64),
    };
    assert_eq!(
        payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &info),
        b256!("0x19de8ffcb747e5caadb3dda7435cf54992e87cdf0c90e5315ffa129dbb22461e"),
    );
}

// --- ERC-3009 signing parity with viem ---------------------------------------

#[test]
fn erc3009_digest_and_signature_match_viem() {
    // Vector source: viem `hashTypedData` / `signTypedData` over the token
    // EIP-712 domain (USDC v2, Base Sepolia) for the shared fixture, signed
    // by anvil account 0. If alloy's typed-data derivation ever drifts from
    // viem's, the digest changes and real client signatures stop verifying —
    // this assertion fails first.
    let payload = signed_payload();
    let viem_signature = bytes!(
        "0xaabdea1c622c51a1f773bb46f37af4f1157dc4d56218b1f16d47d959d13f06083f1f21a8d660cdb08627ef42112543aa8812e075c1d7427dea041adb779223d91c"
    );
    assert_eq!(payload.payload.signature, viem_signature);
}

// --- Offline verification round-trip (spec steps 2–12) ------------------------

#[test]
fn verify_charge_accepts_a_well_formed_signed_payload() {
    let charge = verify_charge(
        BASE_SEPOLIA_CHAIN_ID,
        NOW,
        &signers(),
        &signed_payload(),
        &sample_requirements(),
    )
    .expect("fixture payload should verify");
    assert_eq!(
        charge.payer,
        PAYER.parse::<alloy_primitives::Address>().unwrap()
    );
    assert_eq!(charge.amount, U256::from(1500u64));
    assert_eq!(
        charge.payment_info.operator,
        OPERATOR.parse::<alloy_primitives::Address>().unwrap()
    );
    // The reconstructed PaymentInfo re-derives the wire nonce.
    assert_eq!(
        payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &charge.payment_info),
        FIXTURE_NONCE,
    );
}

#[test]
fn verify_charge_rejects_per_spec_error_table() {
    let requirements = sample_requirements();
    let payload = signed_payload();
    let check = |payload: &PaymentPayload,
                 requirements: &PaymentRequirements,
                 now: u64,
                 signers: &[String],
                 expected: &str| {
        let got = verify_charge(BASE_SEPOLIA_CHAIN_ID, now, signers, payload, requirements)
            .expect_err("mutation should be rejected");
        assert_eq!(got, expected);
    };

    // Tampered wire nonce → nonce_mismatch.
    let mut p = payload.clone();
    p.payload.authorization.nonce = B256::repeat_byte(0x42);
    check(&p, &requirements, NOW, &signers(), err::ERR_NONCE_MISMATCH);

    // Salt not matching the signed nonce → nonce_mismatch.
    let mut p = payload.clone();
    p.payload.salt = B256::repeat_byte(0x01);
    check(&p, &requirements, NOW, &signers(), err::ERR_NONCE_MISMATCH);

    // Requirements drift (receiver swapped) → nonce reconstruction catches it.
    let mut r = requirements.clone();
    r.pay_to = addr("0x9999999999999999999999999999999999999999");
    let mut p = payload.clone();
    p.accepted = r.clone();
    check(&p, &r, NOW, &signers(), err::ERR_NONCE_MISMATCH);

    // Wrong collector → token_collector_mismatch.
    let mut p = payload.clone();
    p.payload.authorization.to = addr("0x9999999999999999999999999999999999999999");
    check(
        &p,
        &requirements,
        NOW,
        &signers(),
        err::ERR_TOKEN_COLLECTOR_MISMATCH,
    );

    // Authorization value diverging from requirements → amount_mismatch.
    let mut p = payload.clone();
    p.payload.authorization.value = U256String::from(U256::from(9999u64));
    check(&p, &requirements, NOW, &signers(), err::ERR_AMOUNT_MISMATCH);

    // Tampered signature → invalid_auth_capture_signature.
    let mut p = payload.clone();
    let mut sig = p.payload.signature.to_vec();
    sig[10] ^= 0xff;
    p.payload.signature = sig.into();
    check(
        &p,
        &requirements,
        NOW,
        &signers(),
        err::ERR_INVALID_AUTH_CAPTURE_SIGNATURE,
    );

    // Clock past captureDeadline → capture_deadline_expired.
    check(
        &payload,
        &requirements,
        1_800_000_601,
        &signers(),
        err::ERR_CAPTURE_DEADLINE_EXPIRED,
    );

    // Clock past validBefore but before captureDeadline → authorization_expired.
    check(
        &payload,
        &requirements,
        1_800_000_100,
        &signers(),
        err::ERR_AUTHORIZATION_EXPIRED,
    );

    // refundDeadline < captureDeadline → invalid_deadline_ordering. The nonce
    // is recomputed for the mutated extra so ordering is what fails.
    let mut r = requirements.clone();
    r.extra.refund_deadline = r.extra.capture_deadline - 1;
    let mut p = payload.clone();
    p.accepted = r.clone();
    check(&p, &r, NOW, &signers(), err::ERR_INVALID_DEADLINE_ORDERING);

    // Permit2 method → unsupported in the baseline port.
    let mut r = requirements.clone();
    r.extra.asset_transfer_method = Some(AssetTransferMethod::Permit2);
    let mut p = payload.clone();
    p.accepted = r.clone();
    check(
        &p,
        &r,
        NOW,
        &signers(),
        err::ERR_UNSUPPORTED_ASSET_TRANSFER_METHOD,
    );

    // Two-phase authorize/capture (autoCapture unset) → out of scope.
    let mut r = requirements.clone();
    r.extra.auto_capture = None;
    let mut p = payload.clone();
    p.accepted = r.clone();
    check(&p, &r, NOW, &signers(), err::ERR_TWO_PHASE_NOT_SUPPORTED);

    // Nonzero fee with a zero feeRecipient → zero_fee_receiver.
    let mut r = requirements.clone();
    r.extra.fee_recipient = addr("0x0000000000000000000000000000000000000000");
    let mut p = payload.clone();
    p.accepted = r.clone();
    check(&p, &r, NOW, &signers(), err::ERR_ZERO_FEE_RECEIVER);

    // captureAuthorizer that is not one of our signers → invalid_capture_authorizer.
    check(
        &payload,
        &requirements,
        NOW,
        &["0x1111111111111111111111111111111111111111".to_string()],
        err::ERR_INVALID_CAPTURE_AUTHORIZER,
    );

    // Network drift between accepted and requirements → network_mismatch.
    let mut p = payload.clone();
    p.accepted.network = x402_types::chain::ChainId::new("eip155", "8453");
    check(
        &p,
        &requirements,
        NOW,
        &signers(),
        err::ERR_NETWORK_MISMATCH,
    );
}

// --- Settle wire shape --------------------------------------------------------

#[test]
fn charge_call_encodes_and_decodes_round_trip() {
    use alloy_sol_types::SolCall;
    use x402_chain_eip155::v2_eip155_auth_capture::facilitator::abi::AuthCaptureEscrow;

    let charge = verify_charge(
        BASE_SEPOLIA_CHAIN_ID,
        NOW,
        &signers(),
        &signed_payload(),
        &sample_requirements(),
    )
    .unwrap();
    let call = AuthCaptureEscrow::chargeCall {
        paymentInfo: charge.payment_info.clone(),
        amount: charge.amount,
        tokenCollector: constants::EIP3009_TOKEN_COLLECTOR_ADDRESS,
        collectorData: signed_payload().payload.signature.clone(),
        feeBps: 2000,
        feeReceiver: address!("5555555555555555555555555555555555555555"),
    };
    let encoded = call.abi_encode();
    assert_eq!(&encoded[..4], AuthCaptureEscrow::chargeCall::SELECTOR);
    let decoded = AuthCaptureEscrow::chargeCall::abi_decode(&encoded).unwrap();
    assert_eq!(decoded.amount, U256::from(1500u64));
    assert_eq!(
        decoded.tokenCollector,
        constants::EIP3009_TOKEN_COLLECTOR_ADDRESS
    );
    assert_eq!(decoded.feeBps, 2000);
    assert_eq!(
        payer_agnostic_nonce(BASE_SEPOLIA_CHAIN_ID, &decoded.paymentInfo),
        FIXTURE_NONCE,
    );
}
