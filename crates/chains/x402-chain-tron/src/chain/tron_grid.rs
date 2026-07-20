//! HTTP client for the TronGrid full-node API, used with `visible: true` so all
//! addresses on the wire are Base58Check.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use crate::chain::TronAddress;
use crate::chain::provider::TronChainProviderError;
use crate::chain::types::{TronTxId, prefixless_hex};

/// A TronGrid HTTP client bound to a single node's base URL.
pub struct TronGridHttp {
    /// TronGrid base URL.
    rpc_url: Url,
    /// HTTP client.
    client: reqwest::Client,
}

impl TronGridHttp {
    /// Creates a client with a fresh `reqwest::Client`.
    pub fn new(rpc_url: Url) -> Self {
        Self {
            rpc_url,
            client: reqwest::Client::new(),
        }
    }

    /// Creates a client reusing an existing `reqwest::Client` (e.g. for connection pooling).
    pub fn with_client(rpc_url: Url, client: reqwest::Client) -> Self {
        Self { rpc_url, client }
    }

    /// POSTs `body` as JSON to `endpoint` (relative to `rpc_url`) and decodes the
    /// response as `TResp`.
    ///
    /// Centralizes request/response handling for all TronGrid calls so that:
    /// - every outgoing request is logged (endpoint + URL) when `telemetry` is enabled;
    /// - transport failures, non-2xx statuses, and JSON decode failures are all logged
    ///   with as much context as possible (status code and a truncated response body),
    ///   instead of a bare "can not decode TronGrid response".
    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self, body),
            fields(
                otel.kind = "client",
                trongrid.endpoint = endpoint,
                http.status_code = tracing::field::Empty,
            )
        )
    )]
    async fn send_json<TReq, TResp>(
        &self,
        endpoint: &str,
        body: &TReq,
    ) -> Result<TResp, TronGridLikeError>
    where
        TReq: Serialize + ?Sized,
        TResp: DeserializeOwned,
    {
        let url = self.rpc_url.join(endpoint)?;

        let response = self
            .client
            .post(url.clone())
            .json(body)
            .send()
            .await
            .map_err(|err| {
                #[cfg(feature = "telemetry")]
                tracing::error!(
                    trongrid.endpoint = endpoint,
                    trongrid.url = %url,
                    error = %err,
                    "TronGrid request failed to send"
                );
                TronGridLikeError::from(err)
            })?;

        let status = response.status();
        #[cfg(feature = "telemetry")]
        tracing::Span::current().record("http.status_code", status.as_u16());

        let text = response.text().await.map_err(|err| {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.endpoint = endpoint,
                http.status_code = status.as_u16(),
                error = %err,
                "failed to read TronGrid response body"
            );
            TronGridLikeError::from(err)
        })?;

        if !status.is_success() {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.endpoint = endpoint,
                http.status_code = status.as_u16(),
                body = %truncate_body(&text),
                "TronGrid returned a non-success HTTP status"
            );
            return Err(TronGridLikeError::HttpStatus {
                endpoint: endpoint.to_string(),
                status: status.as_u16(),
                body: truncate_body(&text),
            });
        }

        serde_json::from_str::<TResp>(&text).map_err(|err| {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.endpoint = endpoint,
                http.status_code = status.as_u16(),
                body = %truncate_body(&text),
                error = %err,
                "failed to decode TronGrid response"
            );
            TronGridLikeError::ParsingError {
                endpoint: endpoint.to_string(),
                status: status.as_u16(),
                reason: err.to_string(),
                body: truncate_body(&text),
            }
        })
    }
}

/// Truncates a response body for logging/error messages so a huge (or unexpected
/// HTML/binary) payload doesn't blow up logs or error strings.
fn truncate_body(body: &str) -> String {
    const MAX_LEN: usize = 10000;
    if body.len() > MAX_LEN {
        let boundary = (0..=MAX_LEN)
            .rfind(|&i| body.is_char_boundary(i))
            .unwrap_or(0);
        format!(
            "{}... [truncated, {} bytes total]",
            &body[..boundary],
            body.len()
        )
    } else {
        body.to_string()
    }
}

impl fmt::Debug for TronGridHttp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TronGridHttp")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

/// Errors from calling the TronGrid HTTP API.
#[derive(Debug, thiserror::Error)]
pub enum TronGridLikeError {
    /// The HTTP request itself failed (network, URL parsing, etc).
    #[error("TronGrid transport: {0}")]
    Transport(String),
    /// TronGrid responded, but with a non-2xx HTTP status. Carries a truncated body so
    /// the cause (rate limiting, maintenance page, auth failure, etc.) is visible.
    #[error("TronGrid HTTP {endpoint} returned status {status}: {body}")]
    HttpStatus {
        endpoint: String,
        status: u16,
        body: String,
    },
    /// The response body didn't have the expected shape. Carries the endpoint, HTTP
    /// status, the underlying (de)serialization error, and a truncated body so the
    /// actual TronGrid payload is visible in logs instead of just "can not decode".
    #[error(
        "failed to parse TronGrid response from {endpoint} (status {status}): {reason}; body: {body}"
    )]
    ParsingError {
        endpoint: String,
        status: u16,
        reason: String,
        body: String,
    },
    /// TronGrid returned a well-formed response reporting failure.
    #[error("TronGrid returned an error: {0}")]
    ReportedError(String),
    /// The response was valid JSON matching the expected envelope, but a nested field
    /// couldn't be decoded further (e.g. ABI-decoding `constant_result`, or a required
    /// field was absent).
    #[error("failed to decode TronGrid response: {0}")]
    Decode(String),
}

impl From<url::ParseError> for TronGridLikeError {
    fn from(value: url::ParseError) -> Self {
        Self::Transport(value.to_string())
    }
}

impl From<reqwest::Error> for TronGridLikeError {
    fn from(value: reqwest::Error) -> Self {
        Self::Transport(value.to_string())
    }
}

impl From<TronGridParsingError> for TronGridLikeError {
    fn from(value: TronGridParsingError) -> Self {
        Self::Decode(value.to_string())
    }
}

impl From<TronGridReportedError> for TronGridLikeError {
    fn from(value: TronGridReportedError) -> Self {
        Self::ReportedError(value.0)
    }
}

/// Internal parsing errors, converted into [`TronGridLikeError::ParsingError`].
#[derive(Debug, thiserror::Error)]
enum TronGridParsingError {
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("can not abi decode: {0}")]
    AbiDecode(#[from] alloy_sol_types::Error),
}

/// A `result: false` reported by TronGrid, carrying its error message.
#[derive(Debug, thiserror::Error)]
#[error("TronGrid reported error: {0}")]
pub struct TronGridReportedError(String);

/// TronGrid wallet API operations needed to read state and submit transactions.
pub trait TronGridLike {
    /// Calls a read-only contract method via `triggerconstantcontract` and ABI-decodes
    /// the return value.
    fn wallet_trigger_constant_contract<TCalldata>(
        &self,
        contract_address: TronAddress,
        calldata: TCalldata,
        from: Option<TronAddress>,
    ) -> impl Future<Output = Result<TCalldata::Return, TronGridLikeError>>
    where
        TCalldata: SolCall + Send;

    /// Build an unsigned transaction via `triggersmartcontract`.
    ///
    /// Uses `visible: true` so addresses are Base58Check throughout.
    fn wallet_trigger_smart_contract<TCalldata>(
        &self,
        contract: TronAddress,
        calldata: TCalldata,
        owner: TronAddress,
    ) -> impl Future<Output = Result<TronTransaction, TronGridLikeError>>
    where
        TCalldata: SolCall;

    /// Broadcast a signed transaction.
    fn wallet_broadcast_transaction(
        &self,
        tx: TronTransaction,
    ) -> impl Future<Output = Result<TronTxId, TronGridLikeError>>;

    /// Fetches confirmation status via `gettransactioninfobyid`. Returns an empty
    /// response while the transaction is still pending.
    fn wallet_get_transaction_info_by_id(
        &self,
        tx_id: &TronTxId,
    ) -> impl Future<Output = Result<TransactionInfoResponse, TronGridLikeError>> + Send;
}

impl TronGridLike for TronGridHttp {
    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self, calldata),
            fields(
                otel.kind = "client",
                trongrid.method = "wallet/triggerconstantcontract",
                trongrid.contract_address = %contract_address,
                trongrid.owner_address = tracing::field::Empty,
            )
        )
    )]
    async fn wallet_trigger_constant_contract<TCalldata>(
        &self,
        contract_address: TronAddress,
        calldata: TCalldata,
        from: Option<TronAddress>,
    ) -> Result<TCalldata::Return, TronGridLikeError>
    where
        TCalldata: SolCall + Send,
    {
        #[cfg(feature = "telemetry")]
        if let Some(from) = &from {
            tracing::Span::current()
                .record("trongrid.owner_address", tracing::field::display(from));
        }
        let calldata = Bytes::from(calldata.abi_encode());
        let body = CallConstantRequest {
            owner_address: from.unwrap_or_default(),
            contract_address,
            data: calldata,
            call_value: 0,
            visible: true,
        };
        let resp: CallConstantResponse = self
            .send_json("wallet/triggerconstantcontract", &body)
            .await?;
        let decoded = resp.into_abi_decoded::<TCalldata>().inspect_err(|err| {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.method = "wallet/triggerconstantcontract",
                trongrid.contract_address = %contract_address,
                error = %err,
                "failed to ABI-decode TronGrid triggerconstantcontract result"
            );
        })?;
        Ok(decoded)
    }

    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self, calldata),
            fields(
                otel.kind = "client",
                trongrid.method = "wallet/triggersmartcontract",
                trongrid.contract_address = %contract,
                trongrid.owner_address = %owner,
            )
        )
    )]
    async fn wallet_trigger_smart_contract<TCalldata>(
        &self,
        contract: TronAddress,
        calldata: TCalldata,
        owner: TronAddress,
    ) -> Result<TronTransaction, TronGridLikeError>
    where
        TCalldata: SolCall,
    {
        let body = TriggerSmartContractRequest {
            owner_address: owner,
            contract_address: contract,
            data: calldata.abi_encode(),
            fee_limit: 100_000_000,
            call_value: 0,
            visible: true,
        };
        let resp: TriggerSmartContractResponse =
            self.send_json("wallet/triggersmartcontract", &body).await?;

        let transaction = resp.try_into().inspect_err(|err| {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.method = "wallet/triggersmartcontract",
                trongrid.contract_address = %contract,
                error = %err,
                "TronGrid triggersmartcontract call failed"
            );
        })?;
        Ok(transaction)
    }

    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self, tx),
            fields(
                otel.kind = "client",
                trongrid.method = "wallet/broadcasttransaction",
                trongrid.tx_id = %tx.tx_id,
            )
        )
    )]
    async fn wallet_broadcast_transaction(
        &self,
        tx: TronTransaction,
    ) -> Result<TronTxId, TronGridLikeError> {
        #[cfg(feature = "telemetry")]
        let submitted_tx_id = tx.tx_id.clone();
        let resp: BroadcastResponse = self.send_json("wallet/broadcasttransaction", &tx).await?;
        let tx_id = resp.try_into().inspect_err(|err| {
            #[cfg(feature = "telemetry")]
            tracing::error!(
                trongrid.method = "wallet/broadcasttransaction",
                trongrid.tx_id = %submitted_tx_id,
                error = %err,
                "TronGrid broadcasttransaction failed"
            );
        })?;
        Ok(tx_id)
    }

    #[cfg_attr(
        feature = "telemetry",
        tracing::instrument(
            skip(self),
            fields(
                otel.kind = "client",
                trongrid.method = "wallet/gettransactioninfobyid",
                trongrid.tx_id = %tx_id,
            )
        )
    )]
    async fn wallet_get_transaction_info_by_id(
        &self,
        tx_id: &TronTxId,
    ) -> Result<TransactionInfoResponse, TronGridLikeError> {
        let body = GetTransactionInfoRequest { value: tx_id };
        let resp: TransactionInfoResponse = self
            .send_json("wallet/gettransactioninfobyid", &body)
            .await?;
        Ok(resp)
    }
}

/// Wraps a [`TronGridLike`] client with the timeout/interval used to poll for
/// transaction confirmation.
pub struct TronGridPolling<A> {
    /// TronGrid client.
    pub tron_grid: A,
    /// How long to wait for a transaction to be confirmed before giving up.
    pub tx_timeout: Duration,
    /// How often to poll `gettransactioninfobyid`.
    pub tx_poll_interval: Duration,
}

impl<A> fmt::Debug for TronGridPolling<A>
where
    A: fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.tron_grid.fmt(f)
    }
}

impl<A> Deref for TronGridPolling<A> {
    type Target = A;

    fn deref(&self) -> &Self::Target {
        &self.tron_grid
    }
}

/// Blocks (async) until a submitted transaction is confirmed on-chain.
pub trait WaitForTxLike {
    /// Polls until the transaction succeeds, fails, or times out.
    fn wait_for_tx(
        &self,
        tx_id: &TronTxId,
    ) -> impl Future<Output = Result<(), TronChainProviderError>> + Send;
}

impl<A> WaitForTxLike for Arc<A>
where
    A: WaitForTxLike,
{
    fn wait_for_tx(
        &self,
        tx_id: &TronTxId,
    ) -> impl Future<Output = Result<(), TronChainProviderError>> {
        self.as_ref().wait_for_tx(tx_id)
    }
}

impl<A> WaitForTxLike for TronGridPolling<A>
where
    A: TronGridLike + Sync,
{
    async fn wait_for_tx(&self, tx_id: &TronTxId) -> Result<(), TronChainProviderError> {
        let timeout = self.tx_timeout;
        let interval = self.tx_poll_interval;
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(TronChainProviderError::TxTimeout);
            }
            let transaction_info_response = self
                .tron_grid
                .wallet_get_transaction_info_by_id(tx_id)
                .await?;
            match transaction_info_response
                .receipt
                .as_ref()
                .and_then(|r| r.result.as_deref())
            {
                None => tokio::time::sleep(interval).await,
                Some("SUCCESS") => return Ok(()),
                Some(status) => return Err(TronChainProviderError::TxFailed(status.to_string())),
            }
        }
    }
}

// ── TronGrid response types ───────────────────────────────────────────────────

/// The nested `result` object inside `trigger*` responses.
/// Distinct from `broadcasttransaction` which has a flat `bool` at `result`.
#[derive(Debug, Deserialize)]
pub struct TriggerStatus {
    result: bool,
    #[serde(default)]
    message: Option<String>,
}

impl TriggerStatus {
    pub fn into_result(self) -> Result<(), TronGridReportedError> {
        if self.result {
            Ok(())
        } else {
            let message = self.message.unwrap_or_else(|| "unknown error".into());
            Err(TronGridReportedError(message))
        }
    }
}

/// Request body for `triggersmartcontract`.
#[derive(Debug, Serialize)]
pub struct TriggerSmartContractRequest {
    pub owner_address: TronAddress,
    pub contract_address: TronAddress,
    #[serde(with = "prefixless_hex")]
    pub data: Vec<u8>,
    pub fee_limit: u64,
    pub call_value: u64,
    pub visible: bool,
}

/// Request body for `gettransactioninfobyid`.
#[derive(Debug, Serialize)]
pub struct GetTransactionInfoRequest<'a> {
    pub value: &'a TronTxId,
}

/// An unsigned transaction returned by `triggersmartcontract`.
///
/// `signature` starts empty; `sign_and_broadcast` fills it before posting to
/// `broadcasttransaction`.  All other fields are captured in `rest` and
/// round-tripped verbatim so nothing is lost.
#[derive(Debug, Deserialize, Serialize)]
pub struct TronTransaction {
    #[serde(rename = "txID")]
    pub tx_id: TronTxId,
    #[serde(default, skip_serializing_if = "HexBytesVec::is_empty")]
    pub signature: HexBytesVec,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

/// Response from `triggersmartcontract`.
#[derive(Debug, Deserialize)]
pub struct TriggerSmartContractResponse {
    pub result: TriggerStatus,
    pub transaction: Option<TronTransaction>,
}

impl TryFrom<TriggerSmartContractResponse> for TronTransaction {
    type Error = TronGridLikeError;

    fn try_from(value: TriggerSmartContractResponse) -> Result<Self, Self::Error> {
        value.result.into_result()?;
        let transaction = value
            .transaction
            .ok_or_else(|| TronGridParsingError::MissingField("transaction".to_string()))?;
        Ok(transaction)
    }
}

/// Response from `broadcasttransaction`.
/// Note: `result` here is a flat `bool`, not a nested object.
#[derive(Debug, Deserialize)]
pub struct BroadcastResponse {
    pub result: bool,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub txid: Option<TronTxId>,
}

impl TryFrom<BroadcastResponse> for TronTxId {
    type Error = TronGridLikeError;

    fn try_from(value: BroadcastResponse) -> Result<Self, Self::Error> {
        if !value.result {
            let msg = value.message.unwrap_or_else(|| "broadcast failed".into());
            return Err(TronGridLikeError::ReportedError(msg));
        }
        let tx_id = value
            .txid
            .ok_or_else(|| TronGridParsingError::MissingField("txid".to_string()))?;
        Ok(tx_id)
    }
}

/// Response from `gettransactioninfobyid`.
/// All fields are optional — an empty object `{}` means the tx is still pending.
#[derive(Debug, Deserialize)]
pub struct TransactionInfoResponse {
    #[serde(default)]
    pub receipt: Option<TxReceipt>,
}

#[derive(Debug, Deserialize)]
pub struct TxReceipt {
    pub result: Option<String>,
}

// ── Serde helpers ─────────────────────────────────────────────────────────────

/// Request body for `triggerconstantcontract`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallConstantRequest {
    pub owner_address: TronAddress,
    pub contract_address: TronAddress,
    #[serde(with = "prefixless_hex")]
    pub data: Bytes,
    pub call_value: u64,
    pub visible: bool,
}

/// Response from `triggerconstantcontract`.
#[derive(Debug, Deserialize)]
pub struct CallConstantResponse {
    pub result: TriggerStatus,
    #[serde(default)]
    pub constant_result: HexBytesVec,
}

impl CallConstantResponse {
    /// ABI-decodes the first `constant_result` entry as `TCalldata`'s return type.
    pub fn into_abi_decoded<TCalldata: SolCall>(
        self,
    ) -> Result<TCalldata::Return, TronGridLikeError> {
        self.result.into_result()?;
        let constant_result = self
            .constant_result
            .0
            .first()
            .ok_or_else(|| TronGridParsingError::MissingField("constant_result".to_string()))?;

        let decoded = TCalldata::abi_decode_returns(constant_result)
            .map_err(TronGridParsingError::AbiDecode)?;
        Ok(decoded)
    }
}

/// A list of byte strings, (de)serialized as prefixless hex strings.
#[derive(Debug, Default)]
pub struct HexBytesVec(pub Vec<Bytes>);

impl HexBytesVec {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for HexBytesVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in &self.0 {
            seq.serialize_element(&prefixless_hex::PrefixlessHex(value))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for HexBytesVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PrefixlessHexVecVisitor;

        impl<'de> serde::de::Visitor<'de> for PrefixlessHexVecVisitor {
            type Value = HexBytesVec;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a list of prefixless hex strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();

                while let Some(value) = seq.next_element::<prefixless_hex::PrefixlessHexOwned>()? {
                    values.push(value.0);
                }

                Ok(HexBytesVec(values))
            }
        }

        deserializer.deserialize_seq(PrefixlessHexVecVisitor)
    }
}
