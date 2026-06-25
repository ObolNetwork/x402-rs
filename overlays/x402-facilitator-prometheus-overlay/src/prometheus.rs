use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use x402_facilitator_local::facilitator_local::{FacilitatorLocal, FacilitatorLocalError};
use x402_types::facilitator::Facilitator;
use x402_types::proto;
use x402_types::scheme::{SchemeRegistry, X402SchemeFacilitatorError};

#[derive(Clone)]
pub struct PrometheusMetrics {
    inner: Arc<PrometheusMetricsInner>,
}

struct PrometheusMetricsInner {
    registry: Registry,
    verify_requests: IntCounterVec,
    settle_requests: IntCounterVec,
    verify_duration: HistogramVec,
    settle_duration: HistogramVec,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let verify_requests = IntCounterVec::new(
            Opts::new(
                "x402_facilitator_verify_requests_total",
                "Total payment verification requests",
            ),
            &["status", "scheme", "chain"],
        )
        .expect("failed to create verify counter");

        let settle_requests = IntCounterVec::new(
            Opts::new(
                "x402_facilitator_settle_requests_total",
                "Total payment settlement requests",
            ),
            &["status", "scheme", "chain"],
        )
        .expect("failed to create settle counter");

        let verify_duration = HistogramVec::new(
            HistogramOpts::new(
                "x402_facilitator_verify_duration_seconds",
                "Payment verification latency in seconds",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["scheme", "chain"],
        )
        .expect("failed to create verify histogram");

        let settle_duration = HistogramVec::new(
            HistogramOpts::new(
                "x402_facilitator_settle_duration_seconds",
                "Payment settlement latency in seconds",
            )
            .buckets(vec![
                0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
            ]),
            &["scheme", "chain"],
        )
        .expect("failed to create settle histogram");

        registry
            .register(Box::new(verify_requests.clone()))
            .expect("failed to register verify counter");
        registry
            .register(Box::new(settle_requests.clone()))
            .expect("failed to register settle counter");
        registry
            .register(Box::new(verify_duration.clone()))
            .expect("failed to register verify histogram");
        registry
            .register(Box::new(settle_duration.clone()))
            .expect("failed to register settle histogram");

        verify_requests.with_label_values(&["ok", "unknown", "unknown"]);
        settle_requests.with_label_values(&["ok", "unknown", "unknown"]);
        verify_duration.with_label_values(&["unknown", "unknown"]);
        settle_duration.with_label_values(&["unknown", "unknown"]);

        Self {
            inner: Arc::new(PrometheusMetricsInner {
                registry,
                verify_requests,
                settle_requests,
                verify_duration,
                settle_duration,
            }),
        }
    }

    fn record_verify(&self, status: &str, scheme: &str, chain: &str, duration_secs: f64) {
        self.inner
            .verify_requests
            .with_label_values(&[status, scheme, chain])
            .inc();
        self.inner
            .verify_duration
            .with_label_values(&[scheme, chain])
            .observe(duration_secs);
    }

    fn record_settle(&self, status: &str, scheme: &str, chain: &str, duration_secs: f64) {
        self.inner
            .settle_requests
            .with_label_values(&[status, scheme, chain])
            .inc();
        self.inner
            .settle_duration
            .with_label_values(&[scheme, chain])
            .observe(duration_secs);
    }

    fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.inner.registry.gather(), &mut buffer)?;
        Ok(buffer)
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn get_metrics(State(metrics): State<PrometheusMetrics>) -> impl IntoResponse {
    match metrics.encode() {
        Ok(buffer) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, TextEncoder::new().format_type())],
            buffer,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("metrics encoding error: {error}"),
        )
            .into_response(),
    }
}

pub fn metrics_router(metrics: PrometheusMetrics) -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .with_state(metrics)
}

type LocalErrorClassifier = fn(&FacilitatorLocalError) -> &'static str;

pub struct PrometheusFacilitatorLocal {
    inner: InstrumentedFacilitator<FacilitatorLocal<SchemeRegistry>, LocalErrorClassifier>,
}

impl PrometheusFacilitatorLocal {
    pub fn new(inner: FacilitatorLocal<SchemeRegistry>, metrics: PrometheusMetrics) -> Self {
        Self {
            inner: InstrumentedFacilitator::new(inner, metrics, classify_local_error),
        }
    }
}

impl Facilitator for PrometheusFacilitatorLocal {
    type Error = FacilitatorLocalError;

    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, Self::Error> {
        self.inner.verify(request).await
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, Self::Error> {
        self.inner.settle(request).await
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, Self::Error> {
        self.inner.supported().await
    }
}

struct InstrumentedFacilitator<F, C> {
    inner: F,
    metrics: PrometheusMetrics,
    classify_error: C,
}

impl<F, C> InstrumentedFacilitator<F, C> {
    fn new(inner: F, metrics: PrometheusMetrics, classify_error: C) -> Self {
        Self {
            inner,
            metrics,
            classify_error,
        }
    }
}

impl<F, C> Facilitator for InstrumentedFacilitator<F, C>
where
    F: Facilitator + Send + Sync,
    C: Fn(&F::Error) -> &'static str + Send + Sync,
{
    type Error = F::Error;

    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, Self::Error> {
        let (scheme, chain) = extract_labels(request);
        let start = Instant::now();
        let result = self.inner.verify(request).await;
        let duration_secs = start.elapsed().as_secs_f64();

        match &result {
            Ok(_) => self
                .metrics
                .record_verify("ok", &scheme, &chain, duration_secs),
            Err(error) => self.metrics.record_verify(
                (self.classify_error)(error),
                &scheme,
                &chain,
                duration_secs,
            ),
        }

        result
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, Self::Error> {
        let (scheme, chain) = extract_labels(request);
        let start = Instant::now();
        let result = self.inner.settle(request).await;
        let duration_secs = start.elapsed().as_secs_f64();

        match &result {
            Ok(_) => self
                .metrics
                .record_settle("ok", &scheme, &chain, duration_secs),
            Err(error) => self.metrics.record_settle(
                (self.classify_error)(error),
                &scheme,
                &chain,
                duration_secs,
            ),
        }

        result
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, Self::Error> {
        self.inner.supported().await
    }
}

fn extract_labels(request: &proto::VerifyRequest) -> (String, String) {
    request
        .scheme_handler_slug()
        .map(|slug| (slug.name, slug.chain_id.to_string()))
        .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()))
}

fn classify_local_error(error: &FacilitatorLocalError) -> &'static str {
    match error {
        FacilitatorLocalError::Verification(inner) | FacilitatorLocalError::Settlement(inner) => {
            classify_scheme_error(inner)
        }
    }
}

fn classify_scheme_error(error: &X402SchemeFacilitatorError) -> &'static str {
    match error {
        X402SchemeFacilitatorError::PaymentVerification(_) => "client_error",
        X402SchemeFacilitatorError::OnchainFailure(_) => "server_error",
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request};
    use axum::response::{IntoResponse, Response};
    use serde_json::json;
    use tower::ServiceExt;
    use x402_facilitator_local::handlers;
    use x402_types::proto::{PaymentVerificationError, SupportedPaymentKind};

    use super::*;

    struct MockFacilitator {
        verify_result: Result<proto::VerifyResponse, MockError>,
        settle_result: Result<proto::SettleResponse, MockError>,
        supported_result: Result<proto::SupportedResponse, MockError>,
    }

    #[derive(Clone, Debug)]
    struct MockError {
        status: StatusCode,
    }

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.status)
        }
    }

    impl IntoResponse for MockError {
        fn into_response(self) -> Response {
            self.status.into_response()
        }
    }

    impl Facilitator for MockFacilitator {
        type Error = MockError;

        async fn verify(
            &self,
            _request: &proto::VerifyRequest,
        ) -> Result<proto::VerifyResponse, Self::Error> {
            self.verify_result.clone()
        }

        async fn settle(
            &self,
            _request: &proto::SettleRequest,
        ) -> Result<proto::SettleResponse, Self::Error> {
            self.settle_result.clone()
        }

        async fn supported(&self) -> Result<proto::SupportedResponse, Self::Error> {
            self.supported_result.clone()
        }
    }

    fn make_wrapper(
        verify_result: Result<proto::VerifyResponse, MockError>,
        settle_result: Result<proto::SettleResponse, MockError>,
    ) -> (
        InstrumentedFacilitator<MockFacilitator, fn(&MockError) -> &'static str>,
        PrometheusMetrics,
    ) {
        let metrics = PrometheusMetrics::new();
        let inner = MockFacilitator {
            verify_result,
            settle_result,
            supported_result: Ok(proto::SupportedResponse {
                kinds: vec![SupportedPaymentKind {
                    x402_version: 2,
                    scheme: "exact".to_string(),
                    network: "eip155:8453".to_string(),
                    extra: None,
                }],
                extensions: Vec::new(),
                signers: Default::default(),
            }),
        };
        let wrapper = InstrumentedFacilitator::new(
            inner,
            metrics.clone(),
            mock_status_label as fn(&MockError) -> &'static str,
        );
        (wrapper, metrics)
    }

    fn mock_status_label(error: &MockError) -> &'static str {
        if error.status.is_server_error() {
            "server_error"
        } else {
            "client_error"
        }
    }

    fn verify_request(json_body: &str) -> proto::VerifyRequest {
        serde_json::from_str(json_body).expect("valid verify request")
    }

    fn settle_request(json_body: &str) -> proto::SettleRequest {
        serde_json::from_str(json_body).expect("valid settle request")
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Runtime::new().expect("runtime")
    }

    #[test]
    fn verify_success_records_counter_and_histogram() {
        let rt = runtime();
        rt.block_on(async {
            let (wrapper, metrics) = make_wrapper(
                Ok(proto::VerifyResponse(json!({ "isValid": true }))),
                Ok(proto::SettleResponse(json!({ "success": true }))),
            );

            wrapper
                .verify(&verify_request(
                    r#"{"x402Version":2,"paymentPayload":{"accepted":{"network":"eip155:8453","scheme":"exact"}}}"#,
                ))
                .await
                .expect("verify succeeds");

            let rendered = String::from_utf8(metrics.encode().expect("encode metrics")).unwrap();
            assert!(rendered.contains(r#"x402_facilitator_verify_requests_total{chain="eip155:8453",scheme="exact",status="ok"} 1"#));
            assert!(rendered.contains(r#"x402_facilitator_verify_duration_seconds_bucket{chain="eip155:8453",scheme="exact""#));
        });
    }

    #[test]
    fn settle_success_records_counter_and_histogram() {
        let rt = runtime();
        rt.block_on(async {
            let (wrapper, metrics) = make_wrapper(
                Ok(proto::VerifyResponse(json!({ "isValid": true }))),
                Ok(proto::SettleResponse(json!({ "success": true }))),
            );

            wrapper
                .settle(&settle_request(
                    r#"{"x402Version":2,"paymentPayload":{"accepted":{"network":"eip155:8453","scheme":"exact"}}}"#,
                ))
                .await
                .expect("settle succeeds");

            let rendered = String::from_utf8(metrics.encode().expect("encode metrics")).unwrap();
            assert!(rendered.contains(r#"x402_facilitator_settle_requests_total{chain="eip155:8453",scheme="exact",status="ok"} 1"#));
            assert!(rendered.contains(r#"x402_facilitator_settle_duration_seconds_bucket{chain="eip155:8453",scheme="exact""#));
        });
    }

    #[test]
    fn local_error_classifier_preserves_client_and_server_outcomes() {
        let verification = FacilitatorLocalError::Verification(
            PaymentVerificationError::InsufficientAllowance.into(),
        );
        let settlement = FacilitatorLocalError::Settlement(
            X402SchemeFacilitatorError::OnchainFailure("rpc failure".to_string()),
        );

        assert_eq!(classify_local_error(&verification), "client_error");
        assert_eq!(classify_local_error(&settlement), "server_error");
    }

    #[test]
    fn malformed_request_uses_unknown_labels() {
        let rt = runtime();
        rt.block_on(async {
            let (wrapper, metrics) = make_wrapper(
                Err(MockError {
                    status: StatusCode::BAD_REQUEST,
                }),
                Ok(proto::SettleResponse(json!({ "success": true }))),
            );

            let _ = wrapper.verify(&verify_request(r#"{"unexpected":true}"#)).await;

            let rendered = String::from_utf8(metrics.encode().expect("encode metrics")).unwrap();
            assert!(rendered.contains(r#"x402_facilitator_verify_requests_total{chain="unknown",scheme="unknown",status="client_error"} 1"#));
        });
    }

    #[test]
    fn metrics_endpoint_returns_registered_metric_families_before_requests() {
        let rt = runtime();
        rt.block_on(async {
            let metrics = PrometheusMetrics::new();
            let app = metrics_router(metrics);
            let response = app
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/metrics")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("metrics response");

            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            assert!(text.contains("# TYPE x402_facilitator_verify_requests_total counter"));
            assert!(text.contains("# TYPE x402_facilitator_settle_requests_total counter"));
            assert!(text.contains("# TYPE x402_facilitator_verify_duration_seconds histogram"));
            assert!(text.contains("# TYPE x402_facilitator_settle_duration_seconds histogram"));
        });
    }

    #[test]
    fn merged_router_serves_protocol_routes_and_metrics() {
        let rt = runtime();
        rt.block_on(async {
            let metrics = PrometheusMetrics::new();
            let wrapper = InstrumentedFacilitator::new(
                MockFacilitator {
                    verify_result: Ok(proto::VerifyResponse(json!({ "isValid": true }))),
                    settle_result: Ok(proto::SettleResponse(json!({ "success": true }))),
                    supported_result: Ok(proto::SupportedResponse {
                        kinds: vec![SupportedPaymentKind {
                            x402_version: 2,
                            scheme: "exact".to_string(),
                            network: "eip155:8453".to_string(),
                            extra: None,
                        }],
                        extensions: Vec::new(),
                        signers: Default::default(),
                    }),
                },
                metrics.clone(),
                mock_status_label as fn(&MockError) -> &'static str,
            );

            let app = Router::new()
                .merge(handlers::routes().with_state(Arc::new(wrapper)))
                .merge(metrics_router(metrics));

            let verify_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/verify")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"x402Version":2,"paymentPayload":{"accepted":{"network":"eip155:8453","scheme":"exact"}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .expect("verify response");
            assert_eq!(verify_response.status(), StatusCode::OK);

            let settle_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/settle")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"x402Version":2,"paymentPayload":{"accepted":{"network":"eip155:8453","scheme":"exact"}}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .expect("settle response");
            assert_eq!(settle_response.status(), StatusCode::OK);

            let supported_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/supported")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("supported response");
            assert_eq!(supported_response.status(), StatusCode::OK);

            let health_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("health response");
            assert_eq!(health_response.status(), StatusCode::OK);

            let metrics_response = app
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/metrics")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("metrics response");
            assert_eq!(metrics_response.status(), StatusCode::OK);
        });
    }
}
