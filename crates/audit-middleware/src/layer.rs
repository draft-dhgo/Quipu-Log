use crate::event::{AuditEvent, TargetSpec};
use crate::filter::{FilterDecision, FilterSet, RequestInfo, ResponseInfo};
use crate::pipeline::AuditHandle;
use audit_core::{Content, EntityInput};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type AuditBody = UnsyncBoxBody<Bytes, BoxError>;

/// Default cap on how many body bytes one audited exchange may capture.
pub const DEFAULT_CAPTURE_LIMIT: usize = 1024 * 1024;

/// Pulls the acting identity out of the request. The default reads the
/// `x-audit-actor` header into the `default_actor` type ("anonymous" if absent).
pub type ActorExtractor = Arc<dyn Fn(&RequestInfo) -> (String, EntityInput) + Send + Sync>;

/// Derives target entities from the full exchange (request info, response
/// info, captured request/response bytes).
pub type TargetExtractor =
    Arc<dyn Fn(&RequestInfo, &ResponseInfo, &[u8], &[u8]) -> Vec<TargetSpec> + Send + Sync>;

/// Which endpoints the proxy audits and how much of the exchange it captures.
#[derive(Clone)]
pub struct EndpointRule {
    /// `None` matches every method.
    pub method: Option<Method>,
    pub path_prefix: String,
    pub capture_request_body: bool,
    pub capture_response_body: bool,
    /// Bodies larger than this are not captured (the request still proxies
    /// through untouched; the audit content records a size note instead).
    /// Without a cap, one oversized upload is buffered whole and then bounces
    /// off the store's record limit into the DLQ.
    pub max_capture_bytes: usize,
    /// Rule-local target derivation; overrides the layer-wide extractor.
    /// Keeping the extractor next to the route rule preserves locality —
    /// a layer-wide closure degenerates into a URL-dispatch function as the
    /// audited surface grows.
    pub targets: Option<TargetExtractor>,
}

impl EndpointRule {
    pub fn prefix(path_prefix: impl Into<String>) -> Self {
        Self {
            method: None,
            path_prefix: path_prefix.into(),
            capture_request_body: false,
            capture_response_body: false,
            max_capture_bytes: DEFAULT_CAPTURE_LIMIT,
            targets: None,
        }
    }

    pub fn method(mut self, m: Method) -> Self {
        self.method = Some(m);
        self
    }

    pub fn capture_request(mut self) -> Self {
        self.capture_request_body = true;
        self
    }

    pub fn capture_response(mut self) -> Self {
        self.capture_response_body = true;
        self
    }

    pub fn capture_limit(mut self, bytes: usize) -> Self {
        self.max_capture_bytes = bytes;
        self
    }

    /// Attach a target extractor to this rule (takes precedence over the
    /// layer-wide [`AuditLayer::target_extractor`]).
    pub fn target_extractor(
        mut self,
        f: impl Fn(&RequestInfo, &ResponseInfo, &[u8], &[u8]) -> Vec<TargetSpec> + Send + Sync + 'static,
    ) -> Self {
        self.targets = Some(Arc::new(f));
        self
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        self.method.as_ref().map(|m| m == method).unwrap_or(true)
            && path.starts_with(&self.path_prefix)
    }
}

fn default_actor_extractor() -> ActorExtractor {
    Arc::new(|req: &RequestInfo| {
        let who = req
            .headers
            .get("x-audit-actor")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("anonymous")
            .to_string();
        (
            "default_actor".to_string(),
            EntityInput::new(who.clone()).text("name", who),
        )
    })
}

/// `tower` layer that wraps a service as an auditing proxy:
/// requests matching an [`EndpointRule`] pass through pre-filters, are
/// forwarded to the inner service, pass through post-filters, and finally an
/// [`AuditEvent`] is emitted to the async pipeline. `B` is the inner service's
/// request body type (for axum: `axum::body::Body`).
pub struct AuditLayer<B> {
    handle: AuditHandle,
    rules: Arc<Vec<EndpointRule>>,
    filters: Arc<FilterSet>,
    actor: ActorExtractor,
    targets: Option<TargetExtractor>,
    _body: PhantomData<fn(B)>,
}

impl<B> Clone for AuditLayer<B> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            rules: self.rules.clone(),
            filters: self.filters.clone(),
            actor: self.actor.clone(),
            targets: self.targets.clone(),
            _body: PhantomData,
        }
    }
}

impl<B> AuditLayer<B> {
    /// Audit every request (no body capture) until rules are added.
    pub fn new(handle: AuditHandle) -> Self {
        Self {
            handle,
            rules: Arc::new(Vec::new()),
            filters: Arc::new(FilterSet::new()),
            actor: default_actor_extractor(),
            targets: None,
            _body: PhantomData,
        }
    }

    /// Restrict auditing to these endpoint rules (first match wins).
    pub fn rules(mut self, rules: Vec<EndpointRule>) -> Self {
        self.rules = Arc::new(rules);
        self
    }

    pub fn filters(mut self, filters: FilterSet) -> Self {
        self.filters = Arc::new(filters);
        self
    }

    pub fn actor_extractor(
        mut self,
        f: impl Fn(&RequestInfo) -> (String, EntityInput) + Send + Sync + 'static,
    ) -> Self {
        self.actor = Arc::new(f);
        self
    }

    pub fn target_extractor(
        mut self,
        f: impl Fn(&RequestInfo, &ResponseInfo, &[u8], &[u8]) -> Vec<TargetSpec> + Send + Sync + 'static,
    ) -> Self {
        self.targets = Some(Arc::new(f));
        self
    }
}

impl<S, B> tower::Layer<S> for AuditLayer<B> {
    type Service = AuditService<S, B>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditService {
            inner,
            layer: self.clone(),
        }
    }
}

pub struct AuditService<S, B> {
    inner: S,
    layer: AuditLayer<B>,
}

impl<S: Clone, B> Clone for AuditService<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, ResB> tower::Service<Request<B>> for AuditService<S, B>
where
    S: tower::Service<Request<B>, Response = Response<ResB>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    B: http_body::Body<Data = Bytes> + From<Bytes> + Send + 'static,
    B::Error: std::fmt::Display + Send,
    ResB: http_body::Body<Data = Bytes> + Send + 'static,
    ResB::Error: Into<BoxError> + Send,
{
    type Response = Response<AuditBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        // the original was polled ready; hand it to the future and keep the clone
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();

        Box::pin(async move {
            let info = RequestInfo {
                method: req.method().clone(),
                uri: req.uri().clone(),
                headers: req.headers().clone(),
            };
            let rule = if layer.rules.is_empty() {
                Some(EndpointRule::prefix("/")) // audit-all default
            } else {
                layer
                    .rules
                    .iter()
                    .find(|r| r.matches(&info.method, info.uri.path()))
                    .cloned()
            };
            // not an audited endpoint, or a pre-filter exempted it -> pure proxy
            let audited = rule.is_some() && layer.filters.run_pre(&info) == FilterDecision::Audit;
            let Some(rule) = rule.filter(|_| audited) else {
                let res = inner.call(req).await?;
                return Ok(res.map(|b| b.map_err(Into::into).boxed_unsync()));
            };

            // capture the request body if asked (replays it for the inner
            // service). An oversized body — judged up front by Content-Length
            // when present — is proxied through untouched and recorded as a
            // size note instead of being buffered.
            let req_declared_len = content_length(req.headers());
            let mut req_capture = Capture::None;
            let req = if rule.capture_request_body {
                if req_declared_len.is_some_and(|n| n > rule.max_capture_bytes as u64) {
                    req_capture = Capture::TooLarge(req_declared_len.unwrap());
                    req
                } else {
                    let (parts, body) = req.into_parts();
                    match body.collect().await {
                        Ok(collected) => {
                            let bytes = collected.to_bytes();
                            req_capture = Capture::measured(bytes.clone(), rule.max_capture_bytes);
                            Request::from_parts(parts, B::from(bytes))
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to read request body for audit");
                            let mut res = Response::new(empty_body());
                            *res.status_mut() = StatusCode::BAD_REQUEST;
                            return Ok(res);
                        }
                    }
                }
            } else {
                req
            };

            let res = inner.call(req).await?;
            let res_info = ResponseInfo {
                status: res.status(),
                headers: res.headers().clone(),
            };

            // capture the response body if asked (rebuilds it for the client)
            let res_declared_len = content_length(res.headers());
            let mut res_capture = Capture::None;
            let res = if rule.capture_response_body
                && res_declared_len.is_none_or(|n| n <= rule.max_capture_bytes as u64)
            {
                let (parts, body) = res.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        res_capture = Capture::measured(bytes.clone(), rule.max_capture_bytes);
                        let body: AuditBody =
                            Full::new(bytes).map_err(|e| match e {}).boxed_unsync();
                        Response::from_parts(parts, body)
                    }
                    Err(e) => {
                        tracing::error!(error = %e.into(), "failed to read response body for audit");
                        let mut res = Response::new(empty_body());
                        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(res);
                    }
                }
            } else {
                if rule.capture_response_body {
                    res_capture = Capture::TooLarge(res_declared_len.unwrap_or(0));
                }
                res.map(|b| b.map_err(Into::into).boxed_unsync())
            };

            // assemble the event: actor, exchange snapshot, derived targets
            let (actor_type, actor) = (layer.actor)(&info);
            let content = Content::Json(serde_json::json!({
                "status": res_info.status.as_u16(),
                "request": req_capture.to_json(),
                "response": res_capture.to_json(),
            }));
            let mut event = AuditEvent::new(
                actor_type,
                actor,
                info.method.to_string(),
                info.uri.to_string(),
                content,
            );
            // rule-local extractor wins over the layer-wide one
            if let Some(extract) = rule.targets.as_ref().or(layer.targets.as_ref()) {
                event.targets = extract(&info, &res_info, req_capture.bytes(), res_capture.bytes());
            }

            if layer.filters.run_post(&info, &res_info, &mut event) == FilterDecision::Audit {
                if let Err(e) = layer.handle.emit_unchecked(event) {
                    tracing::error!(error = %e, "failed to enqueue audit event");
                }
            }
            Ok(res)
        })
    }
}

fn empty_body() -> AuditBody {
    Full::new(Bytes::new())
        .map_err(|e| match e {})
        .boxed_unsync()
}

fn content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Outcome of one body-capture attempt.
enum Capture {
    /// Not captured (rule did not ask for it).
    None,
    Body(Bytes),
    /// Body exceeded the rule's capture limit (size in bytes; 0 = unknown,
    /// e.g. a chunked body with no Content-Length).
    TooLarge(u64),
}

impl Capture {
    fn measured(bytes: Bytes, limit: usize) -> Self {
        if bytes.len() > limit {
            Capture::TooLarge(bytes.len() as u64)
        } else {
            Capture::Body(bytes)
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Capture::Body(b) => b,
            _ => &[],
        }
    }

    /// Best-effort body rendering: JSON if it parses, UTF-8 string otherwise,
    /// size note when over the capture limit, null when empty/uncaptured.
    fn to_json(&self) -> serde_json::Value {
        let bytes = match self {
            Capture::None => return serde_json::Value::Null,
            Capture::TooLarge(n) => {
                return serde_json::Value::String(if *n > 0 {
                    format!("<body of {n} bytes exceeds the capture limit>")
                } else {
                    "<body exceeds the capture limit>".to_string()
                });
            }
            Capture::Body(b) => b,
        };
        if bytes.is_empty() {
            return serde_json::Value::Null;
        }
        if let Ok(v) = serde_json::from_slice(bytes) {
            return v;
        }
        match std::str::from_utf8(bytes) {
            Ok(s) => serde_json::Value::String(s.to_string()),
            Err(_) => serde_json::Value::String(format!("<{} binary bytes>", bytes.len())),
        }
    }
}
