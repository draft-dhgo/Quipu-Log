use crate::event::AuditEvent;
use http::{HeaderMap, Method, StatusCode, Uri};

/// What a filter decided about a request/response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    /// Keep auditing this exchange.
    Audit,
    /// Exempt this exchange from auditing entirely.
    Skip,
}

/// Request-side view handed to pre-filters.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

/// Response-side view handed to post-filters.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

/// Programmable filter that runs *before* the inner service is called.
/// Returning [`FilterDecision::Skip`] exempts the request from auditing.
pub type PreFilter = Box<dyn Fn(&RequestInfo) -> FilterDecision + Send + Sync>;

/// Programmable filter that runs *after* the response is known. It may mutate
/// the pending event (enrich content, add custom columns) or skip it — e.g.
/// "don't audit 304s" or "drop health-check responses".
pub type PostFilter =
    Box<dyn Fn(&RequestInfo, &ResponseInfo, &mut AuditEvent) -> FilterDecision + Send + Sync>;

/// Ordered pre/post filter chains. The first `Skip` wins on both sides.
#[derive(Default)]
pub struct FilterSet {
    pre: Vec<PreFilter>,
    post: Vec<PostFilter>,
}

impl FilterSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pre(
        mut self,
        f: impl Fn(&RequestInfo) -> FilterDecision + Send + Sync + 'static,
    ) -> Self {
        self.pre.push(Box::new(f));
        self
    }

    pub fn post(
        mut self,
        f: impl Fn(&RequestInfo, &ResponseInfo, &mut AuditEvent) -> FilterDecision
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.post.push(Box::new(f));
        self
    }

    pub fn run_pre(&self, req: &RequestInfo) -> FilterDecision {
        for f in &self.pre {
            if f(req) == FilterDecision::Skip {
                return FilterDecision::Skip;
            }
        }
        FilterDecision::Audit
    }

    pub fn run_post(
        &self,
        req: &RequestInfo,
        res: &ResponseInfo,
        event: &mut AuditEvent,
    ) -> FilterDecision {
        for f in &self.post {
            if f(req, res, event) == FilterDecision::Skip {
                return FilterDecision::Skip;
            }
        }
        FilterDecision::Audit
    }
}
