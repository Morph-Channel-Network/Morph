//! Sole Gateway endpoint inventory. Router construction and generated HTTP
//! contracts consume it. Authority checks remain in the canonical handlers.
use crate::{api::*, protocol::*};
use morph_packages::schema::text;
pub struct JsonContract {
    pub name: &'static str,
    pub schema: fn() -> Result<String, serde_json::Error>,
}
pub enum Body {
    Empty,
    Text,
    Json(JsonContract),
    Query(JsonContract),
    Bytes,
    Upstream,
}
#[derive(Clone, Copy)]
pub enum Method {
    Get,
    Post,
    Proxy,
}
impl Method {
    pub fn verbs(self) -> &'static [&'static str] {
        match self {
            Self::Get => &["get"],
            Self::Post => &["post"],
            Self::Proxy => &["get", "head", "post", "put", "patch", "delete"],
        }
    }
}
#[derive(Clone, Copy)]
pub enum Authority {
    Public,
    OperatorBearer,
    PayerSignature,
    StoredCredential,
    PaidResource,
}
impl Authority {
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::OperatorBearer => "operator_bearer",
            Self::PayerSignature => "signed_payer_terms",
            Self::StoredCredential => "stored_credential_and_receipt",
            Self::PaidResource => "paid_credential_or_payment_signature",
        }
    }
}
pub struct Spec {
    pub endpoint: Endpoint,
    pub path: &'static str,
    pub method: Method,
    pub authority: Authority,
    pub request: Body,
    pub response: Body,
    pub success: u16,
    pub retry: &'static str,
}
macro_rules! json {
    ($t:ty) => {
        Body::Json(JsonContract {
            name: stringify!($t),
            schema: text::<$t>,
        })
    };
}
macro_rules! routes {
    ($($variant:ident,$path:literal,$method:ident,$authority:ident,$request:expr,$response:expr,$success:literal,$retry:literal;)+)=>{
        #[derive(Debug,Clone,Copy,PartialEq,Eq)]
        pub enum Endpoint {$($variant,)+}
        impl Endpoint {
            pub const ALL:&'static [Self]=&[$(Self::$variant,)+];
            pub fn spec(self)->Spec {match self {$ (Self::$variant=>Spec {endpoint:self,path:$path,method:Method::$method,authority:Authority::$authority,request:$request,response:$response,success:$success,retry:$retry},)+}}
        }
    };
}
routes! {
    Events,"/v1/events",Post,OperatorBearer,json!(EventPageRequest),json!(EventPage),200,"Read-only durable source-bound pagination. Resume with the exact next cursor; never use these local records as independent chain confirmation.";
    Readiness,"/ready",Get,OperatorBearer,Body::Empty,json!(Readiness),200,"Read-only expiring prerequisites. HTTP 503 carries the same Readiness body. No payment authorization, route liquidity or independent chain confirmation is implied.";
    Metrics,"/metrics",Get,OperatorBearer,Body::Empty,Body::Text,200,"Fixed bounded Prometheus series. Unobserved store values are NaN. Read-only; never retries payments.";
    Health,"/health",Get,Public,Body::Empty,json!(HealthResponse),200,"Read-only liveness; not readiness.";
    Supported,"/v1/supported",Get,Public,Body::Empty,json!(SupportedResponse),200,"Read-only.";
    Challenge,"/v1/challenges",Post,OperatorBearer,json!(CreateChallengeRequest),json!(PaymentRequirements),200,"Creates a fresh challenge. Lost response is ambiguous; no idempotency-key replay contract yet.";
    X402Challenge,"/v1/x402/challenge",Post,OperatorBearer,json!(CreateChallengeRequest),json!(PaymentRequirements),402,"402 is the successful challenge, also encoded in PAYMENT-REQUIRED. Creates fresh state; no automatic retry.";
    Pay,"/v1/pay",Post,PayerSignature,json!(PayRequest),json!(PayResponse),200,"Payment hash binds the exact typed request and configured Fiber endpoint. Only the first durable reservation sends; exact retries query that payment or return its immutable terminal result, including after expiry. Conflicting contents return 409 request_conflict. Unknown outcomes never authorize resubmission. Full provider-neutral/MPP orchestration remains #36.";
    Verify,"/v1/x402/verify",Post,PayerSignature,json!(VerifyRequest),json!(VerifyResponse),200,"Queries Fiber and persists an observation. Does not initiate an outgoing payment.";
    Settle,"/v1/x402/settle",Post,PayerSignature,json!(SettleRequest),json!(SettleResponse),200,"Validates exact stored terms/payer proof and returns the stored receipt when present. No new outgoing payment; this is not a generic key/body replay contract.";
    Authorize,"/v1/payment-gateway/authorize",Post,PayerSignature,json!(SettleRequest),json!(SettleResponse),200,"Same settlement authority and stored-receipt rules as x402 settle.";
    CredentialVerify,"/v1/credentials/verify",Post,StoredCredential,json!(CredentialVerifyRequest),json!(CredentialVerifyResponse),200,"Read-only validation of the stored receipt, credential and exact resource.";
    FairOffer,"/v1/fair-exchange/offers",Post,OperatorBearer,json!(FairExchangeOfferRequest),json!(FairExchangeEnvelope),200,"Creates a fresh encrypted offer and challenge; lost response is ambiguous. No automatic retry.";
    FairClaim,"/v1/fair-exchange/claims",Post,PayerSignature,json!(FairExchangeClaimRequest),json!(FairExchangeClaim),200,"Requires the offer's payer authorization and paid settlement before returning the key. Stored-receipt rules apply.";
    Payments,"/v1/payments",Get,OperatorBearer,Body::Query(JsonContract{name:"PaymentListQuery",schema:text::<PaymentListQuery>}),json!(PaymentListResponse),200,"Read-only bounded latest entries; not a cursor or complete historical pagination.";
    Proxy,"/gateway/{*path}",Proxy,PaidResource,Body::Bytes,Body::Upstream,200,"Exact resource and method authorization. Upstream may mutate even if its response is lost; never infer retry safety from a Gateway timeout.";
}
