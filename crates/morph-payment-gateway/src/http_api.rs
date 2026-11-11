//! HTTP adaptation of the public error contract, including extractor failures.
use crate::api::{API_VERSION, GatewayErrorBody, GatewayErrorCode};
use axum::{
    Json,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Path, Query, Request},
    http::{HeaderValue, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub(crate) struct HttpFailure {
    status: StatusCode,
    code: GatewayErrorCode,
    message: String,
}
impl HttpFailure {
    pub(crate) fn new(
        status: StatusCode,
        code: GatewayErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn body(&self, request_id: String) -> GatewayErrorBody {
        GatewayErrorBody {
            api_version: API_VERSION.into(),
            code: self.code,
            request_id,
            error: self.message.clone(),
        }
    }
}
impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body(String::new()))).into_response();
        response.extensions_mut().insert(self);
        response
    }
}

pub(crate) struct ApiJson<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = HttpFailure;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let status = error.status();
                let (code, message) = match status {
                    StatusCode::PAYLOAD_TOO_LARGE => (
                        GatewayErrorCode::BodyTooLarge,
                        "request body exceeds the limit",
                    ),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE => (
                        GatewayErrorCode::UnsupportedContentType,
                        "application/json content type required",
                    ),
                    _ => (
                        GatewayErrorCode::InvalidJson,
                        "request body does not match the current JSON contract",
                    ),
                };
                HttpFailure::new(status, code, message)
            })
    }
}
pub(crate) struct ApiQuery<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = HttpFailure;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|_| {
                HttpFailure::new(
                    StatusCode::BAD_REQUEST,
                    GatewayErrorCode::InvalidQuery,
                    "query does not match the current bounded contract",
                )
            })
    }
}

pub(crate) async fn not_found() -> HttpFailure {
    HttpFailure::new(
        StatusCode::NOT_FOUND,
        GatewayErrorCode::RouteNotFound,
        "unknown API route",
    )
}
pub(crate) async fn method_not_allowed() -> HttpFailure {
    HttpFailure::new(
        StatusCode::METHOD_NOT_ALLOWED,
        GatewayErrorCode::MethodNotAllowed,
        "method is not supported for this route",
    )
}

pub(crate) async fn response_contract(request: Request, next: Next) -> Response {
    // Diagnostic identity only: never supplied by the caller or used as a retry key.
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let request_id = format!(
        "gateway-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut response = next.run(request).await;
    if let Some(failure) = response.extensions_mut().remove::<HttpFailure>() {
        *response.body_mut() = Json(failure.body(request_id.clone()))
            .into_response()
            .into_body();
    }
    response
        .headers_mut()
        .insert("x-morph-api-version", HeaderValue::from_static(API_VERSION));
    if let Ok(value) = HeaderValue::try_from(request_id) {
        response.headers_mut().insert("x-morph-request-id", value);
    }
    response
}

// The paid proxy also has extractors. Do not leave its size/path errors outside
// the public contract merely because its successful body is not JSON.
pub(crate) struct ApiBytes(pub Bytes);
impl<S: Send + Sync> FromRequest<S> for ApiBytes {
    type Rejection = HttpFailure;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Bytes::from_request(request, state)
            .await
            .map(Self)
            .map_err(|error| {
                let status = error.status();
                let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
                    GatewayErrorCode::BodyTooLarge
                } else {
                    GatewayErrorCode::InvalidRequest
                };
                HttpFailure::new(status, code, "request body is invalid or exceeds the limit")
            })
    }
}
pub(crate) struct ApiPath<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = HttpFailure;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| {
                HttpFailure::new(
                    StatusCode::BAD_REQUEST,
                    GatewayErrorCode::InvalidRequest,
                    "request path does not match the current contract",
                )
            })
    }
}
