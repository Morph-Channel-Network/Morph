use morph_hub_api::*;
use morph_packages::{
    conditional_packages::StoredConditionalBatchPackage,
    multi_asset_funding::{
        RootFundingCollection, RootFundingDraft, RootFundingExport, RootFundingTarget,
    },
    multi_asset_packages::StoredMultiAssetPackage,
    multi_asset_signatures::SignatureMessage,
};
use reqwest::{Client, Method, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HubClientError {
    #[error(
        "Hub endpoint must be an HTTP loopback or HTTPS origin without credentials, query or fragment"
    )]
    InvalidUrl,
    #[error("invalid Hub bearer token")]
    InvalidToken,
    #[error("invalid canonical resource id")]
    InvalidId,
    #[error("public package validation failed: {0}")]
    InvalidPackage(String),
    #[error("Hub read failed; reconnect or refresh")]
    Transport,
    #[error("Mutation outcome unknown; refresh the Hub and reconcile before submitting again")]
    OutcomeUnknown,
    #[error("Hub returned an invalid or oversized response")]
    InvalidResponse,
    #[error("HTTP {status}: {message} (code {code}, request {request_id})")]
    Api {
        status: u16,
        message: String,
        code: String,
        request_id: String,
        retry_after_seconds: Option<u64>,
    },
}

/// Bounded, authenticated short-poll transport. Mutations are never retried automatically.
/// Debug deliberately omits endpoint and credentials; tokens live only in memory.
#[derive(Clone)]
pub struct HubClient {
    base: Url,
    http: Client,
    token: Option<Arc<Zeroizing<String>>>,
}
impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient")
            .field("authenticated", &self.token.is_some())
            .finish_non_exhaustive()
    }
}
impl HubClient {
    pub fn new(endpoint: &str) -> Result<Self, HubClientError> {
        let base = Url::parse(endpoint).map_err(|_| HubClientError::InvalidUrl)?;
        let loopback = base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(base.scheme() == "https" || base.scheme() == "http" && loopback)
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(HubClientError::InvalidUrl);
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(12))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| HubClientError::Transport)?;
        Ok(Self {
            base,
            http,
            token: None,
        })
    }
    pub fn with_token(mut self, token: String) -> Result<Self, HubClientError> {
        if token.trim() != token
            || token.is_empty()
            || token.len() > 8192
            || token.bytes().any(|b| b <= b' ' || b == 127)
        {
            return Err(HubClientError::InvalidToken);
        }
        self.token = Some(Arc::new(Zeroizing::new(token)));
        Ok(self)
    }
    pub async fn state(&self) -> Result<HubView, HubClientError> {
        self.request(Method::GET, "api/state", None).await
    }
    pub async fn state_file(&self) -> Result<Value, HubClientError> {
        self.request(Method::GET, "api/state-file", None).await
    }
    pub async fn preview_restore(&self, state: &Value) -> Result<RestorePreview, HubClientError> {
        self.request(Method::POST, "api/state-file/preview", Some(state))
            .await
    }
    pub async fn restore(
        &self,
        state: &Value,
        confirmation_hash: &str,
    ) -> Result<HubView, HubClientError> {
        self.request(
            Method::PUT,
            "api/state-file",
            Some(&json!({"state":state,"confirmation_hash":confirmation_hash})),
        )
        .await
    }
    pub async fn connect_peer(
        &self,
        request: &ConnectPeerRequest,
    ) -> Result<HubView, HubClientError> {
        self.post("api/peers", request).await
    }
    pub async fn create_invoice(
        &self,
        request: &CreateInvoiceRequest,
    ) -> Result<HubView, HubClientError> {
        self.post("api/invoices", request).await
    }
    pub async fn decode_invoice(
        &self,
        request: &DecodeInvoiceRequest,
    ) -> Result<HubView, HubClientError> {
        self.post("api/invoices/decode", request).await
    }
    pub async fn settle_invoice(
        &self,
        id: &str,
        request: &SettleInvoiceRequest,
    ) -> Result<HubView, HubClientError> {
        self.action("invoices", id, "settle", request).await
    }
    pub async fn receive_invoice(&self, id: &str) -> Result<HubView, HubClientError> {
        self.action("invoices", id, "receive", &json!({})).await
    }
    pub async fn open_channel(
        &self,
        request: &OpenChannelRequest,
    ) -> Result<HubView, HubClientError> {
        self.post("api/channels", request).await
    }
    pub async fn splice_channel(
        &self,
        id: &str,
        request: &SpliceChannelRequest,
    ) -> Result<HubView, HubClientError> {
        self.action("channels", id, "splice", request).await
    }
    pub async fn publish_channel(
        &self,
        id: &str,
        request: &PublishStateRequest,
    ) -> Result<HubView, HubClientError> {
        self.action("channels", id, "publish", request).await
    }
    pub async fn finalise_channel(&self, id: &str) -> Result<HubView, HubClientError> {
        {
            canonical_id(id)?;
            self.request(Method::POST, &format!("api/channels/{id}/finalise"), None)
                .await
        }
    }
    pub async fn open_factory(
        &self,
        request: &OpenFactoryRequest,
    ) -> Result<HubView, HubClientError> {
        self.post("api/factories", request).await
    }
    pub async fn advance_factory(
        &self,
        id: &str,
        request: &AdvanceFactoryRequest,
    ) -> Result<HubView, HubClientError> {
        self.action("factories", id, "advance", request).await
    }
    pub async fn materialise_child(
        &self,
        id: &str,
        request: &MaterialiseChildRequest,
    ) -> Result<HubView, HubClientError> {
        self.action("factories", id, "materialise-child", request)
            .await
    }
    pub async fn import_package(
        &self,
        package: &StoredMultiAssetPackage,
    ) -> Result<HubView, HubClientError> {
        validate(package.validate())?;
        self.post("api/multi-asset-packages", package).await
    }
    pub async fn import_batch(
        &self,
        package: &StoredConditionalBatchPackage,
    ) -> Result<HubView, HubClientError> {
        validate(package.validate())?;
        self.post("api/conditional-batches", package).await
    }
    pub async fn recovery_package(
        &self,
        id: &str,
    ) -> Result<StoredMultiAssetPackage, HubClientError> {
        canonical_id(id)?;
        let package: StoredMultiAssetPackage = self
            .request(Method::GET, &format!("api/multi-asset-packages/{id}"), None)
            .await?;
        let summary = validate(package.validate())?;
        if summary.package_id != id {
            return Err(HubClientError::InvalidResponse);
        }
        Ok(package)
    }
    pub async fn import_root(&self, draft: &RootFundingDraft) -> Result<HubView, HubClientError> {
        validate(draft.inspection())?;
        self.post("api/root-fundings", draft).await
    }
    pub async fn root(&self, id: &str) -> Result<RootFundingCollection, HubClientError> {
        canonical_id(id)?;
        let collection: RootFundingCollection = self
            .request(Method::GET, &format!("api/root-fundings/{id}"), None)
            .await?;
        validate(collection.validate())?;
        if validate(collection.summary())?.root.transaction_hash != id {
            return Err(HubClientError::InvalidResponse);
        }
        Ok(collection)
    }
    pub async fn add_root_signature(
        &self,
        id: &str,
        target: RootFundingTarget,
        receipt: &SignatureMessage,
    ) -> Result<HubView, HubClientError> {
        let mut collection = self.root(id).await?;
        validate(collection.add(target, receipt.clone()))?;
        self.action(
            "root-fundings",
            id,
            "signatures",
            &json!({"target":target,"receipt":receipt}),
        )
        .await
    }
    pub async fn export_root(&self, id: &str) -> Result<RootFundingExport, HubClientError> {
        canonical_id(id)?;
        let export: RootFundingExport = self
            .request(Method::GET, &format!("api/root-fundings/{id}/export"), None)
            .await?;
        if validate(export.inspection())?.transaction_hash != id {
            return Err(HubClientError::InvalidResponse);
        }
        Ok(export)
    }
    async fn action<B: Serialize>(
        &self,
        group: &str,
        id: &str,
        action: &str,
        body: &B,
    ) -> Result<HubView, HubClientError> {
        canonical_id(id)?;
        self.post(&format!("api/{group}/{id}/{action}"), body).await
    }
    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, HubClientError> {
        let value = serde_json::to_value(body).map_err(|_| HubClientError::InvalidResponse)?;
        self.request(Method::POST, path, Some(&value)).await
    }
    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, HubClientError> {
        let mutation = method != Method::GET;
        let uncertain = || {
            if mutation {
                HubClientError::OutcomeUnknown
            } else {
                HubClientError::Transport
            }
        };
        let url = self
            .base
            .join(path)
            .map_err(|_| HubClientError::InvalidUrl)?;
        let mut request = self.http.request(method, url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|_| HubClientError::InvalidResponse)?;
            if bytes.len() > MAX_BODY {
                return Err(HubClientError::InvalidResponse);
            }
            request = request
                .header("content-type", "application/json")
                .body(bytes);
        }
        let mut response = request.send().await.map_err(|_| uncertain())?;
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-morph-hub-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let retry_after_seconds = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(if mutation {
                HubClientError::OutcomeUnknown
            } else {
                HubClientError::InvalidResponse
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| uncertain())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(if mutation {
                    HubClientError::OutcomeUnknown
                } else {
                    HubClientError::InvalidResponse
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let error = serde_json::from_slice::<ApiErrorBody>(&bytes).ok();
            return Err(HubClientError::Api {
                status: status.as_u16(),
                message: error
                    .as_ref()
                    .map(|e| e.error.clone())
                    .unwrap_or_else(|| "request rejected".into()),
                code: error.as_ref().map(|e| e.code.clone()).unwrap_or_default(),
                request_id: error
                    .map(|e| e.request_id)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(request_id),
                retry_after_seconds,
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            if mutation {
                HubClientError::OutcomeUnknown
            } else {
                HubClientError::InvalidResponse
            }
        })
    }
}
fn validate<T>(result: anyhow::Result<T>) -> Result<T, HubClientError> {
    result.map_err(|e| HubClientError::InvalidPackage(e.to_string()))
}
fn canonical_id(id: &str) -> Result<(), HubClientError> {
    if id.len() != 66
        || !id.starts_with("0x")
        || !id[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HubClientError::InvalidId);
    }
    Ok(())
}

/// A closed set of Hub workflows. Callers cannot smuggle an arbitrary URL or HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubOperation {
    Peer,
    CreateInvoice,
    DecodeInvoice,
    SettleInvoice,
    ReceiveInvoice,
    OpenChannel,
    SpliceChannel,
    PublishChannel,
    FinaliseChannel,
    OpenFactory,
    AdvanceFactory,
    MaterialiseChild,
    ImportRecovery,
    ExportRecovery,
    ImportBatch,
    ImportRoot,
    InspectRoot,
    RootExitSignature,
    RootCreationSignature,
    ExportRoot,
    ExportState,
    PreviewRestore,
    Restore,
}
impl HubOperation {
    pub fn required_scope(self) -> AuthScope {
        match self {
            Self::ExportRecovery | Self::InspectRoot | Self::ExportRoot => AuthScope::Read,
            Self::ExportState | Self::PreviewRestore | Self::Restore => AuthScope::Restore,
            Self::CreateInvoice => AuthScope::Sign,
            _ => AuthScope::Write,
        }
    }
    pub fn mutates(self) -> bool {
        !matches!(
            self,
            Self::ExportRecovery
                | Self::InspectRoot
                | Self::ExportRoot
                | Self::ExportState
                | Self::PreviewRestore
        )
    }
}
#[derive(Debug)]
pub enum HubReply {
    State(Box<HubView>),
    Document(Value),
}
impl HubClient {
    pub async fn execute(
        &self,
        op: HubOperation,
        id: &str,
        body: &Value,
    ) -> Result<HubReply, HubClientError> {
        fn from<T: DeserializeOwned>(value: &Value) -> Result<T, HubClientError> {
            serde_json::from_value(value.clone())
                .map_err(|e| HubClientError::InvalidPackage(e.to_string()))
        }
        fn document<T: Serialize>(value: T) -> Result<HubReply, HubClientError> {
            Ok(HubReply::Document(
                serde_json::to_value(value).map_err(|_| HubClientError::InvalidResponse)?,
            ))
        }
        use HubOperation::*;
        let state = match op {
            Peer => self.connect_peer(&from(body)?).await?,
            CreateInvoice => self.create_invoice(&from(body)?).await?,
            DecodeInvoice => self.decode_invoice(&from(body)?).await?,
            SettleInvoice => self.settle_invoice(id, &from(body)?).await?,
            ReceiveInvoice => self.receive_invoice(id).await?,
            OpenChannel => self.open_channel(&from(body)?).await?,
            SpliceChannel => self.splice_channel(id, &from(body)?).await?,
            PublishChannel => self.publish_channel(id, &from(body)?).await?,
            FinaliseChannel => self.finalise_channel(id).await?,
            OpenFactory => self.open_factory(&from(body)?).await?,
            AdvanceFactory => self.advance_factory(id, &from(body)?).await?,
            MaterialiseChild => self.materialise_child(id, &from(body)?).await?,
            ImportRecovery => self.import_package(&from(body)?).await?,
            ImportBatch => self.import_batch(&from(body)?).await?,
            ImportRoot => self.import_root(&from(body)?).await?,
            RootExitSignature | RootCreationSignature => {
                self.add_root_signature(
                    id,
                    if op == RootExitSignature {
                        RootFundingTarget::Exit
                    } else {
                        RootFundingTarget::Creation
                    },
                    &from(body)?,
                )
                .await?
            }
            ExportRecovery => return document(self.recovery_package(id).await?),
            InspectRoot => return document(self.root(id).await?),
            ExportRoot => return document(self.export_root(id).await?),
            ExportState => return document(self.state_file().await?),
            PreviewRestore => return document(self.preview_restore(body).await?),
            Restore => {
                self.restore(
                    &body["state"],
                    body["confirmation_hash"].as_str().ok_or_else(|| {
                        HubClientError::InvalidPackage("missing restore confirmation hash".into())
                    })?,
                )
                .await?
            }
        };
        Ok(HubReply::State(Box::new(state)))
    }
}
