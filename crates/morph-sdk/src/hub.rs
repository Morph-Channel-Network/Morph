use morph_hub_api::endpoints::Endpoint;
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
    #[error(
        "Mutation outcome unknown; retry identical request with its saved context or reconcile before a new request"
    )]
    OutcomeUnknown { mutation: MutationContext },
    #[error("invalid or unsupported mutation context")]
    InvalidMutationContext,
    #[error("Hub returned an invalid or oversized response")]
    InvalidResponse,
    #[error("HTTP {status}: {message} (code {code:?}, request {request_id})")]
    Api {
        status: u16,
        message: String,
        code: Option<ApiErrorCode>,
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
    mutation: Option<MutationContext>,
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
            mutation: None,
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
    /// Explicitly retry the identical request with its original public context.
    /// Never use this context for another body, route or changed proposal.
    pub fn with_mutation(mut self, context: MutationContext) -> Result<Self, HubClientError> {
        if !context.valid() {
            return Err(HubClientError::InvalidMutationContext);
        }
        self.mutation = Some(context);
        Ok(self)
    }
    /// Bind a new mutation to the exact projection the user reviewed.
    /// Do not fetch a newer revision at confirmation time.
    pub fn with_expected_revision(self, revision: u64) -> Result<Self, HubClientError> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| HubClientError::Transport)?;
        self.with_mutation(MutationContext {
            idempotency_key: hex::encode(id),
            expected_revision: revision,
        })
    }
    pub async fn api_info(&self) -> Result<ApiInfo, HubClientError> {
        let info: ApiInfo = self
            .request_inner(Method::GET, "api/meta", None, None)
            .await?;
        if info.api_version != mutation::API_VERSION {
            return Err(HubClientError::InvalidMutationContext);
        }
        Ok(info)
    }
    /// Durable, source-bound pagination; unlike SSE this does not use the UI ring buffer.
    pub async fn event_log(&self, request: &EventPageRequest) -> Result<EventPage, HubClientError> {
        let page: EventPage = self.post("api/event-log", request).await?;
        if !page.valid_for(request) {
            return Err(HubClientError::InvalidResponse);
        }
        Ok(page)
    }
    pub async fn liveness(&self) -> Result<Liveness, HubClientError> {
        self.request(Method::GET, "api/health", None).await
    }
    /// A 503 readiness report is usable observation data, not an API error.
    /// It never grants permission to mutate or sign.
    pub async fn readiness(&self) -> Result<Readiness, HubClientError> {
        self.request(Method::GET, "api/readiness", None).await
    }
    pub async fn state(&self) -> Result<HubView, HubClientError> {
        self.request(Method::GET, "api/state", None).await
    }
    pub async fn state_file(&self) -> Result<StateArchive, HubClientError> {
        self.request(Method::GET, "api/state-file", None).await
    }
    pub async fn preview_restore(
        &self,
        state: &StateArchive,
    ) -> Result<RestorePreview, HubClientError> {
        self.post("api/state-file/preview", state).await
    }
    pub async fn restore(
        &self,
        state: &StateArchive,
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
            &RootReceiptRequest {
                target,
                receipt: receipt.clone(),
            },
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
        let endpoint = Endpoint::resolve(method.as_str(), &format!("/{path}"))
            .ok_or(HubClientError::InvalidUrl)?;
        let context = if endpoint.mutates() {
            Some(match &self.mutation {
                Some(context) => context.clone(),
                None => {
                    let info = self.api_info().await?;
                    let mut id = [0u8; 16];
                    getrandom::fill(&mut id).map_err(|_| HubClientError::Transport)?;
                    MutationContext {
                        idempotency_key: hex::encode(id),
                        expected_revision: info.revision,
                    }
                }
            })
        } else {
            None
        };
        self.request_inner(method, path, body, context.as_ref())
            .await
    }
    async fn request_inner<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        context: Option<&MutationContext>,
    ) -> Result<T, HubClientError> {
        let mutation = context.is_some();
        let uncertain = || match context {
            Some(context) => HubClientError::OutcomeUnknown {
                mutation: context.clone(),
            },
            None => HubClientError::Transport,
        };
        let url = self
            .base
            .join(path)
            .map_err(|_| HubClientError::InvalidUrl)?;
        let mut request = self
            .http
            .request(method, url)
            .header(mutation::API_VERSION_HEADER, mutation::API_VERSION);
        if let Some(context) = context {
            request = request
                .header(mutation::IDEMPOTENCY_HEADER, &context.idempotency_key)
                .header(
                    mutation::REVISION_HEADER,
                    context.expected_revision.to_string(),
                );
        }
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|_| HubClientError::InvalidResponse)?;
            if bytes.len() > 1024 * 1024 {
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
                uncertain()
            } else {
                HubClientError::InvalidResponse
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| uncertain())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(if mutation {
                    uncertain()
                } else {
                    HubClientError::InvalidResponse
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        if path == "api/readiness" && matches!(status.as_u16(), 200 | 503) {
            let report: Readiness =
                serde_json::from_slice(&bytes).map_err(|_| HubClientError::InvalidResponse)?;
            if report.ready != status.is_success()
                || report.service.label() != "hub"
                || !report.consistent()
            {
                return Err(HubClientError::InvalidResponse);
            }
            return serde_json::from_slice(&bytes).map_err(|_| HubClientError::InvalidResponse);
        }
        if !status.is_success() {
            let error = serde_json::from_slice::<ApiErrorBody>(&bytes).ok();
            if mutation
                && (error.is_none()
                    || error
                        .as_ref()
                        .is_some_and(|e| e.code == ApiErrorCode::CommitOutcomeUnknown))
            {
                return Err(uncertain());
            }
            return Err(HubClientError::Api {
                status: status.as_u16(),
                message: error
                    .as_ref()
                    .map(|e| e.error.clone())
                    .unwrap_or_else(|| "request rejected".into()),
                code: error.as_ref().map(|e| e.code),
                request_id: error
                    .map(|e| e.request_id)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(request_id),
                retry_after_seconds,
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            if mutation {
                uncertain()
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
    pub fn endpoint(self) -> Endpoint {
        match self {
            Self::Peer => Endpoint::ConnectPeer,
            Self::CreateInvoice => Endpoint::CreateInvoice,
            Self::DecodeInvoice => Endpoint::DecodeInvoice,
            Self::SettleInvoice => Endpoint::SettleInvoice,
            Self::ReceiveInvoice => Endpoint::ReceiveInvoice,
            Self::OpenChannel => Endpoint::OpenChannel,
            Self::SpliceChannel => Endpoint::SpliceChannel,
            Self::PublishChannel => Endpoint::PublishChannel,
            Self::FinaliseChannel => Endpoint::FinaliseChannel,
            Self::OpenFactory => Endpoint::OpenFactory,
            Self::AdvanceFactory => Endpoint::AdvanceFactory,
            Self::MaterialiseChild => Endpoint::MaterialiseChild,
            Self::ImportRecovery => Endpoint::ImportRecovery,
            Self::ExportRecovery => Endpoint::RecoveryPackage,
            Self::ImportBatch => Endpoint::ImportBatch,
            Self::ImportRoot => Endpoint::ImportRoot,
            Self::InspectRoot => Endpoint::RootCollection,
            Self::ExportRoot => Endpoint::RootExport,
            Self::ExportState => Endpoint::ExportState,
            Self::PreviewRestore => Endpoint::PreviewRestore,
            Self::Restore => Endpoint::RestoreState,
            Self::RootExitSignature | Self::RootCreationSignature => Endpoint::RootSignature,
        }
    }
    pub fn required_scope(self) -> AuthScope {
        self.endpoint().scope()
    }
    pub fn mutates(self) -> bool {
        self.endpoint().mutates()
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
            PreviewRestore => return document(self.preview_restore(&from(body)?).await?),
            Restore => {
                let request: RestoreArchiveRequest = from(body)?;
                self.restore(&request.state, &request.confirmation_hash)
                    .await?
            }
        };
        Ok(HubReply::State(Box::new(state)))
    }
}
