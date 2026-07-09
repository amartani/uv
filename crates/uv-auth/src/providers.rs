use std::borrow::Cow;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use reqsign::aws::DefaultSigner as AwsDefaultSigner;
use reqsign::azure::DefaultSigner as AzureDefaultSigner;
use reqsign::google::DefaultSigner as GcsDefaultSigner;
use reqsign::{Context, default_context};
use rustc_hash::FxHashMap;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::debug;
use url::ParseError;

use uv_preview::{Preview, PreviewFeature};
use uv_redacted::SafeUrl;
use uv_static::EnvVars;
use uv_warnings::warn_user_once;

use crate::Credentials;
use crate::credentials::Token;
use crate::index::is_path_prefix;
use crate::realm::{Realm, RealmRef};

/// The username expected by AWS `CodeArtifact` when using an authorization token.
const CODEARTIFACT_USERNAME: &str = "aws";

/// Request authorization tokens that are valid for one hour, matching
/// [`keyrings.codeartifact`](https://github.com/jmkeyes/keyrings.codeartifact).
const CODEARTIFACT_TOKEN_DURATION_SECS: u64 = 3600;

/// Refresh AWS `CodeArtifact` credentials periodically, since authorization tokens are short-lived.
const CODEARTIFACT_CACHE_DURATION: Duration = Duration::from_mins(55);

/// Avoid waiting indefinitely for AWS credentials or the `CodeArtifact` API.
const CODEARTIFACT_TIMEOUT: Duration = Duration::from_secs(10);

/// Refresh credentials a few minutes before the token expires.
const CODEARTIFACT_EXPIRY_SKEW: Duration = Duration::from_mins(5);

/// A provider for authentication credentials for AWS `CodeArtifact`.
#[derive(Clone, Debug)]
pub struct CodeArtifactEndpointProvider {
    signer: Option<AwsDefaultSigner>,
    context: Context,
    credentials: Arc<Mutex<FxHashMap<CodeArtifactRepository, CachedCodeArtifactCredentials>>>,
}

#[derive(Clone, Debug)]
struct CachedCodeArtifactCredentials {
    credentials: Option<Credentials>,
    expires_at: Instant,
}

/// Identifiers parsed from an AWS `CodeArtifact` repository URL.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CodeArtifactRepository {
    domain: String,
    domain_owner: String,
    region: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeArtifactAuthorizationTokenResponse {
    authorization_token: Option<String>,
    expiration: Option<f64>,
}

/// The shared AWS `CodeArtifact` provider.
static CODEARTIFACT_PROVIDER: LazyLock<CodeArtifactEndpointProvider> =
    LazyLock::new(|| CodeArtifactEndpointProvider {
        signer: None,
        context: default_context(),
        credentials: Arc::new(Mutex::new(FxHashMap::default())),
    });

impl Default for CodeArtifactEndpointProvider {
    fn default() -> Self {
        CODEARTIFACT_PROVIDER.clone()
    }
}

impl CodeArtifactEndpointProvider {
    /// Returns `true` if the URL is for AWS `CodeArtifact`.
    pub fn is_codeartifact(url: &SafeUrl) -> bool {
        Self::parse_repository(url).is_some()
    }

    /// Returns `true` if the username is compatible with AWS `CodeArtifact` credentials.
    pub(crate) fn supports_username(username: Option<&str>) -> bool {
        username.is_none_or(|username| username == CODEARTIFACT_USERNAME)
    }

    /// Returns credentials for AWS `CodeArtifact`, if available.
    ///
    /// This follows the behavior of the `keyrings.codeartifact` package: parse the repository URL,
    /// then call `GetAuthorizationToken` using the default AWS credential chain.
    pub(crate) async fn credentials_for(&self, url: &SafeUrl) -> Option<Credentials> {
        let repository = Self::parse_repository(url)?;

        let mut cached_credentials = self.credentials.lock().await;
        if let Some(credentials) = cached_credentials
            .get(&repository)
            .filter(|credentials| credentials.expires_at > Instant::now())
        {
            return credentials.credentials.clone();
        }

        let (credentials, cache_duration) = if let Some((credentials, cache_duration)) =
            self.credentials_from_api(&repository).await
        {
            debug!("Found AWS CodeArtifact credentials from GetAuthorizationToken");
            (Some(credentials), cache_duration)
        } else {
            debug!("No AWS CodeArtifact credentials found");
            (
                None,
                CODEARTIFACT_CACHE_DURATION.min(Duration::from_mins(1)),
            )
        };

        cached_credentials.insert(
            repository,
            CachedCodeArtifactCredentials {
                credentials: credentials.clone(),
                expires_at: Instant::now() + cache_duration,
            },
        );

        credentials
    }

    /// Returns `true` if credentials are available for AWS `CodeArtifact`.
    pub async fn has_credentials_for(&self, url: &SafeUrl) -> bool {
        self.credentials_for(url).await.is_some()
    }

    fn parse_repository(url: &SafeUrl) -> Option<CodeArtifactRepository> {
        if url.scheme() != "https" {
            return None;
        }

        let host = url.host_str()?;
        let (prefix, region) = host.split_once(".d.codeartifact.")?;
        let region = region.strip_suffix(".amazonaws.com")?;
        if region.is_empty() || region.contains('.') {
            return None;
        }

        let (domain, domain_owner) = split_domain_and_owner(prefix)?;
        if !url.path().starts_with("/pypi/") {
            return None;
        }

        Some(CodeArtifactRepository {
            domain: domain.to_string(),
            domain_owner: domain_owner.to_string(),
            region: region.to_string(),
        })
    }

    async fn credentials_from_api(
        &self,
        repository: &CodeArtifactRepository,
    ) -> Option<(Credentials, Duration)> {
        let endpoint = format!(
            "https://codeartifact.{}.amazonaws.com/v1/authorization-token",
            repository.region
        );
        let mut request_url = SafeUrl::parse(&endpoint)
            .inspect_err(|err| {
                debug!("Failed to build AWS CodeArtifact authorization token URL: {err}");
            })
            .ok()?;
        {
            let mut query = request_url.query_pairs_mut();
            query.append_pair("domain", &repository.domain);
            query.append_pair("domain-owner", &repository.domain_owner);
            query.append_pair("duration", &CODEARTIFACT_TOKEN_DURATION_SECS.to_string());
        }

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(request_url.as_str())
            .header(http::header::CONTENT_LENGTH, "0")
            .body(())
            .inspect_err(|err| {
                debug!("Failed to build AWS CodeArtifact authorization token request: {err}");
            })
            .ok()?;
        let (mut parts, ()) = request.into_parts();

        let signer = self
            .signer
            .clone()
            .unwrap_or_else(|| reqsign::aws::default_signer("codeartifact", &repository.region));
        let Ok(result) =
            tokio::time::timeout(CODEARTIFACT_TIMEOUT, signer.sign(&mut parts, None)).await
        else {
            debug!("Timed out signing AWS CodeArtifact authorization token request");
            return None;
        };
        result
            .inspect_err(|err| {
                debug!("Failed to sign AWS CodeArtifact authorization token request: {err}");
            })
            .ok()?;

        let signed_request = http::Request::from_parts(parts, Bytes::new());
        let Ok(response_result) =
            tokio::time::timeout(CODEARTIFACT_TIMEOUT, self.context.http_send(signed_request))
                .await
        else {
            debug!("Timed out retrieving AWS CodeArtifact authorization token");
            return None;
        };
        let response = response_result
            .inspect_err(|err| {
                debug!("Failed to retrieve AWS CodeArtifact authorization token: {err}");
            })
            .ok()?;

        if !response.status().is_success() {
            debug!(
                "AWS CodeArtifact GetAuthorizationToken returned status {}",
                response.status()
            );
            return None;
        }

        Self::credentials_from_response(response.body())
    }

    fn credentials_from_response(body: &[u8]) -> Option<(Credentials, Duration)> {
        let response = serde_json::from_slice::<CodeArtifactAuthorizationTokenResponse>(body)
            .inspect_err(|err| {
                debug!("Failed to parse AWS CodeArtifact authorization token response: {err}");
            })
            .ok()?;
        let token = response
            .authorization_token
            .filter(|token| !token.is_empty())?;
        let cache_duration = if let Some(expiration) = response.expiration {
            // AWS returns expiration as a Unix timestamp; accept fractional seconds by rounding.
            let expiration_secs = expiration.round();
            if !expiration_secs.is_finite() {
                debug!("Ignoring invalid AWS CodeArtifact authorization token expiration");
                return None;
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "Unix timestamps fit in i64 for CodeArtifact token expirations"
            )]
            let expiration_secs = expiration_secs as i64;
            let expiration = jiff::Timestamp::from_second(expiration_secs)
                .inspect_err(|err| {
                    debug!(
                        "Failed to parse AWS CodeArtifact authorization token expiration: {err}"
                    );
                })
                .ok()?;
            let now = jiff::Timestamp::now();
            if expiration <= now {
                debug!("Ignoring expired AWS CodeArtifact authorization token");
                return None;
            }
            expiration
                .duration_since(now)
                .unsigned_abs()
                .saturating_sub(CODEARTIFACT_EXPIRY_SKEW)
                .min(CODEARTIFACT_CACHE_DURATION)
                .max(Duration::from_secs(1))
        } else {
            CODEARTIFACT_CACHE_DURATION
        };

        Some((
            Credentials::basic(Some(CODEARTIFACT_USERNAME.to_string()), Some(token)),
            cache_duration,
        ))
    }

    #[cfg(test)]
    pub(crate) fn with_signer(signer: AwsDefaultSigner) -> Self {
        Self {
            signer: Some(signer),
            context: default_context(),
            credentials: Arc::new(Mutex::new(FxHashMap::default())),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_context(mut self, context: Context) -> Self {
        self.context = context;
        self
    }

    #[cfg(test)]
    pub(crate) async fn cache_missing_credentials(&self, url: &SafeUrl) {
        let Some(repository) = Self::parse_repository(url) else {
            return;
        };
        self.credentials.lock().await.insert(
            repository,
            CachedCodeArtifactCredentials {
                credentials: None,
                expires_at: Instant::now() + Duration::from_mins(1),
            },
        );
    }

    #[cfg(test)]
    pub(crate) async fn clear_cached_credentials(&self) {
        self.credentials.lock().await.clear();
    }
}

/// Split `domain-012345678901` into `(domain, account)`.
///
/// The account ID is always the final 12-digit segment after a hyphen.
fn split_domain_and_owner(prefix: &str) -> Option<(&str, &str)> {
    let (domain, domain_owner) = prefix.rsplit_once('-')?;
    if domain.is_empty()
        || domain_owner.len() != 12
        || !domain_owner.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((domain, domain_owner))
}

/// The [`Realm`] for the Hugging Face platform.
static HUGGING_FACE_REALM: LazyLock<Realm> = LazyLock::new(|| {
    let url = SafeUrl::parse("https://huggingface.co").expect("Failed to parse Hugging Face URL");
    Realm::from(&url)
});

/// The authentication token for the Hugging Face platform, if set.
static HUGGING_FACE_TOKEN: LazyLock<Option<Vec<u8>>> = LazyLock::new(|| {
    // Extract the Hugging Face token from the environment variable, if it exists.
    let hf_token = std::env::var(EnvVars::HF_TOKEN)
        .ok()
        .map(String::into_bytes)
        .filter(|token| !token.is_empty())?;

    if std::env::var_os(EnvVars::UV_NO_HF_TOKEN).is_some() {
        debug!("Ignoring Hugging Face token from environment due to `UV_NO_HF_TOKEN`");
        return None;
    }

    debug!("Found Hugging Face token in environment");
    Some(hf_token)
});

/// A provider for authentication credentials for the Hugging Face platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HuggingFaceProvider;

impl HuggingFaceProvider {
    /// Returns the credentials for the Hugging Face platform, if available.
    pub(crate) fn credentials_for(url: &SafeUrl) -> Option<Credentials> {
        if RealmRef::from(url) == *HUGGING_FACE_REALM {
            if let Some(token) = HUGGING_FACE_TOKEN.as_ref() {
                return Some(Credentials::Bearer {
                    token: Token::new(token.clone()),
                });
            }
        }
        None
    }
}

/// The [`SafeUrl`] for the S3 endpoint, if set.
static S3_ENDPOINT_URL: LazyLock<Result<Option<SafeUrl>, ParseError>> =
    LazyLock::new(|| endpoint_url(EnvVars::UV_S3_ENDPOINT_URL));

/// A provider for authentication credentials for S3 endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct S3EndpointProvider;

impl S3EndpointProvider {
    /// Returns `true` if the URL matches the configured S3 endpoint.
    pub(crate) fn is_s3_endpoint(url: &SafeUrl, preview: Preview) -> Result<bool> {
        if let Some(s3_endpoint_url) = S3_ENDPOINT_URL
            .as_ref()
            .map_err(|error| *error)
            .with_context(|| format!("Invalid `{}`", EnvVars::UV_S3_ENDPOINT_URL))?
        {
            if !preview.is_enabled(PreviewFeature::S3Endpoint) {
                warn_user_once!(
                    "The `s3-endpoint` option is experimental and may change without warning. Pass `--preview-features {}` to disable this warning.",
                    PreviewFeature::S3Endpoint
                );
            }

            // Treat any URL under the endpoint path on the same domain or subdomain as available
            // for S3 signing.
            if is_endpoint_url(url, s3_endpoint_url) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a new S3 signer with the configured region.
    ///
    /// This is potentially expensive as it may invoke credential helpers, so the result
    /// should be cached.
    pub(crate) fn create_signer() -> AwsDefaultSigner {
        // TODO(charlie): Can `reqsign` infer the region for us? Profiles, for example,
        // often have a region set already.
        let region = std::env::var(EnvVars::AWS_REGION)
            .map(Cow::Owned)
            .unwrap_or_else(|_| {
                std::env::var(EnvVars::AWS_DEFAULT_REGION)
                    .map(Cow::Owned)
                    .unwrap_or_else(|_| Cow::Borrowed("us-east-1"))
            });
        reqsign::aws::default_signer("s3", &region)
    }
}

/// The [`SafeUrl`] for the GCS endpoint, if set.
static GCS_ENDPOINT_URL: LazyLock<Result<Option<SafeUrl>, ParseError>> =
    LazyLock::new(|| endpoint_url(EnvVars::UV_GCS_ENDPOINT_URL));

/// A provider for authentication credentials for GCS endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcsEndpointProvider;

impl GcsEndpointProvider {
    /// Returns `true` if the URL matches the configured GCS endpoint.
    pub(crate) fn is_gcs_endpoint(url: &SafeUrl, preview: Preview) -> Result<bool> {
        if let Some(gcs_endpoint_url) = GCS_ENDPOINT_URL
            .as_ref()
            .map_err(|error| *error)
            .with_context(|| format!("Invalid `{}`", EnvVars::UV_GCS_ENDPOINT_URL))?
        {
            if !preview.is_enabled(PreviewFeature::GcsEndpoint) {
                warn_user_once!(
                    "The `gcs-endpoint` option is experimental and may change without warning. Pass `--preview-features {}` to disable this warning.",
                    PreviewFeature::GcsEndpoint
                );
            }

            // Treat any URL under the endpoint path on the same domain or subdomain as available
            // for GCS signing.
            if is_endpoint_url(url, gcs_endpoint_url) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a new GCS signer.
    ///
    /// This is potentially expensive as it may invoke credential helpers, so the result
    /// should be cached.
    pub(crate) fn create_signer() -> GcsDefaultSigner {
        reqsign::google::default_signer("storage.googleapis.com")
    }
}

/// The [`SafeUrl`] for the Azure endpoint, if set.
static AZURE_ENDPOINT_URL: LazyLock<Result<Option<SafeUrl>, ParseError>> =
    LazyLock::new(|| endpoint_url(EnvVars::UV_AZURE_ENDPOINT_URL));

/// A provider for authentication credentials for Azure endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureEndpointProvider;

impl AzureEndpointProvider {
    /// Returns `true` if the URL matches the configured Azure endpoint.
    pub fn is_azure_endpoint(url: &SafeUrl, preview: Preview) -> Result<bool> {
        if let Some(azure_endpoint_url) = AZURE_ENDPOINT_URL
            .as_ref()
            .map_err(|error| *error)
            .with_context(|| format!("Invalid `{}`", EnvVars::UV_AZURE_ENDPOINT_URL))?
        {
            if !preview.is_enabled(PreviewFeature::AzureEndpoint) {
                warn_user_once!(
                    "The `azure-endpoint` option is experimental and may change without warning. Pass `--preview-features {}` to disable this warning.",
                    PreviewFeature::AzureEndpoint
                );
            }

            // Treat any URL under the endpoint path on the same domain or subdomain as available
            // for Azure signing.
            if is_endpoint_url(url, azure_endpoint_url) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a new Azure signer using the default Azure credential chain.
    ///
    /// This is potentially expensive as it may invoke credential helpers, so the result
    /// should be cached.
    pub(crate) fn create_signer() -> AzureDefaultSigner {
        reqsign::azure::default_signer()
    }
}

/// Returns the configured endpoint [`SafeUrl`], if set and valid.
fn endpoint_url(env_var: &str) -> Result<Option<SafeUrl>, ParseError> {
    let Some(endpoint_url) = std::env::var(env_var).ok() else {
        return Ok(None);
    };
    SafeUrl::parse_relaxed(&endpoint_url).map(Some)
}

/// Returns `true` if `url` is within the configured S3, GCS, or Azure-compatible endpoint URL.
///
/// The URL must be in the same realm, or a subdomain of the endpoint realm, and must be under the
/// endpoint path using complete path-segment prefix matching.
fn is_endpoint_url(url: &SafeUrl, endpoint_url: &SafeUrl) -> bool {
    let endpoint_realm = RealmRef::from(endpoint_url);
    let realm = RealmRef::from(url);
    if realm != endpoint_realm && !realm.is_subdomain_of(endpoint_realm) {
        return false;
    }

    is_path_prefix(endpoint_url.path(), url.path())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use reqsign::HttpSend;

    use super::*;

    #[derive(Clone, Debug)]
    struct TestHttpSend {
        body: Bytes,
        status: http::StatusCode,
        calls: Arc<AtomicUsize>,
    }

    impl TestHttpSend {
        fn new(body: impl AsRef<[u8]>) -> Self {
            Self {
                body: Bytes::copy_from_slice(body.as_ref()),
                status: http::StatusCode::OK,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl HttpSend for TestHttpSend {
        async fn http_send(
            &self,
            _req: http::Request<Bytes>,
        ) -> reqsign::Result<http::Response<Bytes>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(http::Response::builder()
                .status(self.status)
                .body(self.body.clone())
                .expect("test response should build"))
        }
    }

    fn test_codeartifact_provider(http: TestHttpSend) -> CodeArtifactEndpointProvider {
        CodeArtifactEndpointProvider::with_signer(
            reqsign::aws::default_signer("codeartifact", "us-west-2").with_credential_provider(
                reqsign::aws::StaticCredentialProvider::new(
                    "AKIAIOSFODNN7EXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                ),
            ),
        )
        .with_context(Context::new().with_http_send(http))
    }

    #[tokio::test]
    async fn test_codeartifact_credentials_from_api() {
        // Far-future Unix timestamp so the token is treated as unexpired.
        let body = r#"{"authorizationToken":"test-token","expiration":4102444800.0}"#;
        let provider = test_codeartifact_provider(TestHttpSend::new(body));

        assert_eq!(
            provider
                .credentials_for(
                    &SafeUrl::parse(
                        "https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/repo/simple/"
                    )
                    .unwrap()
                )
                .await,
            Some(Credentials::basic(
                Some("aws".to_string()),
                Some("test-token".to_string())
            ))
        );
    }

    #[tokio::test]
    async fn test_codeartifact_credentials_ignores_other_hosts() {
        let provider = test_codeartifact_provider(TestHttpSend::new(
            br#"{"authorizationToken":"test-token"}"#,
        ));

        assert_eq!(
            provider
                .credentials_for(&SafeUrl::parse("https://example.com/pypi/repo/simple/").unwrap())
                .await,
            None
        );
        assert_eq!(
            provider
                .credentials_for(
                    &SafeUrl::parse(
                        "http://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/repo/simple/"
                    )
                    .unwrap()
                )
                .await,
            None
        );
        assert_eq!(
            provider
                .credentials_for(
                    &SafeUrl::parse(
                        "https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/npm/repo/"
                    )
                    .unwrap()
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_codeartifact_credentials_caches_missing_credentials() {
        let http = TestHttpSend::new(br#"{"authorizationToken":"test-token"}"#);
        let calls = http.calls.clone();
        let provider = test_codeartifact_provider(http);
        let url = SafeUrl::parse(
            "https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/repo/simple/",
        )
        .unwrap();
        provider.cache_missing_credentials(&url).await;

        assert_eq!(provider.credentials_for(&url).await, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_codeartifact_credentials_caches_successful_lookup() {
        let http = TestHttpSend::new(br#"{"authorizationToken":"test-token"}"#);
        let calls = http.calls.clone();
        let provider = test_codeartifact_provider(http);
        let url = SafeUrl::parse(
            "https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/repo/simple/",
        )
        .unwrap();

        assert!(provider.credentials_for(&url).await.is_some());
        assert!(provider.credentials_for(&url).await.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_codeartifact_credentials_supports_username() {
        assert!(CodeArtifactEndpointProvider::supports_username(None));
        assert!(CodeArtifactEndpointProvider::supports_username(Some("aws")));
        assert!(!CodeArtifactEndpointProvider::supports_username(Some(
            "user"
        )));
    }

    #[test]
    fn test_codeartifact_parse_repository() {
        assert_eq!(
            CodeArtifactEndpointProvider::parse_repository(
                &SafeUrl::parse(
                    "https://my-domain-123456789012.d.codeartifact.us-west-2.amazonaws.com/pypi/repo/simple/"
                )
                .unwrap()
            ),
            Some(CodeArtifactRepository {
                domain: "my-domain".to_string(),
                domain_owner: "123456789012".to_string(),
                region: "us-west-2".to_string(),
            })
        );
        assert_eq!(
            CodeArtifactEndpointProvider::parse_repository(
                &SafeUrl::parse(
                    "https://domain-with-dashes-123456789012.d.codeartifact.eu-central-1.amazonaws.com/pypi/repo/"
                )
                .unwrap()
            ),
            Some(CodeArtifactRepository {
                domain: "domain-with-dashes".to_string(),
                domain_owner: "123456789012".to_string(),
                region: "eu-central-1".to_string(),
            })
        );
    }

    #[test]
    fn test_codeartifact_credentials_from_response() {
        assert_eq!(
            CodeArtifactEndpointProvider::credentials_from_response(
                br#"{"authorizationToken":"test-token","expiration":4102444800.0}"#
            )
            .map(|(credentials, _)| credentials),
            Some(Credentials::basic(
                Some("aws".to_string()),
                Some("test-token".to_string())
            ))
        );
        assert_eq!(
            CodeArtifactEndpointProvider::credentials_from_response(
                br#"{"authorizationToken":""}"#
            ),
            None
        );
        assert_eq!(
            CodeArtifactEndpointProvider::credentials_from_response(
                br#"{"authorizationToken":"test-token","expiration":1}"#
            ),
            None
        );
    }

    #[test]
    fn test_endpoint_url_matches_path_prefix() {
        let endpoint_url = SafeUrl::parse("https://example.com/private").unwrap();

        for url in [
            "https://example.com/private",
            "https://example.com/private/",
            "https://example.com/private/packages/anyio.whl",
        ] {
            assert!(
                is_endpoint_url(&SafeUrl::parse(url).unwrap(), &endpoint_url),
                "Failed to match endpoint URL prefix: {url}"
            );
        }
    }

    #[test]
    fn test_endpoint_url_rejects_partial_path_segments() {
        let endpoint_url = SafeUrl::parse("https://example.com/private").unwrap();

        for url in [
            "https://example.com/public",
            "https://example.com/private-bucket",
            "https://example.com/privatebucket",
        ] {
            assert!(
                !is_endpoint_url(&SafeUrl::parse(url).unwrap(), &endpoint_url),
                "Should not match URL outside endpoint path: {url}"
            );
        }
    }

    #[test]
    fn test_endpoint_url_matches_subdomain_with_path_prefix() {
        let endpoint_url = SafeUrl::parse("https://example.com/private").unwrap();

        assert!(is_endpoint_url(
            &SafeUrl::parse("https://bucket.example.com/private/package.whl").unwrap(),
            &endpoint_url
        ));
        assert!(!is_endpoint_url(
            &SafeUrl::parse("https://bucket.example.com/public/package.whl").unwrap(),
            &endpoint_url
        ));
    }

    #[test]
    fn test_endpoint_url_root_path_matches_all_paths() {
        let endpoint_url = SafeUrl::parse("https://example.com").unwrap();

        for url in [
            "https://example.com/package.whl",
            "https://bucket.example.com/package.whl",
        ] {
            assert!(
                is_endpoint_url(&SafeUrl::parse(url).unwrap(), &endpoint_url),
                "Failed to match URL under endpoint root: {url}"
            );
        }
    }
}
