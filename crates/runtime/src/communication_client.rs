//! Identity-pinned thin client used by native Agent/program frontends. Remote
//! signing, encryption, pooling and operation continuation stay in the owner.
use super::*;
use peerwork_core::crypto::sha256_hex;
use tokio::sync::Mutex;

pub struct RuntimeClient {
    endpoint_path: PathBuf,
    expected_actor: String,
    expected_origin: String,
    verified: Mutex<Option<String>>,
}
impl RuntimeClient {
    pub async fn connect(
        endpoint_path: PathBuf,
        expected_origin: &str,
        expected_actor: &str,
    ) -> Result<Self> {
        if !endpoint_path.is_absolute() || !opaque_token(expected_actor) {
            return Err(local("CLIENT_BINDING_INVALID"));
        }
        let origin = crate::transport::canonical_lifecycle_origin(expected_origin, true)
            .map_err(|_| local("CLIENT_BINDING_INVALID"))?;
        let client = Self {
            endpoint_path,
            expected_actor: expected_actor.into(),
            expected_origin: origin,
            verified: Mutex::new(None),
        };
        client.call(json!({"method":"capabilities"})).await?;
        Ok(client)
    }
    pub fn actor_id(&self) -> &str {
        &self.expected_actor
    }
    pub fn origin(&self) -> &str {
        &self.expected_origin
    }
    fn unwrap(out: Value) -> Result<Value> {
        if out["ok"] == true {
            return Ok(out["value"].clone());
        }
        Err(serde_json::from_value(out["error"].clone())
            .unwrap_or_else(|_| observation(local("IPC_RESPONSE_INVALID"))))
    }
    async fn verify(&self, endpoint: &Endpoint, fingerprint: &str) -> Result<Value> {
        let caps = Self::unwrap(call_endpoint(endpoint, json!({"method":"capabilities"})).await?)?;
        if caps["format"] != "peerwork.participant-capability.v1"
            || caps["actor_id"] != self.expected_actor
            || caps["origin"] != self.expected_origin
            || caps["admin"] != false
        {
            return Err(local("CLIENT_IDENTITY_OR_ORIGIN_MISMATCH"));
        }
        *self.verified.lock().await = Some(fingerprint.into());
        Ok(caps)
    }
    /// Each exchange uses one protected descriptor snapshot. If the owner
    /// restarts/replaces it, verify its exact new capability before private work;
    /// never check one file version then send through a subsequently reread one.
    pub async fn call(&self, request: Value) -> Result<Value> {
        ClientRequest::parse(request.clone())?;
        let endpoint = load_endpoint(&self.endpoint_path)?;
        if endpoint.access != "CLIENT" {
            return Err(local("CLIENT_ADMIN_ENDPOINT_FORBIDDEN"));
        }
        let fingerprint = sha256_hex(
            serde_json::to_string(&endpoint)
                .map_err(|_| local("ENDPOINT_INVALID"))?
                .as_bytes(),
        );
        if request["method"] == "capabilities" {
            return self.verify(&endpoint, &fingerprint).await;
        }
        let verified = { self.verified.lock().await.clone() };
        if verified.as_deref() != Some(fingerprint.as_str()) {
            self.verify(&endpoint, &fingerprint).await?;
        }
        let original = request["request"]["operation_id"]
            .as_str()
            .or_else(|| request["operation_id"].as_str())
            .filter(|s| identifier(s))
            .map(str::to_owned);
        let result = call_endpoint(&endpoint, request)
            .await
            .and_then(Self::unwrap);
        result.map_err(|mut error| {
            if error.operation_id.is_none() {
                error.operation_id = original;
            }
            error
        })
    }
}
