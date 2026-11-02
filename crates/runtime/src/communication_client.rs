//! Identity-pinned thin client used by native Agent/program frontends. Remote
//! signing, encryption, pooling and operation continuation stay in the owner.
use super::*;
use peerwork_core::crypto::sha256_hex;
use tokio::sync::Mutex;

pub(crate) fn validate_binding(value:&Value,origin:&str,actor:&str)->Result<()> {
    if value["format"]!="peerwork.local-engine-binding.v1" || value["actor_id"]!=actor || value["origin"]!=origin
        || !["engine_digest","state_binding"].iter().all(|field|value[*field].as_str().is_some_and(crate::participant_migration::digest))
        || !value["namespace"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=256)
        || !(value["client_generation"].is_null() || value["client_generation"].as_u64().is_some()) {
        return Err(local("ORIGINAL_RUNTIME_BINDING_INVALID"));
    }
    Ok(())
}
pub(crate) fn canonical_binding(value:&Value)->Value {
    ["format","actor_id","origin","engine_digest","state_binding","namespace","client_generation"]
        .into_iter().map(|field|(field.to_owned(),value[field].clone())).collect::<serde_json::Map<_,_>>().into()
}

pub struct RuntimeClient {
    endpoint_path: PathBuf,
    expected_actor: String,
    expected_origin: String,
    verified: Mutex<Option<String>>,
    binding: Option<Value>,
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
            binding: None,
        };
        client.call(json!({"method":"capabilities"})).await?;
        Ok(client)
    }
    /// Pin the original engine/namespace, and revalidate it on every changed
    /// descriptor snapshot BEFORE sending any operation through that snapshot.
    pub async fn connect_bound(endpoint_path:PathBuf, origin:&str, actor:&str, binding:Value)->Result<Self> {
        let mut client=Self::connect(endpoint_path,origin,actor).await?;
        validate_binding(&binding,&client.expected_origin,&client.expected_actor)?;
        client.binding=Some(binding);
        *client.verified.lock().await=None;
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
        if let Some(expected)=&self.binding {
            let observed=Self::unwrap(call_endpoint(endpoint,json!({"method":"binding"})).await?)?;
            validate_binding(&observed,&self.expected_origin,&self.expected_actor)?;
            for field in ["actor_id","origin","engine_digest","state_binding","namespace","client_generation"] {
                if observed[field]!=expected[field] {return Err(local("ORIGINAL_RUNTIME_BINDING_CHANGED"));}
            }
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
