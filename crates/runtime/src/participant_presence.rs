//! Volatile observations expire independently of durable delivery facts.
use crate::participant::{ParticipantError, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
#[derive(Clone)]
pub(crate) struct Presence {
    pub version: u64,
    host: Value,
    host_at: Option<Instant>,
    keys: Value,
    pub keys_at: Option<Instant>,
}
impl Default for Presence {
    fn default() -> Self {
        Self {
            version: 0,
            host: json!({"mode":"PROGRAM","ready":false,"execution_state":"UNKNOWN"}),
            host_at: None,
            keys: json!({"state":"UNKNOWN","key_id":null,"epoch":null}),
            keys_at: None,
        }
    }
}
impl Presence {
    #[cfg(test)]
    pub fn host(&mut self, value: Value) -> Result<()> {
        self.host_observed(value, Instant::now())
    }
    pub fn host_observed(&mut self, value: Value, observed_at: Instant) -> Result<()> {
        if observed_at > Instant::now()
            || value.as_object().is_none_or(|o| o.len() != 3)
            || !matches!(
                value["mode"].as_str(),
                Some("LIVE" | "IDLE_ONLY" | "QUEUED_ONLY" | "PROGRAM")
            )
            || !value["ready"].is_boolean()
            || !matches!(
                value["execution_state"].as_str(),
                Some("IDLE" | "BUSY" | "WAITING_APPROVAL" | "UNKNOWN" | "OFFLINE")
            )
            || value["mode"] == "QUEUED_ONLY" && value["ready"] == true
        {
            return Err(ParticipantError::local(
                "HOST_PRESENCE_INVALID",
                "HOST_OBSERVATION",
            ));
        }
        // Refresh the observation's actual time without forcing a network
        // pulse for an unchanged, still-current host probe. A real state or
        // freshness transition must be advertised immediately.
        let now = Instant::now();
        let was_current = self.host_at.is_some_and(|at| now.duration_since(at) < Duration::from_secs(10));
        let is_current = now.duration_since(observed_at) < Duration::from_secs(10);
        if self.host != value || was_current != is_current {
            self.version = self.version.saturating_add(1);
        }
        self.host = value;
        self.host_at = Some(observed_at);
        Ok(())
    }
    pub fn keys(&mut self, value: Value) {
        if self.keys != value || self.keys_at.is_none_or(|at| at.elapsed() >= Duration::from_secs(15)) {
            self.version = self.version.saturating_add(1);
        }
        self.keys = value;
        self.keys_at = Some(Instant::now());
    }
    fn age(at: Option<Instant>) -> u64 {
        at.map(|at| at.elapsed().as_millis().min(60000) as u64)
            .unwrap_or(60000)
    }
    pub fn wire(&self, destination: &str, ordered_ready: bool) -> Value {
        json!({"mode":self.host["mode"],"host_ready":self.host["ready"],"host_execution":self.host["execution_state"],"host_age_ms":Self::age(self.host_at),"key_state":self.keys["state"],"key_code":self.keys["code"],"key_id":self.keys["key_id"],"key_epoch":self.keys["epoch"],"key_age_ms":Self::age(self.keys_at),"ordered_ready":ordered_ready,"destination_digest":destination})
    }
    pub fn local(&self) -> Value {
        json!({"host":self.host,"host_current":self.host_at.is_some_and(|t|t.elapsed()<Duration::from_secs(10)),"body_key":self.keys,"key_current":self.keys_at.is_some_and(|t|t.elapsed()<Duration::from_secs(15)),"model_response":"NOT_ATTESTED"})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freshness_is_not_renewed_by_serializing_or_observing_old_facts() {
        let mut p = Presence::default();
        assert_eq!(p.wire("d", true)["host_age_ms"], 60000);
        p.host(json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"}))
            .unwrap();
        p.keys(json!({"state":"READY","key_id":"K","epoch":1}));
        p.host_at = Some(Instant::now() - Duration::from_secs(11));
        p.keys_at = Some(Instant::now() - Duration::from_secs(16));
        assert_eq!(p.local()["host_current"], false);
        assert_eq!(p.local()["key_current"], false);
        assert!(p.wire("d", false)["host_age_ms"].as_u64().unwrap() >= 11000);
        assert_eq!(p.wire("d", false)["ordered_ready"], false);
        assert!(p
            .host(json!({"mode":"QUEUED_ONLY","ready":true,"execution_state":"IDLE"}))
            .is_err());
    }
    #[test]
    fn repeated_current_observations_refresh_age_without_forcing_extra_pulses() {
        let mut p = Presence::default();
        let host = json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"});
        let keys = json!({"state":"READY","key_id":"K","epoch":1});
        p.host(host.clone()).unwrap();p.keys(keys.clone());let initial=p.version;
        p.host_at=Some(Instant::now()-Duration::from_secs(3));
        p.keys_at=Some(Instant::now()-Duration::from_secs(3));
        p.host(host.clone()).unwrap();p.keys(keys.clone());
        assert_eq!(p.version,initial);
        assert!(p.wire("d",true)["host_age_ms"].as_u64().unwrap()<1000);
        assert!(p.wire("d",true)["key_age_ms"].as_u64().unwrap()<1000);
        p.host(json!({"mode":"LIVE","ready":true,"execution_state":"BUSY"})).unwrap();
        assert_eq!(p.version,initial+1);
        p.keys(json!({"state":"READY","key_id":"NEW","epoch":2}));
        assert_eq!(p.version,initial+2);
        p.host_at=Some(Instant::now()-Duration::from_secs(11));
        p.keys_at=Some(Instant::now()-Duration::from_secs(16));
        p.host(host).unwrap();p.keys(keys);assert_eq!(p.version,initial+4);
        let current=p.version;
        p.host_observed(json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"}),Instant::now()-Duration::from_secs(11)).unwrap();
        assert_eq!(p.version,current+1);assert_eq!(p.local()["host_current"],false);
    }
}

#[cfg(test)]
mod delayed_probe_tests {
    use super::*;
    #[test]
    fn slow_host_probe_keeps_its_original_age_and_rejects_future_observation() {
        let mut presence = Presence::default();
        let value = json!({"mode":"LIVE","ready":true,"execution_state":"IDLE"});
        presence
            .host_observed(value.clone(), Instant::now() - Duration::from_secs(11))
            .unwrap();
        assert_eq!(presence.local()["host_current"], false);
        assert!(presence.wire("d", true)["host_age_ms"].as_u64().unwrap() >= 11000);
        let version = presence.version;
        assert!(presence
            .host_observed(value, Instant::now() + Duration::from_secs(1))
            .is_err());
        assert_eq!(presence.version, version);
    }
}
