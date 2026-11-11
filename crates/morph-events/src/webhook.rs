use crate::{Delivery, Error, Failure, Outcome, Result, digest, is_hash};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{io::Read, time::Duration};
use zeroize::Zeroizing;

pub const MAX_ACK_BYTES: usize = 4096;
/// Contains secret material and deliberately has no Debug/Serialize implementation.
pub struct Webhook {
    url: url::Url,
    secret: Zeroizing<[u8; 32]>,
    client: reqwest::blocking::Client,
    policy: String,
}
fn mac(domain: &[u8], id: &str, body: &[u8], key: &[u8]) -> Result<Hmac<Sha256>> {
    if !is_hash(id) {
        return Err(Error::Invalid);
    }
    let mut h = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| Error::Invalid)?;
    h.update(domain);
    h.update(id.as_bytes());
    h.update(&[0]);
    h.update(body);
    Ok(h)
}
/// Receiver must durably apply/deduplicate the event before returning this value.
/// The acknowledgement authenticates the exact ID and bytes, under a distinct domain.
pub fn acknowledgement(id: &str, body: &[u8], key: &[u8; 32]) -> Result<String> {
    Ok(hex::encode(
        mac(b"morph.event.ack.v1\0", id, body, key)?
            .finalize()
            .into_bytes(),
    ))
}
/// Receiver-side verification of the bounded request body. Do not interpret a
/// valid HMAC as admission/signing authority or as permission to replay an effect.
pub fn verify_request(id: &str, body: &[u8], signature: &str, key: &[u8; 32]) -> Result<()> {
    if body.len() > crate::MAX_EVENT_BYTES
        || !is_hash(signature)
        || crate::EventEnvelope::decode(body)?.event_id != id
    {
        return Err(Error::Invalid);
    }
    let signature = hex::decode(signature).map_err(|_| Error::Invalid)?;
    mac(b"morph.event.request.v1\0", id, body, key)?
        .verify_slice(&signature)
        .map_err(|_| Error::Invalid)
}
impl Webhook {
    pub fn new(url: &str, key: Zeroizing<[u8; 32]>) -> Result<Self> {
        let parsed = url::Url::parse(url).map_err(|_| Error::Invalid)?;
        let local = parsed.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && local))
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || *key == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let fingerprint = digest(b"morph.event.webhook_key.v1\0", key.as_slice());
        let policy = digest(
            b"morph.event.webhook_policy.v1\0",
            format!(
                "{}:{fingerprint}:hmac-ack-v1:timeout10000:body4096",
                parsed.as_str()
            )
            .as_bytes(),
        );
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Invalid)?;
        Ok(Self {
            url: parsed,
            secret: key,
            client,
            policy,
        })
    }
    pub fn fingerprint(&self) -> String {
        self.policy.clone()
    }
    pub fn send(&self, delivery: &Delivery) -> Outcome {
        match self.send_checked(delivery) {
            Ok(()) => Outcome::Acknowledged,
            Err(reason) => Outcome::Failed(reason),
        }
    }
    fn send_checked(&self, delivery: &Delivery) -> std::result::Result<(), Failure> {
        if delivery.target() != self.policy {
            return Err(Failure::InvalidAck);
        }
        let signature = mac(
            b"morph.event.request.v1\0",
            delivery.event_id(),
            delivery.body(),
            self.secret.as_slice(),
        )
        .map_err(|_| Failure::InvalidAck)?;
        let response = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .header("x-morph-event-id", delivery.event_id())
            .header("x-morph-signature-algorithm", "HMAC-SHA256")
            .header(
                "x-morph-signature",
                hex::encode(signature.finalize().into_bytes()),
            )
            .body(delivery.body().to_vec())
            .send()
            .map_err(|_| Failure::Transport)?;
        if !response.status().is_success() {
            return Err(Failure::HttpStatus);
        }
        let values = response.headers().get_all("x-morph-ack");
        let mut iter = values.iter();
        let signature = iter
            .next()
            .and_then(|v| v.to_str().ok())
            .filter(|s| is_hash(s))
            .ok_or(Failure::InvalidAck)?;
        if iter.next().is_some() {
            return Err(Failure::InvalidAck);
        }
        let decoded = hex::decode(signature).map_err(|_| Failure::InvalidAck)?;
        mac(
            b"morph.event.ack.v1\0",
            delivery.event_id(),
            delivery.body(),
            self.secret.as_slice(),
        )
        .map_err(|_| Failure::InvalidAck)?
        .verify_slice(&decoded)
        .map_err(|_| Failure::InvalidAck)?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_ACK_BYTES as u64)
        {
            return Err(Failure::InvalidAck);
        }
        let mut bounded = Vec::new();
        response
            .take(MAX_ACK_BYTES as u64 + 1)
            .read_to_end(&mut bounded)
            .map_err(|_| Failure::Transport)?;
        if bounded.len() > MAX_ACK_BYTES {
            return Err(Failure::InvalidAck);
        }
        Ok(())
    }
}
