//! Holder-controlled session namespaces. The session secret is local state,
//! never a verifier-supplied value and never part of a public presentation.
use std::{io, path::Path};
use ring::hmac;
use crate::vault;

pub fn create(path: &Path) -> io::Result<()> { vault::generate_key(path) }

/// Persist the session file across retries; create a new file for each new
/// holder session, even for a different presentation of the same recording.
pub fn request_key(path: &Path, request_id: &str) -> io::Result<String> {
    if request_id.is_empty() || request_id.len() > 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid request id"));
    }
    let secret = vault::load_key(path)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_ref());
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(b"zkmob/session-request/v1\0");
    ctx.update(&(request_id.len() as u64).to_be_bytes());
    ctx.update(request_id.as_bytes());
    Ok(format!("session/v1/{}", ctx.sign().as_ref().iter()
        .map(|b| format!("{b:02x}")).collect::<String>()))
}
