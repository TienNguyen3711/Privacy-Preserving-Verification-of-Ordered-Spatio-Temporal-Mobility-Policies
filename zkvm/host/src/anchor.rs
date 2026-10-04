//! Authenticated online state anchor. Production requires HTTPS and a ledger
//! under independent administration. Plain HTTP is opt-in for loopback tests.
use std::{io, time::Duration};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head { pub wallet_id: String, pub revision: u64, pub tip: String }

pub struct Anchor {
    url: String,
    token: Zeroizing<String>,
    http: reqwest::blocking::Client,
}
fn error(e: impl std::fmt::Display) -> io::Error { io::Error::other(format!("anchor unavailable/rejected: {e}")) }

impl Anchor {
    pub fn new(url: &str, token: &[u8;32], allow_loopback_http: bool) -> io::Result<Self> {
        let parsed = reqwest::Url::parse(url).map_err(error)?;
        let local = matches!(parsed.host_str(), Some("127.0.0.1") | Some("[::1]"));
        if parsed.scheme() != "https" && !(allow_loopback_http && local && parsed.scheme() == "http") {
            return Err(error("HTTPS required (loopback HTTP is test-only)"));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some()
            || parsed.fragment().is_some() || parsed.path() != "/" {
            return Err(error("anchor URL must be an origin without credentials/path/query"));
        }
        Ok(Self { url: url.trim_end_matches('/').to_owned(),
            token: Zeroizing::new(token.iter().map(|b| format!("{b:02x}")).collect()),
            http: reqwest::blocking::Client::builder().timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none()).build().map_err(error)? })
    }
    fn post<T: Serialize>(&self, route: &str, value: &T) -> io::Result<Head> {
        self.http.post(format!("{}{route}", self.url)).bearer_auth(self.token.as_str())
            .json(value).send().map_err(error)?.error_for_status().map_err(error)?
            .json().map_err(error)
    }
    pub fn register(&self, head: &Head) -> io::Result<()> {
        let received = self.post("/register", head)?;
        if &received != head { return Err(error("registration mismatch")); }
        Ok(())
    }
    pub fn current(&self, id: &str) -> io::Result<Head> {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(error("invalid wallet id")); }
        self.http.get(format!("{}/head/{id}", self.url)).bearer_auth(self.token.as_str())
            .send().map_err(error)?.error_for_status().map_err(error)?.json().map_err(error)
    }
    pub fn advance(&self, old: &Head, new: &Head) -> io::Result<()> {
        let result = self.post("/advance", &serde_json::json!({"old":old,"new":new}))?;
        if result != *new { return Err(error("advance mismatch")); }
        Ok(())
    }
}
