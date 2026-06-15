//! Minimal client for the AUR RPC (interface v5).
//!
//! We only need the `info` endpoint for now: given a package name it returns
//! the maintainer, vote/popularity numbers and timestamps that the trust
//! engine reasons about. Docs: <https://aur.archlinux.org/rpc>

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use vouch_core::PackageMeta;

const RPC_BASE: &str = "https://aur.archlinux.org/rpc/v5";
const USER_AGENT: &str = concat!("vouch/", env!("CARGO_PKG_VERSION"));

/// Raw shape of one entry in the RPC `results` array. The AUR uses
/// PascalCase keys; we rename into our normalized [`PackageMeta`].
#[derive(Debug, Deserialize)]
struct RpcResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "PackageBase")]
    package_base: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Maintainer")]
    maintainer: Option<String>,
    #[serde(rename = "NumVotes")]
    num_votes: u64,
    #[serde(rename = "Popularity")]
    popularity: f64,
    #[serde(rename = "FirstSubmitted")]
    first_submitted: i64,
    #[serde(rename = "LastModified")]
    last_modified: i64,
    #[serde(rename = "OutOfDate")]
    out_of_date: Option<i64>,
    #[serde(rename = "URL")]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    results: Vec<RpcResult>,
}

impl From<RpcResult> for PackageMeta {
    fn from(r: RpcResult) -> Self {
        PackageMeta {
            name: r.name,
            package_base: r.package_base,
            version: r.version,
            description: r.description,
            maintainer: r.maintainer,
            num_votes: r.num_votes,
            popularity: r.popularity,
            first_submitted: r.first_submitted,
            last_modified: r.last_modified,
            out_of_date: r.out_of_date,
            url: r.url,
        }
    }
}

/// Look up a single package by exact name. Returns `Ok(None)` if the AUR has
/// no such package (so the caller can distinguish "not found" from a network
/// error).
pub fn info(pkg: &str) -> Result<Option<PackageMeta>> {
    let url = format!("{RPC_BASE}/info?arg[]={}", urlencode(pkg));
    let body = ureq::get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .with_context(|| format!("querying AUR RPC for {pkg}"))?
        .into_string()
        .context("reading AUR RPC response body")?;

    let resp: RpcResponse =
        serde_json::from_str(&body).context("parsing AUR RPC JSON response")?;

    if resp.kind == "error" {
        return Err(anyhow!(
            "AUR RPC error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        ));
    }

    Ok(resp.results.into_iter().next().map(PackageMeta::from))
}

/// Percent-encode the characters that actually matter for a query value.
/// Package names are restricted to a safe charset, but we stay defensive.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'+' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
