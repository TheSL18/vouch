//! Minimal client for the AUR RPC (interface v5).
//!
//! We use the `info` endpoint to fetch the maintainer/vote/timestamp metadata
//! the trust engine reasons about, plus the dependency arrays the resolver
//! needs. Docs: <https://aur.archlinux.org/rpc>

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use vouch_core::PackageMeta;

const RPC_BASE: &str = "https://aur.archlinux.org/rpc/v5";
const USER_AGENT: &str = concat!("vouch/", env!("CARGO_PKG_VERSION"));

/// Raw shape of one entry in the RPC `results` array. The AUR uses PascalCase
/// keys; absent arrays come back as JSON `null`, so the dependency fields are
/// `Option` and defaulted on the way into [`PackageMeta`].
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
    #[serde(rename = "Depends", default)]
    depends: Option<Vec<String>>,
    #[serde(rename = "MakeDepends", default)]
    make_depends: Option<Vec<String>>,
    #[serde(rename = "CheckDepends", default)]
    check_depends: Option<Vec<String>>,
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
            depends: r.depends.unwrap_or_default(),
            make_depends: r.make_depends.unwrap_or_default(),
            check_depends: r.check_depends.unwrap_or_default(),
        }
    }
}

/// GET `url` and parse the standard RPC envelope, surfacing RPC-level errors.
fn get(url: &str) -> Result<Vec<PackageMeta>> {
    let body = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .call()
        .context("querying AUR RPC")?
        .into_string()
        .context("reading AUR RPC response body")?;

    let resp: RpcResponse = serde_json::from_str(&body).context("parsing AUR RPC JSON response")?;
    if resp.kind == "error" {
        return Err(anyhow!(
            "AUR RPC error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        ));
    }
    Ok(resp.results.into_iter().map(PackageMeta::from).collect())
}

/// Look up a single package by exact name. `Ok(None)` if the AUR has no such
/// package (so the caller can tell "not found" from a network error).
pub fn info(pkg: &str) -> Result<Option<PackageMeta>> {
    let url = format!("{RPC_BASE}/info?arg[]={}", urlencode(pkg));
    Ok(get(&url)
        .with_context(|| format!("looking up {pkg}"))?
        .into_iter()
        .next())
}

/// Look up many packages in one request. The result contains only the names
/// that exist in the AUR, in unspecified order.
pub fn info_many(pkgs: &[&str]) -> Result<Vec<PackageMeta>> {
    if pkgs.is_empty() {
        return Ok(Vec::new());
    }
    let mut url = format!("{RPC_BASE}/info");
    let mut sep = '?';
    for p in pkgs {
        url.push(sep);
        url.push_str("arg[]=");
        url.push_str(&urlencode(p));
        sep = '&';
    }
    get(&url)
}

/// Percent-encode the characters that actually matter for a query value.
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
