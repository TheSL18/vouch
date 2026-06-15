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

/// A shared HTTP agent using the system's native TLS (OpenSSL), built once.
///
/// Connection pooling is disabled on purpose. The AUR closes idle keep-alive
/// connections, and `vouch` makes AUR queries with long gaps in between (e.g.
/// after running `pacman -S` for several seconds during an upgrade). Reusing a
/// connection the server already closed surfaces as a "Unexpected EOF" — so we
/// open a fresh connection per request instead.
fn agent() -> &'static ureq::Agent {
    use std::sync::OnceLock;
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let connector = native_tls::TlsConnector::new().expect("initialize native-tls");
        ureq::AgentBuilder::new()
            .tls_connector(std::sync::Arc::new(connector))
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .build()
    })
}

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

/// Execute a request with a few retries on transient transport/EOF errors
/// (the AUR occasionally resets connections), returning the response body.
/// HTTP status errors are returned immediately — they aren't transient.
#[allow(clippy::result_large_err)] // ureq::Error is large; it's ureq's type, not ours
fn execute(make: impl Fn() -> std::result::Result<ureq::Response, ureq::Error>) -> Result<String> {
    let mut delay = std::time::Duration::from_millis(200);
    let mut last = String::new();
    for attempt in 1..=4 {
        match make() {
            Ok(resp) => match resp.into_string() {
                Ok(body) => return Ok(body),
                Err(e) => last = format!("reading response body: {e}"),
            },
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                return Err(anyhow!("AUR RPC returned HTTP {code}: {body}"));
            }
            Err(e) => last = e.to_string(),
        }
        if attempt < 4 {
            std::thread::sleep(delay);
            delay = (delay * 3).min(std::time::Duration::from_secs(2));
        }
    }
    Err(anyhow!("AUR RPC request failed after retries: {last}"))
}

/// Parse the standard RPC envelope, surfacing RPC-level errors.
fn parse_envelope(body: &str) -> Result<Vec<PackageMeta>> {
    let resp: RpcResponse = serde_json::from_str(body).context("parsing AUR RPC JSON response")?;
    if resp.kind == "error" {
        return Err(anyhow!(
            "AUR RPC error: {}",
            resp.error.unwrap_or_else(|| "unknown".into())
        ));
    }
    Ok(resp.results.into_iter().map(PackageMeta::from).collect())
}

/// GET `url` and parse the standard RPC envelope.
#[allow(clippy::result_large_err)]
fn get(url: &str) -> Result<Vec<PackageMeta>> {
    let body = execute(|| {
        agent()
            .get(url)
            .set("User-Agent", USER_AGENT)
            .set("Connection", "close")
            .call()
    })
    .context("querying AUR RPC")?;
    parse_envelope(&body)
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

/// Search the AUR by name and description. Returns matching packages (without
/// dependency arrays, which only the `info` endpoint provides).
pub fn search(query: &str) -> Result<Vec<PackageMeta>> {
    let url = format!("{RPC_BASE}/search/{}?by=name-desc", urlencode(query));
    get(&url).with_context(|| format!("searching the AUR for {query:?}"))
}

/// Maximum packages per `info` request. The AUR drops connections for large
/// requests ("unexpected EOF"), so we keep each query small and batch.
const INFO_CHUNK: usize = 15;

/// Look up many packages, batching into small requests. The result contains
/// only the names that exist in the AUR, in unspecified order.
pub fn info_many(pkgs: &[&str]) -> Result<Vec<PackageMeta>> {
    let mut out = Vec::new();
    for (i, chunk) in pkgs.chunks(INFO_CHUNK).enumerate() {
        if i > 0 {
            // Be gentle: a brief pause between requests avoids the AUR resetting
            // rapid successive connections.
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
        let mut url = format!("{RPC_BASE}/info");
        let mut sep = '?';
        for p in chunk {
            url.push(sep);
            url.push_str("arg[]=");
            url.push_str(&urlencode(p));
            sep = '&';
        }
        out.extend(get(&url).context("querying AUR RPC")?);
    }
    Ok(out)
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
