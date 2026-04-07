use reqwest::Client;

const CLOUDFLARE_URL: &str = "https://1.1.1.1/dns-query";
const QUAD9_URL: &str = "https://9.9.9.9/dns-query";
const NEXTDNS_URL: &str = "https://45.90.28.1/dns-query";

/// Returns the DoH endpoint URL for the given provider name.
pub fn provider_url(provider: &str, custom_url: Option<&str>) -> String {
    match provider {
        "Quad9" => QUAD9_URL.to_string(),
        "NextDNS" => NEXTDNS_URL.to_string(),
        "Custom" => custom_url.unwrap_or(CLOUDFLARE_URL).to_string(),
        _ => CLOUDFLARE_URL.to_string(),
    }
}

/// Sends a raw DNS wire-format query to the given DoH endpoint using the
/// `application/dns-message` binary format (RFC 8484) and returns the raw
/// DNS wire-format response bytes.
pub async fn query_doh(
    client: &Client,
    wire: &[u8],
    url: &str,
    timeout_ms: u32,
) -> Result<Vec<u8>, reqwest::Error> {
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec())
        .timeout(std::time::Duration::from_millis(timeout_ms as u64))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    Ok(resp.to_vec())
}

/// Build a shared reqwest Client configured for DoH. Uses HTTP/2 (default for
/// HTTPS with reqwest) and connection pooling. Per-request timeouts are set
/// in `query_doh` using the configured `timeout_ms` from settings.
pub fn build_client() -> Client {
    Client::builder()
        .build()
        .expect("failed to build DoH HTTP client")
}
