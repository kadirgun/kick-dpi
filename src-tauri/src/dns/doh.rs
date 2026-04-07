use reqwest::Client;

/// Sends a raw DNS wire-format query to Cloudflare's DoH endpoint using the
/// `application/dns-message` binary format (RFC 8484) and returns the raw
/// DNS wire-format response bytes.
pub async fn query_doh(client: &Client, wire: &[u8]) -> Result<Vec<u8>, reqwest::Error> {
    let resp = client
        .post("https://1.1.1.1/dns-query")
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec())
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    Ok(resp.to_vec())
}

/// Build a shared reqwest Client configured for DoH. Uses HTTP/2 (default for
/// HTTPS with reqwest) and a short connect timeout to avoid blocking the
/// DNS listener thread pool for too long.
pub fn build_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("failed to build DoH HTTP client")
}
