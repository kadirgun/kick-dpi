/// Shared TLS ClientHello field offsets, relative to the TCP payload start.
/// Used by the fake/split/disorder strategies to find protocol-aware split
/// points (zapret-compatible position markers).
pub struct TlsInfo {
    /// Byte offset of the SNI extension TLV header (type bytes), or None.
    pub sniext: Option<usize>,
    /// Byte offset of the SNI hostname, or None.
    pub host: Option<usize>,
    /// Hostname length in bytes.
    pub host_len: usize,
    /// Byte offset of the second-level domain inside the payload
    /// (start of the last two labels of the hostname), or None.
    pub sld: Option<usize>,
}

/// Parses the first TLS record of `payload` and locates the SNI fields.
/// Accepts records longer than the buffer (TSO packets); SNI data must still
/// be fully present to resolve `host`/`sld`.
pub fn parse_tls(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    // payload[1] != 0x03 guard is done by callers via is_client_hello.

    let handshake = &payload[5..];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    // After handshake header (4): protocol version (2) + random (32)
    let mut pos = 38usize;

    // Session ID
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 1 >= handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= handshake.len() {
        return None;
    }
    let compression_methods_len = handshake[pos] as usize;
    pos += 1 + compression_methods_len;

    // Extensions
    if pos + 1 >= handshake.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = (pos + extensions_len).min(handshake.len());

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;

        if ext_type == 0x0000 {
            let ext_header = pos; // handshake-relative offset of TLV header
            let ext_data_start = pos + 4;
            let ext_data_end = (ext_data_start + ext_len).min(handshake.len());
            if ext_data_start >= ext_data_end {
                return None;
            }
            let ext_data = &handshake[ext_data_start..ext_data_end];

            // server_name_list: list_len(2) + name_type(1) + name_len(2) + hostname
            if ext_data.len() < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if 5 + name_len > ext_data.len() {
                return None;
            }

            // Payload-relative offsets (handshake starts at payload offset 5)
            let sniext = 5 + ext_header;
            let host = 5 + ext_data_start + 5;
            let host_len = name_len;

            // SLD = start of the last two labels ("google.com" in www.google.com)
            let hostname = &ext_data[5..5 + name_len];
            let sld = find_sld_start(hostname).map(|rel| host + rel);

            return Some(TlsInfo {
                sniext: Some(sniext),
                host: Some(host),
                host_len,
                sld,
            });
        }

        pos += 4 + ext_len;
    }

    None
}

/// Returns the offset of the start of the last two labels of `hostname`.
/// Single-label hostnames fall back to offset 0 (the whole hostname).
fn find_sld_start(hostname: &[u8]) -> Option<usize> {
    match hostname.iter().rposition(|b| *b == b'.') {
        Some(last_dot) => hostname[..last_dot]
            .iter()
            .rposition(|b| *b == b'.')
            .map(|d| d + 1),
        None => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_with_sni(hostname: &str) -> Vec<u8> {
        // Minimal ClientHello wire format: record hdr + handshake + fields
        let mut ext_data = vec![0x00, 0x00]; // server_name_list length placeholder
        ext_data.push(0x00); // name_type: host
        ext_data.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(hostname.as_bytes());
        let list_len = ext_data.len() as u16 - 2;
        ext_data[0..2].copy_from_slice(&list_len.to_be_bytes());

        let ext = {
            let mut e = 0x0000u16.to_be_bytes().to_vec();
            e.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            e.extend_from_slice(&ext_data);
            e
        };

        // Extensions length
        let mut handshake = vec![0x01u8]; // handshake type
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]); // length placeholder (unused here)
        handshake.extend_from_slice(&[0x03, 0x03]); // client version
        handshake.extend_from_slice(&[0u8; 32]); // random
        handshake.push(0x00); // session id len
        handshake.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher suites len
        handshake.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        handshake.push(0x01); // compression methods len
        handshake.push(0x00); // null compression
        handshake.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&ext);

        let mut record = vec![0x16u8, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn resolves_position_markers() {
        // payload: "..." 5-byte record header, then handshake.
        let payload = hello_with_sni("www.google.com");

        let info = parse_tls(&payload).unwrap();
        let sniext = info.sniext.unwrap();
        let host = info.host.unwrap();

        // host comes after the extension header (4) + list len (2) + type (1) + name len (2)
        assert_eq!(host, sniext + 4 + 5);
        assert_eq!(info.host_len, 14); // "www.google.com"

        // sld starts at "google" inside "www.google.com"
        let host_bytes = &payload[host..host + info.host_len];
        assert_eq!(host_bytes, b"www.google.com");
        let sld = info.sld.unwrap();
        let sld_bytes = &payload[sld..sld + 10];
        assert_eq!(sld_bytes, b"google.com");
    }

    #[test]
    fn single_label_host_falls_back_to_host_start() {
        let payload = hello_with_sni("localhost");
        let info = parse_tls(&payload).unwrap();
        assert_eq!(info.sld, info.host);
    }
}
