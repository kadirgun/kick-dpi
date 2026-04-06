use super::super::context::BypassContext;
use super::super::strategy::BypassStrategy;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
const TLS_SERVER_NAME_HOST_NAME: u8 = 0x00;

#[derive(Debug, Default)]
pub struct TcpSniSplittingStrategy;

impl BypassStrategy for TcpSniSplittingStrategy {
    fn name(&self) -> &'static str {
        "tcp_sni_splitting"
    }

    fn process_sni(&mut self, _context: &mut BypassContext, data: &[u8]) -> Vec<Vec<u8>> {
        match find_sni_hostname_split_offset(data) {
            Some(split_at) if split_at > 0 && split_at < data.len() => {
                return vec![data[..split_at].to_vec(), data[split_at..].to_vec()];
            }
            _ => {}
        }

        vec![data.to_vec()]
    }
}

fn find_sni_hostname_split_offset(data: &[u8]) -> Option<usize> {
    let (handshake_bytes, raw_positions) = collect_client_hello_handshake_bytes(data)?;
    let (hostname_start, hostname_len) = find_sni_hostname_range(&handshake_bytes)?;

    if hostname_len < 2 {
        return None;
    }

    let prefix_len = (hostname_len / 2).clamp(1, hostname_len - 1);
    let split_index = TLS_HANDSHAKE_HEADER_LEN + hostname_start + prefix_len;

    raw_positions.get(split_index).copied()
}

fn collect_client_hello_handshake_bytes(data: &[u8]) -> Option<(Vec<u8>, Vec<usize>)> {
    let mut cursor = 0;
    let mut handshake_bytes = Vec::new();
    let mut raw_positions = Vec::new();
    let mut handshake_length: Option<usize> = None;

    loop {
        if data.len() < cursor + TLS_RECORD_HEADER_LEN {
            return None;
        }

        if data[cursor] != TLS_CONTENT_TYPE_HANDSHAKE {
            return None;
        }

        let record_length = u16::from_be_bytes([data[cursor + 3], data[cursor + 4]]) as usize;
        if record_length == 0 {
            return None;
        }

        let record_end = cursor + TLS_RECORD_HEADER_LEN + record_length;
        if data.len() < record_end {
            return None;
        }

        for offset in 0..record_length {
            handshake_bytes.push(data[cursor + TLS_RECORD_HEADER_LEN + offset]);
            raw_positions.push(cursor + TLS_RECORD_HEADER_LEN + offset);
        }

        if handshake_length.is_none() {
            if handshake_bytes.len() < TLS_HANDSHAKE_HEADER_LEN {
                cursor = record_end;
                continue;
            }

            if handshake_bytes[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
                return None;
            }

            let length = (usize::from(handshake_bytes[1]) << 16)
                | (usize::from(handshake_bytes[2]) << 8)
                | usize::from(handshake_bytes[3]);

            if length == 0 {
                return None;
            }

            handshake_length = Some(length);
        }

        let required_len = TLS_HANDSHAKE_HEADER_LEN + handshake_length?;
        if handshake_bytes.len() >= required_len {
            return Some((handshake_bytes, raw_positions));
        }

        cursor = record_end;
    }
}

fn find_sni_hostname_range(handshake_bytes: &[u8]) -> Option<(usize, usize)> {
    if handshake_bytes.len() < TLS_HANDSHAKE_HEADER_LEN {
        return None;
    }

    if handshake_bytes[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }

    let body_len = (usize::from(handshake_bytes[1]) << 16)
        | (usize::from(handshake_bytes[2]) << 8)
        | usize::from(handshake_bytes[3]);

    if handshake_bytes.len() < TLS_HANDSHAKE_HEADER_LEN + body_len {
        return None;
    }

    find_sni_hostname_range_in_body(
        &handshake_bytes[TLS_HANDSHAKE_HEADER_LEN..TLS_HANDSHAKE_HEADER_LEN + body_len],
    )
}

fn find_sni_hostname_range_in_body(body: &[u8]) -> Option<(usize, usize)> {
    if body.len() < 35 {
        return None;
    }

    let mut cursor = 0;
    cursor += 2;
    cursor += 32;

    let session_id_len = usize::from(*body.get(cursor)?);
    cursor += 1;
    if body.len() < cursor + session_id_len + 2 {
        return None;
    }
    cursor += session_id_len;

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return None;
    }
    if body.len() < cursor + cipher_suites_len + 1 {
        return None;
    }
    cursor += cipher_suites_len;

    let compression_methods_len = usize::from(body[cursor]);
    cursor += 1;
    if compression_methods_len == 0 {
        return None;
    }
    if body.len() < cursor + compression_methods_len {
        return None;
    }
    cursor += compression_methods_len;

    if cursor == body.len() {
        return None;
    }

    if body.len() < cursor + 2 {
        return None;
    }

    let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if body.len() < cursor + extensions_len {
        return None;
    }

    let extensions_start = cursor;
    let extensions = &body[extensions_start..extensions_start + extensions_len];
    let mut ext_cursor = 0;

    while ext_cursor < extensions.len() {
        if extensions.len() < ext_cursor + 4 {
            return None;
        }

        let extension_type =
            u16::from_be_bytes([extensions[ext_cursor], extensions[ext_cursor + 1]]);
        let extension_length =
            u16::from_be_bytes([extensions[ext_cursor + 2], extensions[ext_cursor + 3]]) as usize;
        let extension_data_start = ext_cursor + 4;
        ext_cursor += 4;

        if extensions.len() < ext_cursor + extension_length {
            return None;
        }

        let extension_data = &extensions[ext_cursor..ext_cursor + extension_length];
        if extension_type == TLS_EXTENSION_SERVER_NAME {
            return find_hostname_in_server_name_extension(extension_data).map(
                |(hostname_start, hostname_len)| {
                    (
                        extensions_start + extension_data_start + hostname_start,
                        hostname_len,
                    )
                },
            );
        }

        ext_cursor += extension_length;
    }

    None
}

fn find_hostname_in_server_name_extension(data: &[u8]) -> Option<(usize, usize)> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut cursor = 2;
    let list_end = 2 + list_len;

    while cursor < list_end {
        if list_end < cursor + 3 {
            return None;
        }

        let name_type = data[cursor];
        let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        cursor += 3;

        if list_end < cursor + name_len {
            return None;
        }

        if name_type == TLS_SERVER_NAME_HOST_NAME {
            return Some((cursor, name_len));
        }

        cursor += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn build_context() -> BypassContext {
        BypassContext::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)),
        )
    }

    #[test]
    fn splits_sni_hostname_in_the_middle() {
        let mut strategy = TcpSniSplittingStrategy::default();
        let mut context = build_context();
        let buffer = build_tls_client_hello_record(Some("example.com"));

        let chunks = strategy.process_sni(&mut context, &buffer);

        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].ends_with(b"examp"));
        assert!(chunks[1].starts_with(b"le.com"));
        assert_eq!(
            [chunks[0].as_slice(), chunks[1].as_slice()].concat(),
            buffer
        );
    }

    #[test]
    fn splits_fragmented_client_hello_records() {
        let mut strategy = TcpSniSplittingStrategy::default();
        let mut context = build_context();
        let handshake = build_tls_client_hello_handshake(Some("example.com"));
        let split_at = 12;
        let mut buffer = build_tls_record(&handshake[..split_at]);
        buffer.extend_from_slice(&build_tls_record(&handshake[split_at..]));

        let chunks = strategy.process_sni(&mut context, &buffer);

        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].ends_with(b"examp"));
        assert!(chunks[1].starts_with(b"le.com"));
        assert_eq!(
            [chunks[0].as_slice(), chunks[1].as_slice()].concat(),
            buffer
        );
    }

    #[test]
    fn leaves_payload_unchanged_without_sni() {
        let mut strategy = TcpSniSplittingStrategy::default();
        let mut context = build_context();
        let buffer = build_tls_client_hello_record(None);

        let chunks = strategy.process_sni(&mut context, &buffer);

        assert_eq!(chunks, vec![buffer]);
    }

    fn build_tls_client_hello_record(hostname: Option<&str>) -> Vec<u8> {
        build_tls_record(&build_tls_client_hello_handshake(hostname))
    }

    fn build_tls_client_hello_handshake(hostname: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);

        if let Some(hostname) = hostname {
            let hostname_bytes = hostname.as_bytes();
            let mut server_name = Vec::new();
            server_name.push(TLS_SERVER_NAME_HOST_NAME);
            server_name.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
            server_name.extend_from_slice(hostname_bytes);

            let mut extension_data = Vec::new();
            extension_data.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
            extension_data.extend_from_slice(&server_name);

            let mut extensions = Vec::new();
            extensions.extend_from_slice(&TLS_EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(extension_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&extension_data);

            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = body.len() as u32;
        handshake.push(((body_len >> 16) & 0xFF) as u8);
        handshake.push(((body_len >> 8) & 0xFF) as u8);
        handshake.push((body_len & 0xFF) as u8);
        handshake.extend_from_slice(&body);

        handshake
    }

    fn build_tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
        record.push(TLS_CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }
}
