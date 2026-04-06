use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
const TLS_SERVER_NAME_HOST_NAME: u8 = 0x00;
const TLS_CLIENT_HELLO_SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
const TLS_CLIENT_HELLO_MAX_BYTES: usize = 16 * 1024;

pub(super) async fn capture_tls_client_hello(
    stream: &mut TcpStream,
) -> Result<(Vec<u8>, Option<String>), io::Error> {
    let mut buffer = Vec::new();
    let mut scratch = [0u8; 2048];

    loop {
        match probe_tls_client_hello(&buffer) {
            TlsClientHelloProbe::ClientHello { hostname } => return Ok((buffer, hostname)),
            TlsClientHelloProbe::NotTls => return Ok((buffer, None)),
            TlsClientHelloProbe::NeedMoreData => {}
        }

        if buffer.len() >= TLS_CLIENT_HELLO_MAX_BYTES {
            return Ok((buffer, None));
        }

        let read_len = (TLS_CLIENT_HELLO_MAX_BYTES - buffer.len()).min(scratch.len());
        let read_result = tokio::time::timeout(
            TLS_CLIENT_HELLO_SNIFF_TIMEOUT,
            stream.read(&mut scratch[..read_len]),
        )
        .await;

        let bytes_read = match read_result {
            Ok(Ok(0)) => return Ok((buffer, None)),
            Ok(Ok(bytes_read)) => bytes_read,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok((buffer, None)),
        };

        buffer.extend_from_slice(&scratch[..bytes_read]);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TlsClientHelloProbe {
    NeedMoreData,
    NotTls,
    ClientHello { hostname: Option<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsClientHelloParseError {
    NeedMoreData,
    Invalid,
}

fn probe_tls_client_hello(buffer: &[u8]) -> TlsClientHelloProbe {
    match parse_tls_client_hello(buffer) {
        Ok(hostname) => TlsClientHelloProbe::ClientHello { hostname },
        Err(TlsClientHelloParseError::NeedMoreData) => TlsClientHelloProbe::NeedMoreData,
        Err(TlsClientHelloParseError::Invalid) => TlsClientHelloProbe::NotTls,
    }
}

fn parse_tls_client_hello(buffer: &[u8]) -> Result<Option<String>, TlsClientHelloParseError> {
    let mut cursor = 0;
    let mut handshake_bytes = Vec::new();
    let mut handshake_length: Option<usize> = None;

    loop {
        if buffer.len() < cursor + TLS_RECORD_HEADER_LEN {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        if buffer[cursor] != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(TlsClientHelloParseError::Invalid);
        }

        let record_length = u16::from_be_bytes([buffer[cursor + 3], buffer[cursor + 4]]) as usize;
        if record_length == 0 {
            return Err(TlsClientHelloParseError::Invalid);
        }

        let record_end = cursor + TLS_RECORD_HEADER_LEN + record_length;
        if buffer.len() < record_end {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        handshake_bytes.extend_from_slice(&buffer[cursor + TLS_RECORD_HEADER_LEN..record_end]);

        if handshake_length.is_none() {
            if handshake_bytes.len() < TLS_HANDSHAKE_HEADER_LEN {
                cursor = record_end;
                continue;
            }

            if handshake_bytes[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
                return Err(TlsClientHelloParseError::Invalid);
            }

            let length = (usize::from(handshake_bytes[1]) << 16)
                | (usize::from(handshake_bytes[2]) << 8)
                | usize::from(handshake_bytes[3]);
            if length == 0 {
                return Err(TlsClientHelloParseError::Invalid);
            }

            handshake_length = Some(length);
        }

        let required_len = TLS_HANDSHAKE_HEADER_LEN + handshake_length.unwrap();
        if handshake_bytes.len() >= required_len {
            let client_hello_body = &handshake_bytes[TLS_HANDSHAKE_HEADER_LEN..required_len];
            return parse_client_hello_body(client_hello_body);
        }

        cursor = record_end;
    }
}

fn parse_client_hello_body(body: &[u8]) -> Result<Option<String>, TlsClientHelloParseError> {
    if body.len() < 35 {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }

    let mut cursor = 0;
    cursor += 2;
    cursor += 32;

    let session_id_len = usize::from(body[cursor]);
    cursor += 1;
    if body.len() < cursor + session_id_len + 2 {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }
    cursor += session_id_len;

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if cipher_suites_len == 0 || cipher_suites_len % 2 != 0 {
        return Err(TlsClientHelloParseError::Invalid);
    }
    if body.len() < cursor + cipher_suites_len + 1 {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }
    cursor += cipher_suites_len;

    let compression_methods_len = usize::from(body[cursor]);
    cursor += 1;
    if compression_methods_len == 0 {
        return Err(TlsClientHelloParseError::Invalid);
    }
    if body.len() < cursor + compression_methods_len {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }
    cursor += compression_methods_len;

    if cursor == body.len() {
        return Ok(None);
    }

    if body.len() < cursor + 2 {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }

    let extensions_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor += 2;
    if body.len() < cursor + extensions_len {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }

    parse_client_hello_extensions(&body[cursor..cursor + extensions_len])
}

fn parse_client_hello_extensions(
    extensions: &[u8],
) -> Result<Option<String>, TlsClientHelloParseError> {
    let mut cursor = 0;

    while cursor < extensions.len() {
        if extensions.len() < cursor + 4 {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_length =
            u16::from_be_bytes([extensions[cursor + 2], extensions[cursor + 3]]) as usize;
        cursor += 4;

        if extensions.len() < cursor + extension_length {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        let extension_data = &extensions[cursor..cursor + extension_length];
        if extension_type == TLS_EXTENSION_SERVER_NAME {
            return parse_server_name_extension(extension_data);
        }

        cursor += extension_length;
    }

    Ok(None)
}

fn parse_server_name_extension(data: &[u8]) -> Result<Option<String>, TlsClientHelloParseError> {
    if data.len() < 2 {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err(TlsClientHelloParseError::NeedMoreData);
    }

    let mut cursor = 2;
    let list_end = 2 + list_len;

    while cursor < list_end {
        if list_end < cursor + 3 {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        let name_type = data[cursor];
        let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        cursor += 3;

        if list_end < cursor + name_len {
            return Err(TlsClientHelloParseError::NeedMoreData);
        }

        let name_bytes = &data[cursor..cursor + name_len];
        cursor += name_len;

        if name_type == TLS_SERVER_NAME_HOST_NAME {
            let hostname = String::from_utf8_lossy(name_bytes).into_owned();
            if hostname.is_empty() {
                return Ok(None);
            }

            return Ok(Some(hostname));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_from_tls_client_hello() {
        let buffer = build_tls_client_hello_record(Some("example.com"));

        let probe = probe_tls_client_hello(&buffer);

        assert_eq!(
            probe,
            TlsClientHelloProbe::ClientHello {
                hostname: Some("example.com".to_owned())
            }
        );
    }

    #[test]
    fn handles_fragmented_tls_client_hello_records() {
        let handshake = build_tls_client_hello_handshake(Some("example.com"));
        let split_at = 12;
        let mut buffer = build_tls_record(&handshake[..split_at]);
        buffer.extend_from_slice(&build_tls_record(&handshake[split_at..]));

        let probe = probe_tls_client_hello(&buffer);

        assert_eq!(
            probe,
            TlsClientHelloProbe::ClientHello {
                hostname: Some("example.com".to_owned())
            }
        );
    }

    #[test]
    fn accepts_tls_client_hello_without_sni() {
        let buffer = build_tls_client_hello_record(None);

        let probe = probe_tls_client_hello(&buffer);

        assert_eq!(probe, TlsClientHelloProbe::ClientHello { hostname: None });
    }

    #[test]
    fn needs_more_data_for_partial_tls_record() {
        let buffer = build_tls_client_hello_record(Some("example.com"));

        let probe = probe_tls_client_hello(&buffer[..10]);

        assert_eq!(probe, TlsClientHelloProbe::NeedMoreData);
    }

    #[test]
    fn rejects_non_tls_payloads() {
        let probe = probe_tls_client_hello(b"GET / HTTP/1.1\r\n\r\n");

        assert_eq!(probe, TlsClientHelloProbe::NotTls);
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
