use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;

const DOH_ENDPOINT_HOST: &str = "cloudflare-dns.com";
const DOH_ENDPOINT_URL: &str = "https://cloudflare-dns.com/dns-query";
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_HEADER_LEN: usize = 12;
const DNS_RECORD_TYPE_A: u16 = 1;
const DNS_RECORD_TYPE_AAAA: u16 = 28;
const DNS_RECORD_CLASS_IN: u16 = 1;

static DOH_CLIENT: OnceLock<Result<Client, io::Error>> = OnceLock::new();

pub(crate) async fn resolve_target(host: &str, port: u16) -> Result<SocketAddr, io::Error> {
    let normalized_host = normalize_host(host);

    if let Ok(ip_address) = normalized_host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip_address, port));
    }

    if let Some(ip_address) = resolve_host_via_doh(&normalized_host, DNS_RECORD_TYPE_A).await? {
        return Ok(SocketAddr::new(ip_address, port));
    }

    if let Some(ip_address) = resolve_host_via_doh(&normalized_host, DNS_RECORD_TYPE_AAAA).await? {
        return Ok(SocketAddr::new(ip_address, port));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no DNS-over-HTTPS results for {}", normalized_host),
    ))
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_owned()
}

async fn resolve_host_via_doh(host: &str, record_type: u16) -> Result<Option<IpAddr>, io::Error> {
    let query = build_dns_query(host, record_type)?;
    let response = doh_client()?
        .post(DOH_ENDPOINT_URL)
        .header(CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
        .header(ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
        .body(query)
        .send()
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("DoH request failed: {}", error),
            )
        })?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("DoH endpoint returned HTTP {}", response.status()),
        ));
    }

    let body = response.bytes().await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to read DoH response: {}", error),
        )
    })?;

    parse_dns_response(&body, record_type)
}

fn doh_client() -> Result<&'static Client, io::Error> {
    let result = DOH_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(DNS_QUERY_TIMEOUT)
            .resolve(DOH_ENDPOINT_HOST, doh_endpoint_addr())
            .build()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to build DoH client: {}", error),
                )
            })
    });

    result
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

fn doh_endpoint_addr() -> SocketAddr {
    SocketAddr::from(([1, 1, 1, 1], 443))
}

fn build_dns_query(host: &str, record_type: u16) -> Result<Vec<u8>, io::Error> {
    let mut query = Vec::with_capacity(DNS_HEADER_LEN + host.len() + 32);

    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    encode_dns_name(host, &mut query)?;
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&DNS_RECORD_CLASS_IN.to_be_bytes());

    Ok(query)
}

fn encode_dns_name(host: &str, output: &mut Vec<u8>) -> Result<(), io::Error> {
    for label in host.split('.') {
        if label.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS host contains an empty label",
            ));
        }

        if label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("DNS label is too long: {}", label),
            ));
        }

        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }

    output.push(0);
    Ok(())
}

fn parse_dns_response(
    message: &[u8],
    expected_record_type: u16,
) -> Result<Option<IpAddr>, io::Error> {
    if message.len() < DNS_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response is too short",
        ));
    }

    let flags = u16::from_be_bytes([message[2], message[3]]);
    let response_code = flags & 0x000f;
    if response_code != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("DNS response returned error code {}", response_code),
        ));
    }

    if flags & 0x0200 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response was truncated",
        ));
    }

    let question_count = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answer_count = u16::from_be_bytes([message[6], message[7]]) as usize;
    let authority_count = u16::from_be_bytes([message[8], message[9]]) as usize;
    let additional_count = u16::from_be_bytes([message[10], message[11]]) as usize;

    let mut cursor = DNS_HEADER_LEN;

    for _ in 0..question_count {
        skip_dns_name(message, &mut cursor)?;
        ensure_bytes(message, cursor, 4)?;
        cursor += 4;
    }

    for _ in 0..answer_count {
        if let Some(ip_address) =
            parse_dns_resource_record(message, &mut cursor, expected_record_type)?
        {
            return Ok(Some(ip_address));
        }
    }

    for _ in 0..authority_count {
        skip_dns_name(message, &mut cursor)?;
        ensure_bytes(message, cursor, 10)?;
        let rdlength = u16::from_be_bytes([message[cursor + 8], message[cursor + 9]]) as usize;
        cursor += 10 + rdlength;
        ensure_bytes(message, cursor, 0)?;
    }

    for _ in 0..additional_count {
        skip_dns_name(message, &mut cursor)?;
        ensure_bytes(message, cursor, 10)?;
        let rdlength = u16::from_be_bytes([message[cursor + 8], message[cursor + 9]]) as usize;
        cursor += 10 + rdlength;
        ensure_bytes(message, cursor, 0)?;
    }

    Ok(None)
}

fn parse_dns_resource_record(
    message: &[u8],
    cursor: &mut usize,
    expected_record_type: u16,
) -> Result<Option<IpAddr>, io::Error> {
    skip_dns_name(message, cursor)?;
    ensure_bytes(message, *cursor, 10)?;

    let record_type = u16::from_be_bytes([message[*cursor], message[*cursor + 1]]);
    let _record_class = u16::from_be_bytes([message[*cursor + 2], message[*cursor + 3]]);
    let _ttl = u32::from_be_bytes([
        message[*cursor + 4],
        message[*cursor + 5],
        message[*cursor + 6],
        message[*cursor + 7],
    ]);
    let rdlength = u16::from_be_bytes([message[*cursor + 8], message[*cursor + 9]]) as usize;
    *cursor += 10;
    ensure_bytes(message, *cursor, rdlength)?;

    let record_data = &message[*cursor..*cursor + rdlength];
    *cursor += rdlength;

    if record_type != expected_record_type {
        return Ok(None);
    }

    match record_type {
        DNS_RECORD_TYPE_A if rdlength == 4 => Ok(Some(IpAddr::V4(Ipv4Addr::new(
            record_data[0],
            record_data[1],
            record_data[2],
            record_data[3],
        )))),
        DNS_RECORD_TYPE_AAAA if rdlength == 16 => Ok(Some(IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([record_data[0], record_data[1]]),
            u16::from_be_bytes([record_data[2], record_data[3]]),
            u16::from_be_bytes([record_data[4], record_data[5]]),
            u16::from_be_bytes([record_data[6], record_data[7]]),
            u16::from_be_bytes([record_data[8], record_data[9]]),
            u16::from_be_bytes([record_data[10], record_data[11]]),
            u16::from_be_bytes([record_data[12], record_data[13]]),
            u16::from_be_bytes([record_data[14], record_data[15]]),
        )))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected DNS record length {} for type {}",
                rdlength, record_type
            ),
        )),
    }
}

fn skip_dns_name(message: &[u8], cursor: &mut usize) -> Result<(), io::Error> {
    let mut position = *cursor;
    let mut jumped = false;
    let mut steps = 0usize;

    loop {
        ensure_bytes(message, position, 1)?;
        let length = message[position];

        if length & 0xc0 == 0xc0 {
            ensure_bytes(message, position, 2)?;
            if !jumped {
                *cursor = position + 2;
                jumped = true;
            }

            let pointer = (((length & 0x3f) as usize) << 8) | usize::from(message[position + 1]);
            if pointer >= message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS compression pointer is out of bounds",
                ));
            }

            position = pointer;
            steps += 2;
            if steps > message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS name compression loop detected",
                ));
            }
            continue;
        }

        position += 1;

        if length == 0 {
            if !jumped {
                *cursor = position;
            }

            return Ok(());
        }

        position += usize::from(length);
        if !jumped {
            *cursor = position;
        }
    }
}

fn ensure_bytes(message: &[u8], cursor: usize, required: usize) -> Result<(), io::Error> {
    if message.len() < cursor + required {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "DNS response ended unexpectedly",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_ip_literal_without_doh() {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { resolve_target("127.0.0.1", 443).await });

        assert_eq!(result.unwrap(), SocketAddr::from(([127, 0, 0, 1], 443)));
    }

    #[test]
    fn builds_dns_query_for_host() {
        let query = build_dns_query("example.com", DNS_RECORD_TYPE_A).unwrap();

        assert_eq!(&query[..2], &[0x00, 0x00]);
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        assert_eq!(&query[4..6], &[0x00, 0x01]);
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn parses_ipv4_answer_from_dns_response() {
        let response = build_dns_response("example.com", DNS_RECORD_TYPE_A, &[192, 0, 2, 42]);

        let resolved = parse_dns_response(&response, DNS_RECORD_TYPE_A).unwrap();

        assert_eq!(resolved, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))));
    }

    #[test]
    fn parses_ipv6_answer_from_dns_response() {
        let response = build_dns_response(
            "example.com",
            DNS_RECORD_TYPE_AAAA,
            &[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
        );

        let resolved = parse_dns_response(&response, DNS_RECORD_TYPE_AAAA).unwrap();

        assert_eq!(
            resolved,
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x0010, 0x0001, 0x0000, 0x0000, 0x0000, 0x0001,
            )))
        );
    }

    fn build_dns_response(host: &str, record_type: u16, record_data: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();

        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0x8180u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());

        encode_dns_name(host, &mut message).unwrap();
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&DNS_RECORD_CLASS_IN.to_be_bytes());

        message.push(0xc0);
        message.push(0x0c);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&DNS_RECORD_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&60u32.to_be_bytes());
        message.extend_from_slice(&(record_data.len() as u16).to_be_bytes());
        message.extend_from_slice(record_data);

        message
    }
}
