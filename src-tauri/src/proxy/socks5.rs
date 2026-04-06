use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VERSION: u8 = 0x05;
pub(super) const METHOD_NO_AUTH: u8 = 0x00;
pub(super) const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub(super) async fn read_auth_methods(
    stream: &mut TcpStream,
) -> Result<Vec<u8>, super::ProxyError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(Socks5ParseError::InvalidVersion(header[0]).into());
    }

    let method_count = usize::from(header[1]);
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;

    Ok(methods)
}

pub(super) async fn read_request_frame(
    stream: &mut TcpStream,
) -> Result<Vec<u8>, super::ProxyError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != SOCKS5_VERSION {
        return Err(Socks5ParseError::InvalidVersion(header[0]).into());
    }

    let mut frame = header.to_vec();

    match header[3] {
        ATYP_IPV4 => {
            let mut body = [0u8; 6];
            stream.read_exact(&mut body).await?;
            frame.extend_from_slice(&body);
        }
        ATYP_IPV6 => {
            let mut body = [0u8; 18];
            stream.read_exact(&mut body).await?;
            frame.extend_from_slice(&body);
        }
        ATYP_DOMAIN => {
            let mut domain_length = [0u8; 1];
            stream.read_exact(&mut domain_length).await?;
            frame.extend_from_slice(&domain_length);

            let domain_length = usize::from(domain_length[0]);
            let mut body = vec![0u8; domain_length + 2];
            stream.read_exact(&mut body).await?;
            frame.extend_from_slice(&body);
        }
        atyp => {
            return Err(Socks5ParseError::UnsupportedAddressType(atyp).into());
        }
    }

    Ok(frame)
}

pub(super) async fn write_method_selection(
    stream: &mut TcpStream,
    method: u8,
) -> Result<(), io::Error> {
    stream.write_all(&[SOCKS5_VERSION, method]).await
}

pub(super) async fn write_reply(
    stream: &mut TcpStream,
    code: Socks5ReplyCode,
    bind_addr: SocketAddr,
) -> Result<(), io::Error> {
    let mut reply = vec![SOCKS5_VERSION, code.as_byte(), 0x00];
    reply.extend_from_slice(&encode_socket_addr(bind_addr));
    stream.write_all(&reply).await
}

pub(super) fn select_auth_method(methods: &[u8]) -> Result<u8, Socks5ParseError> {
    if methods.contains(&METHOD_NO_AUTH) {
        Ok(METHOD_NO_AUTH)
    } else {
        Err(Socks5ParseError::NoSupportedAuthMethod)
    }
}

pub(super) fn decode_request_frame(frame: &[u8]) -> Result<Socks5Request, Socks5ParseError> {
    if frame.len() < 7 {
        return Err(Socks5ParseError::FrameTooShort {
            expected_at_least: 7,
            actual: frame.len(),
        });
    }

    if frame[0] != SOCKS5_VERSION {
        return Err(Socks5ParseError::InvalidVersion(frame[0]));
    }

    if frame[2] != 0x00 {
        return Err(Socks5ParseError::InvalidReserved(frame[2]));
    }

    let command = Socks5Command::from_byte(frame[1]);

    match frame[3] {
        ATYP_IPV4 => {
            let expected_len = 10;
            if frame.len() != expected_len {
                return Err(Socks5ParseError::UnexpectedFrameLength {
                    expected: expected_len,
                    actual: frame.len(),
                });
            }

            let address = Ipv4Addr::new(frame[4], frame[5], frame[6], frame[7]);
            let port = u16::from_be_bytes([frame[8], frame[9]]);

            Ok(Socks5Request {
                command,
                address: Socks5Address::Ip(SocketAddr::new(IpAddr::V4(address), port)),
            })
        }
        ATYP_IPV6 => {
            let expected_len = 22;
            if frame.len() != expected_len {
                return Err(Socks5ParseError::UnexpectedFrameLength {
                    expected: expected_len,
                    actual: frame.len(),
                });
            }

            let mut octets = [0u8; 16];
            octets.copy_from_slice(&frame[4..20]);
            let address = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([frame[20], frame[21]]);

            Ok(Socks5Request {
                command,
                address: Socks5Address::Ip(SocketAddr::new(IpAddr::V6(address), port)),
            })
        }
        ATYP_DOMAIN => {
            let domain_length = usize::from(frame[4]);
            let expected_len = 7 + domain_length;
            if frame.len() != expected_len {
                return Err(Socks5ParseError::UnexpectedFrameLength {
                    expected: expected_len,
                    actual: frame.len(),
                });
            }

            let domain_bytes = &frame[5..5 + domain_length];
            let domain = std::str::from_utf8(domain_bytes)
                .map_err(|_| Socks5ParseError::InvalidDomainEncoding)?
                .to_owned();

            if domain.is_empty() {
                return Err(Socks5ParseError::EmptyDomain);
            }

            let port_index = 5 + domain_length;
            let port = u16::from_be_bytes([frame[port_index], frame[port_index + 1]]);

            Ok(Socks5Request {
                command,
                address: Socks5Address::Domain(domain, port),
            })
        }
        atyp => Err(Socks5ParseError::UnsupportedAddressType(atyp)),
    }
}

pub(super) fn encode_socket_addr(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(address_v4) => {
            let mut bytes = Vec::with_capacity(7);
            bytes.push(ATYP_IPV4);
            bytes.extend_from_slice(&address_v4.ip().octets());
            bytes.extend_from_slice(&address_v4.port().to_be_bytes());
            bytes
        }
        SocketAddr::V6(address_v6) => {
            let mut bytes = Vec::with_capacity(19);
            bytes.push(ATYP_IPV6);
            bytes.extend_from_slice(&address_v6.ip().octets());
            bytes.extend_from_slice(&address_v6.port().to_be_bytes());
            bytes
        }
    }
}

pub(super) fn describe_socks5_address(address: &Socks5Address) -> String {
    match address {
        Socks5Address::Ip(target) => target.to_string(),
        Socks5Address::Domain(host, port) => format!("{}:{}", host, port),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Socks5Command {
    Connect,
    Bind,
    UdpAssociate,
    Unknown(u8),
}

impl Socks5Command {
    fn from_byte(byte: u8) -> Self {
        match byte {
            CMD_CONNECT => Self::Connect,
            0x02 => Self::Bind,
            0x03 => Self::UdpAssociate,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Socks5ReplyCode {
    Succeeded,
    GeneralFailure,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Socks5ReplyCode {
    fn as_byte(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Socks5Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Socks5Request {
    pub(super) command: Socks5Command,
    pub(super) address: Socks5Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Socks5ParseError {
    FrameTooShort {
        expected_at_least: usize,
        actual: usize,
    },
    UnexpectedFrameLength {
        expected: usize,
        actual: usize,
    },
    InvalidVersion(u8),
    InvalidReserved(u8),
    NoSupportedAuthMethod,
    UnsupportedAddressType(u8),
    InvalidDomainEncoding,
    EmptyDomain,
}

impl fmt::Display for Socks5ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort {
                expected_at_least,
                actual,
            } => {
                write!(
                    f,
                    "frame too short: expected at least {}, got {}",
                    expected_at_least, actual
                )
            }
            Self::UnexpectedFrameLength { expected, actual } => {
                write!(
                    f,
                    "unexpected frame length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidVersion(version) => write!(f, "unsupported SOCKS version: {}", version),
            Self::InvalidReserved(value) => write!(f, "invalid reserved byte: {}", value),
            Self::NoSupportedAuthMethod => {
                write!(f, "client did not offer the no-authentication method")
            }
            Self::UnsupportedAddressType(atyp) => write!(f, "unsupported address type: {}", atyp),
            Self::InvalidDomainEncoding => write!(f, "domain name is not valid UTF-8"),
            Self::EmptyDomain => write!(f, "domain name is empty"),
        }
    }
}

impl std::error::Error for Socks5ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_no_auth_method_when_available() {
        let method = select_auth_method(&[0x02, 0x00, 0x80]).unwrap();
        assert_eq!(method, METHOD_NO_AUTH);
    }

    #[test]
    fn rejects_clients_without_no_auth_method() {
        let error = select_auth_method(&[0x02, 0x80]).unwrap_err();
        assert_eq!(error, Socks5ParseError::NoSupportedAuthMethod);
    }

    #[test]
    fn decodes_ipv4_connect_request() {
        let frame = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];

        let request = decode_request_frame(&frame).unwrap();

        assert_eq!(request.command, Socks5Command::Connect);
        assert_eq!(
            request.address,
            Socks5Address::Ip(SocketAddr::from(([127, 0, 0, 1], 8080)))
        );
    }

    #[test]
    fn decodes_domain_connect_request() {
        let domain = b"example.com";
        let mut frame = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        frame.extend_from_slice(domain);
        frame.extend_from_slice(&443u16.to_be_bytes());

        let request = decode_request_frame(&frame).unwrap();

        assert_eq!(request.command, Socks5Command::Connect);
        assert_eq!(
            request.address,
            Socks5Address::Domain("example.com".to_owned(), 443)
        );
    }

    #[test]
    fn rejects_unknown_address_types() {
        let frame = [0x05, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00];

        let error = decode_request_frame(&frame).unwrap_err();

        assert_eq!(error, Socks5ParseError::UnsupportedAddressType(0x09));
    }

    #[test]
    fn rejects_invalid_version() {
        let frame = [0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];

        let error = decode_request_frame(&frame).unwrap_err();

        assert_eq!(error, Socks5ParseError::InvalidVersion(0x04));
    }
}
