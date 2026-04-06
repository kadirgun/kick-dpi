use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::lookup_host;

use super::socks5::{Socks5Address, Socks5ReplyCode};
use super::ProxyError;

pub(super) async fn resolve_target(address: &Socks5Address) -> Result<SocketAddr, ProxyError> {
    match address {
        Socks5Address::Ip(target) => Ok(*target),
        Socks5Address::Domain(host, port) => {
            let mut resolved = lookup_host((host.as_str(), *port))
                .await
                .map_err(|source| ProxyError::ResolveFailed {
                    host: host.clone(),
                    source,
                })?;

            resolved.next().ok_or_else(|| ProxyError::ResolveFailed {
                host: host.clone(),
                source: io::Error::new(io::ErrorKind::NotFound, "no DNS results"),
            })
        }
    }
}

pub(super) fn fallback_reply_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
}

pub(super) fn map_io_error_to_reply_code(error: &io::Error) -> Socks5ReplyCode {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => Socks5ReplyCode::ConnectionRefused,
        io::ErrorKind::TimedOut => Socks5ReplyCode::TtlExpired,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::AddrInUse => {
            Socks5ReplyCode::NetworkUnreachable
        }
        io::ErrorKind::NotFound => Socks5ReplyCode::HostUnreachable,
        _ => Socks5ReplyCode::GeneralFailure,
    }
}
