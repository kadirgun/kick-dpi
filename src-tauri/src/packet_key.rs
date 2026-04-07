use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub protocol: TransportProtocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

impl ConnectionKey {
    pub fn from_raw(raw: &[u8]) -> Option<Self> {
        let packet = SlicedPacket::from_ip(raw).ok()?;
        let net = packet.net?;
        let transport = packet.transport?;

        let (local_address, remote_address) = match net {
            NetSlice::Ipv4(slice) => (
                IpAddr::V4(slice.header().source_addr()),
                IpAddr::V4(slice.header().destination_addr()),
            ),
            NetSlice::Ipv6(slice) => (
                IpAddr::V6(slice.header().source_addr()),
                IpAddr::V6(slice.header().destination_addr()),
            ),
            _ => return None,
        };

        let (protocol, local_port, remote_port) = match transport {
            TransportSlice::Tcp(slice) => (
                TransportProtocol::Tcp,
                slice.source_port(),
                slice.destination_port(),
            ),
            TransportSlice::Udp(slice) => (
                TransportProtocol::Udp,
                slice.source_port(),
                slice.destination_port(),
            ),
            _ => return None,
        };

        Some(Self {
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
        })
    }
}
