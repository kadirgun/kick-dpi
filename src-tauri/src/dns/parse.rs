/// Minimal DNS wire-format parser.
/// We only need enough to extract the transaction ID, question name and type
/// so we can forward the query to a DoH server. The raw query bytes are also
/// forwarded as-is (application/dns-message), so we don't need a full impl.

/// A parsed DNS question extracted from an outgoing UDP/53 packet.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    /// Raw DNS wire-format message (everything after IP+UDP headers).
    pub wire: Vec<u8>,
    /// 16-bit transaction ID from the DNS header.
    #[allow(dead_code)]
    pub txid: u16,
    /// FQDN from the first question section entry (without trailing dot).
    pub name: String,
    /// QTYPE (e.g. 1 = A, 28 = AAAA, 5 = CNAME, 255 = ANY).
    pub qtype: u16,
}

/// Offsets inside a UDP payload (= raw DNS message).
/// DNS header is 12 bytes. Questions start at byte 12.
pub fn parse_query(dns: &[u8]) -> Option<DnsQuery> {
    if dns.len() < 12 {
        return None;
    }

    let txid = u16::from_be_bytes([dns[0], dns[1]]);

    // Flags: QR bit (bit 15) must be 0 (query)
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    if flags & 0x8000 != 0 {
        return None; // it's a response, not a query
    }

    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse first QNAME
    let mut pos = 12usize;
    let mut labels: Vec<String> = Vec::new();

    loop {
        if pos >= dns.len() {
            return None;
        }
        let len = dns[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointer — unusual in a fresh outgoing query but guard anyway
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len > dns.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&dns[pos..pos + len]).into_owned());
        pos += len;
    }

    if pos + 4 > dns.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([dns[pos], dns[pos + 1]]);

    Some(DnsQuery {
        wire: dns.to_vec(),
        txid,
        name: labels.join("."),
        qtype,
    })
}
