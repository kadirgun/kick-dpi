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

/// Strips record types (AAAA = 28, SVCB = 64, HTTPS = 65) from the ANSWER
/// section of a DNS wire-format response and fixes ANCOUNT.
///
/// Returns `Some(filtered)` when records were removed, `None` when the message
/// is unchanged (nothing to strip or unparseable — caller should pass it
/// through unchanged).
pub fn strip_answer_records(
    dns: &[u8],
    strip_aaaa: bool,
    strip_https: bool,
) -> Option<Vec<u8>> {
    if !strip_aaaa && !strip_https {
        return None;
    }
    if dns.len() < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);

    // Walk past the question section
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(dns, pos)?;
        if pos + 4 > dns.len() {
            return None;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // Collect ranges of kept answers
    let mut kept_ranges: Vec<(usize, usize)> = Vec::with_capacity(ancount);
    let mut kept = 0usize;
    let mut answers_pos = pos;

    for _ in 0..ancount {
        let start = answers_pos;
        answers_pos = skip_name(dns, answers_pos)?;
        if answers_pos + 10 > dns.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([dns[answers_pos], dns[answers_pos + 1]]);
        let rdlength = u16::from_be_bytes([dns[answers_pos + 8], dns[answers_pos + 9]]) as usize;
        let end = answers_pos + 10 + rdlength;
        if end > dns.len() {
            return None;
        }

        let strip = match rtype {
            28 => strip_aaaa,
            64 | 65 => strip_https,
            _ => false,
        };

        if !strip {
            kept += 1;
            kept_ranges.push((start, end));
        }

        answers_pos = end;
    }

    if kept == ancount {
        return None; // nothing stripped
    }

    // Rebuild: header (with fixed ANCOUNT) + everything up to answers + kept answers
    let mut out = Vec::with_capacity(answers_pos);
    out.extend_from_slice(&dns[..pos]);
    out[6..8].copy_from_slice(&(kept as u16).to_be_bytes());
    for (start, end) in kept_ranges {
        out.extend_from_slice(&dns[start..end]);
    }

    Some(out)
}

/// Skips a (possibly compression-pointer) NAME field, returning the offset
/// after it. Pointers are consumed as 2 bytes without chasing (only used for
/// re-serializing unchanged records, so the target stays intact).
fn skip_name(dns: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *dns.get(pos)?;
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire bytes of `label` as a NAME (length-prefixed, zero-terminated).
    fn encode_name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    struct AnswerSpec {
        name: Vec<u8>,
        rtype: u16,
        rdata: Vec<u8>,
    }

    fn build_response(answers: &[AnswerSpec]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAB, 0xCD]); // txid
        out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount

        // Question: example.com A IN
        out.extend_from_slice(&encode_name(&["example", "com"]));
        out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

        for a in answers {
            out.extend_from_slice(&a.name);
            out.extend_from_slice(&a.rtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            out.extend_from_slice(&300u32.to_be_bytes()); // TTL
            out.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&a.rdata);
        }
        out
    }

    fn a_answer() -> AnswerSpec {
        // 0xC0 0x0C = compression pointer at the question's QNAME (offset 12)
        AnswerSpec {
            name: vec![0xC0, 0x0C],
            rtype: 1, // A
            rdata: vec![93, 184, 216, 34],
        }
    }

    fn aaaa_answer() -> AnswerSpec {
        AnswerSpec {
            name: vec![0xC0, 0x0C],
            rtype: 28, // AAAA
            rdata: vec![2u8; 16],
        }
    }

    fn https_answer() -> AnswerSpec {
        AnswerSpec {
            name: vec![0xC0, 0x0C],
            rtype: 65, // HTTPS/SVCB (echconfig bytes)
            rdata: vec![0, 1, 0, 0, 0x92, 0, 2, 1, 0x42],
        }
    }

    #[test]
    fn strips_aaaa_answers() {
        let resp = build_response(&[a_answer(), aaaa_answer()]);
        let filtered = strip_answer_records(&resp, true, false).unwrap();
        assert_eq!(u16::from_be_bytes([filtered[6], filtered[7]]), 1);
        // AAAA wire size: name(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(16) = 28
        assert_eq!(filtered.len(), resp.len() - 28);
        // The kept A record still comes after the question section unchanged
        assert!(filtered.ends_with(&a_answer().rdata));
    }

    #[test]
    fn strips_https_rr() {
        let resp = build_response(&[a_answer(), https_answer()]);
        let filtered = strip_answer_records(&resp, false, true).unwrap();
        assert_eq!(u16::from_be_bytes([filtered[6], filtered[7]]), 1);
        // HTTPS wire size: name(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(9) = 21
        assert_eq!(filtered.len(), resp.len() - 21);
    }

    #[test]
    fn nothing_to_strip_returns_none() {
        let resp = build_response(&[a_answer()]);
        assert!(strip_answer_records(&resp, true, true).is_none());
        assert!(strip_answer_records(&build_response(&[]), true, true).is_none());
    }
}
