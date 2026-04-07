use std::net::Ipv4Addr;

use log::{info, warn};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;

use crate::{settings::Rule, state::AppState};

struct TcpEntry {
    local_addr_raw: u32,
    local_port_raw: u32,
    remote_addr_raw: u32,
    remote_port_raw: u32,
    pid: u32,
    /// Human-readable for logging only
    remote_addr: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
}

fn get_all_tcp_connections() -> Vec<TcpEntry> {
    let mut buf: Vec<u8> = vec![0u8; 4096];
    let mut size = buf.len() as u32;

    loop {
        let ret = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        match ret {
            0 => break,
            122 /* ERROR_INSUFFICIENT_BUFFER */ => {
                buf.resize(size as usize, 0);
            }
            e => {
                warn!("[reset] GetExtendedTcpTable failed: {e}");
                return vec![];
            }
        }
    }

    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let count = table.dwNumEntries as usize;
    let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };

    rows.iter()
        .filter(|row| {
            // Skip LISTEN and non-established sockets (remote port == 0)
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            remote_port != 0
        })
        .map(|row| {
            // Ports in the table are stored as big-endian u32 (only lower 16 bits used)
            let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
            // Addresses are in network byte order; to_ne_bytes() gives correct octets
            let remote_addr = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            TcpEntry {
                local_addr_raw: row.dwLocalAddr,
                local_port_raw: row.dwLocalPort,
                remote_addr_raw: row.dwRemoteAddr,
                remote_port_raw: row.dwRemotePort,
                pid: row.dwOwningPid,
                remote_addr,
                local_port,
                remote_port,
            }
        })
        .collect()
}

pub fn reset_connections_for_rules(rules: &[&Rule], state: &AppState) {
    if rules.is_empty() {
        return;
    }

    let connections = get_all_tcp_connections();
    let mut reset_count = 0;

    for entry in connections {
        let path = state.path_for_pid(entry.pid);
        let path_str = match path.as_deref() {
            Some(p) => p,
            None => continue,
        };

        if !rules.iter().any(|rule| rule.path_matches(path_str)) {
            continue;
        }

        info!(
            "[reset] closing pid={} local_port={} -> {}:{} path={}",
            entry.pid, entry.local_port, entry.remote_addr, entry.remote_port, path_str
        );

        // Must pass the exact values read from the table; only dwState changes to 12 (DELETE_TCB)
        let mut row = MIB_TCPROW_LH {
            Anonymous: windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_LH_0 { dwState: 12 },
            dwLocalAddr: entry.local_addr_raw,
            dwLocalPort: entry.local_port_raw,
            dwRemoteAddr: entry.remote_addr_raw,
            dwRemotePort: entry.remote_port_raw,
        };

        let err = unsafe { SetTcpEntry(&mut row) };
        if err == 0 {
            reset_count += 1;
        } else {
            warn!(
                "[reset] SetTcpEntry failed ({err}) for local_port={}",
                entry.local_port
            );
        }
    }

    info!("[reset] closed {reset_count} connection(s) for matched rules");
}
