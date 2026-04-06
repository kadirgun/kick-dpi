use log::{error, info};
use windivert::{prelude::WinDivertFlags, WinDivert};

use super::strategy::StrategyPipeline;

/// Blocking recv/reinject loop.
pub(super) fn run_listener(pipeline: StrategyPipeline, filter: &str) {
    let handle = match WinDivert::network(filter, 0, WinDivertFlags::default()) {
        Ok(h) => {
            info!("[bypass] WinDivert handle opened (filter: {filter})");
            h
        }
        Err(e) => {
            error!("[bypass] Failed to open WinDivert handle: {e}");
            return;
        }
    };

    let mut buf = vec![0u8; 65_535];

    info!("[bypass] listener loop started");

    loop {
        match handle.recv(&mut buf) {
            Ok(packet) => {
                let mutated_packets = pipeline.run(packet.into_owned());
                for mut mp in mutated_packets {
                    // Reinject the packet into the network stack
                    if let Err(e) = handle.send(&mut mp) {
                        error!("[bypass] failed to send packet: {e}");
                    }
                }
            }
            Err(e) => {
                error!("[bypass] recv error: {e}");
            }
        }
    }
}
