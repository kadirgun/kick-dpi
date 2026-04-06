use windivert::{layer::NetworkLayer, packet::WinDivertPacket};

/// Owned network packet that moves freely through the strategy pipeline.
/// Using `'static` lifetime means the data is fully owned (Cow::Owned internally).
pub type RawPacket = WinDivertPacket<'static, NetworkLayer>;
