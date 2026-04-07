pub mod packet;
pub mod strategies;

mod listener;

const FILTER: &str = "tcp.DstPort == 443 and tcp.PayloadLength > 0";

/// Open the WinDivert handle and spawn the blocking listener thread.
///
/// # Stack size
/// WinDivert's initialisation (which triggers SCM / kernel driver calls) and
/// its internal `recv`/helper subroutines heavily utilize the stack. The Windows
/// default 1 MB stack size leads to `STATUS_STACK_OVERFLOW` (0xc00000fd). We
/// must spawn a distinct thread configured with a much larger stack (32MB).
pub fn start_listener() {
    std::thread::Builder::new()
        .name("windivert-listener".into())
        .spawn(move || listener::run_listener(FILTER))
        .expect("failed to spawn WinDivert listener thread");
}

pub fn stop_listener() {
    listener::stop_listener();
}
