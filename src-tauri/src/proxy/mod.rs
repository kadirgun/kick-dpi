mod session;
mod socks5;
mod tls;
mod transport;

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;

pub fn default_bind_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(127, 22, 22, 22), 8080))
}

pub struct ProxyController {
    bind_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
}

impl ProxyController {
    pub fn start(bind_addr: SocketAddr) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tauri::async_runtime::spawn(async move {
            if let Err(error) = run_proxy(bind_addr, shutdown_rx).await {
                log::error!("SOCKS5 proxy failed on {}: {}", bind_addr, error);
            }
        });

        Self {
            bind_addr,
            shutdown_tx,
        }
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

impl Drop for ProxyController {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn run_proxy(bind_addr: SocketAddr, shutdown_rx: watch::Receiver<bool>) -> io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let actual_bind_addr = listener.local_addr()?;
    let poll_interval = Duration::from_millis(250);

    log::info!("SOCKS5 proxy listening on {}", actual_bind_addr);

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        match tokio::time::timeout(poll_interval, listener.accept()).await {
            Ok(Ok((stream, peer_addr))) => {
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = session::handle_client(stream, peer_addr).await {
                        log::warn!("SOCKS5 client {} closed with error: {}", peer_addr, error);
                    }
                });
            }
            Ok(Err(error)) => {
                log::warn!("SOCKS5 accept error on {}: {}", actual_bind_addr, error);
            }
            Err(_) => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    log::info!("SOCKS5 proxy stopped on {}", actual_bind_addr);
    Ok(())
}

#[derive(Debug)]
enum ProxyError {
    Io(io::Error),
    Parse(socks5::Socks5ParseError),
    ResolveFailed {
        host: String,
        source: io::Error,
    },
    ConnectFailed {
        target_addr: SocketAddr,
        source: io::Error,
    },
    UnsupportedCommand(socks5::Socks5Command),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {}", error),
            Self::Parse(error) => write!(f, "parse error: {}", error),
            Self::ResolveFailed { host, source } => {
                write!(f, "failed to resolve target host {}: {}", host, source)
            }
            Self::ConnectFailed {
                target_addr,
                source,
            } => {
                write!(f, "failed to connect to {}: {}", target_addr, source)
            }
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported SOCKS command: {:?}", command)
            }
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::ResolveFailed { source, .. } => Some(source),
            Self::ConnectFailed { source, .. } => Some(source),
            Self::UnsupportedCommand(_) => None,
        }
    }
}

impl From<io::Error> for ProxyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<socks5::Socks5ParseError> for ProxyError {
    fn from(error: socks5::Socks5ParseError) -> Self {
        Self::Parse(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_proxy_connection() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // Find a random available port
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                drop(listener);

                let bind_addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), port));

                let (shutdown_tx, shutdown_rx) = watch::channel(false);

                // We run proxy using tokio::spawn directly
                let _proxy_task = tokio::spawn(async move {
                    if let Err(error) = run_proxy(bind_addr, shutdown_rx).await {
                        log::error!("SOCKS5 proxy failed on {}: {}", bind_addr, error);
                    }
                });

                // Give proxy time to start
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

                let proxy_url = format!("socks5h://127.0.0.1:{}", port);
                let reqwest_proxy =
                    reqwest::Proxy::all(&proxy_url).expect("Failed to create proxy");

                let client = reqwest::Client::builder()
                    .proxy(reqwest_proxy)
                    .build()
                    .expect("Failed to build reqwest client");

                match client.get("https://example.com").send().await {
                    Ok(response) => {
                        assert!(response.status().is_success());
                        let text = response.text().await.unwrap();
                        println!("Got response: {} bytes", text.len());
                    }
                    Err(e) => {
                        panic!("Failed to connect to example.com via proxy: {}", e);
                    }
                }

                let _ = shutdown_tx.send(true);
            });
    }
}
