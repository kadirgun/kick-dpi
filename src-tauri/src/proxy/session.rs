use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::bypass::{self, BypassContext};

use super::socks5::{self, Socks5Command, Socks5ParseError, Socks5ReplyCode};
use super::tls;
use super::transport;
use super::ProxyError;

pub(super) async fn handle_client(
    mut client: TcpStream,
    peer_addr: SocketAddr,
) -> Result<(), ProxyError> {
    let methods = socks5::read_auth_methods(&mut client).await?;
    let selected_method = match socks5::select_auth_method(&methods) {
        Ok(method) => method,
        Err(error) => {
            socks5::write_method_selection(&mut client, socks5::METHOD_NO_ACCEPTABLE).await?;
            return Err(error.into());
        }
    };
    socks5::write_method_selection(&mut client, selected_method).await?;

    let request_frame = match socks5::read_request_frame(&mut client).await {
        Ok(frame) => frame,
        Err(error @ ProxyError::Parse(Socks5ParseError::UnsupportedAddressType(_))) => {
            socks5::write_reply(
                &mut client,
                Socks5ReplyCode::AddressTypeNotSupported,
                transport::fallback_reply_addr(),
            )
            .await?;
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    let request = socks5::decode_request_frame(&request_frame)?;

    if request.command != Socks5Command::Connect {
        socks5::write_reply(
            &mut client,
            Socks5ReplyCode::CommandNotSupported,
            transport::fallback_reply_addr(),
        )
        .await?;
        return Err(ProxyError::UnsupportedCommand(request.command));
    }

    log::info!(
        "SOCKS5 CONNECT request from {} to {}",
        peer_addr,
        socks5::describe_socks5_address(&request.address)
    );

    let target_addr = transport::resolve_target(&request.address).await?;

    log::info!("SOCKS5 CONNECT resolved for {}: {}", peer_addr, target_addr);

    let mut bypass_context = BypassContext::new(peer_addr, target_addr);
    let mut bypass_pipeline = bypass::default_pipeline();

    let mut upstream = match TcpStream::connect(target_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            socks5::write_reply(
                &mut client,
                transport::map_io_error_to_reply_code(&error),
                transport::fallback_reply_addr(),
            )
            .await?;
            return Err(ProxyError::ConnectFailed {
                target_addr,
                source: error,
            });
        }
    };

    bypass_pipeline.on_connect(&mut bypass_context, &client, &upstream);

    let bind_addr = upstream
        .local_addr()
        .unwrap_or_else(|_| transport::fallback_reply_addr());
    socks5::write_reply(&mut client, Socks5ReplyCode::Succeeded, bind_addr).await?;

    log::info!(
        "SOCKS5 CONNECT established for {} to {}",
        peer_addr,
        target_addr
    );

    let (client_prefix, tls_hostname) = tls::capture_tls_client_hello(&mut client).await?;
    bypass_context.mark_client_hello_seen();
    bypass_pipeline.on_tls_start(&mut bypass_context, &client, &upstream);
    if let Some(hostname) = tls_hostname {
        bypass_context.set_server_name(hostname.clone());
        log::info!(
            "TLS ClientHello SNI from {} to {}: {}",
            peer_addr,
            target_addr,
            hostname
        );
    }

    let relay_state = Arc::new(Mutex::new(RelayState {
        context: bypass_context,
        pipeline: bypass_pipeline,
    }));

    if !client_prefix.is_empty() {
        let sni_processed = {
            let mut state = relay_state.lock().await;
            let RelayState { context, pipeline } = &mut *state;
            pipeline.process_sni(context, &client_prefix)
        };

        for processed_chunk in sni_processed {
            let chunks = {
                let mut state = relay_state.lock().await;
                let RelayState { context, pipeline } = &mut *state;
                pipeline.on_client_data(context, &processed_chunk)
            };

            for chunk in chunks {
                if !chunk.is_empty() {
                    send_chunk(&relay_state, &mut upstream, &chunk).await?;
                }
            }
        }

        let mut state = relay_state.lock().await;
        state.context.record_client_bytes(client_prefix.len());
    }

    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);

    let mut relay_tasks = JoinSet::new();
    relay_tasks.spawn(relay_client_to_upstream(
        client_read,
        upstream_write,
        Arc::clone(&relay_state),
    ));
    relay_tasks.spawn(relay_upstream_to_client(
        upstream_read,
        client_write,
        Arc::clone(&relay_state),
    ));

    let mut relay_error: Option<ProxyError> = None;

    if let Some(result) = relay_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {
                relay_tasks.abort_all();
            }
            Ok(Err(error)) => {
                relay_error = Some(error);
                relay_tasks.abort_all();
            }
            Err(error) => {
                relay_error = Some(join_error_to_proxy_error(error));
                relay_tasks.abort_all();
            }
        }
    }

    while relay_tasks.join_next().await.is_some() {}

    if let Some(error) = relay_error {
        return Err(error);
    }

    let relay_state = relay_state.lock().await;
    log::debug!(
        "SOCKS5 tunnel {} -> {} finished after forwarding {} bytes client->upstream and {} bytes upstream->client",
        peer_addr,
        target_addr,
        relay_state.context.client_bytes(),
        relay_state.context.server_bytes()
    );

    Ok(())
}

struct RelayState {
    context: BypassContext,
    pipeline: bypass::BypassPipeline,
}

async fn relay_client_to_upstream(
    mut client_read: tokio::io::ReadHalf<TcpStream>,
    mut upstream_write: tokio::io::WriteHalf<TcpStream>,
    state: Arc<Mutex<RelayState>>,
) -> Result<(), ProxyError> {
    let mut buffer = [0u8; 2048];

    loop {
        let bytes_read = client_read.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        let chunks = {
            let mut state = state.lock().await;
            let RelayState { context, pipeline } = &mut *state;
            pipeline.on_client_data(context, &buffer[..bytes_read])
        };

        for chunk in chunks {
            if !chunk.is_empty() {
                send_chunk(&state, &mut upstream_write, &chunk).await?;
            }
        }

        let mut state = state.lock().await;
        state.context.record_client_bytes(bytes_read);
    }
}

async fn relay_upstream_to_client(
    mut upstream_read: tokio::io::ReadHalf<TcpStream>,
    mut client_write: tokio::io::WriteHalf<TcpStream>,
    state: Arc<Mutex<RelayState>>,
) -> Result<(), ProxyError> {
    let mut buffer = [0u8; 2048];

    loop {
        let bytes_read = upstream_read.read(&mut buffer).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        {
            let mut state = state.lock().await;
            let RelayState { context, pipeline } = &mut *state;
            context.record_server_bytes(bytes_read);
            pipeline.on_server_data(context, &buffer[..bytes_read]);
        }

        client_write.write_all(&buffer[..bytes_read]).await?;
    }
}

async fn send_chunk<W>(
    state: &Arc<Mutex<RelayState>>,
    writer: &mut W,
    chunk: &[u8],
) -> Result<(), ProxyError>
where
    W: AsyncWrite + Unpin,
{
    let before_send_futures = {
        let mut state = state.lock().await;
        let RelayState { context, pipeline } = &mut *state;
        pipeline.before_send(context, chunk)
    };

    log::info!(
        "send_chunk: upstream write queued for {} bytes after {} before_send hooks",
        chunk.len(),
        before_send_futures.len()
    );

    for future in before_send_futures {
        future.await;
    }

    writer.write_all(chunk).await?;
    Ok(())
}

fn join_error_to_proxy_error(error: tokio::task::JoinError) -> ProxyError {
    ProxyError::from(io::Error::new(
        io::ErrorKind::Other,
        format!("relay task failed: {}", error),
    ))
}
