//! Listener setup: plain HTTP, or direct TLS termination when the config has
//! a `tls` section.
//!
//! TLS is terminated in-process (rustls via `axum-server`) rather than
//! delegated to an assumed reverse proxy: the transport leg carries bearer
//! tokens and audit payloads, so it sits inside this server's threat model,
//! and a standalone deployment must not depend on infrastructure outside the
//! project to keep its security promise. Running behind a proxy stays
//! possible — just omit the `tls` section.

use crate::config::TlsSection;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::future::Future;
use std::net::TcpListener;
use std::time::Duration;

/// Bind separately from serving so bind errors surface before the daemon is
/// considered up (and tests can read the ephemeral port via `local_addr`).
pub fn bind(listen: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(listen)?;
    // axum/tokio require a non-blocking socket when adopting a std listener
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Serve `app` until `shutdown` resolves, then drain in-flight requests.
/// The caller still owns post-serve cleanup (e.g. `pipeline.shutdown()`).
pub async fn serve(
    listener: TcpListener,
    tls: Option<&TlsSection>,
    app: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    match tls {
        None => {
            axum::serve(tokio::net::TcpListener::from_std(listener)?, app)
                .with_graceful_shutdown(shutdown)
                .await
        }
        Some(tls) => {
            let config = RustlsConfig::from_pem_file(&tls.cert_pem_file, &tls.key_pem_file)
                .await
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid TLS cert/key: {e}"),
                    )
                })?;
            let handle = axum_server::Handle::new();
            let drain = handle.clone();
            tokio::spawn(async move {
                shutdown.await;
                // bounded drain: an audit daemon must reach the caller's
                // pipeline.shutdown() (final fsync) even if a client stalls
                drain.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            axum_server::from_tcp_rustls(listener, config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    }
}
