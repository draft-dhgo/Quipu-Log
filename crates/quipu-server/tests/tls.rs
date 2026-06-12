use quipu_core::{AuditStore, KeyRing, StoreConfig, SyncPolicy};
use quipu_middleware::{AuditPipeline, PermissionPolicy, PipelineConfig};
use quipu_server::config::TlsSection;
use quipu_server::{bind, router, serve, AppState, AuthState, ServerConfig, TokenMap};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

fn test_state(root: &std::path::Path) -> (AppState, AuditPipeline) {
    let keys = KeyRing::new().with_hmac_key(b"test-hmac-key");
    let store = AuditStore::open(
        StoreConfig::new(root)
            .keys(keys)
            .sync_policy(SyncPolicy::Always),
    )
    .unwrap();
    // pipeline runs allow_all and the AppState policy enforces, mirroring
    // main.rs; healthz is the only route exercised so no grants are needed
    let pipeline = AuditPipeline::start(
        store,
        root.to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let state = AppState::new(
        pipeline.handle(),
        AuthState {
            tokens: TokenMap::default(),
            policy: PermissionPolicy::deny_by_default(),
            max_concurrent_queries: None,
        },
        root.to_path_buf(),
    );
    (state, pipeline)
}

/// End-to-end over a real socket: rustls termination in front of the router,
/// self-signed cert loaded from PEM files exactly as the config would do.
#[tokio::test]
async fn healthz_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let signed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, signed.cert.pem()).unwrap();
    std::fs::write(&key_path, signed.key_pair.serialize_pem()).unwrap();

    let (state, pipeline) = test_state(&dir.path().join("store"));
    let listener = bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let tls = TlsSection {
        cert_pem_file: cert_path,
        key_pem_file: key_path,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        serve(listener, Some(&tls), router(state), async {
            let _ = stop_rx.await;
        })
        .await
    });

    // client trusts exactly the generated cert — no insecure verifier
    let mut roots = rustls::RootCertStore::empty();
    roots.add(signed.cert.der().clone()).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
    let sni = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = connector.connect(sni, tcp).await.unwrap();

    stream
        .write_all(b"GET /v1/healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("\"status\":\"ok\""), "{response}");

    // graceful shutdown must hand control back so main can run
    // pipeline.shutdown() (the final fsync) on the TLS path too
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
    pipeline.shutdown();
}

#[test]
fn config_parses_tls_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "listen": "127.0.0.1:0",
            "store": { "root": "/tmp/q" },
            "auth": { "tokens": {}, "grants": {} },
            "tls": { "cert_pem_file": "/etc/quipu/cert.pem", "key_pem_file": "/etc/quipu/key.pem" }
        }"#,
    )
    .unwrap();
    let cfg = ServerConfig::load(&path).unwrap();
    let tls = cfg.tls.expect("tls section should parse");
    assert_eq!(
        tls.cert_pem_file,
        std::path::Path::new("/etc/quipu/cert.pem")
    );
    assert_eq!(tls.key_pem_file, std::path::Path::new("/etc/quipu/key.pem"));
}
