use quipu_core::AuditStore;
use quipu_middleware::{AuditPipeline, PermissionPolicy, PipelineConfig};
use quipu_server::{router, AppState, ServerConfig};

fn usage() -> ! {
    eprintln!("usage: quipu-server <config.json>          serve");
    eprintln!("       quipu-server rekey <config.json>    offline re-key (see README)");
    std::process::exit(2);
}

fn load_config(config_path: &str) -> ServerConfig {
    match ServerConfig::load(std::path::Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config '{config_path}': {e}");
            std::process::exit(1);
        }
    }
}

/// Offline re-key: re-wrap RSA-protected registry values (and re-digest
/// their index tokens) under the active key versions, recording a signed
/// re-key event. The server must not be running — the store lock enforces it.
fn run_rekey(config_path: &str) -> ! {
    let cfg = load_config(config_path);
    let store_cfg = match cfg.store_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid store/keys config: {e}");
            std::process::exit(1);
        }
    };
    let root = store_cfg.root.clone();
    let mut store = match AuditStore::open(store_cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "failed to open store at '{}': {e} (is the server still running?)",
                root.display()
            );
            std::process::exit(1);
        }
    };
    let event = match store.rekey() {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("re-key failed: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = store.verify_integrity() {
        eprintln!("re-key wrote an event but post-verification failed: {e}");
        std::process::exit(1);
    }
    println!(
        "re-key complete: RSA values now under key version {}, index tokens under HMAC \
         version {} ({})",
        event.rsa_version,
        event.hmac_version,
        if event.hmac_version == 0 { "none configured" } else { "active" },
    );
    for t in &event.tables {
        println!(
            "  registry '{}': {} records, chain {}.. -> {}..",
            t.type_name,
            t.records,
            &t.old_chain_head[..12.min(t.old_chain_head.len())],
            &t.new_chain_head[..12.min(t.new_chain_head.len())],
        );
    }
    println!("signed re-key event recorded (signing key version {}); integrity verified", event.signing_key_version);
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = match args.as_slice() {
        [cmd, config] if cmd == "rekey" => run_rekey(config),
        [config] => config.clone(),
        _ => usage(),
    };
    let cfg = load_config(&config_path);

    let store_cfg = match cfg.store_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("invalid store/keys config: {e}");
            std::process::exit(1);
        }
    };
    let store_root = store_cfg.root.clone();
    let store = match AuditStore::open(store_cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to open store at '{}': {e}", store_root.display());
            std::process::exit(1);
        }
    };

    // the pipeline is only reachable through the HTTP handlers here, and
    // those gate every call against the hot-reloadable AppState policy — so
    // the pipeline's own (start-time-frozen) policy must not also enforce,
    // or a SIGHUP grant change could never take effect
    let pipeline = match AuditPipeline::start(
        store,
        store_root,
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to start audit pipeline: {e}");
            std::process::exit(1);
        }
    };

    let auth_state = match cfg.auth_state() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid auth config: {e}");
            std::process::exit(1);
        }
    };
    let state = AppState::new(pipeline.handle(), auth_state);

    // SIGHUP = re-read the config file and swap the auth section (token
    // issue/revoke without dropping connections); reload failures keep the
    // previous auth state
    #[cfg(unix)]
    {
        let state = state.clone();
        let path = std::path::PathBuf::from(&config_path);
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "cannot install SIGHUP handler; auth hot-reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                if let Err(e) = state.reload_auth(&path) {
                    tracing::error!(error = %e, "auth reload failed; keeping previous auth config");
                }
            }
        });
    }

    // periodic integrity verification (opt-in `verify` config section);
    // tamper findings surface as `error` log lines
    if let Some(verify) = &cfg.verify {
        quipu_server::spawn_periodic_verify(
            state.clone(),
            std::time::Duration::from_secs(verify.interval_secs),
        );
        tracing::info!(
            interval_secs = verify.interval_secs,
            "periodic integrity verification enabled"
        );
    }

    let listener = match quipu_server::bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind '{}': {e}", cfg.listen);
            std::process::exit(1);
        }
    };
    tracing::info!(listen = %cfg.listen, tls = cfg.tls.is_some(), "quipu-server listening");

    let result = quipu_server::serve(listener, cfg.tls.as_ref(), router(state), async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
    })
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, "server error");
    }

    // flush everything queued before the process exits — audit data must not
    // ride on the OS cache through a shutdown
    pipeline.shutdown();
}
