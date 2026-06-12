use quipu_core::AuditStore;
use quipu_middleware::{AuditPipeline, PermissionPolicy, PipelineConfig};
use quipu_server::{router, AppState, ServerConfig};

fn usage() -> ! {
    eprintln!("usage: quipu-server <config.json>");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let (Some(config_path), None) = (args.next(), args.next()) else {
        usage()
    };
    let cfg = match ServerConfig::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config '{config_path}': {e}");
            std::process::exit(1);
        }
    };

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
            let mut hup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
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

    let listener = match tokio::net::TcpListener::bind(&cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind '{}': {e}", cfg.listen);
            std::process::exit(1);
        }
    };
    tracing::info!(listen = %cfg.listen, "quipu-server listening");

    let serve = axum::serve(listener, router(state)).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
    });
    if let Err(e) = serve.await {
        tracing::error!(error = %e, "server error");
    }

    // flush everything queued before the process exits — audit data must not
    // ride on the OS cache through a shutdown
    pipeline.shutdown();
}
