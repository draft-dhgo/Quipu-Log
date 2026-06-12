use quipu_core::AuditStore;
use quipu_middleware::{AuditPipeline, PipelineConfig};
use quipu_server::{router, AppState, ServerConfig};
use std::sync::Arc;

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

    let pipeline = match AuditPipeline::start(
        store,
        store_root,
        cfg.permission_policy(),
        PipelineConfig::default(),
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to start audit pipeline: {e}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        handle: pipeline.handle(),
        tokens: Arc::new(cfg.auth.tokens.clone()),
        policy: Arc::new(cfg.permission_policy()),
    };

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
