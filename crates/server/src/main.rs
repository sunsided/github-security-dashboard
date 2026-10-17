use anyhow::Context;
use clap::Parser;
use collector::Collector;
use gh::{ClientConfig, GitHub, PatProvider};
use server::api::AppState;
use server::config::Config;
use server::scheduler::Scheduler;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, env = "DASHBOARD_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// Run the collector once and exit instead of serving.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;

    let store = store::connect(&config.storage.url)
        .await
        .context("opening storage")?;
    let tokens = Arc::new(PatProvider::new(config.auth.token()?));
    let github = Arc::new(GitHub::new(ClientConfig::default(), tokens)?);
    let collector = Collector::new(Arc::clone(&github), Arc::clone(&store), config.collector);

    if args.once {
        let summary = collector.run().await?;
        for error in &summary.errors {
            tracing::warn!("{error}");
        }
        tracing::info!(status = ?summary.status, repos = summary.repos, "done");
        return Ok(());
    }

    let scheduler = Arc::new(Scheduler::new(collector, config.poll_interval));
    tokio::spawn(Arc::clone(&scheduler).run_forever());

    let app = server::app(AppState {
        store,
        github,
        scheduler,
    });
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    if !config.listen.ip().is_loopback() {
        tracing::warn!(
            listen = %config.listen,
            "listening on a non-loopback address; the API has no authentication"
        );
    }
    tracing::info!("serving on http://{}", config.listen);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}
