use anyhow::Context;
use clap::Parser;
use collector::Collector;
use daily_digest::{DigestService, Outcome};
use gh::{ClientConfig, GitHub};
use server::api::AppState;
use server::config::Config;
use server::realtime::{Event, Hub};
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

    /// Send the digest to all targets now, regardless of the schedule, and
    /// exit. Needs [digest] enabled; covers events since each target's
    /// last digest.
    #[arg(long, conflicts_with = "once")]
    send_digest: bool,
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
    let client_config = ClientConfig::default();
    let allowed_hosts = server::guard::AllowedHosts::new(&config.allowed_hosts);
    let hub = Arc::new(realtime_hub(&config, allowed_hosts.clone())?);

    let digest = if config.digest.enabled {
        let events = Arc::clone(&hub);
        let service = DigestService::new(Arc::clone(&store), config.digest.clone(), |name| {
            std::env::var(name).ok()
        })
        .map_err(|e| anyhow::anyhow!(e))?
        .with_listener(Arc::new(move |outcome: &Outcome| {
            let (target, kind) = match outcome {
                Outcome::Sent { target, .. } => (target, "sent"),
                Outcome::Quiet { target } => (target, "quiet"),
                Outcome::Failed { target, .. } => (target, "failed"),
            };
            events.publish(Event::DigestDelivered {
                target: target.clone(),
                outcome: kind.into(),
            });
        }));
        Some(Arc::new(service))
    } else {
        None
    };

    if args.send_digest {
        let digest = digest.context("--send-digest needs [digest] enabled = true")?;
        let outcomes = digest.send_now(chrono::Utc::now()).await;
        println!("{}", serde_json::to_string_pretty(&outcomes)?);
        return Ok(());
    }

    let tokens = config
        .auth
        .provider(&client_config, |name| std::env::var(name).ok())?;
    let auth = tokens.label();
    tracing::info!("authenticating with a {auth}");
    let github = Arc::new(GitHub::new(client_config, tokens)?);
    let collector = Collector::new(Arc::clone(&github), Arc::clone(&store), config.collector);

    if args.once {
        let summary = collector.run().await?;
        for error in &summary.errors {
            tracing::warn!("{error}");
        }
        tracing::info!(status = ?summary.status, repos = summary.repos, "done");
        return Ok(());
    }

    let scheduler = Arc::new(Scheduler::new(
        collector,
        config.poll_interval,
        Arc::clone(&store),
        Arc::clone(&hub),
    ));
    tokio::spawn(Arc::clone(&scheduler).run_forever());
    if let Some(digest) = &digest {
        tokio::spawn(Arc::clone(digest).run_forever());
    }

    let app = server::app(
        AppState {
            store,
            github,
            scheduler,
            scoring: config.scoring,
            auth,
            digest,
            realtime: hub,
        },
        allowed_hosts,
    );
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

/// The live-update hub, signing tokens with the configured key or, without
/// one, a key that lives as long as the process.
fn realtime_hub(
    config: &Config,
    allowed_hosts: server::guard::AllowedHosts,
) -> anyhow::Result<Hub> {
    let key = match &config.realtime.signing_key_env {
        Some(var) => std::env::var(var)
            .ok()
            .filter(|k| k.len() >= 32)
            .with_context(|| {
                format!("environment variable {var} must hold a signing key of at least 32 bytes")
            })?
            .into_bytes(),
        None => Hub::random_key().to_vec(),
    };
    Ok(Hub::new(config.realtime.clone(), &key, allowed_hosts))
}
