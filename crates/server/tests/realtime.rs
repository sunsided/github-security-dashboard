//! The live-update WebSocket, exercised over a real socket.

use assert2::check;
use chrono::Utc;
use collector::{Collector, CollectorConfig};
use futures_util::{SinkExt, StreamExt};
use gh::{ClientConfig, GitHub, PatProvider, Secret};
use server::api::AppState;
use server::config::Scoring;
use server::guard::{AllowedHosts, CSRF_HEADER};
use server::realtime::{Event, Hub, RealtimeConfig, close};
use server::scheduler::Scheduler;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Serves the app on an ephemeral port for the duration of the test.
async fn serve(config: RealtimeConfig) -> (String, Arc<Hub>) {
    let store = store::connect("sqlite::memory:").await.unwrap();
    let hub = Arc::new(Hub::new(
        config,
        b"test signing key, long enough",
        AllowedHosts::new(&[]),
    ));
    let github = Arc::new(
        GitHub::new(
            ClientConfig {
                api_url: "http://127.0.0.1:9".into(),
                ..ClientConfig::default()
            },
            Arc::new(PatProvider::new(Secret::new("unused"))),
        )
        .unwrap(),
    );
    let collector = Collector::new(
        Arc::clone(&github),
        Arc::clone(&store),
        CollectorConfig::default(),
    );
    let scheduler = Arc::new(Scheduler::new(
        collector,
        Duration::from_secs(3600),
        Arc::clone(&store),
        Arc::clone(&hub),
    ));
    let state = AppState {
        store,
        github,
        scheduler,
        scoring: Scoring::default(),
        auth: "personal access token",
        digest: None,
        realtime: Arc::clone(&hub),
    };
    let app = server::app(
        state,
        AllowedHosts::new(&[]),
        Arc::new(server::login::Login::none()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("127.0.0.1:{}", addr.port()), hub)
}

async fn open(addr: &str) -> Socket {
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/realtime"))
        .await
        .unwrap();
    socket
}

async fn send(socket: &mut Socket, value: serde_json::Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

/// The next text frame as JSON, or the close code.
async fn next(socket: &mut Socket) -> Result<serde_json::Value, Option<u16>> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("no frame within 5 s")
        {
            Some(Ok(Message::Text(text))) => return Ok(serde_json::from_str(&text).unwrap()),
            Some(Ok(Message::Close(frame))) => return Err(frame.map(|f| u16::from(f.code))),
            Some(Ok(_)) => continue,
            Some(Err(_)) | None => return Err(None),
        }
    }
}

fn connect_message(token: &str) -> serde_json::Value {
    serde_json::json!({ "connect": { "token": token } })
}

#[tokio::test]
async fn connected_clients_receive_events() {
    let (addr, hub) = serve(RealtimeConfig::default()).await;
    let mut socket = open(&addr).await;
    send(
        &mut socket,
        connect_message(&hub.issue_token(Utc::now(), "").token),
    )
    .await;
    let connected = next(&mut socket).await.unwrap();
    check!(connected["connected"]["expires_at"].is_string());

    hub.publish(Event::AlertsChanged {
        repositories: vec!["acme/api".into()],
        events: 3,
    });
    let event = next(&mut socket).await.unwrap();
    check!(
        event
            == serde_json::json!({
                "event": { "type": "alerts.changed", "repositories": ["acme/api"], "events": 3 }
            })
    );
}

#[tokio::test]
async fn nothing_arrives_before_a_valid_token() {
    let (addr, hub) = serve(RealtimeConfig::default()).await;
    let mut socket = open(&addr).await;
    hub.publish(Event::RunStarted);
    send(&mut socket, connect_message("not.a.token")).await;
    check!(next(&mut socket).await == Err(Some(close::INVALID_TOKEN)));
}

#[tokio::test]
async fn expired_tokens_are_refused() {
    let (addr, hub) = serve(RealtimeConfig::default()).await;
    let mut socket = open(&addr).await;
    let old = hub.issue_token(Utc::now() - chrono::Duration::hours(1), "");
    send(&mut socket, connect_message(&old.token)).await;
    check!(next(&mut socket).await == Err(Some(close::TOKEN_EXPIRED)));
}

#[tokio::test]
async fn silent_clients_are_closed() {
    let config = RealtimeConfig {
        connect_timeout: Duration::from_millis(200),
        ..RealtimeConfig::default()
    };
    let (addr, _) = serve(config).await;
    let mut socket = open(&addr).await;
    check!(next(&mut socket).await == Err(Some(close::CONNECT_TIMEOUT)));
}

#[tokio::test]
async fn anything_but_connect_first_is_a_protocol_error() {
    let (addr, hub) = serve(RealtimeConfig::default()).await;
    let mut socket = open(&addr).await;
    send(
        &mut socket,
        serde_json::json!({ "refresh": { "token": hub.issue_token(Utc::now(), "").token } }),
    )
    .await;
    check!(next(&mut socket).await == Err(Some(close::PROTOCOL)));
}

#[tokio::test]
async fn refreshing_keeps_the_connection_and_expiry_ends_it() {
    let config = RealtimeConfig {
        token_ttl: Duration::from_secs(2),
        ..RealtimeConfig::default()
    };
    let (addr, hub) = serve(config).await;

    let mut refreshed = open(&addr).await;
    send(
        &mut refreshed,
        connect_message(&hub.issue_token(Utc::now(), "").token),
    )
    .await;
    next(&mut refreshed).await.unwrap();
    let mut expiring = open(&addr).await;
    send(
        &mut expiring,
        connect_message(&hub.issue_token(Utc::now(), "").token),
    )
    .await;
    next(&mut expiring).await.unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let fresh = hub.issue_token(Utc::now() + chrono::Duration::seconds(30), "");
    send(
        &mut refreshed,
        serde_json::json!({ "refresh": { "token": fresh.token } }),
    )
    .await;
    check!(next(&mut refreshed).await.unwrap()["refreshed"]["expires_at"].is_string());

    // The other one never refreshed.
    check!(next(&mut expiring).await == Err(Some(close::TOKEN_EXPIRED)));

    // The refreshed one outlives its first token.
    hub.publish(Event::RunStarted);
    check!(next(&mut refreshed).await.unwrap()["event"]["type"] == "run.started");
}

#[tokio::test]
async fn foreign_origins_are_refused_before_upgrading() {
    let (addr, _) = serve(RealtimeConfig::default()).await;
    let mut request = format!("ws://{addr}/api/realtime")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    check!(let WsError::Http(response) = error && response.status() == 403);

    let mut own = format!("ws://{addr}/api/realtime")
        .into_client_request()
        .unwrap();
    own.headers_mut()
        .insert("origin", format!("http://{addr}").parse().unwrap());
    check!(tokio_tungstenite::connect_async(own).await.is_ok());
}

#[tokio::test]
async fn tokens_need_the_same_protection_as_other_writes() {
    let (addr, _) = serve(RealtimeConfig::default()).await;
    let (status, _) = post_token(&addr, false).await;
    check!(status == 403, "cross-site POSTs can't mint tokens");

    let (status, body) = post_token(&addr, true).await;
    check!(status == 200);
    let token: serde_json::Value = serde_json::from_str(&body).unwrap();
    let mut socket = open(&addr).await;
    send(
        &mut socket,
        connect_message(token["token"].as_str().unwrap()),
    )
    .await;
    check!(next(&mut socket).await.is_ok());
}

/// A minimal HTTP/1.1 POST without pulling in an HTTP client.
async fn post_token(addr: &str, with_header: bool) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let extra = if with_header {
        format!("{CSRF_HEADER}: 1\r\n")
    } else {
        String::new()
    };
    let request = format!(
        "POST /api/realtime/token HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\n{extra}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    (status, body)
}

#[test]
fn close_codes_are_in_the_application_range() {
    for code in [
        close::PROTOCOL,
        close::INVALID_TOKEN,
        close::TOKEN_EXPIRED,
        close::CONNECT_TIMEOUT,
    ] {
        check!((4000..5000).contains(&code));
        check!(CloseCode::from(code) == CloseCode::Library(code));
    }
}
