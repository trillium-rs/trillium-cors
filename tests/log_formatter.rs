use std::sync::Arc;
use trillium::{Conn, KnownHeaderName as H, Method};
use trillium_cors::{
    Cors,
    log_formatter::{cors_origin, cors_preflight},
};
use trillium_logger::{Logger, Targetable};
use trillium_testing::{TestServer, harness, test};

/// A [`Targetable`] that pushes every written line onto an unbounded channel, so tests can
/// await the next line without racing the server's `after_send` callback.
#[derive(Clone, Debug)]
struct CollectTarget(
    Arc<(
        async_channel::Sender<String>,
        async_channel::Receiver<String>,
    )>,
);

impl Default for CollectTarget {
    fn default() -> Self {
        Self(Arc::new(async_channel::unbounded()))
    }
}

impl Targetable for CollectTarget {
    fn write(&self, data: String) {
        self.0.0.send_blocking(data).unwrap();
    }
}

impl CollectTarget {
    async fn next(&self) -> String {
        self.0.1.recv().await.unwrap()
    }
}

async fn app(cors: Cors) -> (TestServer<impl trillium::Handler>, CollectTarget) {
    let target = CollectTarget::default();

    let logger = Logger::new()
        .with_formatter((cors_origin, " ", cors_preflight))
        .with_target(target.clone())
        .without_init_message();

    let server = TestServer::new((
        logger,
        cors,
        |conn: Conn| async move { conn.ok("the app ran") },
    ))
    .await;

    (server, target)
}

fn configured() -> Cors {
    Cors::allow_origins(["https://app.example.com"]).allow_methods([Method::Post])
}

#[test(harness)]
async fn an_allowed_origin_is_logged() {
    let (server, target) = app(configured()).await;

    server
        .get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await;

    assert_eq!(target.next().await, "https://app.example.com -");
}

#[test(harness)]
async fn a_refused_origin_logs_nothing_identifying() {
    let (server, target) = app(configured()).await;

    server
        .get("/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .await;

    assert_eq!(target.next().await, "- -");
}

#[test(harness)]
async fn a_request_with_no_origin_logs_dashes() {
    let (server, target) = app(configured()).await;

    server.get("/").await;

    assert_eq!(target.next().await, "- -");
}

#[test(harness)]
async fn an_approved_preflight_is_distinguishable_from_the_request_it_asked_about() {
    let (server, target) = app(configured()).await;

    // the preflight is halted before the application, so without this it would be easy to
    // mistake for the POST that follows it
    server
        .build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .await;

    server
        .post("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await;

    assert_eq!(target.next().await, "https://app.example.com preflight");
    assert_eq!(target.next().await, "https://app.example.com -");
}

#[test(harness)]
async fn a_refused_preflight_is_not_an_approved_one() {
    let (server, target) = app(configured()).await;

    server
        .build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "DELETE")
        .await;

    assert_eq!(target.next().await, "- -");
}
