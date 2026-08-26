use trillium::{Conn, KnownHeaderName as H, Method, Status};
use trillium_cors::Cors;
use trillium_testing::{TestServer, harness, test};

fn app(cors: Cors) -> impl trillium::Handler {
    (cors, |conn: Conn| async move { conn.ok("the app ran") })
}

fn rejecting() -> Cors {
    Cors::allow_origins(["https://app.example.com"])
        .allow_methods([Method::Post])
        .reject_disallowed_origins()
}

#[test(harness)]
async fn a_disallowed_origin_is_forbidden() {
    let app = TestServer::new(app(rejecting())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .await
        .assert_status(Status::Forbidden)
        .assert_body_with(|body| assert!(body.is_empty()))
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn an_allowed_origin_is_unaffected() {
    let app = TestServer::new(app(rejecting())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_ok()
        .assert_body("the app ran")
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com");
}

#[test(harness)]
async fn a_request_with_no_origin_is_unaffected() {
    let app = TestServer::new(app(rejecting())).await;

    // a non-browser client sends no `Origin`, and rejecting it would be rejecting everyone
    app.get("/").await.assert_ok().assert_body("the app ran");
}

#[test(harness)]
async fn a_preflight_from_a_disallowed_origin_is_forbidden() {
    let app = TestServer::new(app(rejecting())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .await
        .assert_status(Status::Forbidden)
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn a_preflight_refused_for_its_method_is_not_an_origin_refusal() {
    let app = TestServer::new(app(rejecting())).await;

    // the origin was fine; the method was not. that is not what this setting is about
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "DELETE")
        .await
        .assert_status(Status::NoContent)
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn without_the_opt_in_a_disallowed_origin_still_runs() {
    let app = TestServer::new(app(Cors::allow_origins(["https://app.example.com"]))).await;

    app.get("/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .await
        .assert_ok()
        .assert_body("the app ran");
}
