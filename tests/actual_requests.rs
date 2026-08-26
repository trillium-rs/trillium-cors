use trillium::{Conn, KnownHeaderName as H, Status};
use trillium_cors::{Cors, CorsConnExt};
use trillium_testing::{TestServer, harness, test};

fn app(cors: Cors) -> impl trillium::Handler {
    (cors, |conn: Conn| async move {
        let origin = conn.cors_origin().map(|o| o.ascii_serialization());
        conn.with_response_header("x-secret", "shh")
            .ok(format!("{origin:?}"))
    })
}

fn allowing_app() -> Cors {
    Cors::allow_origins(["https://app.example.com"])
}

#[test(harness)]
async fn no_origin_header_passes_through_untouched() {
    let app = TestServer::new(app(allowing_app())).await;

    app.get("/")
        .await
        .assert_ok()
        .assert_body("None")
        .assert_no_header("access-control-allow-origin")
        // the response could still be cached and later served to a request that does have an
        // `Origin`, so it must advertise that it would have differed
        .assert_header(H::Vary, "origin");
}

#[test(harness)]
async fn allowed_origin_is_echoed() {
    let app = TestServer::new(app(allowing_app())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_ok()
        .assert_body(r#"Some("https://app.example.com")"#)
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_header(H::Vary, "origin")
        .assert_no_header("access-control-allow-credentials")
        .assert_no_header("access-control-expose-headers");
}

#[test(harness)]
async fn the_echoed_value_is_normalized_not_copied() {
    let app = TestServer::new(app(allowing_app())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://APP.example.com:443")
        .await
        .assert_ok()
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com");
}

#[test(harness)]
async fn disallowed_origin_still_runs_the_inner_handler() {
    let app = TestServer::new(app(allowing_app())).await;

    // CORS is enforced by the browser, not us: the request runs, and what the browser
    // withholds from the page is the response
    app.get("/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .await
        .assert_status(Status::Ok)
        .assert_body("None")
        .assert_no_header("access-control-allow-origin")
        .assert_header(H::Vary, "origin");
}

#[test(harness)]
async fn null_and_unparseable_origins_are_refused() {
    let app = TestServer::new(app(allowing_app())).await;

    for origin in ["null", "not a url", "https://app.example.com.evil.com"] {
        app.get("/")
            .with_request_header(H::Origin, origin)
            .await
            .assert_body("None")
            .assert_no_header("access-control-allow-origin");
    }
}

#[test(harness)]
async fn any_origin_sends_a_wildcard_and_does_not_vary() {
    let app = TestServer::new(app(Cors::allow_any_origin())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://anyone.example.com")
        .await
        .assert_ok()
        .assert_header(H::AccessControlAllowOrigin, "*")
        // the response is identical for every origin, so there is nothing to vary on
        .assert_no_header("vary");
}

#[test(harness)]
async fn credentials_never_send_a_wildcard() {
    let app = TestServer::new(app(allowing_app().allow_credentials())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_ok()
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_header(H::AccessControlAllowCredentials, "true");
}

#[test(harness)]
async fn credentials_are_not_advertised_to_a_refused_origin() {
    let app = TestServer::new(app(allowing_app().allow_credentials())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .await
        .assert_no_header("access-control-allow-origin")
        .assert_no_header("access-control-allow-credentials");
}

#[test(harness)]
async fn exposed_headers_are_listed() {
    let app = TestServer::new(app(allowing_app().expose_headers(["x-secret", "x-other"]))).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_header(H::AccessControlExposeHeaders, "x-secret, x-other");
}

#[test(harness)]
async fn expose_any_header_is_a_wildcard() {
    let app = TestServer::new(app(allowing_app().expose_any_header())).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_header(H::AccessControlExposeHeaders, "*");
}

#[test(harness)]
async fn vary_set_by_the_application_is_preserved() {
    let inner = |conn: Conn| async move {
        conn.with_response_header(H::Vary, "accept-encoding")
            .ok("hello")
    };
    let app = TestServer::new((allowing_app(), inner)).await;

    app.get("/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_header_with(H::Vary, |values| {
            let values = values.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>();
            assert_eq!(values, ["accept-encoding", "origin"]);
        });
}

#[test]
#[should_panic = "cannot be combined with `allow_any_origin`"]
fn any_origin_plus_credentials_panics() {
    Cors::allow_any_origin().allow_credentials();
}
