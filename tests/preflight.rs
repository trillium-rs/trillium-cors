use trillium::{Conn, KnownHeaderName as H, Method, Status};
use trillium_cors::Cors;
use trillium_testing::{TestServer, harness, test};

fn app(cors: Cors) -> impl trillium::Handler {
    (cors, |conn: Conn| async move { conn.ok("the app ran") })
}

fn configured() -> Cors {
    Cors::allow_origins(["https://app.example.com"])
        .allow_methods([Method::Get, Method::Post, Method::Delete])
        .allow_headers([H::ContentType, H::Authorization])
        .max_age(std::time::Duration::from_secs(600))
}

#[test(harness)]
async fn approved_preflight_does_not_reach_the_application() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "DELETE")
        .with_request_header(
            H::AccessControlRequestHeaders,
            "Content-Type, Authorization",
        )
        .await
        .assert_status(Status::NoContent)
        .assert_body("")
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_header(H::AccessControlAllowMethods, "GET, POST, DELETE")
        .assert_header(H::AccessControlAllowHeaders, "Content-Type, Authorization")
        .assert_header(H::AccessControlMaxAge, "600");
}

#[test(harness)]
async fn an_options_request_without_a_requested_method_is_the_applications() {
    let app = TestServer::new(app(configured())).await;

    // not a preflight — a real OPTIONS request the application may want to answer
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .await
        .assert_ok()
        .assert_body("the app ran")
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_no_header("access-control-allow-methods");
}

#[test(harness)]
async fn a_refused_method_gets_no_cors_headers() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "PUT")
        .await
        .assert_status(Status::NoContent)
        .assert_no_header("access-control-allow-origin")
        .assert_no_header("access-control-allow-methods")
        // still halted: a preflight is never the application's to answer
        .assert_body("");
}

#[test(harness)]
async fn a_refused_header_gets_no_cors_headers() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .with_request_header(H::AccessControlRequestHeaders, "content-type, x-custom")
        .await
        .assert_status(Status::NoContent)
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn a_refused_origin_gets_no_cors_headers() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://evil.example.com")
        .with_request_header(H::AccessControlRequestMethod, "GET")
        .await
        .assert_status(Status::NoContent)
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn an_unrecognized_method_is_refused() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "NOTAMETHOD")
        .await
        .assert_status(Status::NoContent)
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn safelisted_methods_need_no_configuration() {
    let app = TestServer::new(app(Cors::allow_origins(["https://app.example.com"]))).await;

    // a browser exempts GET, HEAD, and POST from the preflight method check whatever
    // Access-Control-Allow-Methods says, so refusing them here would be stricter than the
    // spec while protecting nothing
    for method in ["GET", "HEAD", "POST"] {
        app.build(Method::Options, "/")
            .with_request_header(H::Origin, "https://app.example.com")
            .with_request_header(H::AccessControlRequestMethod, method)
            .await
            .assert_status(Status::NoContent)
            .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
            // nothing was configured, so there is no narrower policy to state
            .assert_no_header("access-control-allow-methods");
    }

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "DELETE")
        .await
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn a_get_preflighted_only_for_its_headers_needs_no_method_configuration() {
    let cors = Cors::allow_origins(["https://app.example.com"]).allow_headers(["x-custom"]);
    let app = TestServer::new(app(cors)).await;

    // the browser preflights this GET because of the custom header, not the method
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "GET")
        .with_request_header(H::AccessControlRequestHeaders, "x-custom")
        .await
        .assert_status(Status::NoContent)
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_header(H::AccessControlAllowHeaders, "x-custom");
}

#[test(harness)]
async fn safelisted_request_headers_need_no_configuration() {
    let cors = Cors::allow_origins(["https://app.example.com"]).allow_methods([Method::Post]);
    let app = TestServer::new(app(cors)).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .with_request_header(H::AccessControlRequestHeaders, "accept, accept-language")
        .await
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com");

    // content-type is safelisted only for the three form encodings, so a preflight naming it
    // is a page announcing it intends something else
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .with_request_header(H::AccessControlRequestHeaders, "content-type")
        .await
        .assert_no_header("access-control-allow-origin");
}

#[test(harness)]
async fn allow_any_header_is_a_wildcard() {
    let cors = Cors::allow_origins(["https://app.example.com"])
        .allow_methods([Method::Post])
        .allow_any_header();
    let app = TestServer::new(app(cors)).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .with_request_header(H::AccessControlRequestHeaders, "x-whatever, x-else")
        .await
        .assert_status(Status::NoContent)
        .assert_header(H::AccessControlAllowHeaders, "*");
}

#[test(harness)]
async fn allow_any_header_names_them_when_credentials_are_on() {
    let cors = Cors::allow_origins(["https://app.example.com"])
        .allow_methods([Method::Post])
        .allow_any_header()
        .allow_credentials();
    let app = TestServer::new(app(cors)).await;

    // a credentialed request reads `*` as an ordinary header name, so it has to be spelled out
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "POST")
        .with_request_header(H::AccessControlRequestHeaders, "x-whatever, x-else")
        .await
        .assert_header(H::AccessControlAllowHeaders, "x-whatever, x-else");
}

#[test(harness)]
async fn the_configured_list_is_sent_whole() {
    let app = TestServer::new(app(configured())).await;

    // the whole configured list, not just the subset that was asked for
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "GET")
        .with_request_header(H::AccessControlRequestHeaders, "content-type")
        .await
        .assert_header(H::AccessControlAllowHeaders, "Content-Type, Authorization");
}

#[test(harness)]
async fn preflight_varies_on_what_the_browser_asked() {
    let app = TestServer::new(app(configured())).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "GET")
        .await
        .assert_header_with(H::Vary, |values| {
            let values = values.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>();
            assert_eq!(
                values,
                [
                    "origin",
                    "access-control-request-method",
                    "access-control-request-headers"
                ]
            );
        });
}

#[test(harness)]
async fn preflight_does_not_send_expose_headers() {
    let cors = configured().expose_headers(["x-request-id"]);
    let app = TestServer::new(app(cors)).await;

    // exposing response headers is about the actual response, not the permission check
    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "GET")
        .await
        .assert_no_header("access-control-expose-headers");
}

#[test(harness)]
async fn credentialed_preflight_echoes_the_origin() {
    let cors = configured().allow_credentials();
    let app = TestServer::new(app(cors)).await;

    app.build(Method::Options, "/")
        .with_request_header(H::Origin, "https://app.example.com")
        .with_request_header(H::AccessControlRequestMethod, "DELETE")
        .await
        .assert_header(H::AccessControlAllowOrigin, "https://app.example.com")
        .assert_header(H::AccessControlAllowCredentials, "true");
}
