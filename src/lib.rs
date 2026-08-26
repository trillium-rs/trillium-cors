//! # Cross-origin resource sharing for trillium.rs
//!
//! By default a browser will not let a page read a response from a different origin than
//! the page itself. This handler is how a server says which origins it will make an
//! exception for, implementing the [Fetch standard's CORS
//! protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
//!
//! ```
//! use trillium_cors::Cors;
//! use trillium::Method;
//!
//! let app = (
//!     Cors::allow_origins(["https://app.example.com"])
//!         .allow_methods([Method::Get, Method::Post, Method::Delete])
//!         .allow_headers(["content-type", "authorization"]),
//!     "hello from an api",
//! );
//! ```
//!
//! Mount it ahead of the rest of the application. It does two things: it answers the
//! `OPTIONS` preflight a browser sends before any request that isn't a plain `GET`, `HEAD`,
//! or form `POST`, and it adds the headers that let a page read the response to the
//! requests that follow.
//!
//! ## The browser is the enforcement point
//!
//! CORS is not a server-side access control. A request from an origin this handler does not
//! allow still runs; what the browser withholds is the page's ability to read the
//! *response*. So a disallowed origin is answered normally, minus the CORS headers, and a
//! request with no `Origin` header at all passes through untouched — which is what keeps
//! non-browser clients working. [`Cors::reject_disallowed_origins`] trades that for a
//! `403`.
//!
//! Anything that must actually be denied — authentication, authorization, CSRF — needs a
//! handler that enforces it, whether or not this one is present.
//!
//! ## WebSockets
//!
//! Browsers do not apply CORS to the WebSocket handshake; RFC 6455 assigns that check to
//! the server, which has to compare the `Origin` header itself. This handler does not cover
//! it, and adding it to an application will not protect a WebSocket endpoint.
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    unused_qualifications
)]

// Compile the README as a doctest so its examples stay in sync with the crate.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}

mod origin;
use origin::{OriginPolicy, OriginPredicate, parse_request_origin};

mod vary;
use vary::append_vary;

use std::time::Duration;
use trillium::{Conn, Handler, HeaderName, KnownHeaderName, Method, Status};
pub use url::Origin;

/// The origin of a request that the policy allowed, stored in conn state.
#[derive(Debug, Clone)]
struct AllowedOrigin(Origin);

/// The methods a browser may use cross-origin without asking permission, and which the
/// preflight check therefore approves whether or not they were configured.
const SAFELISTED_METHODS: [Method; 3] = [Method::Get, Method::Head, Method::Post];

/// The request headers a browser may send cross-origin without asking permission.
///
/// `content-type` is deliberately absent. It is safelisted only for the three form encodings,
/// and a preflight that names it is a page announcing it intends something else —
/// `application/json`, most often — which is exactly the case that should have to be
/// configured.
const SAFELISTED_REQUEST_HEADERS: [&str; 3] = ["accept", "accept-language", "content-language"];

/// What the origin policy made of this request.
enum OriginDecision {
    /// No `Origin` header — not a browser, or a same-origin request.
    Absent,

    /// An `Origin` the policy would not allow, or one that could not be parsed.
    Refused,

    Allowed(Origin),
}

/// Marks a request as a preflight the policy fully approved.
#[derive(Debug, Clone, Copy)]
struct Preflight;

/// Which request headers a page is allowed to send on a cross-origin request.
#[derive(Debug, Default)]
enum AllowHeaders {
    /// Only the CORS-safelisted request headers, which never need permission.
    #[default]
    Safelisted,

    List(Vec<HeaderName<'static>>),

    /// Sent as `*`, or as the names the preflight asked for when credentials are allowed.
    Any,
}

fn is_safelisted_request_header(header: &str) -> bool {
    SAFELISTED_REQUEST_HEADERS
        .iter()
        .any(|safelisted| safelisted.eq_ignore_ascii_case(header))
}

impl AllowHeaders {
    fn allows(&self, header: &str) -> bool {
        match self {
            Self::Safelisted => false,
            Self::Any => true,
            Self::List(list) => list
                .iter()
                .any(|allowed| allowed.as_ref().eq_ignore_ascii_case(header)),
        }
    }
}

/// Which response headers a page is allowed to read, beyond the CORS-safelisted set.
#[derive(Debug, Default)]
enum ExposeHeaders {
    /// Send no `Access-Control-Expose-Headers`, leaving the browser's safelisted set.
    #[default]
    Safelisted,

    List(Vec<HeaderName<'static>>),

    /// Send a literal `*`.
    Any,
}

/// Cross-origin resource sharing.
///
/// Build one by naming an origin policy — [`Cors::allow_origins`],
/// [`Cors::allow_origin_fn`], or [`Cors::allow_any_origin`] — then refine it with the
/// setters.
#[derive(Debug)]
pub struct Cors {
    origin_policy: OriginPolicy,
    allow_credentials: bool,
    expose_headers: ExposeHeaders,
    reject_disallowed_origins: bool,
    allow_methods: Vec<Method>,
    allow_headers: AllowHeaders,
    max_age: Option<Duration>,
}

impl Cors {
    /// Allows a fixed list of origins.
    ///
    /// An origin is scheme, host, and port, and all three are compared: a request from
    /// `http://example.com` does not match an allowed `https://example.com`. A default port
    /// is implicit, so `https://example.com` and `https://example.com:443` are the same
    /// origin.
    ///
    /// ```
    /// # use trillium_cors::Cors;
    /// let cors = Cors::allow_origins(["https://app.example.com"]);
    /// let cors = Cors::allow_origins(["https://app.example.com", "http://localhost:8080"]);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if any of the provided strings is not a url with a scheme and a host, or if it
    /// carries anything beyond a scheme, host, and optional port. An `Origin` never contains
    /// a path, so an allowed origin written as `https://example.com/app` would silently match
    /// every page on `example.com`.
    pub fn allow_origins<'a>(origins: impl IntoIterator<Item = &'a str>) -> Self {
        Self::from(OriginPolicy::list(origins))
    }

    /// Allows origins for which the provided predicate returns true.
    ///
    /// The predicate receives a parsed [`Origin`], which is always a tuple origin of scheme,
    /// host, and port. Requests whose `Origin` header is absent, opaque (`null`), or
    /// unparseable never reach the predicate and are never allowed.
    ///
    /// ```
    /// # use trillium_cors::{Cors, Origin};
    /// let cors = Cors::allow_origin_fn(|origin| match origin {
    ///     Origin::Tuple(scheme, host, _) => scheme == "https" && host.to_string().ends_with(".example.com"),
    ///     Origin::Opaque(_) => false,
    /// });
    /// ```
    pub fn allow_origin_fn<F>(predicate: F) -> Self
    where
        F: Fn(&Origin) -> bool + Send + Sync + 'static,
    {
        Self::from(OriginPolicy::Predicate(OriginPredicate::from(predicate)))
    }

    /// Allows every origin, sending a literal `*`.
    ///
    /// This makes the handler's responses readable by any page on the web, so it is only
    /// appropriate for genuinely public data. Because `*` cannot be combined with
    /// credentials, calling `allow_credentials` on a handler built this way panics.
    pub fn allow_any_origin() -> Self {
        Self::from(OriginPolicy::Any)
    }
}

impl Cors {
    /// Allows the browser to send credentials — cookies, TLS client certificates, and
    /// `Authorization` headers — with cross-origin requests, and to expose the response to a
    /// page that asked for them.
    ///
    /// # Panics
    ///
    /// Panics if this handler allows any origin. Credentials cannot be combined with a
    /// wildcard, and the usual workaround — reflecting whatever origin asked back at it —
    /// hands every site on the web an authenticated read of this one.
    pub fn allow_credentials(mut self) -> Self {
        assert!(
            !self.origin_policy.is_any(),
            "`allow_credentials` cannot be combined with `allow_any_origin`: credentialed \
             requests may not be answered with a wildcard origin. Name the origins you trust \
             with `allow_origins` or `allow_origin_fn` instead."
        );

        self.allow_credentials = true;
        self
    }

    /// Answers a request from a disallowed origin with `403 Forbidden` instead of running it.
    ///
    /// The default is to answer normally and omit the CORS headers, leaving the browser to
    /// block the page's read. That also means a non-browser client that happens to send an
    /// `Origin` header keeps working, which this setting gives up.
    ///
    /// Only the origin check is affected. A preflight refused for its method or its headers
    /// is still answered with an ordinary `204` carrying no CORS headers.
    pub fn reject_disallowed_origins(mut self) -> Self {
        self.reject_disallowed_origins = true;
        self
    }

    /// Allows these methods on cross-origin requests.
    ///
    /// This gates preflight only. `GET`, `HEAD`, and `POST` are permitted without being
    /// listed, because a browser exempts them from the preflight method check whatever this
    /// says; listing them anyway is harmless. Every other method has to be named.
    ///
    /// ```
    /// # use trillium_cors::Cors;
    /// # use trillium::Method;
    /// let cors = Cors::allow_origins(["https://app.example.com"])
    ///     .allow_methods([Method::Get, Method::Post, Method::Delete]);
    /// ```
    pub fn allow_methods(mut self, methods: impl IntoIterator<Item = Method>) -> Self {
        self.allow_methods = methods.into_iter().collect();
        self
    }

    /// Allows a page to send these request headers on a cross-origin request.
    ///
    /// `accept`, `accept-language`, and `content-language` are always permitted and do not need
    /// to be listed, because a browser may send them cross-origin without asking.
    ///
    /// Everything else does need listing — including `content-type`, which is safelisted only
    /// for the three form encodings. A preflight naming it means the page intends something
    /// else, `application/json` most often, so it is treated as needing permission.
    ///
    /// ```
    /// # use trillium_cors::Cors;
    /// # use trillium::KnownHeaderName;
    /// let cors = Cors::allow_origins(["https://app.example.com"])
    ///     .allow_headers([KnownHeaderName::ContentType, KnownHeaderName::Authorization]);
    /// ```
    pub fn allow_headers<N>(mut self, headers: impl IntoIterator<Item = N>) -> Self
    where
        N: Into<HeaderName<'static>>,
    {
        self.allow_headers = AllowHeaders::List(headers.into_iter().map(Into::into).collect());
        self
    }

    /// Allows a page to send any request header it asks for in a preflight.
    ///
    /// Sent as a literal `*`, except on a handler that also allows credentials — there `*` is
    /// an ordinary header name rather than a wildcard, so the headers the preflight asked for
    /// are named individually instead.
    pub fn allow_any_header(mut self) -> Self {
        self.allow_headers = AllowHeaders::Any;
        self
    }

    /// How long a browser may cache a preflight response.
    ///
    /// Browsers enforce a maximum of their own, so a long duration is a ceiling rather than a
    /// promise. Omitting this means a preflight before every request that needs one.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Allows a page to read these response headers, in addition to the CORS-safelisted ones
    /// it can always read (`cache-control`, `content-language`, `content-length`,
    /// `content-type`, `expires`, `last-modified`, and `pragma`).
    ///
    /// ```
    /// # use trillium_cors::Cors;
    /// # use trillium::KnownHeaderName;
    /// let cors = Cors::allow_origins(["https://app.example.com"])
    ///     .expose_headers([KnownHeaderName::ContentDisposition]);
    /// let cors = Cors::allow_origins(["https://app.example.com"])
    ///     .expose_headers(["x-request-id", "x-total-count"]);
    /// ```
    pub fn expose_headers<N>(mut self, headers: impl IntoIterator<Item = N>) -> Self
    where
        N: Into<HeaderName<'static>>,
    {
        self.expose_headers = ExposeHeaders::List(headers.into_iter().map(Into::into).collect());
        self
    }

    /// Allows a page to read every response header, as a literal `*`.
    ///
    /// This exposes headers the application may not have thought of as public — whatever a
    /// reverse proxy appended, request ids, `server`, anything left over from debugging.
    /// Prefer naming them with [`Cors::expose_headers`].
    ///
    /// A browser ignores `*` here on a credentialed request, so on a handler that also calls
    /// [`Cors::allow_credentials`] this exposes nothing at all. Name the headers instead.
    pub fn expose_any_header(mut self) -> Self {
        self.expose_headers = ExposeHeaders::Any;
        self
    }
}

impl From<OriginPolicy> for Cors {
    fn from(origin_policy: OriginPolicy) -> Self {
        Self {
            origin_policy,
            allow_credentials: false,
            expose_headers: ExposeHeaders::default(),
            reject_disallowed_origins: false,
            allow_methods: Vec::new(),
            allow_headers: AllowHeaders::default(),
            max_age: None,
        }
    }
}

impl Cors {
    fn origin_decision(&self, conn: &Conn) -> OriginDecision {
        let Some(header) = conn.request_headers().get_str(KnownHeaderName::Origin) else {
            return OriginDecision::Absent;
        };

        match parse_request_origin(header).filter(|origin| self.origin_policy.allows(origin)) {
            Some(origin) => OriginDecision::Allowed(origin),
            None => {
                log::debug!("cors: refused origin `{header}`");
                OriginDecision::Refused
            }
        }
    }

    fn refuse(&self, conn: Conn, refused_status: Status) -> Conn {
        let status = if self.reject_disallowed_origins {
            Status::Forbidden
        } else {
            refused_status
        };

        conn.with_status(status).halt()
    }

    /// A preflight is an `OPTIONS` request carrying the method the page actually intends to
    /// use. An `OPTIONS` without one is a real request for the application to answer.
    fn requested_method(conn: &Conn) -> Option<&str> {
        if conn.method() != Method::Options {
            return None;
        }

        conn.request_headers()
            .get_str(KnownHeaderName::AccessControlRequestMethod)
    }

    fn approves_preflight(&self, conn: &Conn, requested_method: &str) -> bool {
        let Ok(requested_method) = requested_method.parse::<Method>() else {
            log::debug!("cors: refused preflight for unrecognized method `{requested_method}`");
            return false;
        };

        if !SAFELISTED_METHODS.contains(&requested_method)
            && !self.allow_methods.contains(&requested_method)
        {
            log::debug!("cors: refused preflight for method `{requested_method}`");
            return false;
        }

        conn.request_headers()
            .token_iter(KnownHeaderName::AccessControlRequestHeaders)
            .all(|header| {
                is_safelisted_request_header(header) || self.allow_headers.allows(header) || {
                    log::debug!("cors: refused preflight for request header `{header}`");
                    false
                }
            })
    }
}

impl Handler for Cors {
    async fn run(&self, conn: Conn) -> Conn {
        let decision = self.origin_decision(&conn);
        let requested_method = Self::requested_method(&conn).map(String::from);

        let Some(requested_method) = requested_method else {
            return match decision {
                OriginDecision::Allowed(origin) => conn.with_state(AllowedOrigin(origin)),
                OriginDecision::Absent => conn,
                OriginDecision::Refused if self.reject_disallowed_origins => {
                    conn.with_status(Status::Forbidden).halt()
                }
                OriginDecision::Refused => conn,
            };
        };

        // A preflight is a browser asking permission, not a request for the application to
        // answer, so it is halted here whether or not it was approved. Refusing it means
        // answering with no CORS headers, which is what makes the browser fail the request it
        // was asking about.
        match decision {
            OriginDecision::Refused => self.refuse(conn, Status::NoContent),

            // a preflight is issued by a browser, which always sends `Origin`
            OriginDecision::Absent => conn.with_status(Status::NoContent).halt(),

            OriginDecision::Allowed(origin) => {
                let conn = conn.with_status(Status::NoContent).halt();

                // a refusal for the method or the headers is not an origin refusal, so it
                // stays a 204 even under `reject_disallowed_origins`
                if self.approves_preflight(&conn, &requested_method) {
                    conn.with_state(AllowedOrigin(origin)).with_state(Preflight)
                } else {
                    conn
                }
            }
        }
    }

    async fn before_send(&self, mut conn: Conn) -> Conn {
        // Even a response with no CORS headers has to advertise that it would have differed
        // for a different `Origin`, or a shared cache will hand one origin's response to
        // another. That includes requests with no `Origin` at all, whose response may later
        // be served to one that has it.
        let preflight = conn.state::<Preflight>().is_some();

        if !self.origin_policy.is_any() {
            append_vary(conn.response_headers_mut(), "origin");
        }

        // whether this preflight was approved at all depends on the method and headers it
        // named, so a cache must key on them
        if preflight {
            let headers = conn.response_headers_mut();
            append_vary(headers, "access-control-request-method");
            append_vary(headers, "access-control-request-headers");
        }

        let allow_origin = if self.origin_policy.is_any() {
            String::from("*")
        } else {
            let Some(AllowedOrigin(origin)) = conn.state() else {
                return conn;
            };

            // derived from the parsed origin rather than copied out of the request, so a
            // crafted `Origin` cannot inject into the response
            origin.ascii_serialization()
        };

        let allow_headers = preflight
            .then(|| match &self.allow_headers {
                AllowHeaders::Safelisted => String::new(),

                AllowHeaders::List(list) => list
                    .iter()
                    .map(HeaderName::as_ref)
                    .collect::<Vec<_>>()
                    .join(", "),

                // `*` is a literal header name rather than a wildcard on a credentialed
                // request, so the only way to say "all of them" is to name the ones asked for
                AllowHeaders::Any if self.allow_credentials => conn
                    .request_headers()
                    .token_iter(KnownHeaderName::AccessControlRequestHeaders)
                    .collect::<Vec<_>>()
                    .join(", "),

                AllowHeaders::Any => String::from("*"),
            })
            .filter(|headers| !headers.is_empty());

        let headers = conn.response_headers_mut();
        headers.insert(KnownHeaderName::AccessControlAllowOrigin, allow_origin);

        if self.allow_credentials {
            headers.insert(KnownHeaderName::AccessControlAllowCredentials, "true");
        }

        if preflight {
            // omitted rather than sent empty: a browser approves the safelisted methods with
            // or without this header, so an empty list would be noise, not a narrower policy
            if !self.allow_methods.is_empty() {
                let allow_methods = self
                    .allow_methods
                    .iter()
                    .map(Method::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                headers.insert(KnownHeaderName::AccessControlAllowMethods, allow_methods);
            }

            if let Some(allow_headers) = allow_headers {
                headers.insert(KnownHeaderName::AccessControlAllowHeaders, allow_headers);
            }

            if let Some(max_age) = self.max_age {
                headers.insert(KnownHeaderName::AccessControlMaxAge, max_age.as_secs());
            }

            return conn;
        }

        match &self.expose_headers {
            ExposeHeaders::Safelisted => {}
            ExposeHeaders::Any => {
                headers.insert(KnownHeaderName::AccessControlExposeHeaders, "*");
            }
            ExposeHeaders::List(list) if !list.is_empty() => {
                headers.insert(
                    KnownHeaderName::AccessControlExposeHeaders,
                    list.iter()
                        .map(HeaderName::as_ref)
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            ExposeHeaders::List(_) => {}
        }

        conn
    }
}

/// Extends [`Conn`] with access to the CORS decision made for this request.
pub trait CorsConnExt {
    /// The request's origin, if it was present and the policy allowed it.
    ///
    /// Returns `None` for same-origin requests, non-browser clients, and origins the policy
    /// refused, so a handler can use this to distinguish a trusted cross-origin caller
    /// without re-parsing the header.
    fn cors_origin(&self) -> Option<&Origin>;

    /// Whether this request was a preflight that the policy approved.
    ///
    /// Approved preflights are halted by this handler, so an application handler will never
    /// see one. This is for handlers that run on the way out, such as loggers.
    fn is_cors_preflight(&self) -> bool;
}

impl CorsConnExt for Conn {
    fn cors_origin(&self) -> Option<&Origin> {
        self.state::<AllowedOrigin>().map(|AllowedOrigin(o)| o)
    }

    fn is_cors_preflight(&self) -> bool {
        self.state::<Preflight>().is_some()
    }
}

/// Formatters for use with a request logger.
pub mod log_formatter {
    use super::{Conn, CorsConnExt};
    use std::borrow::Cow;

    /// The allowed origin of the request, or `-` if there was none or it was refused.
    pub fn cors_origin(conn: &Conn, _color: bool) -> Cow<'static, str> {
        conn.cors_origin().map_or(Cow::Borrowed("-"), |origin| {
            Cow::Owned(origin.ascii_serialization())
        })
    }

    /// `preflight` if this request was an approved CORS preflight, `-` otherwise.
    ///
    /// Approved preflights are halted before reaching the application, so without this they
    /// are easy to mistake for the request they were asking about.
    pub fn cors_preflight(conn: &Conn, _color: bool) -> Cow<'static, str> {
        if conn.is_cors_preflight() {
            Cow::Borrowed("preflight")
        } else {
            Cow::Borrowed("-")
        }
    }
}

/// Alias for [`Cors::allow_origins`].
///
/// # Panics
///
/// See [`Cors::allow_origins`].
pub fn cors<'a>(origins: impl IntoIterator<Item = &'a str>) -> Cors {
    Cors::allow_origins(origins)
}
