use std::fmt::{self, Debug, Formatter};
use url::{Origin, Url};

/// Which origins are allowed to read responses from this handler.
pub(crate) enum OriginPolicy {
    /// Any origin, sent as a literal `*`.
    Any,

    /// The request `Origin` must be one of these.
    List(Vec<Origin>),

    Predicate(OriginPredicate),
}

impl Debug for OriginPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("Any"),
            Self::List(origins) => f.debug_tuple("List").field(origins).finish(),
            Self::Predicate(_) => f
                .debug_tuple("Predicate")
                .field(&format_args!(".."))
                .finish(),
        }
    }
}

type PredicateFn = Box<dyn Fn(&Origin) -> bool + Send + Sync + 'static>;
pub(crate) struct OriginPredicate(PredicateFn);

impl<F> From<F> for OriginPredicate
where
    F: Fn(&Origin) -> bool + Send + Sync + 'static,
{
    fn from(f: F) -> Self {
        Self(Box::new(f))
    }
}

impl OriginPolicy {
    pub(crate) fn list<'a>(origins: impl IntoIterator<Item = &'a str>) -> Self {
        Self::List(origins.into_iter().map(parse_allowed_origin).collect())
    }

    pub(crate) fn allows(&self, origin: &Origin) -> bool {
        match self {
            Self::Any => true,
            Self::List(allowed) => allowed.contains(origin),
            Self::Predicate(OriginPredicate(predicate)) => predicate(origin),
        }
    }

    /// Whether the response depends on the request's `Origin`, and therefore whether the
    /// response must `Vary` on it.
    pub(crate) const fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }
}

/// Parses an `Origin` request header.
///
/// Opaque origins are rejected. Browsers send `Origin: null` from sandboxed iframes,
/// `file://` documents, and some redirect chains; because any sandboxed document can
/// present it, `null` identifies no one and can never be granted access.
pub(crate) fn parse_request_origin(header: &str) -> Option<Origin> {
    let origin = Url::parse(header).ok()?.origin();
    origin.is_tuple().then_some(origin)
}

/// # Panics
///
/// Panics if the provided string is not a url with a scheme and a host, or if it carries
/// anything beyond scheme, host, and port. `Origin` never contains a path, so an allowed
/// origin written as `https://example.com/app` would silently match every page on
/// `example.com`.
fn parse_allowed_origin(origin: &str) -> Origin {
    let url = Url::parse(origin)
        .unwrap_or_else(|error| panic!("could not parse allowed origin `{origin}`: {error}"));

    let origin_tuple = url.origin();

    assert!(
        origin_tuple.is_tuple(),
        "allowed origin `{origin}` does not have a host"
    );

    assert!(
        url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "allowed origin `{origin}` must contain only a scheme, host, and optional port"
    );

    origin_tuple
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(s: &str) -> Origin {
        parse_request_origin(s).unwrap()
    }

    #[test]
    fn list_matches_scheme_host_and_port() {
        let policy = OriginPolicy::list(["https://app.example.com", "http://localhost:8080"]);

        assert!(policy.allows(&origin("https://app.example.com")));
        assert!(policy.allows(&origin("http://localhost:8080")));

        // the default port is implicit and equivalent
        assert!(policy.allows(&origin("https://app.example.com:443")));

        // unlike the websockets same-origin default, an explicit list compares the scheme
        assert!(!policy.allows(&origin("http://app.example.com")));

        assert!(!policy.allows(&origin("https://example.com")));
        assert!(!policy.allows(&origin("https://app.example.com.evil.com")));
        assert!(!policy.allows(&origin("https://app.example.com:8443")));
    }

    #[test]
    fn any_allows_everything() {
        let policy = OriginPolicy::Any;
        assert!(policy.allows(&origin("https://evil.example.com")));
        assert!(policy.is_any());
    }

    #[test]
    fn predicate_receives_the_parsed_origin() {
        let policy = OriginPolicy::Predicate(OriginPredicate::from(
            |origin: &Origin| matches!(origin, Origin::Tuple(scheme, ..) if scheme == "https"),
        ));

        assert!(policy.allows(&origin("https://example.com")));
        assert!(!policy.allows(&origin("http://example.com")));
        assert!(!policy.is_any());
    }

    #[test]
    fn opaque_and_unparseable_origins_are_rejected_before_the_policy_sees_them() {
        assert!(parse_request_origin("null").is_none());
        assert!(parse_request_origin("not a url").is_none());
        assert!(parse_request_origin("").is_none());
        assert!(parse_request_origin("data:text/html,hello").is_none());
        assert!(parse_request_origin("/just/a/path").is_none());
    }

    #[test]
    fn a_parsed_origin_reserializes_without_the_request_bytes() {
        // the echoed value is derived from the parsed origin, never copied from the header,
        // so a crafted `Origin` cannot inject into the response
        assert_eq!(
            origin("https://example.com:443").ascii_serialization(),
            "https://example.com"
        );
        assert_eq!(
            origin("https://EXAMPLE.com").ascii_serialization(),
            "https://example.com"
        );
    }

    #[test]
    #[should_panic = "could not parse allowed origin"]
    fn allowed_origin_rejects_a_bare_host() {
        OriginPolicy::list(["example.com"]);
    }

    #[test]
    #[should_panic = "must contain only a scheme, host, and optional port"]
    fn allowed_origin_rejects_a_path() {
        OriginPolicy::list(["https://example.com/app"]);
    }

    #[test]
    #[should_panic = "must contain only a scheme, host, and optional port"]
    fn allowed_origin_rejects_credentials() {
        OriginPolicy::list(["https://user:pass@example.com"]);
    }

    #[test]
    #[should_panic = "does not have a host"]
    fn allowed_origin_rejects_an_opaque_origin() {
        OriginPolicy::list(["data:text/html,hello"]);
    }
}
