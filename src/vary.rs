use trillium::{Headers, KnownHeaderName};

/// Adds a field name to the response `Vary` header without disturbing any names already
/// there.
///
/// Runs from `before_send`, so the application has already had its say — clobbering `Vary`
/// would tell caches that a response varying on, say, `accept-encoding` does not.
pub(crate) fn append_vary(headers: &mut Headers, field_name: &'static str) {
    if vary_contains(headers, field_name) {
        return;
    }

    headers.append(KnownHeaderName::Vary, field_name);
}

/// `*` already subsumes every field name.
fn vary_contains(headers: &Headers, field_name: &str) -> bool {
    headers
        .token_iter(KnownHeaderName::Vary)
        .any(|existing| existing == "*" || existing.eq_ignore_ascii_case(field_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(vary: &[&'static str]) -> Headers {
        let mut headers = Headers::new();
        for value in vary {
            headers.append(KnownHeaderName::Vary, *value);
        }
        headers
    }

    fn vary(headers: &Headers) -> Vec<&str> {
        headers.token_iter(KnownHeaderName::Vary).collect()
    }

    #[test]
    fn appends_when_absent() {
        let mut headers = headers(&[]);
        append_vary(&mut headers, "origin");
        assert_eq!(vary(&headers), ["origin"]);
    }

    #[test]
    fn preserves_what_the_application_set() {
        let mut headers = headers(&["accept-encoding"]);
        append_vary(&mut headers, "origin");
        assert_eq!(vary(&headers), ["accept-encoding", "origin"]);
    }

    #[test]
    fn does_not_duplicate() {
        let mut already = headers(&["Origin"]);
        append_vary(&mut already, "origin");
        assert_eq!(vary(&already), ["Origin"]);

        let mut in_a_list = headers(&["accept-encoding, Origin"]);
        append_vary(&mut in_a_list, "origin");
        assert_eq!(vary(&in_a_list), ["accept-encoding", "Origin"]);
    }

    #[test]
    fn star_subsumes_everything() {
        let mut headers = headers(&["*"]);
        append_vary(&mut headers, "origin");
        assert_eq!(vary(&headers), ["*"]);
    }
}
