# trillium-cors

[![ci][ci-badge]][ci]
[![crates.io version][version-badge]][crate]
[![docs.rs][docs-badge]][docs]
[![codecov][codecov-badge]][codecov]

[ci]: https://github.com/trillium-rs/trillium-cors/actions?query=workflow%3ACI
[ci-badge]: https://github.com/trillium-rs/trillium-cors/workflows/CI/badge.svg
[version-badge]: https://img.shields.io/crates/v/trillium-cors.svg?style=flat-square
[crate]: https://crates.io/crates/trillium-cors
[docs-badge]: https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square
[docs]: https://docs.rs/trillium-cors
[codecov-badge]: https://codecov.io/gh/trillium-rs/trillium-cors/graph/badge.svg
[codecov]: https://codecov.io/gh/trillium-rs/trillium-cors

By default a browser will not let a page read a response from a different origin than the
page itself. This handler is how a server says which origins it will make an exception for,
implementing the [Fetch standard's CORS
protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).

Mount it ahead of the rest of the application. It answers the `OPTIONS` preflight a browser
sends before any request that isn't a plain `GET`, `HEAD`, or form `POST`, and it adds the
headers that let a page read the response to the requests that follow.

## Example

```rust
use trillium_cors::Cors;
use trillium::Method;

let app = (
    Cors::allow_origins(["https://app.example.com"])
        .allow_methods([Method::Get, Method::Post, Method::Delete])
        .allow_headers(["content-type", "authorization"])
        .max_age(std::time::Duration::from_secs(600)),
    "hello from an api",
);
```

## The browser is the enforcement point

CORS is not a server-side access control. A request from an origin this handler does not
allow still runs; what the browser withholds is the page's ability to read the *response*.
A disallowed origin is answered normally minus the CORS headers, and a request with no
`Origin` header passes through untouched, which is what keeps non-browser clients working.
`reject_disallowed_origins()` trades that for a `403`.

Anything that must actually be denied — authentication, authorization, CSRF — needs a
handler that enforces it, whether or not this one is present.

## WebSockets

Browsers do not apply CORS to the WebSocket handshake; RFC 6455 assigns that check to the
server, which has to compare the `Origin` header itself. This handler does not cover it, and
adding it to an application will not protect a WebSocket endpoint.

## Safety

This crate uses `#![forbid(unsafe_code)]`.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br/>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
