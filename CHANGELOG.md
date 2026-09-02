# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/trillium-rs/trillium-cors/compare/v0.1.0...v0.1.1) - 2026-09-02

### Other

- *(deps)* update codecov/codecov-action action to v7
- Merge pull request #2 from trillium-rs/renovate/actions-upload-pages-artifact-5.x
- *(deps)* update actions/upload-pages-artifact action to v5

## [0.1.0] - 2026-08-26

Initial release.

### Added

- `Cors` handler implementing the Fetch standard's CORS protocol: preflight responses and
  cross-origin response headers.
- Origin policies via `Cors::allow_origins`, `Cors::allow_origin_fn`, and
  `Cors::allow_any_origin`, plus the `cors(origins)` alias.
- `allow_methods`, `allow_headers`, `allow_any_header`, `expose_headers`,
  `expose_any_header`, `allow_credentials`, and `max_age`.
- `reject_disallowed_origins` to answer a disallowed origin with `403` rather than omitting
  the CORS headers.
- `CorsConnExt` with `cors_origin` and `is_cors_preflight`.
- `log_formatter::cors_origin` and `log_formatter::cors_preflight` for use with a request
  logger.
