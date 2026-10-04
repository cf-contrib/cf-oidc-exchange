# cf-oidc-exchange-sdk

The Rust SDK for the broker's HTTP API. The API is written in
[TypeSpec](https://typespec.io), in
[`openapi/oidc/exchange/v1/exchangev1.tsp`](openapi/oidc/exchange/v1/exchangev1.tsp),
which compiles to the OpenAPI document
[`exchangev1.yaml`](openapi/oidc/exchange/v1/exchangev1.yaml) beside it.
`build.rs` generates the SDK from the document with
[openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust). The health
endpoints aren't part of it: they're hand-written, in
`src/service/handler.rs`, mounted into `v1` beside the generated code.

The document is checked in, so a Rust build needs no Node; none of the Rust is.
Edit the `.tsp`, then compile it:

```sh
cd openapi
nix develop -c npm ci             # once
nix develop -c npm run generate   # after editing the .tsp
```

CI compiles it again and fails if the document differs from the one checked in.

| Feature | |
|---|---|
| (always) | the types: requests, responses, the authorization server metadata (RFC 8414) and OpenID Provider metadata, the JWKS, OAuth errors |
| `server` | `ExchangeServiceApi`, a response enum per operation, and `exchange_service_api_router`, an axum router that checks each request against the spec before it reaches a handler. `HealthHandler`, which answers the health endpoints beside it, `/health/live` and `/health/ready`. |
| `client` | `HttpClient`, a method per operation, and `HealthClient`, which asks the health endpoints. |

Bodies are form-encoded (`application/x-www-form-urlencoded`), as RFC 8693 and
RFC 7009 have it; anything else is a `415`.
