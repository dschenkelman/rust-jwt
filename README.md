rust-jwt
========

A simple implementation to work with JWTs in Rust

Validating claims (not the signature)
=================

Use this approach to validate the token claims (without checking its signature):
```rust
extern cargo jwt;
/* ... */

use jwt::{Claims,validate_claims};

/* ... */

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

let expected_claims = Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

match validate_claims(token, &expected_claims){
  Ok(claims) => {
    // claims are valid, have access to claims.aud, claims.iss and claims.exp
  },
  Err(message) => {
    // invalid claims, the error message details the one that failed
  }
}
```
