rust-jwt
========

A simple implementation to work with JWTs in Rust

## Validate tokens
The only valid algorithm today is HMAC SHA 256. The following code snippet provides an example on how to validate a tokens signature and specific claims:
```rust
extern cargo jwt;
/* ... */

use jwt::{Claims,validate_token};

/* ... */

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

let expected_claims = Claims::new("audience", "issuer");

match jwt::validate_token(token, "secret", &Some(expected_claims)){
   Ok(payload) => {
    // access to json::Json struct with payload
  },
  Err(m) => {
    // error message in m
  }
}
```

## Validating claims (not the signature)

Use this approach to validate the token claims (without checking its signature):
```rust
extern cargo jwt;
/* ... */

use jwt::{Claims,validate_claims};

/* ... */

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

let expected_claims = jwt::Claims::new("audience", "issuer");

match jwt::validate_claims(token, &Some(expected_claims)){
  Ok(payload) => {
    // access to json::Json struct with payload
  },
  Err(m) => {
    // error message in m
  }
}
```
