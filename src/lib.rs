// Copyright 2014 Damian Schenkelman

#![crate_name = "jwt"]
#![license = "MIT"]
#![crate_type = "lib"]

extern crate libc;
extern crate serialize;
extern crate openssl;
#[cfg(test)] extern crate test;

/// Tools for dealing with JWT (Json Web Tokens)
/// as specified [here](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

pub mod jwt;