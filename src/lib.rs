// Copyright 2014 Damian Schenkelman

#![crate_name = "jwt"]
#![license = "MIT"]
#![crate_type = "lib"]

extern crate libc;
extern crate serialize;
extern crate openssl;
#[cfg(test)] extern crate test;

pub mod jwt;