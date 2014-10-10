extern crate serialize;
extern crate libc;

use libc::time_t;
use serialize::base64::FromBase64;
use serialize::json;

use std::str;

#[deriving(Decodable)]
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub exp: Option<i64>
}

#[deriving(Decodable)]
pub struct Header {
  pub alg: String,
  pub typ: String,
}

extern {
  fn time(time: *mut time_t) -> time_t;
}

fn epoch_seconds() -> i64 {
  unsafe {
    let mut t: i64 = 0;
    time(&mut t);
    return t;
  }
}

pub fn validate_claims(token: &str, expected_claims: &Claims) -> Result<Claims, String>{
  let parts: Vec<&str> = token.split('.').collect();
  if parts.len() != 3{
    return Err("Invalid number of parts".to_string());
  }

  // let header_part = parts[0];
  let claims_part = parts[1];

  // let decoded_header_part = header_part.as_slice().from_base64().unwrap();
  let decoded_claims_part = claims_part.as_slice().from_base64().unwrap();

  // let header_json_str = match str::from_utf8(decoded_header_part.as_slice()) {
  //     Some(e) => e,
  //     None => fail!("Invalid UTF-8 sequence"),
  // };

  let claims_json_str = match str::from_utf8(decoded_claims_part.as_slice()) {
    Some(e) => e,
    None => return Err("Invalid UTF-8 sequence".to_string()),
  };

  // let header: Header = json::decode(header_json_str.as_slice()).unwrap();

  let claims: Claims = json::decode(claims_json_str.as_slice()).unwrap();

  if expected_claims.aud != claims.aud {
    return Err("incorrect audience".to_string());
  }

  if expected_claims.iss != claims.iss {
    return Err("incorrect issuer".to_string());
  }

  match claims.exp {
    Some(exp) => {
      if exp < epoch_seconds() {
        return Err("token expired".to_string());
      }
    },
    None => {}
  }

  return Ok(claims);
}

#[cfg(test)]
mod test {
  use jwt::{Claims, validate_claims};

  #[test]
  fn test_expired_token() {
    /* always expired (unless time is wrong) */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6MTQxMjkxMjE3MH0.1IokUgfvD7zLOKdtIT5nVn4IJC-tvs0V_68LVI82jFg";

    let expected_claims = Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("token expired".to_string(), m)
    }
  }

  #[test]
  fn test_wrong_issuer() {
    /* iss should be "issuer" */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = Claims { aud: "audience".to_string(), iss: "wrong".to_string(), exp: None };

    match validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("incorrect issuer".to_string(), m)
    }
  }

  #[test]
  fn test_wrong_audience() {
    /* aud should be "audience" */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = Claims { aud: "wrong".to_string(), iss: "issuer".to_string(), exp: None };

    match validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("incorrect audience".to_string(), m)
    }
  }

  #[test]
  fn test_valid() {
    /* always valid (unless time is wrong) */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match validate_claims(token, &expected_claims){
      Ok(claims) => {
        assert_eq!(claims.aud, "audience".to_string());
        assert_eq!(claims.iss, "issuer".to_string());
        assert_eq!(claims.exp.unwrap(), 9412912170i64);
      },
      Err(_) => assert!(false)
    }
  }
}
