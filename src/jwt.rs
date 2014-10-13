extern crate serialize;
extern crate libc;
extern crate openssl;

use libc::time_t;
use serialize::base64::FromBase64;
use serialize::json;

use std::str;
use openssl::crypto::hash::{SHA256};
use openssl::crypto::hmac::{HMAC};

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
    t
  }
}

pub fn validate_token(token: &str, secret: &str, expected_claims: &Claims) -> Result<json::Json, String>{
  let parts = match split_token(token){
    Ok(p) => p,
    Err(m) => return Err(m)
  };

  let header_part = parts[0];

  let decoded_header_part = header_part.as_slice().from_base64().unwrap();

  let header_json_str = match str::from_utf8(decoded_header_part.as_slice()) {
      Some(e) => e,
      None => return Err("Invalid UTF-8 sequence".to_string()),
  };

  let header: Header = json::decode(header_json_str.as_slice()).unwrap();

  if header.alg.as_slice() != "HS256"{
    return Err(format!("Unsupported algorithm {:s}. Only supports HS256.", header.alg));
  }

  let signing_input = format!("{0}.{1}", parts[0], parts[1]);

  let mut hmac = HMAC(SHA256, secret.as_bytes());

  hmac.update(signing_input.as_bytes());

  let signature_bytes = hmac.finalize();

  let decoded_signature_part = parts[2].as_slice().from_base64().unwrap();

  if signature_bytes != decoded_signature_part{
    return Err("invalid signature".to_string());
  }

  internal_validate_claims(parts[1], expected_claims)
}

fn internal_validate_claims(payload_part: &str, expected_claims: &Claims) -> Result<json::Json, String>{
  let decoded_claims_part = payload_part.as_slice().from_base64().unwrap();

  let claims_json_str = match str::from_utf8(decoded_claims_part.as_slice()) {
    Some(e) => e,
    None => return Err("Invalid UTF-8 sequence".to_string()),
  };

  let json_payload = match json::from_str(claims_json_str){
    Ok(p) => p,
    Err(_) => return Err("Failed to parse payload section".to_string())
  };

  let aud = match json_payload.find(&"aud".to_string()){
    Some(v) => match v.as_string(){
      Some(aud) => aud,
      None => return Err("aud claim is not string".to_string())
    },
    None => return Err("aud was not provided".to_string())
  };

  let iss = match json_payload.find(&"iss".to_string()){
    Some(v) => match v.as_string(){
      Some(iss) => iss,
      None => return Err("iss claim is not string".to_string())
    },
    None => return Err("iss was not provided".to_string())
  };

  let exp = match json_payload.find(&"exp".to_string()){
    Some(v) => match v.as_i64(){
      Some(exp) => Some(exp),
      None => return Err("exp claim is not valid value".to_string())
    },
    None => None
  };

  if expected_claims.aud.as_slice() != aud {
    return Err("incorrect audience".to_string());
  }

  if expected_claims.iss.as_slice() != iss {
    return Err("incorrect issuer".to_string());
  }

  match exp {
    Some(exp) => {
      if exp < epoch_seconds() {
        return Err("token expired".to_string());
      }
    },
    None => {}
  }

  Ok(json_payload.clone())
}

fn split_token(token: &str) -> Result<Vec<&str>, String>{
  let parts: Vec<&str> = token.split('.').collect();
  if parts.len() != 3{
    return Err("Invalid number of parts".to_string());
  }

  Ok(parts)
}

pub fn validate_claims(token: &str, expected_claims: &Claims) -> Result<json::Json, String>{
  let parts = match split_token(token){
    Ok(p) => p,
    Err(m) => return Err(m)
  };

  internal_validate_claims(parts[1], expected_claims)
}

#[cfg(test)]
mod test {
  use jwt;

  #[test]
  fn test_expired_token() {
    /* always expired (unless time is wrong) */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6MTQxMjkxMjE3MH0.1IokUgfvD7zLOKdtIT5nVn4IJC-tvs0V_68LVI82jFg";

    let expected_claims = jwt::Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match jwt::validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("token expired".to_string(), m)
    }
  }

  #[test]
  fn test_wrong_issuer() {
    /* iss should be "issuer" */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = jwt::Claims { aud: "audience".to_string(), iss: "wrong".to_string(), exp: None };

    match jwt::validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("incorrect issuer".to_string(), m)
    }
  }

  #[test]
  fn test_wrong_audience() {
    /* aud should be "audience" */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = jwt::Claims { aud: "wrong".to_string(), iss: "issuer".to_string(), exp: None };

    match jwt::validate_claims(token, &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("incorrect audience".to_string(), m)
    }
  }

  #[test]
  fn test_valid_claims() {
    /* always valid (unless time is wrong) */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = jwt::Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match jwt::validate_claims(token, &expected_claims){
      Ok(payload) => {
        assert_eq!(payload.find(&"aud".to_string()).unwrap().as_string().unwrap().to_string(), "audience".to_string());
        assert_eq!(payload.find(&"iss".to_string()).unwrap().as_string().unwrap().to_string(), "issuer".to_string());
        assert_eq!(payload.find(&"exp".to_string()).unwrap().as_i64().unwrap(), 9412912170i64);
      },
      Err(_) => assert!(false)
    }
  }

  #[test]
  fn test_valid_token() {
    /* always valid (unless time is wrong) */
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = jwt::Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match jwt::validate_token(token, "secret", &expected_claims){
       Ok(payload) => {
        assert_eq!(payload.find(&"aud".to_string()).unwrap().as_string().unwrap().to_string(), "audience".to_string());
        assert_eq!(payload.find(&"iss".to_string()).unwrap().as_string().unwrap().to_string(), "issuer".to_string());
        assert_eq!(payload.find(&"exp".to_string()).unwrap().as_i64().unwrap(), 9412912170i64);
      },
      Err(_) => assert!(false)
    }
  }

  #[test]
  fn test_invalid_token_secret() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3VlciIsImV4cCI6OTQxMjkxMjE3MH0.CY-7e30citzNlDK3y3SP2ElZovyp6gID3rKpXozHo3M";

    let expected_claims = jwt::Claims { aud: "audience".to_string(), iss: "issuer".to_string(), exp: None };

    match jwt::validate_token(token, "incorrect", &expected_claims){
      Ok(_) => assert!(false),
      Err(m) => assert_eq!("invalid signature".to_string(), m)
    }
  }
}
