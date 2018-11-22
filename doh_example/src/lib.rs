#![feature(proc_macro_hygiene)]
extern crate base64;
extern crate byteorder;
#[macro_use]
extern crate http_guest;
#[macro_use]
extern crate failure;
extern crate maud;

mod dns;
mod dnsstamps;
mod help;
mod utils;

use failure::Error;
use help::*;
use http_guest::{Request, Response, DNS};
use utils::*;

const BLOCK_SIZE: usize = 128;
const DOH_PATH: &str = "/doh";
const DNS_QUERY_PARAM: &str = "dns";
const MAX_TTL: u32 = 86400 * 7;
const MIN_TTL: u32 = 1;
const ERR_TTL: u32 = 1;

/// Core application logic
fn server() -> Result<Response<Vec<u8>>, Error> {
    if !is_doh_query() {
        return help();
    }
    let dns_query = match get_dns_query() {
        Ok(dns_query) => dns_query,
        Err(_) => {
            let resp = Response::builder()
                .status(501)
                .body("Unsupported".as_bytes().to_vec())?;
            return Ok(resp);
        }
    };
    let dns_response = DNS::query_raw(&dns_query)?;
    let ttl = match dns::min_ttl(&dns_response, MIN_TTL, MAX_TTL, ERR_TTL) {
        Err(_) => Err(format_err!("Invalid DNS response"))?,
        Ok(min_ttl) => min_ttl,
    };
    let resp = Response::builder()
        .status(200)
        .header("Content-Type", "application/dns-message")
        .header("Vary", "Accept")
        .header("Cache-Control", format!("max-age={}", ttl).as_str())
        .header("X-Padding", padding_string(dns_response.len(), BLOCK_SIZE))
        .body(dns_response)?;
    Ok(resp)
}

/// Get a DNS query
fn get_dns_query() -> Result<Vec<u8>, Error> {
    let dns_query = match incoming_http_request().get_method().as_str() {
        "GET" => {
            let question_str = get_query_param(DNS_QUERY_PARAM);
            match question_str.and_then(|question_str| {
                base64::decode_config(&question_str, base64::URL_SAFE_NO_PAD).ok()
            }) {
                Some(question) => question,
                _ => Err(format_err!("Missing or invalid DNS query"))?,
            }
        }
        _ => Err(format_err!("Unsupported HTTP verb"))?,
    };
    Ok(dns_query)
}

/// Wrapper for the server that turns the error case into a 500 response showing
/// the error:
fn server_(_: &Request<Vec<u8>>) -> Response<Vec<u8>> {
    match server() {
        Ok(resp) => resp,
        Err(e) => {
            let body = format!("DoH demo Error: {:?}", e);
            Response::builder()
                .status(500)
                .body(body.as_bytes().to_vec())
                .unwrap()
        }
    }
}

/// Macro that sets server_ as the entry point of the guest application:
guest_app!(server_);
