use http_guest::hostcalls::types::*;
use super::DOH_PATH;

/// Returns an object representing the incomding HTTP request
#[inline]
pub(crate) fn incoming_http_request() -> RequestHandle {
    RequestHandle::INCOMING
}

/// Returns a parameter from a query string
pub(crate) fn get_query_param(param: &str) -> Option<String> {
    let path = incoming_http_request().get_path();
    let mut path_parts = path.splitn(2, '?');
    if path_parts.next().is_none() {
        return None;
    }
    let query = match path_parts.next() {
        Some(query) if !query.is_empty() => query,
        _ => return None,
    };
    for parts in query.split('&') {
        let mut kv = parts.split('=');
        if let Some(k) = kv.next() {
            if k == param {
                return kv.next().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Returns the host name
pub(crate) fn get_hostname() -> Option<String> {
    let hosts = incoming_http_request().get_header("Host");
    if hosts.len() != 1 {
        return None;
    }
    hosts[0].split(':').next().map(|s| s.to_string())
}

pub(crate) fn padding_string(input_size: usize, block_size: usize) -> String {
    let block_size_ = block_size - 1;
    let padding_len = block_size_ - (input_size + block_size_) & block_size_;
    String::from_utf8(vec![b'X'; padding_len]).unwrap()
}

pub(crate) fn is_doh_query() -> bool {
    let path = incoming_http_request().get_path();
    let mut path_parts = path.splitn(2, '?');
    match path_parts.next() {
        Some(path) if path == DOH_PATH => true,
        _ => false,
    }
}
