use super::utils::get_hostname;
use super::DOH_PATH;
use dnsstamps::*;
use failure::Error;
use http_guest::Response;
use maud::{html, DOCTYPE};

/// Explain how to configure clients
pub(crate) fn help() -> Result<Response<Vec<u8>>, Error> {
    let connection_parameters = get_connection_parameters()?;
    let body = html!(
(DOCTYPE)
html {
    body {
        h1 { "Test DNS-over-HTTPS server" }
        p { "Your DNS-over-HTTPS server is ready to accept client connections!" }
        h2 { "Usage with Mozilla Firefox" }
        ul {
            li { "In the address bar, type " code { "about:config" } "and press Return" }
            li { "Click \"I accept the risk!\" to continue to the " code { "about:config" } " page" }
            li { "Search for " code { "network.trr" } " and change its value to " code { "2" } }
            li { "Search for " code { "network.trr.uri" } " and set it to " code { (connection_parameters.uri) } }
        }
        h2 { "Usage with dnscrypt-proxy, DNSCloak and YourfriendlyDNS" }
        ul {
            li { "Copy&paste the following DNS stamp: " code { (connection_parameters.stamp) } }
        }
    }
}
    )
    .into_string();
    let resp = Response::builder()
        .status(200)
        .header("Content-Type", "text/html")
        .header("Vary", "Accept")
        .header("Cache-Control", "max-age=86400")
        .body(body.as_bytes().to_vec())?;
    Ok(resp)
}

struct ConnectionParameters {
    stamp: String,
    uri: String,
}

fn get_connection_parameters() -> Result<ConnectionParameters, Error> {
    let hostname = match get_hostname() {
        None => Err(format_err!("No host name"))?,
        Some(host_name) => host_name,
    };
    let scheme = "https";
    let path = DOH_PATH;
    let uri = format!("{}://{}{}", scheme, hostname, path);
    let stamp = DoHBuilder::new(hostname, path.to_string())
        .with_informal_property(InformalProperty::DNSSEC)
        .with_informal_property(InformalProperty::NoFilters)
        .serialize()?;

    Ok(ConnectionParameters { stamp, uri })
}
