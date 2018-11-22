use byteorder::{LittleEndian, WriteBytesExt};
use std::io::{self, Write};

/// Compute the DNS stamp of a DoH server
#[derive(Default, Debug)]
pub struct DoHBuilder {
    informal_properties: u64,
    addrs: Vec<String>,
    hashes: Vec<Vec<u8>>,
    hostname: String,
    path: String,
    bootstrap_ips: Vec<String>,
}

impl DoHBuilder {
    pub fn new(hostname: String, path: String) -> Self {
        DoHBuilder {
            informal_properties: 0,
            addrs: vec![],
            hostname,
            path,
            hashes: vec![],
            bootstrap_ips: vec![],
        }
    }

    pub fn with_address(mut self, addr: String) -> Self {
        self.addrs.push(addr);
        self
    }

    pub fn with_cert_hash(mut self, hash: Vec<u8>) -> Self {
        self.hashes.push(hash);
        self
    }

    pub fn with_bootstrap_ip(mut self, ip: String) -> Self {
        self.bootstrap_ips.push(ip);
        self
    }

    pub fn serialize(self) -> io::Result<String> {
        let mut bin = vec![];
        bin.push(0x02);
        bin.write_u64::<LittleEndian>(self.informal_properties)?;
        let addrs_bin: Vec<_> = self
            .addrs
            .iter()
            .map(|addr| addr.as_bytes().to_vec())
            .collect();
        vlp_encode(&mut bin, &addrs_bin)?;
        vlp_encode(&mut bin, &self.hashes)?;
        lp_encode(&mut bin, &self.hostname.as_bytes())?;
        lp_encode(&mut bin, &self.path.as_bytes())?;
        if !self.bootstrap_ips.is_empty() {
            let bootstrap_ips_bin: Vec<_> = self
                .bootstrap_ips
                .iter()
                .map(|ip| ip.as_bytes().to_vec())
                .collect();
            vlp_encode(&mut bin, &bootstrap_ips_bin)?;
        }
        let serialized = base64::encode_config(
            &bin,
            base64::Config::new(base64::CharacterSet::UrlSafe, false),
        );
        Ok(format!("sdns://{}", serialized))
    }
}

pub enum InformalProperty {
    DNSSEC,
    NoLogs,
    NoFilters,
}

impl From<InformalProperty> for u64 {
    fn from(informal_property: InformalProperty) -> u64 {
        match informal_property {
            InformalProperty::DNSSEC => 0x01,
            InformalProperty::NoLogs => 0x02,
            InformalProperty::NoFilters => 0x04,
        }
    }
}

pub trait WithInformalProperty {
    fn with_informal_property(self, informal_property: InformalProperty) -> Self;
}

fn lp_encode<W: Write>(writer: &mut W, string: &[u8]) -> io::Result<()> {
    let mut encoded = vec![];
    let len = string.len();
    assert!(len <= 0xff);
    encoded.push(len as u8);
    encoded.extend(&string[..]);
    writer.write_all(&encoded)
}

fn vlp_encode<W: Write>(writer: &mut W, strings: &[Vec<u8>]) -> io::Result<()> {
    if strings.is_empty() {
        return writer.write_all(&[0u8]);
    }
    let mut encoded = vec![];
    let mut it = strings.iter();
    let mut next = it.next();
    while let Some(string) = next {
        next = it.next();
        let len = string.len();
        assert!(len < 0x80);
        match next {
            None => encoded.push(len as u8),
            _ => encoded.push(0x80 | len as u8),
        };
        encoded.extend(&string[..]);
    }
    writer.write_all(&encoded)
}

impl WithInformalProperty for DoHBuilder {
    fn with_informal_property(mut self, informal_property: InformalProperty) -> Self {
        self.informal_properties |= u64::from(informal_property);
        self
    }
}

#[test]
fn test_doh() {
    let b = DoHBuilder::new("example.com".to_owned(), "/dns".to_owned())
        .with_address("127.0.0.1:443".to_string())
        .with_informal_property(InformalProperty::DNSSEC)
        .serialize()
        .unwrap();
    assert_eq!(
        b,
        "sdns://AgEAAAAAAAAADTEyNy4wLjAuMTo0NDMAC2V4YW1wbGUuY29tBC9kbnM",
    )
}
