use anyhow::{anyhow, bail, ensure, Context, Result};
use nom::Err;
use serde::Serialize;
use std::borrow::Cow;
use std::io::prelude::*;
use std::io::{self, ErrorKind};
use std::net::TcpStream;
use tls_parser::tls::{parse_tls_plaintext, MAX_RECORD_LEN};
use tls_parser::tls_extensions::parse_tls_extensions;
use tls_parser::TlsMessage::Handshake;
use tls_parser::TlsMessageHandshake::ClientHello;
use tls_parser::{TlsCipherSuiteID, TlsClientHelloContents, TlsExtension, TlsVersion};
use rocket_contrib::templates::Template;

#[derive(Serialize)]
struct Version {
    name: &'static str,
    version: u16,
}

impl Version {
    fn new(version: TlsVersion) -> Self {
        let name = match version {
            TlsVersion::Ssl30 => "SSL 3.0",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
            TlsVersion::Tls13Draft18 => "TLS 1.3 Draft 18",
            TlsVersion::Tls13Draft19 => "TLS 1.3 Draft 19",
            TlsVersion::Tls13Draft20 => "TLS 1.3 Draft 20",
            TlsVersion::Tls13Draft21 => "TLS 1.3 Draft 21",
            TlsVersion::Tls13Draft22 => "TLS 1.3 Draft 22",
            TlsVersion::Tls13Draft23 => "TLS 1.3 Draft 23",
            _ => "UNKNOWN",
        };

        Self {
            name,
            version: version.0,
        }
    }
}

#[derive(Serialize)]
struct Cipher {
    name: &'static str,
    id: u16,
}

impl Cipher {
    fn new(id: TlsCipherSuiteID) -> Self {
        let name = match id.get_ciphersuite() {
            Some(suite) => suite.name,
            None => "UNKNOWN",
        };

        Self { name, id: id.0 }
    }
}

#[derive(Serialize, Default)]
struct Hello<'a> {
    raw: String,
    versions: Vec<Version>,
    ciphers: Vec<Cipher>,
    compression: bool,

    sni: Vec<Cow<'a, str>>,
}

impl<'a> Hello<'a> {
    fn new(contents: TlsClientHelloContents, extensions: Vec<TlsExtension<'a>>) -> Self {
        let raw = format!("{:#?}\n\nExtensions {:#?}", contents, extensions);
        let ciphers = contents.ciphers.into_iter().map(Cipher::new).collect();

        let mut hello = Self {
            raw,
            ciphers,
            compression: !contents.comp.is_empty(),

            ..Self::default()
        };

        for extension in extensions {
            match extension {
                TlsExtension::SNI(sni) => {
                    hello.sni = sni
                        .into_iter()
                        .map(|(_, name)| String::from_utf8_lossy(name))
                        .collect();
                }
                TlsExtension::SupportedVersions(versions) => {
                    hello.versions = versions.into_iter().map(Version::new).collect();
                }
                e => eprintln!("e = {:#?}", e),
            }
        }

        hello
    }
}

pub fn get_client_hello(stream: &mut TcpStream) -> Result<Template> {
    let mut buffer = [0; MAX_RECORD_LEN as usize];

    let written = stream.read(&mut buffer)?;
    ensure!(written > 0, io::Error::new(ErrorKind::UnexpectedEof, ""));

    let res = parse_tls_plaintext(&buffer[..written]);

    let record = match res {
        Ok((_rem, record)) => record,
        Err(Err::Incomplete(needed)) => {
            bail!("needed: {:?}", needed);
        }
        Err(e) => bail!("record parse error: {:?}", e),
    };

    let contents = match record.msg.into_iter().next() {
        Some(Handshake(ClientHello(hello))) => hello,
        other => bail!("unexpected message: {:?}", other),
    };

    let (_, extensions) = parse_tls_extensions(contents.ext.context("No extensions")?)
        .map_err(|err| anyhow!("extensions parse error: {:?}", err))?;

    Ok(Template::render("report", Hello::new(contents, extensions)))
}
