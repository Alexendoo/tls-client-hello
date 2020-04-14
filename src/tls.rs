use anyhow::{anyhow, bail, ensure, Context, Result};
use nom::Err;
use std::io::prelude::*;
use std::io::{self, ErrorKind};
use std::net::TcpStream;
use tls_parser::tls::{parse_tls_plaintext, MAX_RECORD_LEN};
use tls_parser::tls_extensions::parse_tls_extensions;
use tls_parser::TlsMessage::Handshake;
use tls_parser::TlsMessageHandshake::ClientHello;

pub fn get_client_hello(stream: &mut TcpStream) -> Result<String> {
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

    let hello = match record.msg.into_iter().next() {
        Some(Handshake(ClientHello(hello))) => hello,
        other => bail!("unexpected message: {:?}", other),
    };

    let (_, extensions) = parse_tls_extensions(hello.ext.context("No extensions")?)
        .map_err(|err| anyhow!("extensions parse error: {:?}", err))?;

    Ok(format!("{:#?}\n\nExtensions {:#?}", hello, extensions))
}
