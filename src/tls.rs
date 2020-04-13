use anyhow::{ensure, bail, Context, Result};
use std::io::{self, ErrorKind};
use std::io::prelude::*;
use std::net::TcpStream;
use tls_parser::tls::{parse_tls_plaintext, MAX_RECORD_LEN};
use tls_parser::{TlsVersion, TlsCipherSuiteID, TlsCompressionID};
use nom::Err;

pub fn get_client_hello(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = [0; MAX_RECORD_LEN as usize];

    let written = stream.read(&mut buffer)?;
    ensure!(written > 0, io::Error::new(ErrorKind::UnexpectedEof, ""));

    let res = parse_tls_plaintext(&buffer[..written]);

    let record = match res {
        Ok((_rem, record)) => {
            record
        }
        Err(Err::Incomplete(needed)) => {
            bail!("needed: {:?}", needed);
        }
        Err(e) => {
            bail!("parse error: {:?}", e)
        }
    };

    Ok(format!("{:#?}", record))
}
