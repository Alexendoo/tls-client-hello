use anyhow::{ensure, bail, Context, Result};
use std::io::{self, ErrorKind};
use std::io::prelude::*;
use std::net::TcpStream;
use tls_parser::tls::{parse_tls_plaintext, TlsPlaintext, MAX_RECORD_LEN};
use nom::Err;

pub fn get_client_hello(stream: &mut TcpStream) -> Result<()> {
    let mut buffer = [0; MAX_RECORD_LEN as usize];

    let written = dbg!(stream.read(&mut buffer)?);
    ensure!(written > 0, io::Error::new(ErrorKind::UnexpectedEof, ""));

    let res = dbg!(parse_tls_plaintext(&buffer[..written]));

    match res {
        Ok((_rem, record)) => {
            dbg!(record);
        }
        Err(Err::Incomplete(needed)) => {
            dbg!(needed);
        }
        Err(e) => {
            dbg!(e);
        }
    }

    Ok(())
}
