#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use anyhow::{bail, Context, Result};
use rustls::internal::msgs::deframer::MessageDeframer;
use rustls::internal::msgs::handshake::ClientHelloPayload;
use rustls::internal::msgs::handshake::HandshakeMessagePayload;
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::hsjoiner::HandshakeJoiner;
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload;
use std::net::{TcpListener, TcpStream};

#[get("/")]
fn index() -> Result<String> {
    let listener = TcpListener::bind("localhost:0")?;

    Ok(format!("{:?}", listener.local_addr()))
}

fn get_client_hello(stream: &mut TcpStream) -> Result<ClientHelloPayload> {
    let mut joiner = HandshakeJoiner::new();
    let mut deframer = MessageDeframer::new();

    while joiner.frames.is_empty() {
        deframer.read(stream)?;

        for frame in deframer.frames.drain(..) {
            joiner.take_message(frame).context("Corrupt TLS Message")?;
        }
    }

    if let Some(Message {
        payload:
            MessagePayload::Handshake(HandshakeMessagePayload {
                payload: HandshakePayload::ClientHello(hello),
                ..
            }),
        ..
    }) = joiner.frames.into_iter().next()
    {
        return Ok(hello)
    }

    bail!("Expected ClientHello");
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
