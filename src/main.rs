#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use anyhow::{bail, Context, Result};
use rand::Rng; 
use rand::distributions::Alphanumeric;
use rocket::State;
use rocket_contrib::templates::Template;
use rustls::internal::msgs::deframer::MessageDeframer;
use rustls::internal::msgs::handshake::ClientHelloPayload;
use rustls::internal::msgs::handshake::HandshakeMessagePayload;
use rustls::internal::msgs::handshake::HandshakePayload;
use rustls::internal::msgs::hsjoiner::HandshakeJoiner;
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload;
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::collections::HashMap;

#[get("/")]
fn index(listeners: State<Listeners>) -> Result<String> {
    let listener = TcpListener::bind("localhost:0")?;
    let port = listener.local_addr()?.port();

    let id = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(7)
        .collect();
    let res = format!("port: {}, URL: http://localhost:8000/report/{}", port, id);

    listeners.0.lock().unwrap().insert(id, listener);

    Ok(res)
}

#[get("/report/<report>")]
fn report(report: String, listeners: State<Listeners>) -> Result<Option<String>> {
    let listener = match listeners.0.lock().unwrap().remove(&report) {
        Some(listener) => listener,
        None => return Ok(None),
    };

    let (mut stream, _) = listener.accept()?;
    let hello = get_client_hello(&mut stream)?;

    let response = format!("{:#?}", hello);

    Ok(Some(response))
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
        return Ok(hello);
    }

    bail!("Expected ClientHello");
}

#[derive(Default)]
struct Listeners(Mutex<HashMap<String, TcpListener>>);

fn main() {
    let listeners = Listeners::default();
    
    rocket::ignite()
        .attach(Template::fairing())
        .manage(listeners)
        .mount("/", routes![index, report])
        .launch();
}
