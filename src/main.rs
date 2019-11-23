#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

mod tls;

use anyhow::Result;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rocket::State;
use rocket_contrib::templates::Template;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Mutex;

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
    let hello = tls::get_client_hello(&mut stream)?;

    let response = format!("{:#?}", hello);

    Ok(Some(response))
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
