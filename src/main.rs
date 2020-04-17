#![feature(proc_macro_hygiene, decl_macro)]

mod tls;

use anyhow::Result;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rocket::State;
use rocket::{get, routes};
use rocket_contrib::templates::Template;
use serde::Serialize;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Mutex;

#[derive(Serialize)]
struct IndexContext {
    port: u16,
    url: String,
}

#[get("/")]
fn index(listeners: State<Listeners>) -> Result<Template> {
    let listener = TcpListener::bind("localhost:0")?;

    let id = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(7)
        .collect();

    let template = Template::render(
        "index",
        IndexContext {
            port: listener.local_addr()?.port(),
            url: format!("/report/{}/", id),
        },
    );
    listeners.0.lock().unwrap().insert(id, listener);

    Ok(template)
}

#[get("/report/<report>")]
fn report(report: String, listeners: State<Listeners>) -> Result<Option<Template>> {
    let listener = match listeners.0.lock().unwrap().remove(&report) {
        Some(listener) => listener,
        None => return Ok(None),
    };

    let (mut stream, _) = listener.accept()?;
    let hello = tls::get_client_hello(&mut stream)?;

    Ok(Some(hello))
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
