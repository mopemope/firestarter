extern crate actix_web;
extern crate listenfd;

use actix_web::{server, App, HttpRequest, Responder};
use listenfd::ListenFd;

use std::env;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn index(_req: HttpRequest) -> impl Responder {
    "Hello World!"
}

fn main() {
    let mut listenfd = ListenFd::from_env();
    let mut server = server::new(|| App::new().resource("/", |r| r.f(index)));

    if let Some(sock_path) = env::var_os("FIRESTARTER_SOCK_PATH") {
        // manual ack
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .write_all(b"{\"command\":\"worker:ack\", \"pid\":0,\"signal\":null}")
            .unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        server.listen(l)
    } else {
        server.bind("127.0.0.1:3000").unwrap()
    };

    server.run();
}
