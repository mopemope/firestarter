// Zero-dependency demo server used alongside `firestarter`:
// - honors the LISTEN_FDS fd-3 handoff exactly like before, falling back to 127.0.0.1:3000;
// - sends the manual ack when FIRESTARTER_SOCK_PATH is set (the wire format is
//   guarded by command.rs's test_command_wire_format);
// - answers "Hello World!" on GET requests.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;

const ACK: &[u8] = b"{\"command\":\"worker:ack\", \"pid\":0,\"signal\":null}\n";
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello World!";

fn main() {
    if let Some(sock_path) = env::var_os("FIRESTARTER_SOCK_PATH") {
        // manual ack
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream.write_all(ACK).unwrap();
        stream.flush().unwrap();
    }

    let listener = match env::var("LISTEN_FDS") {
        Ok(fds) if fds.parse::<usize>().unwrap_or(0) >= 1 => unsafe {
            // fd 3 is the first handed-off socket (LISTEN_fds contract)
            TcpListener::from_raw_fd(3 as RawFd)
        },
        _ => TcpListener::bind("127.0.0.1:3000").unwrap(),
    };

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle(stream);
                });
            }
            Err(e) => {
                eprintln!("demo: accept failed: {}", e);
            }
        };
    }
}

fn handle(mut stream: TcpStream) {
    // consume the request so the client does not error on a reset connection
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);
    stream.write_all(HTTP_RESPONSE).unwrap();
    stream.flush().unwrap();
}
