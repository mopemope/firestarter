// Zero-dependency demo server used alongside `firestarter`:
// - honors the LISTEN_FDS fd-3 handoff exactly like before, falling back to 127.0.0.1:3000;
// - sends the manual ack when FIRESTARTER_SOCK_PATH is set (the wire format is
//   guarded by command.rs's test_command_wire_format);
// - answers "Hello World!" for "/" like the old actix demo (all methods);
//   other paths get 404.

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
    // actix dispatched on a fully received request line: accumulate until the
    // first '\n' (or EOF / buffer full) so a TCP segment boundary inside the
    // request line cannot be judged as a wrong request.
    let mut buf = [0u8; 1024];
    let mut used = 0;
    let line_end = loop {
        if used == buf.len() {
            break buf.len();
        }
        match stream.read(&mut buf[used..]) {
            Ok(0) => break used,
            Ok(n) => {
                used += n;
                if let Some(pos) = buf[..used].iter().position(|&b| b == b'\n') {
                    break pos;
                }
            }
            Err(_) => return,
        }
    };
    // Same contract as the original actix demo (resource("/", r.f(index)),
    // an unfiltered route): every method on "/" answers "Hello World!";
    // other paths get 404 (actix's default for unmatched paths).
    let path = buf[..line_end]
        .split(|&b| b == b' ')
        .filter(|p| !p.is_empty())
        .nth(1)
        .unwrap_or(b"");
    let response: &[u8] = if path == b"/" {
        HTTP_RESPONSE
    } else {
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    };
    let _ = stream.write_all(response);
    let _ = stream.flush();
}
