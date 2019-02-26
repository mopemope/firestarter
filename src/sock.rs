use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::str::FromStr;

use failure::{err_msg, Error};
use lazy_static::lazy_static;
use libc::close;
use nix::sys::socket;
use regex::Regex;

lazy_static! {
    static ref SPLIT_PREFIX: Regex = Regex::new(r"^([a-zA-Z]+)::(.+)$").unwrap();
}

#[derive(Debug)]
pub enum ListenFd {
    TcpListener(SocketAddr),
    UnixListener(PathBuf),
    UdpSocket(SocketAddr),
}

impl ListenFd {
    /// Creates a new listener from a string.
    pub fn new_listener(s: &str) -> Result<ListenFd, Error> {
        if let Ok(port) = s.parse() {
            Ok(ListenFd::TcpListener(SocketAddr::new(
                Ipv4Addr::new(127, 0, 0, 1).into(),
                port,
            )))
        } else if let Ok(socket_addr) = s.parse() {
            Ok(ListenFd::TcpListener(socket_addr))
        } else if s.contains('/') {
            ListenFd::new_unix_listener(s)
        } else {
            Err(err_msg(format!(
                "unsupported specification '{}'. please provide \
                 an explicit socket type",
                s
            )))
        }
    }

    /// Creates a new tcp listener from a string.
    pub fn new_tcp_listener(s: &str) -> Result<ListenFd, Error> {
        if let Ok(port) = s.parse() {
            Ok(ListenFd::TcpListener(SocketAddr::new(
                Ipv4Addr::new(127, 0, 0, 1).into(),
                port,
            )))
        } else {
            Ok(ListenFd::TcpListener(s.parse()?))
        }
    }

    /// Creates a new unix listener from a string.
    pub fn new_unix_listener(s: &str) -> Result<ListenFd, Error> {
        Ok(ListenFd::UnixListener(PathBuf::from(s)))
    }

    /// Creates a new udp socket from a string.
    pub fn new_udp_socket(s: &str) -> Result<ListenFd, Error> {
        if let Ok(port) = s.parse() {
            Ok(ListenFd::UdpSocket(SocketAddr::new(
                Ipv4Addr::new(127, 0, 0, 1).into(),
                port,
            )))
        } else {
            Ok(ListenFd::UdpSocket(s.parse()?))
        }
    }

    fn should_listen(&self) -> bool {
        match self {
            ListenFd::TcpListener(..) => true,
            ListenFd::UnixListener(..) => true,
            ListenFd::UdpSocket(..) => false,
        }
    }

    /// Creates a raw fd from the fd spec.
    pub fn create_raw_fd(&self, backlog: usize) -> Result<RawFd, Error> {
        create_raw_fd(self, backlog)
    }

    pub fn describe_raw_fd(&self, raw_fd: RawFd) -> Result<String, Error> {
        let addr = describe_addr(raw_fd)?;
        Ok(match self {
            ListenFd::TcpListener(..) => format!("{} fd:{} (tcp listener)", addr, raw_fd),
            ListenFd::UnixListener(..) => format!("{} fd:{} (unix listener)", addr, raw_fd),
            ListenFd::UdpSocket(..) => format!("{} fd:{} (udp)", addr, raw_fd),
        })
    }
}

impl FromStr for ListenFd {
    type Err = Error;

    fn from_str(s: &str) -> Result<ListenFd, Error> {
        let (ty, val) = if let Some(caps) = SPLIT_PREFIX.captures(s) {
            (
                Some(caps.get(1).unwrap().as_str()),
                caps.get(2).unwrap().as_str(),
            )
        } else {
            (None, s)
        };

        match ty {
            Some("tcp") => ListenFd::new_tcp_listener(val),
            Some("unix") => ListenFd::new_unix_listener(val),
            Some("udp") => ListenFd::new_udp_socket(val),
            Some(ty) => Err(err_msg(format!("unknown socket type '{}'", ty))),
            None => ListenFd::new_listener(val),
        }
    }
}

pub fn create_raw_fd(fd: &ListenFd, backlog: usize) -> Result<RawFd, Error> {
    let (addr, fam, ty) = sock_info(fd)?;
    let sock = socket::socket(fam, ty, socket::SockFlag::empty(), None)?;
    socket::setsockopt(sock, socket::sockopt::ReuseAddr, &true)?;
    let rv = socket::bind(sock, &addr).map_err(From::from).and_then(|_| {
        if fd.should_listen() {
            socket::listen(sock, backlog)?;
        }
        Ok(())
    });

    if rv.is_err() {
        unsafe { close(sock) };
    }

    rv.map(|_| sock)
}

pub fn describe_addr(raw_fd: RawFd) -> Result<impl Display, Error> {
    Ok(socket::getsockname(raw_fd)?)
}

fn sock_info(
    fd: &ListenFd,
) -> Result<(socket::SockAddr, socket::AddressFamily, socket::SockType), Error> {
    Ok(match fd {
        ListenFd::TcpListener(addr) => (
            socket::SockAddr::new_inet(socket::InetAddr::from_std(addr)),
            if addr.is_ipv4() {
                socket::AddressFamily::Inet
            } else {
                socket::AddressFamily::Inet6
            },
            socket::SockType::Stream,
        ),
        ListenFd::UdpSocket(addr) => (
            socket::SockAddr::new_inet(socket::InetAddr::from_std(addr)),
            if addr.is_ipv4() {
                socket::AddressFamily::Inet
            } else {
                socket::AddressFamily::Inet6
            },
            socket::SockType::Datagram,
        ),
        ListenFd::UnixListener(path) => (
            socket::SockAddr::new_unix(path)?,
            socket::AddressFamily::Unix,
            socket::SockType::Stream,
        ),
    })
}
