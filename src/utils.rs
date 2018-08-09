use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use chrono::Duration;
use libc;

pub fn check_fd() {
    let path = Path::new("/tmp/a");
    let file: File = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    let fd = file.as_raw_fd();
    info!("! FD = {:?}", fd);
}

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

impl IsMinusOne for i32 {
    fn is_minus_one(&self) -> bool {
        *self == -1
    }
}
impl IsMinusOne for isize {
    fn is_minus_one(&self) -> bool {
        *self == -1
    }
}

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    use std::io;

    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

pub fn set_nonblock(fd: libc::c_int) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        cvt(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)).map(|_| ())
    }
}

pub fn set_block(fd: libc::c_int) -> io::Result<()> {
    unsafe { cvt(libc::fcntl(fd, libc::F_SETFL, 0)).map(|_| ()) }
}

pub fn format_duration(d: Duration) -> String {
    let h = d.num_hours();
    let m = d.num_minutes() % 60;
    let s = d.num_seconds() % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}
