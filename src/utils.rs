use std::path::PathBuf;
use std::{env, io, time};

use chrono::Duration;
use libc;

use app::APP_NAME;

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

pub fn get_process_watch_file(name: &str, id: u64) -> PathBuf {
    let mut dir = env::temp_dir();
    dir.push(format!("{}-process-{}-{}.id", APP_NAME, name, id));
    dir
}

pub fn get_process_mtime(name: &str, id: u64) -> io::Result<time::SystemTime> {
    let path = get_process_watch_file(name, id);
    let metadata = path.metadata()?;
    Ok(metadata.modified()?)
}

pub fn timeout_process(timeout: u64, name: &str, id: u64) -> io::Result<bool> {
    let mtime = get_process_mtime(name, id)?;
    let ret = match mtime.elapsed() {
        Ok(elapsed) => {
            let sec = elapsed.as_secs();
            sec > timeout
        }
        Err(e) => {
            warn!("fail get elapsed. cause {:?}", e);
            false
        }
    };
    Ok(ret)
}
