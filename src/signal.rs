use std::io;
use std::str::FromStr;

use failure::{err_msg, Error};
use libc;

use crate::utils::cvt;

pub fn send_sigkill(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGKILL)).map(|_| ()) }
}

pub fn send_sigterm(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGTERM)).map(|_| ()) }
}

pub fn send_sigint(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGINT)).map(|_| ()) }
}

pub fn send_sigquit(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGQUIT)).map(|_| ()) }
}

pub fn send_sighup(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGHUP)).map(|_| ()) }
}

pub fn send_sigwinch(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGWINCH)).map(|_| ()) }
}

pub fn send_sigttin(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGTTIN)).map(|_| ()) }
}

pub fn send_sigttou(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGTTOU)).map(|_| ()) }
}

pub fn send_sigusr1(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGUSR1)).map(|_| ()) }
}

pub fn send_sigusr2(pid: libc::pid_t) -> io::Result<()> {
    unsafe { cvt(libc::kill(pid, libc::SIGUSR2)).map(|_| ()) }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Signal {
    #[serde(rename = "SIGKILL")]
    SIGKILL,
    #[serde(rename = "SIGTERM")]
    SIGTERM,
    #[serde(rename = "SIGINT")]
    SIGINT,
    #[serde(rename = "SIGQUIT")]
    SIGQUIT,
    #[serde(rename = "SIGHUP")]
    SIGHUP,
    #[serde(rename = "SIGWINCH")]
    SIGWINCH,
    #[serde(rename = "SIGTTIN")]
    SIGTTIN,
    #[serde(rename = "SIGTTOU")]
    SIGTTOU,
    #[serde(rename = "SIGUSR1")]
    SIGUSR1,
    #[serde(rename = "SIGUSR2")]
    SIGUSR2,
}

pub trait SignalSend {
    fn signal(&self, signal: Signal) -> io::Result<()>;
}

impl SignalSend for libc::pid_t {
    fn signal(&self, signal: Signal) -> io::Result<()> {
        match signal {
            Signal::SIGKILL => {
                send_sigkill(*self)?;
            }
            Signal::SIGTERM => {
                send_sigterm(*self)?;
            }
            Signal::SIGINT => {
                send_sigint(*self)?;
            }
            Signal::SIGQUIT => {
                send_sigquit(*self)?;
            }
            Signal::SIGHUP => {
                send_sighup(*self)?;
            }
            Signal::SIGWINCH => {
                send_sigwinch(*self)?;
            }
            Signal::SIGTTIN => {
                send_sigttin(*self)?;
            }
            Signal::SIGTTOU => {
                send_sigttou(*self)?;
            }
            Signal::SIGUSR1 => {
                send_sigusr1(*self)?;
            }
            Signal::SIGUSR2 => {
                send_sigusr2(*self)?;
            }
        }
        Ok(())
    }
}

impl SignalSend for u32 {
    fn signal(&self, signal: Signal) -> io::Result<()> {
        let pid = *self as libc::pid_t;
        match signal {
            Signal::SIGKILL => {
                send_sigkill(pid)?;
            }
            Signal::SIGTERM => {
                send_sigterm(pid)?;
            }
            Signal::SIGINT => {
                send_sigint(pid)?;
            }
            Signal::SIGQUIT => {
                send_sigquit(pid)?;
            }
            Signal::SIGHUP => {
                send_sighup(pid)?;
            }
            Signal::SIGWINCH => {
                send_sigwinch(pid)?;
            }
            Signal::SIGTTIN => {
                send_sigttin(pid)?;
            }
            Signal::SIGTTOU => {
                send_sigttou(pid)?;
            }
            Signal::SIGUSR1 => {
                send_sigusr1(pid)?;
            }
            Signal::SIGUSR2 => {
                send_sigusr2(pid)?;
            }
        }
        Ok(())
    }
}

impl FromStr for Signal {
    type Err = Error;

    fn from_str(s: &str) -> Result<Signal, Error> {
        match s {
            "SIGKILL" => Ok(Signal::SIGKILL),
            "SIGTERM" => Ok(Signal::SIGTERM),
            "SIGINT" => Ok(Signal::SIGINT),
            "SIGQUIT" => Ok(Signal::SIGQUIT),
            "SIGHUP" => Ok(Signal::SIGHUP),
            "SIGWINCH" => Ok(Signal::SIGWINCH),
            "SIGTTIN" => Ok(Signal::SIGTTIN),
            "SIGTTOU" => Ok(Signal::SIGTTOU),
            "SIGUSR1" => Ok(Signal::SIGUSR1),
            "SIGUSR2" => Ok(Signal::SIGUSR2),
            _ => Err(err_msg(format!("{} not support.", s))),
        }
    }
}
