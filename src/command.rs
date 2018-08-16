use std::io::{BufRead, BufReader, Write};
use std::ops::Add;
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::string::ToString;
use std::{io, path};

use failure::{err_msg, Error};
use nix::unistd::getpid;
use serde_json;

use signal::Signal;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Command {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "worker:killall")]
    KillAll,
    #[serde(rename = "worker:start")]
    Start,
    #[serde(rename = "worker:stop")]
    Stop,
    #[serde(rename = "worker:upgrade")]
    Upgrade, // upgrade swap process
    #[serde(rename = "worker:ack")]
    Ack,
    #[serde(rename = "worker:inc")]
    Inc,
    #[serde(rename = "worker:dec")]
    Dec,
    #[serde(rename = "worker:status")]
    Status,
}

// Use from client
impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Command, Error> {
        match s {
            "upgrade" => Ok(Command::Upgrade),
            "killall" => Ok(Command::KillAll),
            "start" => Ok(Command::Start),
            "stop" => Ok(Command::Stop),
            "inc" => Ok(Command::Inc),
            "dec" => Ok(Command::Dec),
            "status" => Ok(Command::Status),
            _ => Err(err_msg(format!("{} not support.", s))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonCommand {
    pub command_type: CommandType,
    pub worker: Option<String>,
    pub command: Option<CtrlCommand>,
    pub pid: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CommandType {
    #[serde(rename = "list")]
    List,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "ctrl_worker")]
    CtrlWorker,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CtrlCommand {
    pub command: Command,
    pub pid: u32,
    pub signal: Option<Signal>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Status {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CommandResponse {
    pub status: Status,
    pub command: Command,
    pub pid: u32,
    pub message: String,
}

impl ToString for CommandResponse {
    fn to_string(&self) -> String {
        let buf = String::new();
        // buf = buf.add(&format!("status  {:?}\n", self.status));
        // buf.add(&format!("{}", self.message))
        // buf.add(&format!("\nresponse from pid [{}]\n", self.pid))
        buf.add(&self.message)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListResponse {
    pub pid: u32,
    pub workers: Vec<String>,
}

impl ToString for ListResponse {
    fn to_string(&self) -> String {
        let mut buf = String::new();
        for w in &self.workers {
            buf = buf.add(&format!("{}\n", w));
        }
        buf
        // buf.add(&format!("\nresponse from pid [{}]\n", self.pid))
    }
}

pub fn read_daemon_command(stream: &mut UnixStream) -> io::Result<DaemonCommand> {
    let pid = getpid();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let _len = reader.read_line(&mut line)?;
    debug!("receive daemon command {:?}. pid [{}]", line, pid);
    match serde_json::from_str(&line) {
        Err(e) => {
            warn!("ctrl socket error {:?}. pid [{}]", e, pid);
            Err(io::Error::new(io::ErrorKind::InvalidInput, e))
        }
        Ok(cmd) => {
            info!("receive command. {:?}. pid [{}]", cmd, pid);
            Ok(cmd)
        }
    }
}

pub fn read_command(stream: &UnixStream) -> io::Result<CtrlCommand> {
    let pid = getpid();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let _len = reader.read_line(&mut line)?;
    debug!("receive command {:?}. pid [{}]", line, pid);
    match serde_json::from_str(&line) {
        Err(e) => {
            warn!("fail deserialize command. cause {:?}. pid [{}]", e, pid);
            Err(io::Error::new(io::ErrorKind::InvalidInput, e))
        }
        Ok(cmd) => {
            info!("receive command. {:?}. pid [{}]", cmd, pid);
            Ok(cmd)
        }
    }
}

pub fn send_ctrl_command(sock_path: &str, cmd: &CtrlCommand) -> io::Result<CommandResponse> {
    if path::Path::new(sock_path).exists() {
        let pid = getpid();
        debug!("send command to {}. pid [{}]", sock_path, pid);
        let buf = serde_json::to_string(cmd)?;
        let mut stream = UnixStream::connect(sock_path)?;
        stream.write_all(buf.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        debug!("sended ctrl command {:?}. pid [{}]", cmd, pid);
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        debug!("wait receive command response. pid [{}]", pid);
        let _len = reader.read_line(&mut line)?;
        debug!("received response {}. pid [{}]", line, pid);
        let res = serde_json::from_str(&line)?;
        Ok(res)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "require sock path",
        ))
    }
}

pub fn send_daemon_command(sock_path: &str, cmd: &DaemonCommand) -> io::Result<Box<ToString>> {
    if !path::Path::new(sock_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "require sock path",
        ));
    }
    let pid = getpid();
    debug!("send command to {}. cmd {:?} pid [{}]", sock_path, cmd, pid);
    let buf = serde_json::to_string(cmd)?;
    let mut stream = UnixStream::connect(sock_path)?;
    stream.write_all(buf.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    debug!(
        "sended command to {}. cmd {:?} pid [{}]",
        sock_path, cmd, pid
    );
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    debug!("wait receive command response. pid [{}]", pid);
    let _len = reader.read_line(&mut line)?;
    debug!("received response {}. pid [{}]", line, pid);
    if let Ok(res @ ListResponse { .. }) = serde_json::from_str(&line) {
        Ok(Box::new(res))
    } else {
        match serde_json::from_str(&line)? {
            res @ CommandResponse { .. } => Ok(Box::new(res)),
        }
    }
}

pub fn send_daemon_list_command(
    sock_path: &str,
    cmd: &DaemonCommand,
) -> io::Result<Vec<Box<ToString>>> {
    if !path::Path::new(sock_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "require sock path",
        ));
    }
    let pid = getpid();
    debug!("send command to {}. cmd {:?} pid [{}]", sock_path, cmd, pid);
    let buf = serde_json::to_string(cmd)?;
    let mut stream = UnixStream::connect(sock_path)?;
    stream.write_all(buf.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    debug!(
        "sended command to {}. cmd {:?} pid [{}]",
        sock_path, cmd, pid
    );

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    debug!("wait receive command response. pid [{}]", pid);
    let _len = reader.read_line(&mut line)?;
    debug!("received response {}. pid [{}]", line, pid);
    let response: Vec<CommandResponse> = serde_json::from_str(&line)?;
    let mut result: Vec<Box<ToString>> = Vec::new();
    for res in response {
        result.push(Box::new(res));
    }
    Ok(result)
}

pub fn send_response(stream: &mut UnixStream, res: &CommandResponse) -> io::Result<()> {
    let buf = serde_json::to_string(res)?;
    stream.write_all(buf.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}
