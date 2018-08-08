use failure::Error;
use libc::pid_t;
use nix::unistd::getpid;

use command::*;
use signal::Signal;

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Client {}
    }

    pub fn list(&mut self, sock_path: &str) -> Result<(), Error> {
        info!("show worker names.",);
        self.send_list(sock_path)
    }

    pub fn status(&mut self, sock_path: &str) -> Result<(), Error> {
        info!("show worker status.",);
        self.send_status(sock_path)
    }

    pub fn run(
        &mut self,
        sock_path: &str,
        name: &str,
        command: &str,
        signal: Option<&str>,
    ) -> Result<(), Error> {
        info!("start client. [{}] [{}]", name, command);
        self.send_ctrl_command(sock_path, name, command, signal)
    }

    fn send_ctrl_command(
        &self,
        sock_path: &str,
        name: &str,
        command: &str,
        signal: Option<&str>,
    ) -> Result<(), Error> {
        let signal = signal.map(|signal| {
            let signal: Signal = signal.parse().unwrap();
            signal
        });
        let c: Command = command.parse().unwrap();
        let pid = pid_t::from(getpid());
        let ctrl_cmd = CtrlCommand {
            command: c,
            pid: pid as u32,
            signal,
        };
        let dcmd = DaemonCommand {
            command_type: CommandType::CtrlWorker,
            worker: Some(name.to_owned()),
            command: Some(ctrl_cmd),
            pid: pid as u32,
        };
        let res = send_daemon_command(sock_path, &dcmd)?;
        println!("send ctrl command [{}] to [{}] worker", command, name);
        println!("{}", res.to_string());
        Ok(())
    }

    fn send_list(&self, sock_path: &str) -> Result<(), Error> {
        let pid = pid_t::from(getpid());
        let dcmd = DaemonCommand {
            command_type: CommandType::List,
            worker: None,
            command: None,
            pid: pid as u32,
        };
        let res = send_daemon_command(sock_path, &dcmd)?;
        println!("worker names:");
        println!("{}", res.to_string());
        Ok(())
    }

    fn send_status(&self, sock_path: &str) -> Result<(), Error> {
        let pid = pid_t::from(getpid());
        let ctrl_cmd = CtrlCommand {
            command: Command::Status,
            pid: pid as u32,
            signal: None,
        };
        let dcmd = DaemonCommand {
            command_type: CommandType::Status,
            worker: None,
            command: Some(ctrl_cmd),
            pid: pid as u32,
        };
        let res = send_daemon_list_command(sock_path, &dcmd)?;
        for r in res {
            println!("{}", r.to_string());
        }
        Ok(())
    }
}
