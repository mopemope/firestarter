use crate::command::*;
use crate::config::Config;
use crate::monitor::{ExitStatus, MonitorProcess};
use crate::process::{process_normally_exited, process_output, run_upgrader};
use crate::reloader;
use crate::sock::ListenFd;
use anyhow::{Context, Result};
use libc::pid_t;
use log::{debug, error, info, warn};
use mio::unix::EventedFd;
use mio::{Events, Poll, PollOpt, Ready, Token};
use nix::sys::signal;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet};
use nix::unistd::{getpid, Pid};
use serde_json;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{fs, path, thread, time};

extern "C" fn handle_signal(_signum: i32) {}

// #[derive(Debug)]
pub struct Daemon {
    config: Config,
    monitors: HashMap<String, MonitorProcess>,
    pid: Pid,
}

impl Daemon {
    pub fn new(config: Config) -> Result<Self> {
        let sa = SigAction::new(
            SigHandler::Handler(handle_signal),
            SaFlags::empty(),
            SigSet::empty(),
        );
        unsafe {
            sigaction(signal::SIGINT, &sa).context("failed set sigaction")?;
            sigaction(signal::SIGQUIT, &sa).context("failed set sigaction")?;
        }

        let pid = getpid();
        Ok(Daemon {
            config,
            monitors: HashMap::new(),
            pid,
        })
    }

    fn is_daemon_process(&self) -> bool {
        self.pid == getpid()
    }

    fn listen_ctrl_sock(path: &str) -> Result<UnixListener> {
        let listen_fd: ListenFd = path.parse().context("failed parse path")?;
        let pid = getpid();
        match listen_fd {
            ListenFd::UnixListener(_) => {
                let raw_fd = listen_fd.create_raw_fd(1)?;
                info!(
                    "listen control socket {}. pid [{}]",
                    listen_fd.describe_raw_fd(raw_fd)?,
                    pid,
                );
                let listener: UnixListener = unsafe { UnixListener::from_raw_fd(raw_fd) };
                Ok(listener)
            }
            _ => Err(anyhow::format_err!("{:?} not support", listen_fd)),
        }
    }

    fn send_command_worker(&mut self, cmd: DaemonCommand, stream: &mut UnixStream) -> Result<()> {
        if let Some(name) = cmd.worker {
            if let Some(config) = self.config.workers.get(&name) {
                let sock_path = config.control_sock(&name);
                let res = send_ctrl_command(&sock_path, &cmd.command.context("failed command")?)?;
                let buf = serde_json::to_string(&res)?;
                stream.write_all(buf.as_bytes())?;
                stream.write_all(b"\n")?;
                stream.flush()?;
            }
        }
        Ok(())
    }

    fn send_command_workers(&mut self, cmd: DaemonCommand, stream: &mut UnixStream) -> Result<()> {
        let cmd = &cmd.command.context("failed command")?;
        let mut v = Vec::new();
        for (name, config) in &self.config.workers {
            let sock_path = config.control_sock(name);
            let res = send_ctrl_command(&sock_path, cmd)?;
            v.push(res);
        }
        let buf = serde_json::to_string(&v)?;
        stream.write_all(buf.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(())
    }

    fn check_upgrade(&mut self) -> Result<()> {
        for (name, monitor) in &mut self.monitors {
            let config = &self.config.workers[name];
            if let Some(timeout) = config.upgrader_active_sec {
                if monitor.is_upgrade_active_time(timeout) {
                    if let Some(ref _upgrader) = config.upgrader {
                        if monitor.upgrade_process.is_none() {
                            let proc = run_upgrader(&config.upgrader_cmd)?;
                            monitor.upgrade_process = Some(proc);
                        }
                    }
                    monitor.upgrade_active_time = time::SystemTime::now();
                }
            }
        }

        Ok(())
    }

    fn check_cmd_modified(&mut self) -> Result<()> {
        let pid = getpid();
        for (name, monitor) in &mut self.monitors {
            let config = &self.config.workers[name];
            if config.auto_upgrade {
                let modified =
                    reloader::is_modified_cmd(&config, &monitor.cmd_path, &monitor.cmd_mtime)?;
                if modified {
                    info!("program upgrade detected. start upgrade. pid [{}]", pid);
                    // start upgrade
                    let upgrade_cmd = CtrlCommand {
                        command: Command::Upgrade,
                        pid: pid_t::from(self.pid) as u32,
                        signal: None,
                    };
                    let sock_path = config.control_sock(&name);
                    let res = send_ctrl_command(&sock_path, &upgrade_cmd)?;
                    let _buf = serde_json::to_string(&res)?;

                    let cmd_path = reloader::cmd_path(config);
                    let metadata = cmd_path.metadata()?;
                    let cmd_mtime = metadata.modified()?;
                    monitor.cmd_path = cmd_path;
                    monitor.cmd_mtime = cmd_mtime;
                }
            }
        }
        Ok(())
    }

    pub fn wait(&mut self, listener: &UnixListener) -> Result<()> {
        let timeout = time::Duration::from_secs(1);
        let poll = Poll::new().context("failed create Poll")?;
        let ctrl_fd: RawFd = listener.as_raw_fd();
        let listen_token = Token(1);
        poll.register(
            &EventedFd(&ctrl_fd),
            listen_token,
            Ready::readable(),
            PollOpt::edge(),
        )?;

        // start loop
        let mut now = time::SystemTime::now();
        let mut events = Events::with_capacity(128);
        while !self.monitors.is_empty() {
            if let Err(e) = poll.poll_interruptible(&mut events, Some(timeout)) {
                // Interrupt
                debug!("interrupt main loop. caused by: {} pid [{}]", e, self.pid);
                self.clean_process();
                return Ok(());
            }
            for event in &events {
                let token = event.token();
                if listen_token == token {
                    let (mut stream, _addr) = listener.accept()?;
                    let cmd = read_daemon_command(&mut stream)?;
                    match cmd.command_type {
                        CommandType::CtrlWorker => self.send_command_worker(cmd, &mut stream)?,
                        CommandType::Status => self.send_command_workers(cmd, &mut stream)?,
                        CommandType::Stop => {
                            self.send_command_workers(cmd, &mut stream)?;
                            self.stop_monitors();
                            self.clean_process();
                            return Ok(());
                        }
                        CommandType::List => self.send_list(&mut stream)?,
                    }
                }
            }

            // check every 1sec
            if let Ok(elapsed) = now.elapsed() {
                if elapsed.as_secs() >= 1 {
                    if let Err(e) = self.check_cmd_modified() {
                        warn!("fail check modified command. caused by: {}", e);
                    }
                    if let Err(e) = self.check_upgrade() {
                        warn!("fail check upgrade. caused by: {}", e);
                    }
                    if let Err(e) = self.check_upgrader_process() {
                        warn!("fail check upgrader process. caused by: {}", e);
                    }
                    if let Err(e) = self.check_monitor_processes() {
                        warn!("fail check monitor process. caused by: {}", e);
                    }
                    now = time::SystemTime::now();
                }
            }
        }
        self.clean_process();
        info!("exited daemon. pid [{}]", self.pid);
        Ok(())
    }

    fn clean_upgrade_process(&mut self, success: Vec<String>) {
        for name in success {
            if let Some(monitor) = self.monitors.get_mut(&name) {
                monitor.upgrade_process.take();
            }
        }
    }

    fn check_upgrader_process(&mut self) -> Result<()> {
        let mut need_clean = Vec::new();
        for (name, monitor) in &mut self.monitors {
            if let Some(ref mut p) = monitor.upgrade_process {
                let config = &self.config.workers[name];
                match process_normally_exited(p) {
                    Ok(true) => {
                        process_output(p);
                        info!(
                            "upgrade process terminated successfully. start upgrade pid [{}]",
                            p.id()
                        );
                        let upgrade_cmd = CtrlCommand {
                            command: Command::Upgrade,
                            pid: pid_t::from(self.pid) as u32,
                            signal: None,
                        };
                        monitor.upgrade_active_time = time::SystemTime::now();
                        let sock_path = config.control_sock(&name);
                        let res = send_ctrl_command(&sock_path, &upgrade_cmd)?;
                        let _buf = serde_json::to_string(&res)?;
                        need_clean.push(name.to_owned());
                    }
                    Ok(false) => {
                        if let Ok(elapsed) = monitor.upgrade_active_time.elapsed() {
                            if elapsed.as_secs() > config.upgrader_timeout {
                                // timeout upgrade
                                if let Err(e) = p.kill() {
                                    warn!(
                                        "fail kill upgrader process pid [{}]. caused by: {}",
                                        p.id(),
                                        e
                                    );
                                }
                                warn!(
                                    "upgrader process timeout. kill upgrader process pid [{}]",
                                    p.id()
                                );
                                monitor.upgrade_active_time = time::SystemTime::now();
                                need_clean.push(name.to_owned());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("upgrade process terminated abnormally. caused by: {}", e);
                        monitor.upgrade_active_time = time::SystemTime::now();
                        need_clean.push(name.to_owned());
                    }
                }
            }
        }

        self.clean_upgrade_process(need_clean);
        Ok(())
    }

    fn check_monitors(&mut self) -> Vec<String> {
        let mut exit_keys: Vec<String> = Vec::new();
        let mut restart_keys: Vec<String> = Vec::new();
        for (name, monitor) in &mut self.monitors {
            match monitor.try_wait() {
                Ok(ExitStatus::Interrupt) => {
                    exit_keys.push(name.to_owned());
                }
                Ok(ExitStatus::ForceExit) => {
                    exit_keys.push(name.to_owned());
                }
                Ok(ExitStatus::Restart) => {
                    restart_keys.push(name.to_owned());
                }
                Err(e) => {
                    error!(
                        "exited monitor [{}] process. caused by: {}",
                        monitor.name, e
                    );
                    exit_keys.push(name.to_owned());
                }
                _ => {}
            };
        }
        for key in exit_keys {
            if let Some(m) = self.monitors.remove(&key) {
                m.remove_ctrl_sock();
            }
        }
        for key in &restart_keys {
            if let Some(ref mut m) = self.monitors.remove(key) {
                m.remove_ctrl_sock();
            }
        }
        restart_keys
    }

    fn check_monitor_processes(&mut self) -> Result<()> {
        let timeout = time::Duration::from_millis(500);
        let restarts = self.check_monitors();
        for name in &restarts {
            if let Some(config) = self.config.workers.get(name) {
                info!("wait respawn monitor process [{}]", name);
                thread::sleep(timeout);
                let mut monitor = MonitorProcess::new(name, config)?;
                if monitor.spawn(name, config)? {
                    self.monitors.insert(name.to_owned(), monitor);
                }
            }
        }
        Ok(())
    }

    fn stop_monitors(&mut self) {
        for mon in self.monitors.values_mut() {
            if let Err(e) = mon.stop() {
                error!("fail stop monitor process. caused by: {}", e);
            }
        }
    }

    fn clean_process(&mut self) {
        for mon in self.monitors.values_mut() {
            if let Err(_e) = mon.kill_all() {}
        }
        if let Err(e) = self.check_monitor_processes() {
            error!("fail spwan monitor process. caused by: {}", e);
        }
        let delay = time::Duration::from_millis(500);
        while !self.monitors.is_empty() {
            if let Err(e) = self.check_monitor_processes() {
                error!("fail spwan monitor process. caused by: {}", e);
            }
            thread::sleep(delay);
        }
    }

    pub fn run(&mut self) -> Result<()> {
        info!("start daemon. pid [{}]", self.pid);
        for (name, config) in &mut self.config.workers {
            if !self.monitors.contains_key(name) {
                let mut monitor = MonitorProcess::new(name, config)?;
                if monitor.spawn(name, config)? {
                    self.monitors.insert(name.to_owned(), monitor);
                }
            }
        }

        if self.is_daemon_process() {
            let listener = Daemon::listen_ctrl_sock(&self.config.control_sock)?;
            if !self.monitors.is_empty() {
                self.wait(&listener)?
            }
        }
        Ok(())
    }

    fn send_list(&mut self, stream: &mut UnixStream) -> Result<()> {
        let pid = pid_t::from(getpid());
        let mut v: Vec<String> = Vec::new();
        for name in self.config.workers.keys() {
            v.push(name.to_owned());
        }
        let res = ListResponse {
            pid: pid as u32,
            workers: v,
        };
        let buf = serde_json::to_string(&res)?;
        stream.write_all(buf.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let pid = getpid();
        for (name, config) in &self.config.workers {
            let sock_path = config.control_sock(name);
            if path::Path::new(&sock_path).exists() {
                if let Err(e) = fs::remove_file(&sock_path) {
                    warn!("fail remove control socket. caused by: {} pid [{}]", e, pid);
                } else {
                    info!("remove control socke {} pid [{}]", &sock_path, pid);
                }
            }
        }
        let path = &self.config.control_sock;
        if path::Path::new(path).exists() {
            if let Err(e) = fs::remove_file(path) {
                warn!("fail remove control socket. caused by: {} pid [{}]", e, pid);
            } else {
                info!("remove control socket {} pid [{}]", path, pid);
            }
        }
    }
}
