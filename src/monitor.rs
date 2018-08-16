use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::process::exit;
use std::string::String;
use std::{env, fs, io, path, thread, time};

use failure::{err_msg, Error};
use glob::glob;
use libc;
use mio::unix::EventedFd;
use mio::{Events, Poll, PollOpt, Ready, Token};
use nix::sys::signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, fork, getpid, ForkResult, Pid};

use app::{APP_NAME, APP_NAME_UPPER};
use command::*;
use config::WorkerConfig;
use reloader;
use signal::{Signal, SignalSend};
use sock::ListenFd;
use utils::format_duration;
use worker::Worker;

extern "C" fn handle_signal(signum: i32) {
    let s = signum as libc::c_int;
    let sigint = signal::SIGINT as libc::c_int;
    let sigquit = signal::SIGQUIT as libc::c_int;
    if s != sigint && s != sigquit {
        env::set_var(
            format!("{}_HANDLE_SIGNAL", APP_NAME_UPPER),
            format!("{}", signum),
        );
    }
}

pub enum ExitStatus {
    StillAlive,
    Interrupt,
    ForceExit,
    Restart,
}

pub struct MonitorProcess {
    pub name: String,
    pub pid: Option<Pid>,
    sock_path: String,
    pub listen_fd: Vec<RawFd>,
    pub cmd_path: path::PathBuf,
    pub cmd_mtime: time::SystemTime,
}

fn close_fds() {
    for i in 3..128 {
        let fd = i as RawFd;
        // ignore
        if let Err(e) = close(fd) {
            trace!("fd close err {:?}", e);
        }
    }
}

impl Drop for MonitorProcess {
    fn drop(&mut self) {
        self.close_listen_fd();
        self.remove_ctrl_sock();
    }
}

impl MonitorProcess {
    pub fn new(name: String, config: &WorkerConfig) -> Self {
        let sock_path = config.control_sock(&name);
        let cmd_path = reloader::cmd_path(&config);
        let metadata = cmd_path.metadata().unwrap();
        let cmd_mtime = metadata.modified().unwrap();

        MonitorProcess {
            name,
            pid: None,
            sock_path,
            listen_fd: Vec::new(),
            cmd_path,
            cmd_mtime,
        }
    }

    fn close_listen_fd(&self) {
        for fd in &self.listen_fd {
            if let Err(err) = close(*fd) {
                trace!("fail close fd. {:?} {}", err, fd);
            }
        }
    }

    pub fn remove_ctrl_sock(&self) {
        let sock_path = &self.sock_path;
        if path::Path::new(sock_path).exists() {
            if let Err(err) = fs::remove_file(&sock_path) {
                warn!("fail remove control socket {}. cause {:?}", sock_path, err);
            } else {
                info!("remove control socket. {:?}", &sock_path);
            }
        }
        self.remove_process_watch_files();
    }

    pub fn remove_process_watch_files(&self) {
        if let Some(root) = env::temp_dir().to_str() {
            if let Ok(paths) = glob(&format!("{}/{}-process-{}-*", root, APP_NAME, self.name)) {
                for entry in paths {
                    match entry {
                        Ok(ref path) => {
                            if let Err(e) = fs::remove_file(path) {
                                warn!("fail remove watch file {:?}. cause {:?}", path, e);
                            } else {
                                info!("remove watch file {:?}", path);
                            }
                        }
                        Err(_e) => {}
                    }
                }
            }
        }
    }

    pub fn send_ctrl_command(&self, cmd: &CtrlCommand) -> io::Result<()> {
        let sock_path = &self.sock_path;
        send_ctrl_command(sock_path, cmd)?;
        Ok(())
    }

    fn listen_fds(&mut self, config: &WorkerConfig) -> Result<Vec<RawFd>, Error> {
        let mut vec: Vec<RawFd> = Vec::new();
        for addr in &config.socket_address {
            let listen_fd: ListenFd = addr.parse().unwrap();
            debug!("try listen sock {}. pid [{}]", addr, getpid());
            let raw_fd = listen_fd.create_raw_fd(128)?;
            info!(
                "listen {}. pid [{}]",
                listen_fd.describe_raw_fd(raw_fd)?,
                getpid()
            );
            vec.push(raw_fd);
        }
        Ok(vec)
    }

    fn listen_ctrl_sock(&mut self) -> Result<RawFd, Error> {
        let control_sock = &self.sock_path;
        let listen_fd: ListenFd = control_sock.parse().unwrap();
        match listen_fd {
            ListenFd::UnixListener(_) => {
                let raw_fd = listen_fd.create_raw_fd(1)?;
                info!(
                    "listen control socket {}. pid [{}]",
                    listen_fd.describe_raw_fd(raw_fd)?,
                    getpid(),
                );
                Ok(raw_fd)
            }
            _ => Err(err_msg(format!("{:?} not support", listen_fd))),
        }
    }

    pub fn try_wait(&mut self) -> Result<ExitStatus, Error> {
        let self_pid = getpid();
        let flag = WaitPidFlag::WNOHANG;
        match waitpid(None, Some(flag)) {
            Ok(WaitStatus::StillAlive) => Ok(ExitStatus::StillAlive),
            Ok(WaitStatus::Exited(pid, status)) => {
                debug!(
                    "exited monitor pid [{:?}] exit_code [{:?}]",
                    libc::pid_t::from(pid),
                    status
                );
                if status == 255 {
                    Ok(ExitStatus::Restart)
                } else {
                    Ok(ExitStatus::Interrupt)
                }
            }
            Ok(WaitStatus::Continued(_pid)) => Ok(ExitStatus::StillAlive),
            Ok(WaitStatus::Stopped(pid, signal)) => {
                debug!(
                    "catch signal {:?}. name [{}] pid [{:}]",
                    signal, self.name, pid
                );
                match signal {
                    signal::SIGINT => Ok(ExitStatus::Interrupt),
                    signal::SIGQUIT => Ok(ExitStatus::Interrupt),
                    signal::SIGKILL => Ok(ExitStatus::ForceExit),
                    signal::SIGABRT => Ok(ExitStatus::ForceExit),
                    _ => Ok(ExitStatus::Restart),
                }
            }
            Ok(WaitStatus::Signaled(pid, signal, _)) => {
                debug!(
                    "catch signal {:?}. name [{}] pid [{:?}]",
                    signal, self.name, pid
                );
                match signal {
                    signal::SIGINT => Ok(ExitStatus::Interrupt),
                    signal::SIGQUIT => Ok(ExitStatus::Interrupt),
                    signal::SIGKILL => Ok(ExitStatus::ForceExit),
                    signal::SIGABRT => Ok(ExitStatus::ForceExit),
                    _ => Ok(ExitStatus::Restart),
                }
            }
            Ok(_) => Ok(ExitStatus::ForceExit),
            Err(err) => Err(err_msg(format!(
                "fail monitor process wait. cause {}. pid [{:?}]",
                err, self_pid
            ))),
        }
    }

    pub fn spawn(&mut self, name: &str, config: &WorkerConfig) -> io::Result<bool> {
        let key = config.environment_base_name.to_owned();
        match fork().expect("failed fork") {
            ForkResult::Parent { child } => {
                // parent
                self.pid = Some(child);
                Ok(true)
            }
            ForkResult::Child => {
                self.pid = Some(getpid());
                let mut worker = Worker::new(name, config);

                if let Err(err) = self.start(&key, &mut worker, config) {
                    // do cleanup
                    warn!("fail monitor start. cause {}", err);
                    return Err(err);
                }
                Ok(false)
            }
        }
    }

    pub fn start(
        &mut self,
        key: &str,
        worker: &mut Worker,
        config: &WorkerConfig,
    ) -> io::Result<bool> {
        let sa = signal::SigAction::new(
            signal::SigHandler::Handler(handle_signal),
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );
        unsafe {
            signal::sigaction(signal::SIGINT, &sa).unwrap();
            signal::sigaction(signal::SIGQUIT, &sa).unwrap();
            signal::sigaction(signal::SIGTERM, &sa).unwrap();
            signal::sigaction(signal::SIGABRT, &sa).unwrap();
            signal::sigaction(signal::SIGHUP, &sa).unwrap();
        }
        if config.warmup_delay > 0 {
            let delay = time::Duration::from_secs(config.warmup_delay);
            thread::sleep(delay);
        }
        let pid = self.pid.unwrap();
        info!("launched [{}] monitor process. pid [{}]", worker.name, pid);
        // 1. close all fd
        close_fds();
        // 2. listen fd
        let fds = self.listen_fds(config).unwrap();
        // child
        if !fds.is_empty() {
            let listen_fds = fds.len();
            info!(
                "listen [{}] fd {:?}. set env LISTEN_FDS={:?}. pid [{}]",
                worker.name,
                fds,
                listen_fds,
                getpid()
            );
            worker.add_extra_env("LISTEN_FDS", &listen_fds.to_string());
            worker.add_extra_env(&format!("{}_FD_COUNT", key), &listen_fds.to_string());
            for (i, fd) in fds.iter().enumerate() {
                worker.add_extra_env(&format!("{}_FD_{}", key, i), &fd.to_string());
                self.listen_fd.push(*fd);
            }
        }

        // 3. open control socket
        let ctrl_fd = self.listen_ctrl_sock().unwrap();
        worker.add_extra_env(&format!("{}_SOCK_FD", key), &ctrl_fd.to_string());
        worker.add_extra_env(&format!("{}_SOCK_PATH", key), &self.sock_path);
        worker.add_extra_env(&format!("{}_MASTER_PID", key), &getpid().to_string());

        let giveup = config.giveup;
        // 4. create monitor
        let mut monitor = Monitor::new(ctrl_fd, giveup);
        monitor.watch_ctrl_fd(ctrl_fd)?;
        // 5. spawn worker
        if fds.is_empty() || worker.start_immediate() {
            worker.run(&mut monitor)?;
        } else {
            // watch_fd
            for fd in fds {
                let raw_fd = fd as RawFd;
                monitor.watch_listen_fd(raw_fd)?;
            }
        }
        // 6. monitor.run
        monitor.start(worker)?;
        Ok(false)
    }

    pub fn kill_all(&mut self) -> io::Result<()> {
        self.send_ctrl_command(&CtrlCommand {
            command: Command::KillAll,
            pid: 0,
            signal: Some(Signal::SIGKILL),
        })
    }

    pub fn signal(&mut self, signal: Signal) {
        if let Some(pid) = self.pid {
            let pid = libc::pid_t::from(pid) as u32;
            debug!(
                "signal [{:?}] monitor [{}]. pid [{}]",
                signal, self.name, pid
            );
            if let Err(err) = pid.signal(signal) {
                warn!(
                    "fail signal [{:?}] monitor [{}]. cause {:?}. pid [{}]",
                    signal, self.name, err, pid
                );
            }
        }
    }
}

pub enum OutputKind {
    StdOut,
    StdErr,
}

struct IOEvent {
    pub token: Token,
    pub fd: RawFd,
    pub reader: fs::File,
    pub kind: OutputKind,
}

enum FdEvent {
    CtrlFdEvent(RawFd, Token),
    LisetnFdEvent(RawFd, Token),
}

impl IOEvent {
    fn new(token: Token, fd: RawFd, kind: OutputKind) -> Self {
        let reader: fs::File = unsafe { fs::File::from_raw_fd(fd) };
        IOEvent {
            token,
            fd,
            reader,
            kind,
        }
    }
}

pub struct Monitor {
    poll: Poll,
    token_count: usize,
    io_events: HashMap<Token, IOEvent>,
    fd_events: HashMap<Token, FdEvent>,
    ctrl_sock: UnixListener,
    giveup: u64,
    active: bool,
    pid: Pid,
}

impl Monitor {
    pub fn new(fd: RawFd, giveup: u64) -> Self {
        let listener: UnixListener = unsafe { UnixListener::from_raw_fd(fd) };
        let pid = getpid();
        Monitor {
            poll: Poll::new().unwrap(),
            token_count: 0,
            io_events: HashMap::new(),
            fd_events: HashMap::new(),
            ctrl_sock: listener,
            giveup,
            active: false,
            pid,
        }
    }

    fn next_token(&mut self) -> Token {
        self.token_count += 1;
        Token(self.token_count)
    }

    pub fn watch_io(&mut self, fd: RawFd, kind: OutputKind) -> io::Result<()> {
        let token = self.next_token();
        self.poll
            .register(&EventedFd(&fd), token, Ready::readable(), PollOpt::level())?;
        self.io_events.insert(token, IOEvent::new(token, fd, kind));
        Ok(())
    }

    pub fn watch_listen_fd(&mut self, fd: RawFd) -> io::Result<()> {
        let token = self.next_token();
        self.poll
            .register(&EventedFd(&fd), token, Ready::readable(), PollOpt::edge())?;
        self.fd_events
            .insert(token, FdEvent::LisetnFdEvent(fd, token));
        Ok(())
    }

    pub fn watch_ctrl_fd(&mut self, fd: RawFd) -> io::Result<()> {
        let token = self.next_token();
        self.poll
            .register(&EventedFd(&fd), token, Ready::readable(), PollOpt::level())?;
        self.fd_events
            .insert(token, FdEvent::CtrlFdEvent(fd, token));
        Ok(())
    }

    fn exec_command(
        &mut self,
        command: &Command,
        signal: Option<Signal>,
        worker: &mut Worker,
    ) -> io::Result<CommandResponse> {
        let name = worker.name.to_owned();
        let self_pid = libc::pid_t::from(self.pid) as u32;
        debug!("exec_command {:?} pid [{}]", command, self.pid);
        let res = match command {
            Command::KillAll => {
                let pids = worker.kill()?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("kill processes pid {:?}", pids),
                }
            }
            Command::Start => {
                let pids = worker.run(self)?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("start processes pid {:?}", pids),
                }
            }
            Command::Stop => {
                let signal = signal.unwrap_or(Signal::SIGTERM);
                let pids = worker.signal_all(signal)?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("send signal {:?} pid {:?}", signal, pids),
                }
            }
            Command::Inc => {
                let pid = worker.inc(self)?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("increments worker process pid [{}]", pid),
                }
            }
            Command::Dec => {
                let signal = signal.unwrap_or(Signal::SIGTERM);
                let pid = worker.dec(signal)?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("decrements worker process pid [{}]", pid),
                }
            }
            Command::Upgrade => {
                let signal = signal.unwrap_or(Signal::SIGUSR2);
                let (new, old) = worker.upgrade(self, signal)?;
                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!("upgrade processes new {:?} old {:?}", new, old),
                }
            }
            Command::Ack => CommandResponse {
                status: Status::Ok,
                command: command.clone(),
                pid: self_pid,
                message: "received ack".to_string(),
            },
            Command::Status => {
                let active = if worker.is_alive() {
                    "active"
                } else {
                    "stopped"
                };

                CommandResponse {
                    status: Status::Ok,
                    command: command.clone(),
                    pid: self_pid,
                    message: format!(
                        "[{}] {}\nprocesses {:?}\ntime {}",
                        name,
                        active,
                        worker.process_pid(),
                        format_duration(worker.uptime()),
                    ),
                }
            }
            cmd => CommandResponse {
                status: Status::Error,
                command: cmd.clone(),
                pid: self_pid,
                message: "not implement".to_string(),
            },
        };
        Ok(res)
    }

    fn send_ctrl_command(&mut self, cmd: &CtrlCommand, worker: &mut Worker) -> CommandResponse {
        let CtrlCommand {
            ref command,
            signal,
            ..
        } = cmd;

        match self.exec_command(command, *signal, worker) {
            Ok(res) => res,
            Err(err) => {
                error!("fail exec command. cause {:?} pid [{}]", err, self.pid);
                let pid = libc::pid_t::from(self.pid);
                CommandResponse {
                    status: Status::Error,
                    command: Command::None,
                    pid: pid as u32,
                    message: err.to_string(),
                }
            }
        }
    }

    fn wait_activate_socket(&mut self, worker: &mut Worker) -> io::Result<()> {
        // activate
        let mut events = Events::with_capacity(8);
        while !worker.active {
            info!(
                "wait client connection [{}]. pid [{}]",
                worker.name, self.pid
            );
            self.poll.poll_interruptible(&mut events, None)?;
            for event in &events {
                let token = event.token();
                if let Some(fd) = self.get_listen_event(token)? {
                    self.poll.deregister(&EventedFd(&fd))?;
                    // spawn
                    if !worker.active {
                        worker.run(self)?;
                    }
                }
                if let Err(err) = self.process_ctrl_event(token, worker) {
                    warn!("fail process ctrl event. cause {:?}", err);
                }
            }
        }
        Ok(())
    }

    fn process_log_event(&mut self, worker: &mut Worker, token: Token) -> io::Result<bool> {
        let remove = if let Some(ref mut event) = self.io_events.get_mut(&token) {
            let mut remove = false;
            let mut buf = vec![0; 4096];
            let size = event.reader.read(&mut buf[..])?;
            if size == 0 {
                self.poll.deregister(&EventedFd(&event.fd))?;
                remove = true;
            }
            match event.kind {
                OutputKind::StdOut => {
                    if let Some(ref mut log) = worker.stdout_log {
                        log.write_all(&buf[..size])?;
                        log.flush()?;
                    };
                }
                OutputKind::StdErr => {
                    if let Some(ref mut log) = worker.stderr_log {
                        log.write_all(&buf[..size])?;
                        log.flush()?;
                    };
                }
            }
            remove
        } else {
            false
        };
        Ok(remove)
    }

    fn get_listen_event(&mut self, token: Token) -> io::Result<Option<RawFd>> {
        let res = if let Some(ref mut event) = self.fd_events.get_mut(&token) {
            match event {
                FdEvent::LisetnFdEvent(fd, _) => Some(*fd),
                _ => None,
            }
        } else {
            None
        };
        Ok(res)
    }

    fn is_ctrl_event(&self, token: Token) -> bool {
        if let Some(event) = self.fd_events.get(&token) {
            if let FdEvent::CtrlFdEvent(..) = event {
                return true;
            }
        }
        false
    }

    fn get_ack_event(&mut self, token: Token) -> io::Result<Option<Signal>> {
        if self.is_ctrl_event(token) {
            let (stream, _addr) = &mut self.ctrl_sock.accept()?;
            let cmd = read_command(stream)?;
            let CtrlCommand {
                ref command,
                signal,
                ..
            } = cmd;

            match command {
                Command::Ack => return Ok(signal),
                _ => warn!("now upgrading. ignore command. pid [{}]", self.pid),
            }
        }
        Ok(None)
    }

    fn process_ctrl_event(&mut self, token: Token, worker: &mut Worker) -> io::Result<()> {
        if self.is_ctrl_event(token) {
            let (mut stream, _addr) = self.ctrl_sock.accept()?;
            let cmd = read_command(&stream)?;
            let res = self.send_ctrl_command(&cmd, worker);
            match res.command {
                Command::Ack => {
                    // ignore ack response
                    debug!("skip ack response");
                }
                _ => {
                    send_response(&mut stream, &res)?;
                }
            }
        }
        Ok(())
    }

    pub fn start(&mut self, worker: &mut Worker) -> io::Result<()> {
        info!("start [{}] monitor. pid [{}]", worker.name, self.pid);
        self.active = true;
        // listen activate socket
        if let Err(err) = self.wait_activate_socket(worker) {
            error!(
                "fail spawn process [{}] monitor. cause {:?}",
                worker.name, err
            );
            info!("exited [{}] monitor. pid [{}]", worker.name, self.pid);
            return Err(err);
        };

        let mut fail = 0;
        let timeout = Some(time::Duration::from_secs(1));
        let mut events = Events::with_capacity(1024);
        let mut now = time::SystemTime::now();

        while self.active {
            let mut alive = true;
            match self.poll.poll_interruptible(&mut events, timeout) {
                Ok(size) => {
                    for event in &events {
                        let token = event.token();
                        // catch err ?
                        if self.process_log_event(worker, token)? {
                            alive = false;
                            self.io_events.remove(&token);
                        }
                        if let Err(err) = self.process_ctrl_event(token, worker) {
                            warn!(
                                "fail process ctrl event. cause {:?} pid [{}]",
                                err, self.pid
                            );
                        }
                    }

                    if let Ok(elapsed) = now.elapsed() {
                        if elapsed.as_secs() > 1 {
                            worker.check_live_processes();
                            now = time::SystemTime::now();
                        }
                    }
                    if alive && size > 0 {
                        continue;
                    }
                    let (_alive, respawn) = worker.health_check();
                    for _ in 0..respawn {
                        if let Err(err) = worker.run_process(self) {
                            error!("respawn error. cause {} pid [{}]", err, self.pid);
                            fail += 1;
                            if self.giveup != 0 && fail >= self.giveup {
                                // giveup !!
                                self.active = false;
                                error!("GIVEUP! the process can not started. pid [{}]", self.pid);
                            }
                        } else {
                            // reset
                            fail = 0;
                        }
                    }
                }
                Err(err) => {
                    // cleanup
                    if let Err(err) = worker.signal_all(Signal::SIGTERM) {
                        warn!("fail send signal SIGTERM. cause {:?}", err);
                    }
                    if let Ok(_var) = env::var(format!("{}_HANDLE_SIGNAL", APP_NAME_UPPER)) {
                        exit(-1);
                    }
                    return Err(err);
                }
            }
        }
        worker.active = false;
        info!("exited [{}] monitor. pid [{}]", worker.name, self.pid);
        Ok(())
    }

    pub fn wait_ack(
        &mut self,
        worker: &mut Worker,
        default_signal: Signal,
    ) -> io::Result<Vec<Signal>> {
        let mut events = Events::with_capacity(1024);
        let mut ack = Vec::new();
        let timeout = Some(time::Duration::from_secs(1));
        let mut count = 0;
        while ack.is_empty() && count < 10 {
            if let Err(err) = self.poll.poll_interruptible(&mut events, timeout) {
                // cleanup
                worker.signal_all(Signal::SIGTERM)?;
                if let Ok(_var) = env::var(format!("{}_HANDLE_SIGNAL", APP_NAME_UPPER)) {
                    exit(-1);
                }
                return Err(err);
            }
            count += 1;
            for event in &events {
                let token = event.token();
                if self.process_log_event(worker, token)? {
                    self.io_events.remove(&token);
                }
                let signal = self.get_ack_event(token)?;
                ack.push(signal.unwrap_or(default_signal));
            }

            let mut i = 0;
            while i != worker.processes.len() {
                if Worker::is_spawn_fail(&mut worker.processes[i]) {
                    let _p = worker.processes.remove(i);
                } else {
                    i += 1;
                }
            }
        }

        Ok(ack)
    }
}
