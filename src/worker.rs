use std::collections::HashMap;
use std::ops::Sub;
use std::os::unix::io::AsRawFd;
use std::{io, thread, time};

use chrono::{DateTime, Duration, Utc};
use nix::unistd::getpid;

use config::{AckKind, RestartStrategy, WorkerConfig};
use logs::RollingLogFile;
use monitor::{Monitor, OutputKind};
use process::Process;
use signal::{Signal, SignalSend};

// #[derive(Debug)]
pub struct Worker<'a> {
    pub id: u64,
    pub name: &'a str,
    pub config: &'a WorkerConfig,
    pub processes: Vec<Process>,
    pub stdout_log: Option<Box<io::Write>>,
    pub stderr_log: Option<Box<io::Write>>,
    pub active: bool,
    pub num_processes: u64,
    extra_env: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
}

impl<'a> Worker<'a> {
    pub fn new(name: &'a str, config: &'a WorkerConfig) -> Self {
        let num_processes = config.numprocesses;
        let now = Utc::now();
        Worker {
            id: 0,
            name,
            config,
            processes: Vec::new(),
            stdout_log: None,
            stderr_log: None,
            active: false,
            num_processes,
            extra_env: Vec::new(),
            created_at: now,
            updated_at: now,
            started_at: None,
        }
    }

    pub fn add_extra_env(&mut self, k: &str, v: &str) {
        self.extra_env.push(format!("{}={}", k, v));
    }

    fn get_log_writer(s: &str) -> io::Result<Box<io::Write>> {
        // TODO support other
        let mut log: RollingLogFile = s.parse().unwrap();
        log.open()?;
        Ok(Box::new(log))
    }

    pub fn run(&mut self, monitor: &mut Monitor) -> io::Result<Vec<u32>> {
        let pid = getpid();
        let mut res = Vec::new();
        if self.stdout_log.is_none() {
            if let Some(ref s) = self.config.stdout_log {
                let w = Worker::get_log_writer(s)?;
                self.stdout_log = Some(w);
            }
        }

        if self.stderr_log.is_none() {
            if let Some(ref s) = self.config.stderr_log {
                let w = Worker::get_log_writer(s)?;
                self.stderr_log = Some(w);
            }
        }

        info!("start [{}] worker. pid [{}]", self.name, pid);
        let mut num: usize = self.num_processes as usize;
        num -= self.processes.len();
        info!(
            "spawn [{}] {} processes wait. pid [{}]",
            self.name, num, pid
        );
        for _ in 0..num {
            let pid = self.run_process(monitor)?;
            res.push(pid);
        }
        let now = Utc::now();
        self.updated_at = now;
        self.started_at = Some(now);
        self.active = true;
        Ok(res)
    }

    pub fn inc(&mut self, monitor: &mut Monitor) -> io::Result<u32> {
        let pid = getpid();
        info!("inc [{}] worker. pid [{}]", self.name, pid);
        self.num_processes += 1;
        info!("spawn processes. pid [{}]", pid);
        self.run_process(monitor)
    }

    pub fn dec(&mut self, signal: Signal) -> io::Result<u32> {
        let pid = getpid();
        if self.num_processes > 1 {
            info!("dec [{}] worker. pid [{}]", self.name, pid);
            self.num_processes -= 1;
            info!("kill processes. pid [{}]", pid);
            self.signal_one_process(signal)
        } else {
            Ok(0)
        }
    }

    pub fn run_process(&mut self, monitor: &mut Monitor) -> io::Result<u32> {
        match self.spawn_process() {
            Ok(mut p) => {
                if let Some(ref mut child) = p.child() {
                    if self.stdout_log.is_some() {
                        let stdout = child.stdout.as_ref().unwrap().as_raw_fd();
                        monitor.watch_io(stdout, OutputKind::StdOut)?;
                    };

                    if self.stderr_log.is_some() {
                        let stderr = child.stderr.as_ref().unwrap().as_raw_fd();
                        monitor.watch_io(stderr, OutputKind::StdErr)?;
                    };
                }
                info!("spawned process {}", p.process_name());
                let pid = p.pid().unwrap();
                self.processes.push(p);
                Ok(pid)
            }
            Err(e) => Err(e),
        }
    }

    fn exited(restarter: RestartStrategy, p: &mut Process, respawn: &mut usize) -> (bool) {
        p.try_wait()
            .map(|exit_code| {
                info!(
                    "exited process [{}]. exit_code [{}]",
                    p.process_name(),
                    exit_code
                );
                if restarter.need_respawn(exit_code) {
                    *respawn += 1;
                    warn!("respawn process scheduled. {}", p.process_name());
                }
                true
            })
            .unwrap_or(false)
    }

    pub fn health_check(&mut self) -> (usize, usize) {
        if self.processes.is_empty() {
            self.started_at = None;
            return (0, 0);
        }

        let restarter = self.config.restart;
        let respawn = &mut 0;
        let mut i = 0;
        while i != self.processes.len() {
            if Worker::exited(restarter, &mut self.processes[i], respawn) {
                let _p = self.processes.remove(i);
            } else {
                i += 1;
            }
        }
        (self.processes.len(), *respawn)
    }

    pub fn is_alive(&self) -> bool {
        !self.processes.is_empty()
    }

    pub fn process_pid(&mut self) -> Vec<u32> {
        let mut ret = Vec::new();
        for p in &mut self.processes {
            if let Some(pid) = p.pid() {
                ret.push(pid);
            }
        }

        ret
    }

    pub fn start_immediate(&mut self) -> bool {
        self.config.start_immediate
    }

    fn spawn_process(&mut self) -> io::Result<Process> {
        self.id += 1;
        let default = "./".to_owned();
        let wd = self.config.working_directory.as_ref().unwrap_or(&default);
        let mut penv: HashMap<String, String> = HashMap::new();

        for mut env in &self.config.environments {
            let v: Vec<&str> = env.splitn(2, '=').collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        for mut env in &self.extra_env {
            let v: Vec<&str> = env.splitn(2, '=').collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        if self.config.cmd.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fail command not found",
            ));
        }
        let mut p = Process::new(
            self.id,
            self.name.to_owned(),
            wd.to_string(),
            penv,
            &self.config,
        );
        p.spawn()?;
        Ok(p)
    }

    pub fn signal_one_process(&mut self, signal: Signal) -> io::Result<u32> {
        let mut ret = 0;
        if let Some(mut p) = self.processes.pop() {
            if let Some(pid) = p.pid() {
                ret = pid;
                if let Err(err) = pid.signal(signal) {
                    warn!("fail send signal process. cause {}", err);
                } else {
                    info!("send signal process. pid [{}]", pid);
                }
            }
        }
        Ok(ret)
    }

    fn kill_process(p: &mut Process) -> Option<u32> {
        if let Err(e) = p.kill() {
            warn!("fail kill process. cause {}", e);
            None
        } else {
            if let Some(pid) = p.pid() {
                info!("kill process. pid [{}]", pid);
                return Some(pid);
            }
            None
        }
    }

    pub fn kill(&mut self) -> io::Result<Vec<u32>> {
        debug!("kill worker processes {}", self.processes.len());
        let mut res = Vec::new();
        let mut i = 0;
        while i != self.processes.len() {
            if let Some(pid) = Worker::kill_process(&mut self.processes[i]) {
                res.push(pid);
            }
            self.processes.remove(i);
            i += 1;
        }
        self.updated_at = Utc::now();
        Ok(res)
    }

    pub fn signal_all(&mut self, sig: Signal) -> io::Result<Vec<u32>> {
        let mut pids: Vec<u32> = Vec::new();
        for p in &mut self.processes {
            let pid = p.pid().unwrap();
            debug!("send signal {:?}. {}", sig, p.process_name());
            if let Err(err) = pid.signal(sig) {
                warn!("fail send signal {:?} to pid [{}]. cause {}", sig, pid, err);
            } else {
                info!("send signal {:?} to pid [{}]", sig, pid);
                if sig == Signal::SIGTERM || sig == Signal::SIGKILL {
                    p.cleanup();
                }
                pids.push(pid);
            };
        }
        debug!("sended signal pid {:?}", pids);
        Ok(pids)
    }

    fn move_old_process(&mut self) -> Vec<Process> {
        let self_pid = getpid();
        let mut old_processes: Vec<Process> = Vec::with_capacity(self.processes.len());
        while let Some(p) = self.processes.pop() {
            old_processes.push(p);
        }
        info!(
            "move old processes. [{}] worker. pid [{}]",
            self.name, self_pid
        );
        old_processes
    }

    fn spawn_upgrade_processes(&mut self, monitor: &mut Monitor) -> io::Result<Vec<u32>> {
        let self_pid = getpid();
        let mut new = Vec::new();
        let num: usize = self.num_processes as usize;
        for _ in 0..num {
            let pid = self.run_process(monitor)?;
            new.push(pid);
        }
        info!(
            "spawn upgraded processes {:?}. [{}] worker. pid [{}]",
            new, self.name, self_pid
        );
        Ok(new)
    }

    pub fn is_spawn_fail(p: &mut Process) -> bool {
        if p.try_wait().is_some() {
            error!("fail upgrade process. pid [{:?}]", p.pid());
            true
        } else {
            false
        }
    }

    fn run_timer_ack(
        &mut self,
        monitor: &mut Monitor,
        default_signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let mut old = Vec::new();
        let self_pid = getpid();
        let mut old_processes = self.move_old_process();
        self.spawn_upgrade_processes(monitor)?;
        info!(
            "upgrading. wait ack [{:?}] [{}] worker. pid [{}]",
            self.config.ack, self.name, self_pid
        );
        let timeout = time::Duration::from_secs(self.config.ack_timeout);
        thread::sleep(timeout);
        // check new process ACK'd
        let mut failed = 0;
        let mut i = 0;
        while i != self.processes.len() {
            if Worker::is_spawn_fail(&mut self.processes[i]) {
                self.processes.remove(i);
                failed += 1;
            } else {
                i += 1;
            }
        }

        while failed > 0 {
            if let Some(p) = old_processes.pop() {
                // do not terminate old process
                self.processes.push(p);
                failed -= 1;
            }
        }

        for p in &mut old_processes {
            if let Some(pid) = p.pid() {
                debug!("send signal {:?} {}", default_signal, p.process_name(),);
                pid.signal(default_signal)?;
                old.push(pid);
            }
        }
        thread::sleep(time::Duration::from_secs(1));
        while let Some(ref mut p) = old_processes.pop() {
            if p.try_wait().is_none() {
                if let Err(err) = p.kill() {
                    warn!("fail old kill process. cause {:?}", err);
                }
                warn!("no reaction. killed old process {}", p.process_name(),);
            }
            info!("exited old process {}", p.process_name());
        }
        Ok((self.process_pid(), old))
    }

    fn run_manual_ack(
        &mut self,
        monitor: &mut Monitor,
        default_signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let mut old = Vec::new();
        let self_pid = getpid();
        let mut old_processes = self.move_old_process();
        self.spawn_upgrade_processes(monitor)?;
        info!(
            "upgrading. wait ack [{:?}] [{}] worker. pid [{}]",
            self.config.ack, self.name, self_pid
        );
        let mut tmp: Vec<Process> = Vec::with_capacity(old_processes.len());
        while !old_processes.is_empty() {
            let signals = monitor.wait_ack(self, default_signal)?;
            debug!("receive ack. custom signals {:?}", signals);
            for ack_sig in signals {
                if let Some(mut p) = old_processes.pop() {
                    if let Some(pid) = p.pid() {
                        pid.signal(ack_sig)?;
                        old.push(pid);
                        tmp.push(p);
                        debug!("sended signal {:?} to pid [{}]", ack_sig, pid);
                    }
                }
            }
            let mut failed = self.num_processes as usize - self.processes.len();
            while failed > 0 {
                if let Some(p) = old_processes.pop() {
                    self.processes.push(p);
                    failed -= 1;
                }
            }
        }
        thread::sleep(time::Duration::from_secs(1));
        while let Some(ref mut p) = tmp.pop() {
            if p.try_wait().is_none() {
                if let Err(err) = p.kill() {
                    warn!("fail kill old process. cause {:?}", err);
                }
                warn!("no reaction. killed old process {}", p.process_name());
            }
            info!("exited old process {}", p.process_name());
        }

        Ok((self.process_pid(), old))
    }

    fn run_no_ack(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let mut old = Vec::new();
        let self_pid = getpid();
        info!(
            "upgrading. wait ack [{:?}] [{}] worker. pid [{}]",
            self.config.ack, self.name, self_pid
        );

        for p in &mut self.processes {
            if let Some(pid) = p.pid() {
                debug!("send signal {:?} to {}", signal, p.process_name());
                pid.signal(signal)?;
                old.push(pid);
            }
        }
        thread::sleep(time::Duration::from_secs(1));
        while let Some(ref mut p) = self.processes.pop() {
            if p.try_wait().is_none() {
                if let Err(err) = p.kill() {
                    warn!("fail old kill process. cause {:?}", err);
                }
                warn!("no reaction. killed old process {}", p.process_name(),);
            }
            info!("exited old process {}", p.process_name());
        }
        self.spawn_upgrade_processes(monitor)?;
        Ok((self.process_pid(), old))
    }

    pub fn upgrade(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let self_pid = getpid();

        if !self.active {
            let new = Vec::new();
            let old = Vec::new();
            warn!(
                "worker not active [{}] worker. pid [{}]",
                self.name, self_pid
            );
            return Ok((new, old));
        }

        info!("start upgrade [{}] worker. pid [{}]", self.name, self_pid);
        let result = match self.config.ack {
            AckKind::Timer => self.run_timer_ack(monitor, signal)?,
            AckKind::Manual => self.run_manual_ack(monitor, signal)?,
            AckKind::None => self.run_no_ack(monitor, signal)?,
        };

        self.updated_at = Utc::now();
        info!(
            "finish upgrade [{}] worker. new_pid {:?} old_pid {:?}. pid [{}]",
            self.name, result.0, result.1, self_pid
        );
        Ok(result)
    }

    pub fn uptime(&mut self) -> Duration {
        if let Some(start) = self.started_at {
            let now = Utc::now();
            now.sub(start)
        } else {
            Duration::zero()
        }
    }

    pub fn check_live_processes(&mut self) {
        for p in &mut self.processes {
            if p.check_live_timeout(self.config.live_check_timeout) {
                // timeout process
                if let Some(pid) = p.pid() {
                    if let Err(err) = p.kill() {
                        warn!("fail kill process. cause {}", err);
                    } else {
                        info!("kill process. pid [{}]", pid);
                    }
                }
            }
        }
    }
}
