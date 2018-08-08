use std::collections::HashMap;
use std::ops::Sub;
use std::os::unix::io::AsRawFd;
use std::{io, thread, time};

use chrono::{DateTime, Duration, Utc};
use nix::unistd::getpid;

use config::{AckKind, WorkerConfig};
use logs::RollingLogFile;
use monitor::{Monitor, OutputKind};
use process::Process;
use signal::{Signal, SignalSend};

// #[derive(Debug)]
pub struct Worker {
    pub id: u64,
    pub name: String,
    pub config: WorkerConfig,
    processes: Vec<Process>,
    pub stdout_log: Option<Box<io::Write>>,
    pub stderr_log: Option<Box<io::Write>>,
    pub active: bool,
    pub num_processes: u64,
    extra_env: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
}

impl Worker {
    pub fn new(name: String, config: WorkerConfig) -> Self {
        // validate
        if let Some(ref stdout) = config.stdout_log {
            let _stdout_log: RollingLogFile = stdout.parse().unwrap();
        }
        if let Some(ref stderr) = config.stderr_log {
            let _stderr_log: RollingLogFile = stderr.parse().unwrap();
        }
        let num = config.numprocesses;
        let now = Utc::now();
        Worker {
            id: 0,
            name,
            config,
            processes: Vec::new(),
            stdout_log: None,
            stderr_log: None,
            active: false,
            num_processes: num,
            extra_env: Vec::new(),
            created_at: now,
            updated_at: now,
            started_at: None,
        }
    }

    pub fn set_config(&mut self, config: WorkerConfig) {
        self.config = config;
    }

    pub fn add_env(&mut self, k: &str, v: &str) {
        self.config.environments.push(format!("{}={}", k, v));
    }

    pub fn add_extra_env(&mut self, k: &str, v: &str) {
        self.extra_env.push(format!("{}={}", k, v));
    }

    pub fn clear_extra_env(&mut self) {
        self.extra_env.clear();
    }

    fn get_log_writer(s: &String) -> io::Result<Box<io::Write>> {
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
        num = num - self.processes.len();
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

    pub fn dec(&mut self) -> io::Result<u32> {
        let pid = getpid();
        if self.num_processes > 1 {
            info!("dec [{}] worker. pid [{}]", self.name, pid);
            self.num_processes -= 1;
            info!("kill processes. pid [{}]", pid);
            self.kill_process()
        } else {
            Ok(0)
        }
    }

    pub fn run_process(&mut self, monitor: &mut Monitor) -> io::Result<u32> {
        // ?
        match self.spawn_process() {
            Ok(mut p) => {
                if let Some(ref mut child) = p.child() {
                    if self.stdout_log.is_some() {
                        let stdout = child.stdout.as_ref().unwrap().as_raw_fd();
                        monitor.watch_io(&stdout, OutputKind::StdOut)?;
                    };

                    if self.stderr_log.is_some() {
                        let stderr = child.stderr.as_ref().unwrap().as_raw_fd();
                        monitor.watch_io(&stderr, OutputKind::StdErr)?;
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

    pub fn health_check(&mut self) -> (usize, usize) {
        if self.processes.len() == 0 {
            self.started_at = None;
            return (0, 0);
        }

        let restarter = self.config.restart;
        let mut respawn: usize = 0;
        self.processes.drain_filter(|p| {
            p.try_wait()
                .map(|exit_code| {
                    info!(
                        "exited process [{}]. exit_code [{}]",
                        p.process_name(),
                        exit_code
                    );
                    if restarter.need_respawn(exit_code) {
                        respawn += 1;
                        warn!("respawn process scheduled. {}", p.process_name());
                    }
                    true
                }).unwrap_or(false)
        });
        (self.processes.len(), respawn)
    }

    pub fn is_alive(&self) -> bool {
        self.processes.len() > 0
    }

    pub fn process_pid(&mut self) -> Vec<u32> {
        let mut ret = Vec::new();
        for p in self.processes.iter_mut() {
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
            let v: Vec<&str> = env.splitn(2, "=").collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        for mut env in &self.extra_env {
            let v: Vec<&str> = env.splitn(2, "=").collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        if self.config.cmd.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fail command not found",
            ));
        }
        let mut p = Process::new(
            self.id,
            self.name.clone(),
            &self.config.cmd,
            wd.to_string(),
            penv,
            self.config.stdout_log.is_some(),
            self.config.stderr_log.is_some(),
            self.config.uid,
            self.config.gid,
        );
        p.spawn()?;
        return Ok(p);
    }

    pub fn kill_process(&mut self) -> io::Result<u32> {
        let mut pid = 0;
        if let Some(mut p) = self.processes.pop() {
            pid = p.pid().unwrap();
            if let Err(err) = p.kill() {
                warn!("fail kill process. cause {}", err);
            } else {
                info!("kill process. pid [{}]", pid);
            }
        }
        Ok(pid)
    }

    pub fn kill(&mut self) -> io::Result<Vec<u32>> {
        debug!("kill worker processes {}", self.processes.len());
        let mut res: Vec<u32> = Vec::new();
        self.processes.drain_filter(|p| {
            if let Err(err) = p.kill() {
                warn!("fail kill process. cause {}", err);
            } else {
                info!("kill process. pid [{}]", p.pid().unwrap());
                p.pid().map(|p| res.push(p));
            }
            true
        });
        self.updated_at = Utc::now();
        Ok(res)
    }

    pub fn signal(&mut self, sig: Signal) -> io::Result<Vec<u32>> {
        let mut pids: Vec<u32> = Vec::new();
        for p in self.processes.iter_mut() {
            let pid = p.pid().unwrap();
            debug!("send signal {:?}. [{}]", sig, p.process_name());
            if let Err(err) = pid.signal(sig) {
                warn!("fail send signal {:?} to pid [{}]. cause {}", sig, pid, err);
            } else {
                info!("send signal {:?} to pid [{}]", sig, pid);
                pids.push(pid);
            };
        }
        debug!("sended signal pid {:?}", pids);
        Ok(pids)
    }

    pub fn upgrade(
        &mut self,
        monitor: &mut Monitor,
        sig: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let mut new = Vec::new();
        let mut old = Vec::new();
        let self_pid = getpid();

        if !self.active {
            warn!(
                "worker not active [{}] worker. pid [{}]",
                self.name, self_pid
            );
            return Ok((new, old));
        }

        info!("start upgrade [{}] worker. pid [{}]", self.name, self_pid);
        // 1, swap process
        let mut old_processes: Vec<Process> = Vec::with_capacity(self.processes.len());
        while self.processes.len() > 0 {
            if let Some(p) = self.processes.pop() {
                old_processes.push(p);
            }
        }
        self.processes.clear();
        info!(
            "spawn new processes wait. [{}] worker. pid [{}]",
            self.name, self_pid
        );

        // 2. spawn new process
        let num: usize = self.num_processes as usize;
        for _ in 0..num {
            // upgrade
            let pid = self.run_process(monitor)?;
            new.push(pid);
        }

        // 3. wait ack
        let timeout = time::Duration::from_secs(self.config.ack_timeout);
        info!(
            "upgrading. wait ack [{:?}] [{}] worker. pid [{}]",
            self.config.ack, self.name, self_pid
        );

        match self.config.ack {
            AckKind::Timer => {
                thread::sleep(timeout);
                // 4. kill old process
                // 4-1 send graceful shutdown signal
                // 4-2 wait
                // 4-3 force kill
                for p in old_processes.iter_mut() {
                    // send graceful shutdown signal
                    if let Some(pid) = p.pid() {
                        debug!(
                            "send signal {:?} [{}]. pid [{}]",
                            sig,
                            p.process_name(),
                            pid,
                        );
                        pid.signal(sig)?;
                        old.push(pid);
                    }
                }
                thread::sleep(timeout);
                while old_processes.len() > 0 {
                    if let Some(ref mut p) = old_processes.pop() {
                        let pid = p.pid().unwrap();
                        if p.try_wait().is_none() {
                            // force kill
                            p.kill()?;
                            warn!(
                                "no reaction. killed process [{}]. pid [{}]",
                                p.process_name(),
                                pid,
                            );
                        }
                        info!("exited process {}", p.process_name());
                    }
                }
            }

            AckKind::Manual => {
                let mut tmp: Vec<Process> = Vec::with_capacity(old_processes.len());
                while old_processes.len() > 0 {
                    let signals = monitor.wait_ack(self)?;
                    debug!("receive ack {:?}", signals);
                    // do n timwes
                    for ack_sig in signals {
                        if let Some(mut p) = old_processes.pop() {
                            // send graceful shutdown signal
                            let sig = ack_sig.unwrap_or(sig);
                            let _process_name = p.process_name();
                            if let Some(pid) = p.pid() {
                                pid.signal(sig)?;
                                old.push(pid);
                                tmp.push(p);
                                debug!("sended signal {:?} to pid [{}]", sig, pid);
                            }
                        }
                    }
                }
                thread::sleep(timeout);
                while tmp.len() > 0 {
                    if let Some(ref mut p) = tmp.pop() {
                        let pid = p.pid().unwrap();
                        if p.try_wait().is_none() {
                            if let Err(err) = p.kill() {
                                warn!("fail process kill. cause {:?}", err);
                            }
                            warn!(
                                "no reaction. killed process {}. pid {:?}",
                                p.process_name(),
                                pid,
                            );
                        }
                        info!("exited process {}. pid {:?}", p.process_name(), pid);
                    }
                }
            }
        }
        self.updated_at = Utc::now();
        info!(
            "finish upgrade [{}] worker. new {:?} old {:?}. pid [{}]",
            self.name, new, old, self_pid
        );
        Ok((new, old))
    }

    pub fn uptime(&mut self) -> Duration {
        if let Some(start) = self.started_at {
            let now = Utc::now();
            now.sub(start)
        } else {
            Duration::zero()
        }
    }
}
