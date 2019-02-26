use std::collections::HashMap;
use std::ops::Sub;
use std::os::unix::io::AsRawFd;
use std::{io, thread, time};

use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use nix::unistd::getpid;

use crate::config::{AckKind, RestartStrategy, RunUpgrader, WorkerConfig};
use crate::logs::LogFile;
use crate::monitor::{Monitor, OutputKind};
use crate::process::{
    output_stderr_log, output_stdout_log, process_exited, run_exec_stop, run_upgrader, Process,
};
use crate::signal::{Signal, SignalSend};

// #[derive(Debug)]
pub struct Worker<'a> {
    pub id: u64,
    pub name: &'a str,
    pub config: &'a WorkerConfig,
    pub processes: Vec<Process<'a>>,
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
        let mut log: LogFile = s.parse().unwrap();
        log.open()?;
        Ok(Box::new(log))
    }

    pub fn run(&mut self, monitor: &mut Monitor) -> io::Result<Vec<u32>> {
        let pid = getpid();
        debug!(
            "prepare [{}] worker. created [{}] pid [{}]",
            self.name, self.created_at, pid
        );
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

    fn process_health_check(
        restarter: RestartStrategy,
        p: &mut Process,
        respawn: &mut usize,
    ) -> (bool) {
        p.try_wait()
            .map(|exit_code| {
                info!(
                    "detect exited process {}. exit_code [{}]",
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
            if Worker::process_health_check(restarter, &mut self.processes[i], respawn) {
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

    fn spawn_process(&mut self) -> io::Result<Process<'a>> {
        self.id += 1;
        let mut penv: HashMap<String, String> = HashMap::new();
        for env in &self.config.environments {
            let v: Vec<&str> = env.splitn(2, '=').collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        for env in &self.extra_env {
            let v: Vec<&str> = env.splitn(2, '=').collect();
            if v.len() == 2 {
                penv.insert(v[0].to_string(), v[1].to_string());
            } else {
                warn!("skip broken env configuration. {:?}", v);
            }
        }
        if self.config.exec_start_cmd.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fail command not found",
            ));
        }
        let mut p = Process::new(
            self.id,
            self.name,
            &self.config.working_directory,
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
                if let Err(e) = pid.signal(signal) {
                    warn!("fail send signal process. caused by: {}", e);
                } else {
                    info!("send signal process. pid [{}]", pid);
                }
            }
        }
        Ok(ret)
    }

    fn kill_process(p: &mut Process) -> Option<u32> {
        if let Err(e) = p.kill() {
            warn!("fail kill process. caused by: {}", e);
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
        while let Some(ref mut p) = self.processes.pop() {
            if let Some(pid) = Worker::kill_process(p) {
                res.push(pid);
            }
            p.wait();
        }
        self.updated_at = Utc::now();
        Ok(res)
    }

    pub fn signal_all(&mut self, sig: Signal) -> io::Result<Vec<u32>> {
        let mut pids: Vec<u32> = Vec::new();
        for p in &mut self.processes {
            let pid = p.pid().unwrap();
            debug!("send signal {:?}. {}", sig, p.process_name());
            if let Err(e) = pid.signal(sig) {
                warn!(
                    "fail send signal {:?} to pid [{}]. caused by: {}",
                    sig, pid, e
                );
            } else {
                info!("send signal {:?} to pid [{}]", sig, pid);
                pids.push(pid);
            };
        }
        debug!("sended signal pid {:?}", pids);
        Ok(pids)
    }

    pub fn signal_and_wait(&mut self, sig: Signal) -> io::Result<Vec<u32>> {
        let mut pids: Vec<u32> = Vec::new();
        while let Some(ref mut p) = self.processes.pop() {
            let pid = p.pid().unwrap();
            debug!("send signal {:?}. {}", sig, p.process_name());
            if let Err(e) = pid.signal(sig) {
                warn!(
                    "fail send signal {:?} to pid [{}]. caused by: {}",
                    sig, pid, e
                );
            } else {
                info!("send signal {:?} to pid [{}]", sig, pid);
                pids.push(pid);
            };
            p.wait();
        }
        debug!("sended signal pid {:?}", pids);
        Ok(pids)
    }

    pub fn cleanup_process(&mut self, p: &mut Process) -> io::Result<()> {
        if let Some(ref mut p) = p.child() {
            if let Some(ref mut writer) = self.stdout_log {
                output_stdout_log(p, writer)?;
            }
            if let Some(ref mut writer) = self.stderr_log {
                output_stderr_log(p, writer)?;
            }
        }
        Ok(())
    }

    fn move_old_process(&mut self) -> Vec<Process<'a>> {
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
            "spawn new processes {:?}. [{}] worker. pid [{}]",
            new, self.name, self_pid
        );
        Ok(new)
    }

    fn run_timer_ack(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
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
            if process_exited(&mut self.processes[i]) {
                let mut p = self.processes.remove(i);
                if let Err(e) = self.cleanup_process(&mut p) {
                    warn!("fail cleanup process {}. caused by {}", p.process_name(), e);
                }
                info!("exited process {}", p.process_name(),);
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
                info!("send ack signal {:?} {}", signal, p.process_name(),);
                pid.signal(signal)?;
                old.push(pid);
            }
        }
        monitor.wait_process_io(self, 1)?;
        while let Some(ref mut p) = old_processes.pop() {
            if p.try_wait().is_none() {
                if let Err(e) = p.kill() {
                    warn!("fail old kill process. caused by: {}", e);
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
        signal: Signal,
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
            let signals = monitor.wait_ack(self, signal)?;
            debug!("receive ack. custom signals {:?}", signals);
            for ack_sig in signals {
                if let Some(mut p) = old_processes.pop() {
                    if let Some(pid) = p.pid() {
                        info!("send ack signal {:?} {}", signal, p.process_name());
                        pid.signal(ack_sig)?;
                        old.push(pid);
                        tmp.push(p);
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

        monitor.wait_process_io(self, 1)?;
        while let Some(ref mut p) = tmp.pop() {
            if p.try_wait().is_none() {
                if let Err(e) = p.kill() {
                    warn!("fail kill old process. caused by: {}", e);
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
        let self_pid = getpid();
        info!(
            "upgrading. wait ack [{:?}] [{}] worker. pid [{}]",
            self.config.ack, self.name, self_pid
        );

        let old_pid = self.stop_processes(monitor, signal)?;
        while let Some(ref mut p) = self.processes.pop() {
            if p.try_wait().is_none() {
                if let Err(e) = p.kill() {
                    warn!("fail old kill process. caused by: {}", e);
                }
                warn!("no reaction. killed old process {}", p.process_name(),);
            }
            info!("exited old process {}", p.process_name());
        }
        self.spawn_upgrade_processes(monitor)?;
        Ok((self.process_pid(), old_pid))
    }

    pub fn upgrade(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let self_pid = getpid();
        info!("start upgrade [{}] worker. pid [{}]", self.name, self_pid);
        if !self.active {
            let new_pid = Vec::new();
            let old_pid = Vec::new();
            warn!(
                "worker not active [{}] worker. pid [{}]",
                self.name, self_pid
            );
            return Ok((new_pid, old_pid));
        }

        if self.config.run_upgrader == RunUpgrader::OnUpgrade {
            if let Some(ref _upgrader) = self.config.upgrader {
                let mut proc = run_upgrader(&self.config.upgrader_cmd)?;
                if !monitor.wait_on_upgrader(self, &mut proc)? {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "upgrade process terminated abnormally",
                    ));
                }
            }
        }

        let result = match self.config.ack {
            AckKind::Timer => self.run_timer_ack(monitor, signal)?,
            AckKind::Manual => self.run_manual_ack(monitor, signal)?,
            AckKind::None => self.run_no_ack(monitor, signal)?,
        };

        self.updated_at = Utc::now();
        info!(
            "success upgrade [{}] worker. new_pid {:?} old_pid {:?}. pid [{}]",
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
                    if let Err(e) = p.kill() {
                        warn!("fail kill process. caused by: {}", e);
                    } else {
                        info!("kill process. pid [{}]", pid);
                    }
                }
            }
        }
    }

    pub fn stop_processes(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
    ) -> io::Result<Vec<u32>> {
        let mut old_pid = Vec::new();
        if self.processes.is_empty() {
            return Ok(old_pid);
        }
        if self.config.exec_stop_cmd.is_empty() {
            for p in &mut self.processes {
                if let Some(pid) = p.pid() {
                    info!("send terminate signal {:?} {}", signal, p.process_name());
                    pid.signal(signal)?;
                    old_pid.push(pid);
                }
            }
            monitor.wait_process_io(self, 1)?;
        } else {
            for p in &mut self.processes {
                if let Some(pid) = p.pid() {
                    old_pid.push(pid);
                }
            }

            let stopper = run_exec_stop(&self.config.exec_stop_cmd)?;
            monitor.wait_process_io(self, 1)?;
            let pid = stopper.id();
            let output = stopper.wait_with_output()?;
            let code = output.status.code();
            info!("exec stop process exit code {:?}. pid [{}]", code, pid);
            let buf = String::from_utf8(output.stdout).unwrap();
            if !buf.is_empty() {
                info!("exec stop process stdout. pid [{}]\n{}", pid, buf);
            }

            let buf = String::from_utf8(output.stderr).unwrap();
            if !buf.is_empty() {
                info!("exec stop process stderr. pid [{}]\n{}", pid, buf);
            }
        }

        Ok(old_pid)
    }

    pub fn restart(
        &mut self,
        monitor: &mut Monitor,
        signal: Signal,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let self_pid = getpid();
        info!("start restart [{}] worker. pid [{}]", self.name, self_pid);
        if !self.active {
            let new_pid = Vec::new();
            let old_pid = Vec::new();
            warn!(
                "worker not active [{}] worker. pid [{}]",
                self.name, self_pid
            );
            return Ok((new_pid, old_pid));
        }

        let old_pid = self.stop_processes(monitor, signal)?;
        while let Some(ref mut p) = self.processes.pop() {
            if p.try_wait().is_none() {
                if let Err(e) = p.kill() {
                    warn!("fail old kill process. caused by: {}", e);
                }
                warn!("no reaction. killed old process {}", p.process_name(),);
            }
            info!("exited old process {}", p.process_name());
        }
        self.spawn_upgrade_processes(monitor)?;
        self.updated_at = Utc::now();
        let new_pid = self.process_pid();
        info!(
            "success restart [{}] worker. new_pid {:?} old_pid {:?}. pid [{}]",
            self.name, new_pid, old_pid, self_pid
        );
        Ok((new_pid, old_pid))
    }
}
