use crate::app::APP_NAME_UPPER;
use crate::config::WorkerConfig;
use crate::utils::{get_process_watch_file, timeout_process};
use libc;
use log::{debug, error, info, warn};
use nix::unistd::getpid;
use std::collections::HashMap;
use std::io::{copy, Read, Write};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::{fs, io, thread, time};

#[derive(Debug)]
pub struct Process<'a> {
    pub id: u64,
    pub name: &'a str,
    pub cmdline: &'a [String],
    environment: HashMap<String, String>,
    working_directory: &'a str,
    child: Option<Child>,
    stdout_pipe: bool,
    stderr_pipe: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    watch_file: Option<PathBuf>,
}

impl PartialEq for Process<'_> {
    fn eq(&self, other: &Process) -> bool {
        self.cmdline == other.cmdline
    }
}

impl<'a> Process<'a> {
    pub fn new(
        id: u64,
        name: &'a str,
        working_directory: &'a str,
        environment: HashMap<String, String>,
        config: &'a WorkerConfig,
    ) -> Self {
        let watch_file = if config.live_check_timeout > 0 {
            Some(PathBuf::new())
        } else {
            None
        };
        Process {
            id,
            name,
            cmdline: &config.exec_start_cmd,
            environment,
            working_directory,
            child: None,
            stdout_pipe: config.stdout_log.is_some(),
            stderr_pipe: config.stderr_log.is_some(),
            uid: config.uid,
            gid: config.gid,
            watch_file,
        }
    }

    pub fn process_name(&mut self) -> String {
        let name = &self.name;
        let id = self.id;
        let pid = self.child.as_ref().unwrap();
        format!("[{}] pid [{}] (id:{})", name, pid.id(), id)
    }

    pub fn spawn(&mut self) -> io::Result<()> {
        let &mut Process {
            id,
            ref name,
            ref cmdline,
            ref working_directory,
            ref mut environment,
            uid,
            gid,
            ref mut watch_file,
            ..
        } = self;

        let cmd: Vec<&str> = cmdline.iter().map(|c| c.as_ref()).collect();
        let current_dir_path = Path::new(working_directory);
        let path = current_dir_path.canonicalize()?;
        let current_dir = path.as_path();

        // new command
        let mut process = Command::new(&cmd[0]);
        // add args
        process.args(&cmd[1..]);
        // set current dir
        process.current_dir(current_dir);
        if self.stdout_pipe {
            process.stdout(Stdio::piped());
        } else {
            process.stdout(Stdio::null());
        }
        if self.stderr_pipe {
            process.stderr(Stdio::piped());
        } else {
            process.stderr(Stdio::null());
        }
        if let Some(uid) = uid {
            process.uid(uid);
        }
        if let Some(gid) = gid {
            process.gid(gid);
        }
        Process::create_watch_file(name, id, watch_file, environment)?;
        debug!("process cmd {:?}", cmd);
        debug!("process current_dir {:?}", current_dir);
        debug!("process environment {:?}", environment);
        debug!("process watch_file {:?}", watch_file);
        // set environment
        process.envs(environment);
        match process.spawn() {
            Ok(mut child) => {
                child.try_wait()?;
                self.child = Some(child);
                Ok(())
            }
            Err(e) => {
                error!("fail spawn process command {}. caused by: {}", &cmd[0], e);
                Err(e)
            }
        }
    }

    fn create_watch_file(
        name: &str,
        id: u64,
        watch_file: &mut Option<PathBuf>,
        environment: &mut HashMap<String, String>,
    ) -> io::Result<()> {
        if let Some(ref mut watch_file) = watch_file {
            let path = get_process_watch_file(name, id);
            let mut f = fs::File::create(&path)?;
            f.write_all(format!("{}-{}", name, id).as_bytes())?;
            f.sync_all()?;
            if let Some(file_path) = path.to_str() {
                environment.insert(
                    format!("{}_WATCH_FILE", APP_NAME_UPPER),
                    file_path.to_owned(),
                );
            }
            *watch_file = path;
        }
        Ok(())
    }

    pub fn try_wait(&mut self) -> Option<i32> {
        let &mut Process {
            ref mut child,
            ref watch_file,
            ..
        } = self;

        let child: &mut Child = child.as_mut()?;
        let pid = child.id();
        match child.try_wait() {
            Ok(Some(status)) => {
                Process::remove_watch_file(watch_file);
                if status.success() {
                    status.code()
                } else {
                    warn!(
                        "exited process. catch signal {:?} pid [{}]",
                        status.signal(),
                        pid
                    );
                    Some(-1)
                }
            }
            Ok(None) => None,
            Err(e) => {
                error!("fail process wait. caused by: {}", e);
                Process::remove_watch_file(watch_file);
                Some(-1)
            }
        }
    }

    pub fn wait(&mut self) -> Option<i32> {
        let &mut Process {
            ref mut child,
            ref watch_file,
            ..
        } = self;

        let child: &mut Child = child.as_mut()?;
        let pid = child.id();
        match child.wait() {
            Ok(status) => {
                Process::remove_watch_file(watch_file);
                if status.success() {
                    status.code()
                } else {
                    warn!(
                        "exited process. catch signal {:?} pid [{}]",
                        status.signal(),
                        pid
                    );
                    Some(-1)
                }
            }
            Err(e) => {
                error!("fail process wait. caused by: {}", e);
                Process::remove_watch_file(watch_file);
                Some(-1)
            }
        }
    }

    fn remove_watch_file(watch_file: &Option<PathBuf>) {
        if let Some(ref watch_file) = watch_file {
            if let Err(e) = fs::remove_file(watch_file) {
                warn!("fail remove watch file {:?}. caused by: {}", watch_file, e);
            } else {
                info!("remove watch file {:?}", watch_file);
            }
        }
    }

    pub fn cleanup(&mut self) {
        let &mut Process { ref watch_file, .. } = self;
        Process::remove_watch_file(watch_file);
    }

    pub fn check_live_timeout(&mut self, timeout: u64) -> bool {
        let &mut Process {
            id,
            ref name,
            ref watch_file,
            ..
        } = self;
        if timeout == 0 || watch_file.is_none() {
            return false;
        }
        match timeout_process(timeout, name, id) {
            Ok(ret) => ret,
            Err(e) => {
                warn!("fail get mtime. caused by: {}", e);
                false
            }
        }
    }

    pub fn pid(&mut self) -> Option<u32> {
        self.child.as_mut().map(|child| child.id())
    }

    pub fn kill(&mut self) -> io::Result<u32> {
        self.cleanup();
        if let Some(ref mut child) = self.child {
            child.kill()?;
            return Ok(child.id());
        }
        Ok(0)
    }

    pub fn child(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }
}

pub fn run_upgrader(upgrader: &[String]) -> io::Result<Child> {
    let self_pid = getpid();
    let mut process = Command::new(&upgrader[0]);
    info!("start upgrader {:?}. pid [{}]", &upgrader, self_pid);
    process.args(&upgrader[1..]);
    process.stdin(Stdio::null());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    let child = match process.spawn() {
        Ok(mut child) => {
            child.try_wait()?;
            info!(
                "running upgrader process {:?}. pid [{}]",
                &upgrader,
                child.id()
            );
            child
        }
        Err(e) => {
            error!(
                "fail spawn upgrader process. caused by: {}. command {:?}",
                e, &upgrader
            );
            return Err(e);
        }
    };
    Ok(child)
}

pub fn run_exec_stop(cmd: &[String]) -> io::Result<Child> {
    let self_pid = getpid();
    let mut process = Command::new(&cmd[0]);
    info!("start exec_stop {:?}. pid [{}]", &cmd, self_pid);
    process.args(&cmd[1..]);
    process.stdin(Stdio::null());
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    let child = match process.spawn() {
        Ok(mut child) => {
            child.try_wait()?;
            info!("running exec_stop process {:?}. pid [{}]", &cmd, child.id());
            child
        }
        Err(e) => {
            error!(
                "fail spawn exec_stop process. caused by: {}. command {:?}",
                e, &cmd
            );
            return Err(e);
        }
    };
    Ok(child)
}

pub fn process_exited(p: &mut Process) -> bool {
    p.try_wait().is_some()
}

pub fn process_normally_exited(p: &mut Child) -> io::Result<bool> {
    let status = p.try_wait()?;
    match status {
        Some(status) => {
            if status.success() {
                Ok(true)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "process exit_code is not 0",
                ))
            }
        }
        _ => Ok(false),
    }
}

pub fn process_output(p: &mut Child) {
    let pid = p.id();

    if let Some(ref mut stdout) = p.stdout {
        let mut buf = String::new();
        if let Ok(size) = stdout.read_to_string(&mut buf) {
            if size > 0 {
                info!("process stdout. pid [{}]\n{}", pid, buf);
            }
        }
    }
    if let Some(ref mut stderr) = p.stderr {
        let mut buf = String::new();
        if let Ok(size) = stderr.read_to_string(&mut buf) {
            if size > 0 {
                info!("process stderr. pid [{}]\n {}", pid, buf);
            }
        }
    }
}

pub fn output_stdout_log(p: &mut Child, writer: &mut dyn io::Write) -> io::Result<()> {
    let retry = if let Some(ref mut reader) = p.stdout {
        match copy(reader, writer) {
            Ok(_size) => {
                writer.flush()?;
                false
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::EWOULDBLOCK)
                    || e.raw_os_error() == Some(libc::EAGAIN)
                {
                    writer.flush()?;
                    true
                } else {
                    return Err(e);
                }
            }
        }
    } else {
        false
    };
    if retry {
        thread::sleep(time::Duration::from_millis(100));
        output_stdout_log(p, writer)?;
    }
    Ok(())
}

pub fn output_stderr_log(p: &mut Child, writer: &mut dyn io::Write) -> io::Result<()> {
    let retry = if let Some(ref mut reader) = p.stderr {
        match copy(reader, writer) {
            Ok(_size) => {
                writer.flush()?;
                false
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::EWOULDBLOCK)
                    || e.raw_os_error() == Some(libc::EAGAIN)
                {
                    writer.flush()?;
                    true
                } else {
                    return Err(e);
                }
            }
        }
    } else {
        false
    };
    if retry {
        thread::sleep(time::Duration::from_millis(100));
        output_stderr_log(p, writer)?;
    }
    Ok(())
}
