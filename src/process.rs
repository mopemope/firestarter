use std::collections::HashMap;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::{fs, io};

use app::APP_NAME_UPPER;
use config::WorkerConfig;
use utils::{get_process_watch_file, timeout_process};

#[derive(Debug)]
pub struct Process {
    pub id: u64,
    pub name: String,
    pub cmdline: Vec<String>,
    environment: HashMap<String, String>,
    working_directory: String,
    child: Option<Child>,
    stdout_pipe: bool,
    stderr_pipe: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    watch_file: Option<PathBuf>,
}

impl PartialEq for Process {
    fn eq(&self, other: &Process) -> bool {
        self.cmdline == other.cmdline
    }
}

impl Process {
    pub fn new(
        id: u64,
        name: String,
        working_directory: String,
        environment: HashMap<String, String>,
        config: &WorkerConfig,
    ) -> Self {
        let cmdline = config.cmd.iter().map(|c| c.to_string()).collect();
        let watch_file = if config.live_check_timeout > 0 {
            Some(PathBuf::new())
        } else {
            None
        };
        Process {
            id,
            name,
            cmdline,
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
            Err(err) => {
                error!("fail spawn process. cause {}. command {}", err, &cmd[0]);
                Err(err)
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
                    format!("{}_WATCH_FILE", APP_NAME_UPPER).to_owned(),
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
                error!("fail {:?}", e);
                Process::remove_watch_file(watch_file);
                Some(-1)
            }
        }
    }

    fn remove_watch_file(watch_file: &Option<PathBuf>) {
        if let Some(ref watch_file) = watch_file {
            if let Err(e) = fs::remove_file(watch_file) {
                warn!("fail remove watch file {:?}. cause {:?}", watch_file, e);
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
                warn!("fail get mtime. cause {:?}", e);
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

    pub fn child(&mut self) -> Option<&Child> {
        self.child.as_ref()
    }
}
