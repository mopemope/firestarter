use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use config::WorkerConfig;

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
        }
    }

    // pub fn new(
    //     id: u64,
    //     name: String,
    //     cmdline: &[String],
    //     working_directory: String,
    //     environment: HashMap<String, String>,
    //     stdout_pipe: bool,
    //     stderr_pipe: bool,
    //     uid: Option<u32>,
    //     gid: Option<u32>,
    // ) -> Self {
    //     let cmdline = cmdline.iter().map(|c| c.to_string()).collect();
    //     Process {
    //         id,
    //         name,
    //         cmdline,
    //         environment,
    //         working_directory,
    //         child: None,
    //         stderr_pipe,
    //         stdout_pipe,
    //         uid,
    //         gid,
    //     }
    // }

    pub fn process_name(&mut self) -> String {
        let name = &self.name;
        let id = self.id;
        let pid = self.child.as_ref().unwrap();
        format!("[{}] pid [{}] (index:{})", name, pid.id(), id)
    }

    pub fn spawn(&mut self) -> io::Result<()> {
        let cmd: Vec<&str> = self.cmdline.iter().map(|c| c.as_ref()).collect();
        let current_dir_path = Path::new(&self.working_directory);
        let path = current_dir_path.canonicalize()?;
        //.unwrap();
        let current_dir = path.as_path();

        // new command
        let mut process = Command::new(&cmd[0]);

        // add args
        process.args(&cmd[1..]);
        // set current dir
        process.current_dir(current_dir);
        // set environment
        process.envs(&self.environment);
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
        if let Some(uid) = self.uid {
            process.uid(uid);
        }
        if let Some(gid) = self.gid {
            process.gid(gid);
        }
        debug!("process cmd {:?}", cmd);
        debug!("process current_dir {:?}", current_dir);
        debug!("process environment {:?}", self.environment);

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

    pub fn try_wait(&mut self) -> Option<i32> {
        let child: &mut Child = self.child.as_mut()?;
        let pid = child.id();
        match child.try_wait() {
            Ok(Some(status)) => {
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
                Some(-1)
            }
        }
    }

    pub fn pid(&mut self) -> Option<u32> {
        self.child.as_mut().map(|child| child.id())
    }

    pub fn kill(&mut self) -> io::Result<u32> {
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
