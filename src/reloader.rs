use std::{io, path, time};

use config::WorkerConfig;

fn is_modified(path: &path::PathBuf, current_mtime: &time::SystemTime) -> io::Result<bool> {
    let metadata = path.metadata()?;
    let mtime = metadata.modified()?;
    if mtime != *current_mtime {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn cmd_path(config: &WorkerConfig) -> path::PathBuf {
    let cmd = &config.cmd[0];
    let cmd_path = path::Path::new(cmd);
    if cmd_path.is_absolute() {
        cmd_path.to_owned()
    } else if let Some(ref base) = config.working_directory {
        let root = path::Path::new(base).canonicalize().unwrap();
        root.join(cmd_path).canonicalize().unwrap()
    } else {
        cmd_path.canonicalize().unwrap()
    }
}

pub fn is_modified_cmd(
    config: &WorkerConfig,
    current_path: &path::PathBuf,
    current_mtime: &time::SystemTime,
) -> io::Result<bool> {
    let path = cmd_path(config);
    if *current_path != path {
        return Ok(true);
    }
    is_modified(&path, current_mtime)
}
