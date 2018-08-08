use std::ffi::OsStr;
use std::fs::{rename, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use failure::{err_msg, Error};

#[derive(Debug)]
pub enum RollingPolicy {
    SizeRollingPolicy { max_file_size: u64, max_backup: u32 },
}

impl RollingPolicy {
    pub fn rotate(&self, p: &Path, file: &File) -> io::Result<bool> {
        match self {
            RollingPolicy::SizeRollingPolicy {
                ref max_file_size,
                ref max_backup,
                ..
            } => self.size_rotate(p, file, *max_file_size, *max_backup),
        }
    }

    fn size_rotate(
        &self,
        p: &Path,
        file: &File,
        max_file_size: u64,
        max_backup: u32,
    ) -> io::Result<bool> {
        let metadata = file.metadata()?;
        let size = metadata.len();
        if max_file_size > size {
            return Ok(false);
        }
        if !p.exists() {
            return Ok(false);
        }
        let log_ext = p.extension().unwrap_or(OsStr::new(""));
        let parent = p.parent().unwrap();
        let name = match p.file_stem() {
            Some(f) => f,
            None => p.file_name().unwrap(),
        };

        let file_name = if let Some(ext) = Path::new(name).extension().and_then(OsStr::to_str) {
            let mut log_num: u32 = ext.parse().unwrap();
            log_num += 1;
            if log_num > max_backup {
                return Ok(false);
            }
            let name = Path::new(name).file_stem().and_then(OsStr::to_str).unwrap();
            format!("{}.{}.{}", name, log_num, OsStr::to_str(log_ext).unwrap())
        } else {
            let name = Path::new(name).to_str().unwrap();
            format!("{}.1.{}", name, OsStr::to_str(log_ext).unwrap())
        };

        let pbuf = Path::new(parent).join(file_name);
        let new_path = pbuf.as_path();
        if new_path.exists() {
            self.size_rotate(new_path, file, max_file_size, max_backup)?;
        }
        debug!("rename backup log file. {:?} -> {:?}", p, new_path);
        rename(p, new_path)?;
        Ok(true)
    }
}

#[derive(Debug)]
pub struct RollingLogFile {
    inner: Option<File>,
    path: PathBuf,
    policy: RollingPolicy,
}

impl RollingLogFile {
    pub fn new(path: PathBuf, policy: RollingPolicy) -> Self {
        RollingLogFile {
            inner: None,
            path,
            policy,
        }
    }

    pub fn open(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.path.as_path())?;
        self.inner = Some(file);
        Ok(())
    }

    fn try_rotate(&mut self) -> io::Result<()> {
        let newfile = if let Some(ref mut inner) = self.inner {
            inner.flush()?;
            let &mut RollingLogFile {
                ref path,
                ref mut policy,
                ..
            } = self;
            if policy.rotate(path, &inner)? {
                let file = OpenOptions::new().append(true).create(true).open(path)?;
                Some(file)
            } else {
                None
            }
        } else {
            None
        };

        if newfile.is_some() {
            self.inner = newfile;
        }

        Ok(())
    }
}

impl Write for RollingLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.try_rotate()?;
        if let Some(ref mut inner) = self.inner {
            inner.write(buf)
        } else {
            Ok(0)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut inner) = self.inner {
            inner.flush()
        } else {
            Ok(())
        }
    }
}

impl FromStr for RollingLogFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<RollingLogFile, Error> {
        let log_cfg: Vec<&str> = s.split(":").collect();
        let log_type = log_cfg[0];
        match log_type {
            "size" => {
                // size:100000:5:/tmp.log
                let max_file_size: u64 = log_cfg[1].parse().unwrap();
                let max_backup: u32 = log_cfg[2].parse().unwrap();
                let path = log_cfg[3];
                let policy = RollingPolicy::SizeRollingPolicy {
                    max_file_size,
                    max_backup,
                };
                let log = RollingLogFile::new(PathBuf::from(path), policy);
                Ok(log)
            }
            _ => Err(err_msg("unknown log type")),
        }
    }
}
