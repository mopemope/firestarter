use std::ffi::OsStr;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::SystemTime;

use chrono::{DateTime, Duration, Utc};
use failure::{err_msg, Error};
use glob::glob;

pub trait RotatePolicy {
    fn rotate(&mut self, buf: &[u8], p: &Path, file: &File) -> io::Result<bool>;
}

struct SizeRotatePolicy {
    max_file_size: u64,
    max_backup: u32,
}

impl SizeRotatePolicy {
    fn new(max_file_size: u64, max_backup: u32) -> Self {
        SizeRotatePolicy {
            max_file_size,
            max_backup,
        }
    }
}

impl RotatePolicy for SizeRotatePolicy {
    fn rotate(&mut self, buf: &[u8], p: &Path, file: &File) -> io::Result<bool> {
        let max_file_size = self.max_file_size;
        let max_backup = self.max_backup;
        let buf_len = buf.len() as u64;

        let metadata = file.metadata()?;
        let size = metadata.len();
        if max_file_size > buf_len + size {
            return Ok(false);
        }
        if !p.exists() {
            return Ok(false);
        }
        let (parent, name, ext) = get_log_names(p);

        let file_name = if let Some(log_ext) = Path::new(name).extension().and_then(OsStr::to_str) {
            let mut log_num: u32 = ext.parse().unwrap();
            log_num += 1;
            if log_num > max_backup {
                return Ok(false);
            }
            let name = Path::new(name).file_stem().and_then(OsStr::to_str).unwrap();
            format!("{}.{}.{}", name, log_ext, log_num)
        } else {
            let name = Path::new(name).to_str().unwrap();
            format!("{}.{}.1", name, ext)
        };

        let pbuf = Path::new(parent).join(file_name);
        let new_path = pbuf.as_path();
        if new_path.exists() {
            self.rotate(buf, new_path, file)?;
        }
        debug!("rename backup log file. {:?} -> {:?}", p, new_path);
        rename(p, new_path)?;
        Ok(true)
    }
}

struct TimedRotatePolicy {
    roll_over_at: DateTime<Utc>,
    duration: Duration,
    format: String,
    max_backup: u32,
    check_time: SystemTime,
}

impl TimedRotatePolicy {
    fn new(interval: u32, when: &str, max_backup: u32) -> Self {
        let now = Utc::now();
        let (interval_secs, fmt): (i64, &str) = match when {
            "S" => (1, "%Y%m%d%H%M%S"),
            "M" => (60, "%Y%m%d%H%M"),
            "H" => (60 * 60, "%Y%m%d%H"),
            "D" => (60 * 60 * 24, "%Y%m%d"),
            _ => panic!("unknown type"),
        };
        let duration = Duration::seconds(interval_secs * i64::from(interval));
        let roll_over_at = now + duration;
        let check_time = SystemTime::now();
        TimedRotatePolicy {
            roll_over_at,
            duration,
            format: fmt.to_owned(),
            max_backup,
            check_time,
        }
    }

    fn get_timed_filename(&mut self, p: &Path) -> PathBuf {
        let (parent, name, ext) = get_log_names(p);
        let t = self.roll_over_at - self.duration;
        let suffix = t.format(&self.format);
        let file_name = format!("{}.{}.{}", name, ext, suffix);
        Path::new(parent).join(file_name)
    }

    fn timed_rotate(&mut self, p: &Path) -> io::Result<bool> {
        let max_backup = self.max_backup;
        let now = Utc::now();
        if self.roll_over_at > now {
            return Ok(false);
        }
        if !p.exists() {
            return Ok(false);
        }
        let new_path = self.get_timed_filename(p);
        if new_path.exists() {
            remove_file(&new_path)?;
        }
        debug!("rename backup log file. {:?} -> {:?}", p, new_path);
        rename(p, &new_path)?;
        TimedRotatePolicy::remove_old_backup(p, max_backup as usize)?;
        self.roll_over_at = now + self.duration;
        Ok(true)
    }

    fn remove_old_backup(p: &Path, max_backup: usize) -> io::Result<()> {
        if let Ok(paths) = glob(&format!("{}.*", p.to_str().unwrap())) {
            let mut tmp = Vec::new();
            for entry in paths {
                match entry {
                    Ok(path) => {
                        tmp.push(path);
                    }
                    Err(e) => {
                        warn!("fail get path. caused by: {}", e);
                    }
                }
            }
            let size = tmp.len();
            if size > max_backup {
                tmp.sort();
                for p in tmp.drain(0..size - max_backup) {
                    remove_file(&p)?;
                    debug!("remove backup {:?}", &p);
                }
            }
        }
        Ok(())
    }
}

impl RotatePolicy for TimedRotatePolicy {
    fn rotate(&mut self, _buf: &[u8], p: &Path, _file: &File) -> io::Result<bool> {
        if let Ok(elapsed) = self.check_time.elapsed() {
            if elapsed.as_secs() >= 1 {
                self.check_time = SystemTime::now();
                return self.timed_rotate(p);
            }
        }
        Ok(false)
    }
}

pub struct LogFile {
    inner: Option<File>,
    log_file: PathBuf,
    policy: Box<RotatePolicy>,
}

impl LogFile {
    pub fn new(log_file: PathBuf, policy: Box<RotatePolicy>) -> Self {
        LogFile {
            inner: None,
            log_file,
            policy,
        }
    }

    pub fn open(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.log_file.as_path())?;
        self.inner = Some(file);
        Ok(())
    }

    fn try_rotate(&mut self, buf: &[u8]) -> io::Result<()> {
        let newfile = if let Some(ref mut inner) = self.inner {
            inner.flush()?;

            let &mut LogFile {
                ref log_file,
                ref mut policy,
                ..
            } = self;

            if policy.rotate(buf, log_file, &inner)? {
                let file = OpenOptions::new().append(true).create(true).open(log_file)?;
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

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.try_rotate(buf)?;
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

impl FromStr for LogFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<LogFile, Error> {
        let log_cfg: Vec<&str> = s.split(':').collect();
        let log_type = log_cfg[0];
        match log_type {
            "size" => {
                // size:100000:5:/tmp.log
                let max_file_size: u64 = log_cfg[1].parse().unwrap();
                let max_backup: u32 = log_cfg[2].parse().unwrap();
                let path = log_cfg[3];
                let policy = SizeRotatePolicy::new(max_file_size, max_backup);
                let log = LogFile::new(PathBuf::from(path), Box::new(policy));
                Ok(log)
            }
            "time" => {
                // time:7:D:5:/tmp.log
                let roll_over: u32 = log_cfg[1].parse().unwrap();
                let when = log_cfg[2];
                let max_backup: u32 = log_cfg[3].parse().unwrap();
                let path = log_cfg[4];
                let policy = TimedRotatePolicy::new(roll_over, when, max_backup);
                let log = LogFile::new(PathBuf::from(path), Box::new(policy));
                Ok(log)
            }
            _ => Err(err_msg("unknown log type")),
        }
    }
}

fn get_log_names(p: &Path) -> (&Path, &str, &str) {
    let log_ext = p.extension().unwrap_or_else(|| OsStr::new(""));
    let parent = p.parent().unwrap();
    let name = match p.file_stem() {
        Some(f) => f,
        None => p.file_name().unwrap(),
    };
    let name = name.to_str().unwrap();
    let ext = log_ext.to_str().unwrap();
    (parent, name, ext)
}
