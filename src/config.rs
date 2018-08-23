use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::{env, io};

use toml::from_str;

use app::{APP_NAME, APP_NAME_UPPER};
use logs::RollingLogFile;
use signal;

#[derive(Debug, Clone)]
pub struct Config {
    pub control_sock: String,
    pub workers: HashMap<String, WorkerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WorkerConfig {
    #[serde(default = "default_vec_str")]
    pub cmd: Vec<String>,
    #[serde(default = "default_num")]
    pub numprocesses: u64,
    #[serde(default = "default_bool")]
    pub start_immediate: bool,
    #[serde(default = "default_vec_str")]
    pub socket_address: Vec<String>,
    #[serde(default = "default_vec_str")]
    pub environments: Vec<String>,
    #[serde(default = "default_directory")]
    pub working_directory: String,
    #[serde(default = "default_restart")]
    pub restart: RestartStrategy,
    #[serde(default = "default_ack")]
    pub ack: AckKind,
    #[serde(default = "default_num")]
    pub ack_timeout: u64,
    #[serde(default = "default_ack_signal")]
    pub ack_signal: signal::Signal,
    #[serde(default = "default_base_name")]
    pub environment_base_name: String,
    #[serde(default = "default_zero")]
    pub giveup: u64,
    #[serde(default = "default_zero")]
    pub warmup_delay: u64,
    pub stdout_log: Option<String>,
    pub stderr_log: Option<String>,
    pub control_socket: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    #[serde(default = "default_bool")]
    pub auto_upgrade: bool,
    #[serde(default = "default_zero")]
    pub live_check_timeout: u64,

    pub upgrader: Option<Vec<String>>,
    #[serde(skip, default = "default_run_upgrader")]
    pub run_upgrader: RunUpgrader,
    pub upgrader_active_sec: Option<u64>,
    #[serde(default = "default_upgrader_timeout")]
    pub upgrader_timeout: u64,
}

fn default_bool() -> bool {
    false
}
fn default_num() -> u64 {
    1
}
fn default_zero() -> u64 {
    0
}
fn default_vec_str() -> Vec<String> {
    Vec::new()
}
fn default_directory() -> String {
    "./".to_owned()
}
fn default_base_name() -> String {
    APP_NAME_UPPER.to_owned()
}
fn default_ack() -> AckKind {
    AckKind::Timer
}
fn default_ack_signal() -> signal::Signal {
    signal::Signal::SIGUSR2
}
fn default_restart() -> RestartStrategy {
    RestartStrategy::None
}
fn default_run_upgrader() -> RunUpgrader {
    RunUpgrader::None
}
fn default_upgrader_timeout() -> u64 {
    300
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum RestartStrategy {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "always")]
    Always,
    #[serde(rename = "on-failure")]
    OnFailure,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum AckKind {
    #[serde(rename = "timer")]
    Timer,
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
pub enum RunUpgrader {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "on-upgrade")]
    OnUpgrade,
    #[serde(rename = "on-active-sec")]
    OnActiveSec,
    // TODO schedule upgrade
    // #[serde(rename = "on-calendar")]
    // OnCalendar,
}

impl RestartStrategy {
    pub fn need_respawn(self, code: i32) -> bool {
        match self {
            RestartStrategy::None => false,
            RestartStrategy::Always => true,
            RestartStrategy::OnFailure => code != 0,
        }
    }
}

impl Config {}

impl WorkerConfig {
    pub fn control_sock(&self, name: &str) -> String {
        if self.control_socket.is_some() {
            self.control_socket.clone().unwrap()
        } else {
            let mut dir = env::temp_dir();
            dir.push(format!("{}-{}.socket", APP_NAME, name));
            let path = dir.to_str().unwrap();
            String::from(path)
        }
    }
}

pub fn parse_config(path: &str) -> io::Result<Config> {
    let mut config_toml = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut config_toml)?;

    let mut dir = env::temp_dir();
    dir.push(format!("{}-control.socket", APP_NAME));
    let path = dir.to_str().unwrap();
    let sock = String::from(path);

    let mut config = Config {
        control_sock: sock,
        workers: HashMap::new(),
    };

    let mut wrkrs: HashMap<String, WorkerConfig> =
        from_str(&config_toml).expect("toml parse error");

    for wrk_config in &mut wrkrs.values_mut() {
        // validate config
        if let Some(ref stdout) = wrk_config.stdout_log {
            let _stdout_log: RollingLogFile = stdout.parse().unwrap();
        }
        if let Some(ref stderr) = wrk_config.stderr_log {
            let _stderr_log: RollingLogFile = stderr.parse().unwrap();
        }

        if let Some(ref _upgrader) = wrk_config.upgrader {
            if wrk_config.upgrader_active_sec.is_some() {
                wrk_config.run_upgrader = RunUpgrader::OnActiveSec;
            } else {
                wrk_config.run_upgrader = RunUpgrader::OnUpgrade;
            }
        }

        debug!("{:?}", wrk_config);
    }
    config.workers = wrkrs;
    Ok(config)
}
