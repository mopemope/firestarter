use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::{env, io};

use nom::types::CompleteStr;
use nom::Err;
use toml::from_str;

use app::{APP_NAME, APP_NAME_UPPER};
use logs::LogFile;
use signal;

#[derive(Debug, Clone)]
pub struct Config {
    pub control_sock: String,
    pub workers: HashMap<String, WorkerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WorkerConfig {
    pub exec_start: String,
    pub exec_stop: Option<String>,
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
    pub upgrader: Option<String>,
    #[serde(skip, default = "default_run_upgrader")]
    pub run_upgrader: RunUpgrader,
    pub upgrader_active_sec: Option<u64>,
    #[serde(default = "default_upgrader_timeout")]
    pub upgrader_timeout: u64,

    #[serde(skip, default = "default_vec_str")]
    pub exec_start_cmd: Vec<String>,
    #[serde(skip, default = "default_vec_str")]
    pub exec_stop_cmd: Vec<String>,
    #[serde(skip, default = "default_vec_str")]
    pub upgrader_cmd: Vec<String>,
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

        let cmd = parse_cmd(&wrk_config.exec_start).expect("fail parse exec_start");
        wrk_config.exec_start_cmd = cmd;

        if let Some(ref cmd) = wrk_config.exec_stop {
            let cmd = parse_cmd(cmd).expect("fail parse exec_stop");
            wrk_config.exec_stop_cmd = cmd;
        }

        if let Some(ref stdout) = wrk_config.stdout_log {
            let _stdout_log: LogFile = stdout.parse().unwrap();
        }
        if let Some(ref stderr) = wrk_config.stderr_log {
            let _stderr_log: LogFile = stderr.parse().unwrap();
        }

        if let Some(ref upgrader) = wrk_config.upgrader {
            let cmd = parse_cmd(upgrader).expect("fail parse upgrader");
            wrk_config.upgrader_cmd = cmd;
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

fn token_char(ch: char) -> bool {
    if ch.len_utf8() > 1 {
        return false;
    }
    match ch {
        '\x00'...'\x20' => false,
        '\x7f' | '"' | '\'' | '>' | '<' | '|' | ';' | '{' | '}' | '$' => false,
        _ => true,
    }
}

fn var_char(ch: char) -> bool {
    match ch {
        'a'...'z' => true,
        'A'...'Z' => true,
        '0'...'9' => true,
        '_' => true,
        _ => false,
    }
}

enum TokenPart {
    Bare(String),
    Placeholder,
    EnvVariable(String),
}

struct Token(Vec<TokenPart>);

impl Token {
    fn into_string(self) -> Result<String, env::VarError> {
        let mut token = String::from("");
        for part in self.0 {
            match part {
                TokenPart::Bare(s) => token += &s,
                TokenPart::Placeholder => token += "{}",
                TokenPart::EnvVariable(name) => {
                    debug!("Environment variable {}", name);
                    token += &env::var(name)?
                }
            }
        }
        Ok(token)
    }
}

named!(bare_token<CompleteStr, TokenPart>,
       map!(take_while1_s!(token_char), |s| TokenPart::Bare(String::from(s.as_ref()))));

named!(quoted_token<CompleteStr, TokenPart>,
       map!(delimited!(tag_s!("\""), take_until_s!("\""), tag_s!("\"")),
            |s| TokenPart::Bare(String::from(s.as_ref()))));

named!(place_holder<CompleteStr, TokenPart>,
       map!(tag_s!("{}"), |_| TokenPart::Placeholder));

named!(env_var<CompleteStr, TokenPart>,
       map!(preceded!(tag!("$"), take_while1_s!(var_char)),
            |name| TokenPart::EnvVariable(String::from(name.as_ref()))));

named!(command_token<CompleteStr, Token>,
       map!(many1!(alt!(bare_token | quoted_token | place_holder | env_var)),
            Token));

named!(command< CompleteStr, Vec<Token> >,
       terminated!(ws!(many1!(command_token)), eof!()));

fn parse_cmd(cmd: &str) -> Result<Vec<String>, env::VarError> {
    let tokens = match command(CompleteStr(cmd)) {
        Ok((_, result)) => result,
        Err(Err::Error(e)) | Err(Err::Failure(e)) => panic!("Error {:?}. cmd {}", e, cmd),
        Err(Err::Incomplete(needed)) => panic!("Needed {:?}. cmd {}", needed, cmd),
    };
    tokens
        .into_iter()
        .map(|token| token.into_string())
        .collect::<Result<Vec<_>, _>>()
}

#[test]
fn test_parse_cmd() {
    let tokens = parse_cmd(
        r#"cmd 1 2
                              3 "
  4" {}"#,
    ).unwrap();
    assert_eq!("cmd", tokens[0]);
    assert_eq!("1", tokens[1]);
    assert_eq!("2", tokens[2]);
    assert_eq!("3", tokens[3]);
    assert_eq!("\n  4", tokens[4]);
    assert_eq!("{}", tokens[5]);
}

#[test]
fn test_parse_cmd_env() {
    use env_logger;
    env_logger::init();
    env::set_var("MY_VAR", "VALUE");
    let tokens = parse_cmd("echo $MY_VAR/dir").unwrap();
    assert_eq!("VALUE/dir", tokens[1]);
}
