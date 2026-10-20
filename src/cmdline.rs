use crate::app::{get_app_name, APP_NAME};
use crate::client::Client;
use crate::config::parse_config;
use crate::daemon::Daemon;
use anyhow::{Context, Result};
use clap::{Arg, Command};
use lazy_static::lazy_static;
use std::{env, path};

lazy_static! {
    pub static ref SOCK_PATH: path::PathBuf = {
        let mut dir = env::temp_dir();
        dir.push(format!("{}-control.socket", get_app_name()));
        dir
    };
}

fn socket_arg(sock_path: &'static str) -> Arg {
    Arg::new("socket-path")
        .value_name("PATH")
        .short('d')
        .long("socket-path")
        .default_value(sock_path)
        .help("set ctrl socket path.")
}

fn make_app() -> Result<Command> {
    // clap 4 requires the strings baked into the CLI (defaults, choices) to
    // be 'static; the app name path is computed once, so leak a copy.
    let sock_path = SOCK_PATH
        .to_str()
        .context("failed get sock path")?
        .to_owned();
    let sock_path: &'static str = Box::leak(sock_path.into_boxed_str());
    let app = Command::new(APP_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about("A process and shared socket manager")
        .subcommand(
            Command::new("run")
                .about("Run daemon")
                .arg(
                    Arg::new("config")
                        .required(true)
                        .value_name("FILE")
                        .short('c')
                        .long("config")
                        .help("set config file."),
                )
                .arg(socket_arg(sock_path)),
        )
        .subcommand(
            Command::new("list")
                .about("Show worker names")
                .arg(socket_arg(sock_path)),
        )
        .subcommand(
            Command::new("stop")
                .about("Stop daemon")
                .arg(socket_arg(sock_path)),
        )
        .subcommand(
            Command::new("status")
                .about("Show worker status")
                .arg(socket_arg(sock_path)),
        )
        .subcommand(
            Command::new("ctrl")
                .about("Run control client")
                .arg(socket_arg(sock_path))
                .arg(
                    Arg::new("signal")
                        .value_name("SIGNAL")
                        .value_parser([
                            "SIGKILL", "SIGINT", "SIGQUIT", "SIGTERM", "SIGHUP", "SIGUSR1",
                            "SIGUSR2",
                        ])
                        .short('s')
                        .long("signal")
                        .help("override send signal"),
                )
                .arg(
                    Arg::new("name")
                        .required(true)
                        .value_name("WORKER_CONFIG_NAME")
                        .help("set worker name."),
                )
                .arg(
                    Arg::new("command")
                        .required(true)
                        .value_name("COMMAND")
                        .value_parser([
                            "start", "stop", "inc", "dec", "upgrade", "killall", "status",
                            "restart",
                        ])
                        .help("set send command."),
                ),
        );
    Ok(app)
}

pub fn execute() -> Result<()> {
    let app = make_app()?;
    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("run", m)) => {
            let sock_path = m
                .get_one::<String>("socket-path")
                .expect("require control socket path");
            let path = m.get_one::<String>("config").expect("require config path");
            let mut config = { parse_config(path)? };
            config.control_sock = sock_path.to_owned();
            Daemon::new(config)?.run()
        }
        Some(("list", m)) => {
            let sock_path = m
                .get_one::<String>("socket-path")
                .expect("require control socket path");
            Client::new().list(sock_path)
        }
        Some(("stop", m)) => {
            let sock_path = m
                .get_one::<String>("socket-path")
                .expect("require control socket path");
            Client::new().stop(sock_path)
        }
        Some(("status", m)) => {
            let sock_path = m
                .get_one::<String>("socket-path")
                .expect("require control socket path");
            Client::new().status(sock_path)
        }
        Some(("ctrl", m)) => {
            let sock_path = m
                .get_one::<String>("socket-path")
                .expect("require control socket path");
            let name = m.get_one::<String>("name").expect("require worker name");
            let command = m.get_one::<String>("command").expect("require command");
            let signal = m.get_one::<String>("signal");
            Client::new().run(sock_path, name, command, signal.map(|s| s.as_str()))
        }
        _ => Ok(()),
    }
}
