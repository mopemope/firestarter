use std::{env, path};

use clap::{App, AppSettings, Arg, SubCommand};
use failure::Error;

use app::APP_NAME;
use client::Client;
use config::parse_config;
use daemon::Daemon;

lazy_static! {
    pub static ref SOCK_PATH: path::PathBuf = {
        let mut dir = env::temp_dir();
        dir.push(format!("{}-control.socket", APP_NAME));
        dir
    };
}

fn make_app() -> App<'static, 'static> {
    let sock_path = SOCK_PATH.to_str().unwrap();
    App::new(APP_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .about("A process and shared socket manager")
        .subcommand(
            SubCommand::with_name("run")
                .about("Run daemon")
                .arg(
                    Arg::with_name("config")
                        .required(true)
                        .multiple(false)
                        .value_name("FILE")
                        .short("c")
                        .long("config")
                        .help("set config file."),
                )
                .arg(
                    Arg::with_name("socket-path")
                        .multiple(false)
                        .value_name("PATH")
                        .short("d")
                        .long("socket-path")
                        .default_value(sock_path)
                        .help("set ctrl socket path."),
                ),
        )
        .subcommand(
            SubCommand::with_name("list")
                .about("Show worker names")
                .arg(
                    Arg::with_name("socket-path")
                        .multiple(false)
                        .value_name("PATH")
                        .short("d")
                        .long("socket-path")
                        .default_value(sock_path)
                        .help("set ctrl socket path."),
                ),
        )
        .subcommand(
            SubCommand::with_name("status")
                .about("Show worker status")
                .arg(
                    Arg::with_name("socket-path")
                        .multiple(false)
                        .value_name("PATH")
                        .short("d")
                        .long("socket-path")
                        .default_value(sock_path)
                        .help("set ctrl socket path."),
                ),
        )
        .subcommand(
            SubCommand::with_name("ctrl")
                .about("Run control client")
                .arg(
                    Arg::with_name("socket-path")
                        .value_name("PATH")
                        .short("d")
                        .long("socket-path")
                        .default_value(sock_path)
                        .help("set ctrl socket path."),
                )
                .arg(
                    Arg::with_name("signal")
                        .value_name("SIGNAL")
                        .possible_values(&[
                            "SIGKILL", "SIGINT", "SIGQUIT", "SIGTERM", "SIGHUP", "SIGUSR1",
                            "SIGUSR2",
                        ])
                        .short("s")
                        .long("signal")
                        .help("set signal"),
                )
                .arg(
                    Arg::with_name("name")
                        .required(true)
                        .value_name("WORKER_CONFIG_NAME")
                        .help("set worker name."),
                )
                .arg(
                    Arg::with_name("command")
                        .required(true)
                        .possible_values(&[
                            "start", "stop", "inc", "dec", "upgrade", "killall", "status", "restart",
                        ])
                        .value_name("COMMAND")
                        .help("set send command."),
                ),
        )
}

pub fn execute() -> Result<(), Error> {
    let app = make_app();
    let matches = app.get_matches();

    match matches.subcommand() {
        ("run", Some(m)) => {
            let sock_path = m
                .value_of("socket-path")
                .expect("require control socket path");
            let path = m.value_of("config").expect("require config path");
            let mut config = { parse_config(path)? };
            config.control_sock = sock_path.to_owned();
            Daemon::new(config).run()
        }
        ("list", Some(m)) => {
            let sock_path = m
                .value_of("socket-path")
                .expect("require control socket path");
            Client::new().list(sock_path)
        }
        ("status", Some(m)) => {
            let sock_path = m
                .value_of("socket-path")
                .expect("require control socket path");
            Client::new().status(sock_path)
        }
        ("ctrl", Some(m)) => {
            let sock_path = m
                .value_of("socket-path")
                .expect("require control socket path");
            let name = m.value_of("name").expect("require worker name");
            let command = m.value_of("command").expect("require command");
            let signal = m.value_of("signal");
            Client::new().run(sock_path, name, command, signal)
        }
        _ => Ok(()),
    }
}
