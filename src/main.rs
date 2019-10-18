use firestarter::cmdline;

fn main() {
    use log::error;
    use nix::unistd::{getpid, getppid};
    use std::env;
    let want_bt = match env::var("RUST_BACKTRACE").as_ref().map(|x| x.as_str()) {
        Ok("1") | Ok("full") => true,
        _ => false,
    };
    env_logger::init();
    let main_pid = getpid();
    match cmdline::execute() {
        Ok(()) => (),
        Err(err) => {
            let ppid = getppid();
            if main_pid == ppid {
                return;
            }
            error!("exit {}", err);
            for cause in err.iter_chain().skip(1) {
                error!("  caused by: {}", cause);
            }
            if want_bt {
                let bt = err.backtrace();
                error!("{}", bt);
            } else if cfg!(debug_assertions) {
                error!("hint: you can set RUST_BACKTRACE=1 to get the entire backtrace.");
            }
        }
    }
}
