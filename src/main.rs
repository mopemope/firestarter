use firestarter::cmdline;

fn main() {
    use log::error;
    use nix::unistd::{getpid, getppid};

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
        }
    }
}
