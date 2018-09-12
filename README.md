# Firestarter: A process and shared socket manager

[![crates.io](https://img.shields.io/crates/v/firestarter.svg)](https://crates.io/crates/firestarter)
[![Patreon](https://img.shields.io/badge/patreon-become%20a%20patron-red.svg)](https://www.patreon.com/mopemope)

Firestarter is simple process and shared socket manager, it designed like [circus][] and [einhorn][], it works with lightweight and faster.

Firestarter can manage groups of processes and shared sockets like [circus][]. And like [einhorn][] we support manual ack.
And you can control Firestarter daemon, such as increasing worker process from ctrl command.

Firestarter shares sockets using the `systemd socket passing protocol` (LISTEN_FDS).

Firestarter uses explicit configuration files rather than complex command line options.

## Features

* Easy install
* Fast and saving memory
* Using explicit configuration file
* Support control command like [circus][]
* Support ack like [einhorn][]
* Execute upgrader program

## Installation

You can get `firestarter` by installing it with cargo:

```
$ cargo install firestarter
```

## Usage

Firestarter is process and shared socket manager. Run `firestarter -h` to see detailed usage.

```
firestarter
process and shared socket manager

USAGE:
    firestarter <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    ctrl      Run control client
    help      Prints this message or the help of the given subcommand(s)
    list      Show worker names
    run       Run daemon
    status    Show worker status
    stop      Stop daemon
```

Example

```
$ firestarter run --config misc/config.toml
```

The configuration file uses toml. An example is below.

```
[worker1] # set worker group name.

# set to commands with their arguments that are executed when this worker is started.
# exec_start = "./demo/target/debug/demo"
exec_start = "/usr/bin/emacs --fg-daemon"

# set to commands to execute to stop the service started via exec_start.
# if you do not set it, sigterm will be sent to the exec_start process.
# note that upgrade ack does not use this command.
exec_stop = "/usr/bin/emacsclient --eval (kill-emacs)"

# set the number of startup processes.
numprocesses = 1

# set working directory.
# working_directory = "/tmp".

# set restart policy. default is none.
# none: not restart process.
# on-failure: restart the process if it is not completed normally.
# always: restart the process whenever you exit.
restart = "on-failure"

# set the seconds to delay the startup of the process.
# warmup_delay = 1

# start the process immediately without starting the process when connecting the client socket.
start_immediate = true

# set shared socket addresses.
# it also support unix domain socket. (e.g.: /tmp/foo.sock)
socket_address = ["127.0.0.1:4000", "127.0.0.1:4001"]

# set processes environment.
environments=["TEST_A=XXXX", "TEST_B=YYYY"]

# set upgrade ack type. this is similar to einhorn 's ACKs. timer is default.
# timer: it will terminate the old process after a certain time (sec).
# manual: send ack manually. For details, refer to einhorn's manual ack document
# none: no ack. simple stop and start
ack = "manual"

# set timer ack time in seconds. default 1sec.
# ack_timeout = 1

# set ack signal. default is SIGUSR2.
# ack_signal = "SIGUSR2"

# set uid.
# uid = 1000

# set gid.
# gid = 10

# set stdout to file.
# size and timed rotate supported.
# the format is below.
# size:<max file size>:<number of backup>:<output path>
# time:<rollover interval>:<type of interval>:<timzone for rotate>:<number of backup>:<output path>
# the type of timezeone for rotate,the list of possible values is below.
#‘U’UTC
#‘L’Local
# the type of interval,the list of possible values is below.
#‘S’Seconds
#‘M’Minutes
#‘H’Hours
#‘D’Days
#
# exmple
# stdout_log = "size:10240:5:/tmp/web1_out.log"
# it rolls over in 3 days and keeps 5 backups.
# stdout_log = "time:3:D:U:7:/tmp/web1_out.log"

# set stderr to file.
# it is the same as stdout.
# stderr_log = "size:10240:5:/tmp/web1_err.log"

# set process live check configuration.
# we will check the existence of the process (experimental).
# the process needs to periodically update the mtime of the file passed in environment variable FIRESTARTER_WATCH_FILE.
# the monitoring process kills the process when the mtime update interval exceeds the threshold. this is the same process as gunicorn's worker notify.
# the unit is seconds, and the default value is 0. (disable live check)
# live_check_timeout = 60

# set auto upgrade.
# it will send upgrade command when their command file is modified.
# it does the same processing as circus.plugins.CommandReloader.
# auto_upgrade = false

# set upgrader program.
# set to the upgrader command.
# run upgrade only when the upgrader command terminates normally.
# upgrader = "/a/b/upgrader --config abc"

# set upgrade timing.
# execute the upgrader command for each specified seconds.
# if not set, execute the upgrade command when executing the upgrade ctrl command.
# upgrader_active_sec=10
# upgrader_timeout=60

...


```

## Control command

Firestarter also provides a client that controls the running daemon.

For example, you can check the status with the following command.

```
$ firestarter ctrl worker1 status
send ctrl command [status] to [worker1] worker
[worker1] active
processes [24170]
time 00:00:06
```

For details, please refer to the help `firestarter ctrl -h`.

## Contributing

Contributions are extremely welcome! Please push PR to `dev` branch.

[circus]: https://circus.readthedocs.io/
[einhorn]: https://github.com/stripe/einhorn
