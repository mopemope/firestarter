# Firestarter: Process and shared socket manager

Firestarter is simple process and shared socket manager, it designed like [circus][] and [einhorn][].

Firestarter can manage groups of processes and shared sockets like [circus][]. And like [einhorn][] we support manual ack.
And you can control Firestarter daemon, such as increasing worker process from ctrl command.

Firestarter shares sockets using the `systemd socket passing protocol` (LISTEN_FDS).

Firestarter uses explicit configuration files rather than complex command line options.

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
```

Example

```
$ firestarter run --config misc/config.toml
```

The configuration file uses toml. An example is below.

```
[web1] # set worker group name

# set startup process and args
cmd = ["./demo/target/debug/demo"]

# set the number of startup processes
numprocesses = 2

# set working directory
# working_directory = "/tmp"

# set restart policy. default is none
# none: not restart process
# on-failure: restart the process if it is not completed normally
# always: restart the process whenever you exit
restart = "on-failure"

# set the seconds to delay the startup of the process
warmup_delay = 1

# start the process immediately without starting the process when connecting the client socket
start_immediate = true

# set shared socket addresses
socket_address = ["127.0.0.1:4000", "127.0.0.1:4001"]

# set processes environment
environments=["TEST_A=XXXX", "TEST_B=YYYY"]

# set upgrade ack type. default is timer
# timer: it will terminate the old process after a certain time
# manual: send ack manually. For details, refer to einhorn's manual ack document
ack = "manual"

# set timer ack time in seconds
# ack_timeout = 2

# set uid
# uid = 1000

# set gid
# gid = 10

# output stdout to file
# only size rotation is supported
# size:<file size>:<number of backup>:<output path>
# stdout_log = "size:10240:5:/tmp/web1_out.log"

# output stderr to file
# only size rotation is supported
# size:<file size>:<number of backup>:<output path>
# stderr_log = "size:10240:5:/tmp/web1_err.log"

[web2] # set worker group name

# set startup process and args
cmd = ["./demo/target/debug/demo"]

# set the number of startup processes
numprocesses = 1

# set working directory
# working_directory = "/tmp"

# set restart policy. default is none
# none: not restart process
# on-failure: restart the process if it is not completed normally
# always: restart the process whenever you exit
restart = "on-failure"

# set the seconds to delay the startup of the process
warmup_delay = 2

# start the process immediately without starting the process when connecting the client socket
start_immediate = true

# set shared socket addresses
socket_address = ["127.0.0.1:5000"]

# set processes environment
environments=["TEST_A=XXXX", "TEST_B=YYYY"]

# set upgrade ack type. default is timer
# timer: it will terminate the old process after a certain time
# manual: send ack manually. For details, refer to einhorn's manual ack document
# ack = "manual"

# set timer ack time in seconds
# ack_timeout = 2

# set uid
# uid = 1000

# set gid
# gid = 10

# output stdout to file
# only size rotation is supported
# size:<file size>:<number of backup>:<output path>
# stdout_log = "size:10240:5:/tmp/web1_out.log"

# output stderr to file
# only size rotation is supported
# size:<file size>:<number of backup>:<output path>
# stderr_log = "size:10240:5:/tmp/web1_err.log"

```

## Contributing

Contributions are extremely welcome! Please push PR to `dev` branch.

[circus]: https://circus.readthedocs.io/
[einhorn]: https://github.com/stripe/einhorn
