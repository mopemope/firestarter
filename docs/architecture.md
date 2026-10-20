# Architecture and behavior spec

Authoritative description of how firestarter behaves. Config option *syntax* lives in
`README.md` / `misc/config.toml`; this file covers what the code does with them.
When behavior changes, update this file in the same commit.

## 1. Process model

```
firestarter run            (daemon; src/daemon.rs)
 ├─ monitor process [w1]   (fork per worker group; src/monitor.rs)
 │   ├─ worker process 1   (std::process::Command; src/process.rs)
 │   └─ worker process N
 └─ monitor process [w2] ...
```

- **Daemon** (`Daemon::run`): parses config, forks one *monitor* per `[worker]` table, then loops
  (`Daemon::wait`, mio poll, 1 s tick) serving the daemon control socket. The loop ends when no monitors
  remain or after a `stop` command.
- **Monitor** (`MonitorProcess::spawn` -> `start_monitoring`, runs in the forked child): closes fds 3..127,
  binds the shared sockets, opens its own control socket, spawns the worker processes, then runs `Monitor::start`
  (mio poll, 1 s timeout) which pumps stdout/stderr into log files, serves control commands, and respawns dead
  workers according to `restart` / `giveup`.
- **Worker processes**: plain children of the monitor. They inherit the shared socket fds and find them via env.
- The code is single-threaded on purpose (`fork` safety). `thread::sleep` is used only for delays. Do not
  introduce threads before `fork`.

### Startup order inside a monitor (order matters)
1. install signal handlers, optional `warmup_delay` sleep
2. `close_fds()` (3..127)
3. bind each `socket_address` (`ListenFd`, backlog 128) -> raw fds
4. bind the per-worker control socket (backlog 1)
5. export env for workers (below), create `Monitor`
6. if there are no sockets or `start_immediate`: spawn workers now; otherwise wait for the first client
   connection on a shared socket (`wait_activate_socket`) and spawn then
7. `Monitor::start` loop

### Environment given to workers
| Variable | Meaning |
|---|---|
| `LISTEN_FDS` | number of shared sockets (systemd protocol; fds are allocated after step 2, so normally start at 3) |
| `<BASE>_FD_COUNT`, `<BASE>_FD_<i>` | same count, and the i-th fd number |
| `<BASE>_SOCK_FD`, `<BASE>_SOCK_PATH` | monitor control socket fd / path (workers use it for manual ack) |
| `<BASE>_MASTER_PID` | monitor pid |
| `<BASE>_WATCH_FILE` | only if `live_check_timeout > 0`; worker must touch it periodically |
| `environments = [...]` from config | user env, applied first (extras above win on conflict) |

`<BASE>` is `environment_base_name` (default `FIRESTARTER`).

### Files in `$TMPDIR` (`std::env::temp_dir()`)
`<app>-control.socket` (daemon), `<app>-<worker>.socket` (monitor, or config `control_socket`),
`<app>-process-<worker>-<id>.id` (live-check watch files). `<app>` is `firestarter` unless the env var
`FIRESTARTER_APP_NAME` is set — **use that plus `TMPDIR` to isolate test daemons** (`scripts/smoke.sh` does).

## 2. Control protocol

Newline-delimited JSON over Unix stream sockets; one request, one response, then close.

```
client ──DaemonCommand──▶ daemon ──CtrlCommand──▶ monitor
client ◀────response───── daemon ◀──CommandResponse── monitor
```

- `DaemonCommand { command_type: "list"|"status"|"ctrl_worker"|"stop", worker?: str, command?: CtrlCommand, pid }`
- `CtrlCommand { command, pid, signal?: "SIGTERM"|... }`
- `command` wire names: `none`, `worker:killall|start|stop|restart|upgrade|ack|inc|dec|status`, `monitor:stop`.
  The CLI accepts `start stop inc dec upgrade killall status restart` only (`Command::from_str`); `ack` is sent by workers.
- Responses: `ctrl_worker` -> one `CommandResponse { status: "ok"|"error", command, pid, message }`;
  `status` and `stop` -> JSON array of `CommandResponse` (one per worker); `list` -> `ListResponse { pid, workers }`.
- `stop` = send `worker:stop` to every worker group, then `monitor:stop`, then kill leftovers, then the daemon exits.
- `worker:ack` never gets a response (the monitor ignores it outside an upgrade).
- The wire names are pinned by `command::test_command_wire_format`; changing them breaks workers that ack manually.

## 3. Worker lifecycle semantics (`src/worker.rs`)

- `restart` policy (`RestartStrategy::need_respawn`): `none` never, `always` always, `on-failure` when exit code != 0.
  A process killed by a signal counts as exit code -1 (failure). `giveup = N` stops the monitor after N consecutive
  respawn *spawn errors* (e.g. exec fails; a worker that starts then dies does not count); 0 = never give up.
- `inc` / `dec`: change `numprocesses` by one. `dec` is a no-op at 1.
- `stop`: runs `exec_stop` if configured, otherwise sends the signal (default SIGTERM) to every worker; then
  drains IO for 1 s. `restart` = stop, kill stragglers, spawn `numprocesses` new ones.
- `upgrade` (zero-downtime swap) — first runs `upgrader` if `run_upgrader == OnUpgrade` (abort on non-zero
  exit or after `upgrader_timeout`), then by `ack`:
  - `timer`: spawn new workers, sleep `ack_timeout`; new workers that already died are "failed" and keep one old
    worker alive each; signal the other old workers with `ack_signal` (default SIGUSR2); kill any that do not exit.
  - `manual`: spawn new workers, then wait for `worker:ack` messages on the monitor control socket (each ack may carry
    a `signal` overriding `ack_signal`); every ack signals one old worker.
  - `none`: stop old workers (as in `stop`), then spawn new ones (brief downtime).
- Upgrade is skipped (returns empty pid lists) when the worker group is not active.
- `auto_upgrade`: daemon checks every second whether the `exec_start` binary's path/mtime changed and, if so,
  sends `worker:upgrade`. `upgrader_active_sec`: daemon runs the upgrader every N seconds and upgrades on success.
- `live_check_timeout`: monitor kills workers whose watch file mtime is older than the timeout (checked ~every 1 s).

### Monitor exit codes (as seen by the daemon, `MonitorProcess::try_wait`)
Exit code 255 (`exit(-1)` after SIGTERM/SIGHUP/SIGABRT hit the monitor) -> **daemon respawns the monitor** after 500 ms.
Any other exit code, or death by SIGINT/SIGQUIT/SIGKILL/SIGABRT -> monitor is dropped, not respawned.
Death by any other signal -> treated like 255 (respawned).

## 4. Module map

| File | Responsibility |
|---|---|
| `main.rs`, `cmdline.rs` | entry point; clap 2 CLI (`run list stop status ctrl`), default socket paths |
| `config.rs` | TOML -> `WorkerConfig` (serde defaults), command-line tokenizer (nom 4 macros: quoting, `$VAR`) |
| `daemon.rs` | daemon loop, forwarding commands to monitors, upgrade/upgrader scheduling |
| `monitor.rs` | `MonitorProcess` (fork + setup, runs in daemon) and `Monitor` (event loop, runs in child) |
| `worker.rs` | worker group state machine: run/inc/dec/stop/restart/upgrade/health check |
| `process.rs` | one OS process: spawn, wait, kill, watch file; upgrader / exec_stop helpers |
| `command.rs` | wire types and socket send/read helpers |
| `client.rs` | CLI-side wrappers that build and print `DaemonCommand`s |
| `sock.rs` | `ListenFd` parsing (`4000`, `host:port`, `/path`, `tcp::`/`udp::`/`unix::` prefixes), bind/listen via nix |
| `logs.rs` | `LogFile` with size / timed rotation (`size:...`, `time:...` specs) |
| `signal.rs` | `Signal` enum (serde names), `kill(2)` wrappers |
| `reloader.rs` | locate the `exec_start` binary and detect modification |
| `app.rs`, `utils.rs` | app name / env override, small helpers |
| `demo/` | separate crate, zero external dependencies; std-only sample worker (LISTEN_FDS handoff + manual ack); excluded from the package |

## 5. Known quirks (read before "fixing")

- `exec_start`'s first token must be an absolute path or a path relative to `working_directory`. There is **no
  `PATH` lookup**; `reloader::cmd_path` canonicalizes and `unwrap()`s, so a bare `sleep` panics the daemon at start.
- Config errors (bad TOML, bad command line, bad log spec) `panic!`/`expect` instead of returning errors
  (`config.rs`, `logs.rs`).
- `MonitorProcess::try_wait` calls `waitpid(None, WNOHANG)` (any child) inside a per-monitor loop, so with several
  worker groups an exit can be attributed to the wrong monitor.
- Debug builds run fine since the `nix` 0.31 upgrade (the old nix 0.17 `offset_of!` debug abort is gone; the
  upgrade touched `sock.rs`, `monitor.rs`, `daemon.rs`).
- Signal handlers communicate via `env::set_var("<APP>_HANDLE_SIGNAL", ..)` and the poll loop checks it afterwards.
  Not async-signal-safe; keep handlers minimal.
- `nom 4` triggers a future-incompatibility warning; the tokenizer in `config.rs` is the only user.
