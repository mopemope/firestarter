---
name: add-ctrl-command
description: Use when adding or changing a firestarter ctrl command (e.g. `firestarter ctrl <worker> <cmd>`), its wire name, or the daemon/monitor control protocol. Lists every file that must change.
---

# Add or change a ctrl command

A ctrl command crosses 4 layers; missing one compiles fine but fails at runtime. Walk them in order.
Background: `docs/architecture.md` section 2 (protocol) and 3 (semantics).

1. `src/command.rs` — add a `Command` variant with `#[serde(rename = "worker:<name>")]`; add the CLI string to
   `Command::from_str` (skip if workers send it, like `ack`). Update `test_command_from_str` /
   `test_command_wire_format`.
2. `src/cmdline.rs` — add the string to the `possible_values(&[...])` list of the `ctrl` subcommand's `command` arg
   (clap rejects it otherwise). Client code in `client.rs` needs no change for per-worker commands.
3. `src/monitor.rs` — add an arm in `Monitor::exec_command` returning a `CommandResponse`
   (`status`, `command: command.clone()`, `pid: self_pid`, `message`). Without an arm the fallback replies
   `"not implement"` with status error.
4. `src/worker.rs` — put the behavior in a `Worker` method (state lives there). Use `monitor.wait_process_io(self, 1)`
   after signalling so stdout/stderr pipes drain. Keep it single-threaded.
5. Docs — `README.md` (ctrl section), `docs/architecture.md` (wire names list + semantics).

Special cases: daemon-level commands (`list`, `status`, `stop`) are a different path: `CommandType` in
`command.rs`, handled in `Daemon::wait` in `daemon.rs`, built in `client.rs`.

Verify: `scripts/check.sh`, then `scripts/smoke.sh`; extend the `step ...` lines in `scripts/smoke.sh` with the new
command so it stays covered.
