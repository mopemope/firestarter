# firestarter

Rust (edition 2018) process + shared-socket manager for Unix, in the spirit of circus/einhorn. ~4.5k lines,
library crate `firestarter` + thin `main.rs`. Single-threaded, `fork`-based. Linux/Unix only.

## Verify your change (cheapest first)
- `scripts/check.sh` — fmt + `cargo check --all-targets` + unit tests, noise filtered. Run after every edit.
- `scripts/check.sh quick` — skip tests.
- `scripts/smoke.sh` — real daemon end-to-end (start, inc/dec/restart/upgrade, stop). **Run it when you touch**
  `daemon.rs monitor.rs worker.rs process.rs command.rs sock.rs client.rs cmdline.rs`. It uses a release build.
- Single test: `cargo test <name>`. Debug logs: `RUST_LOG=debug`.
- Do not paste raw `cargo build`/`cargo clippy` output into your context: ~20 warnings come from dependencies
  (nom 4 macros) and old code. Use `cargo check -q --message-format short`; clippy is advisory only here
  (many pre-existing findings; fix only what you touch).

## Where things are (details: `docs/architecture.md`)
daemon (`daemon.rs`) forks one monitor per worker group (`monitor.rs`) which spawns worker processes
(`worker.rs` -> `process.rs`). Client talks JSON-lines over Unix sockets (`command.rs`, `client.rs`).
Config is TOML (`config.rs`); sample in `misc/config.toml`; user docs in `README.md`.
Read `docs/architecture.md` before changing lifecycle, upgrade/ack, signals, or the control protocol.

## Rules that are not obvious from the code
- `exec_start` must be an absolute path (or relative to `working_directory`); no `PATH` lookup. Tests/configs using
  bare `sleep` panic the daemon.
- Debug builds of the daemon abort on current rustc (nix 0.17 `offset_of!` null deref). Run the daemon from
  `--release` only. Unit tests are fine in debug. Don't "fix" this by editing code; the real fix is a `nix` upgrade.
- Wire names in `command.rs` (`worker:upgrade`, ...) are a protocol; changing them breaks running daemons and
  manual-ack workers. `command::test_command_wire_format` guards it.
- Stay single-threaded before `fork`. No new threads/async runtime in daemon or monitor paths.
- Signal handlers must stay trivial (they set an env var; the poll loop reads it).
- Isolate any daemon you start in tests: set `FIRESTARTER_APP_NAME=<unique>` and `TMPDIR=<fresh dir>`, never
  touch the default `/tmp/firestarter-*.socket`, and kill what you start.
- Don't touch the nom macros in `config.rs` (tokenizer for `exec_start` etc.) unless the task is about them.

## Conventions
- Errors: `anyhow::Result` with `.context("...")`; logging via `log` macros, messages like
  `"fail xxx. caused by: {}"`. Public config options need a serde default fn in `config.rs`.
- Tests: top-level `#[test] fn test_*` next to the code (no `mod tests`). Add one for any pure logic you change.
- Docs sync: new/changed config option => `config.rs`, `misc/config.toml`, README example, `docs/architecture.md`.
  New/changed ctrl command => see below.
- Format with `cargo fmt` (rustfmt.toml: 4 spaces). Commits are short imperative lines. PRs target `dev`.
- `demo/` is a separate crate (own `Cargo.lock`, excluded from the package); don't build it unless asked.

## Task checklists (skills, readable by any agent)
- Adding/changing a ctrl command: `.claude/skills/add-ctrl-command/SKILL.md`
- Adding/changing a worker config option: `.claude/skills/add-config-option/SKILL.md`
