---
name: add-config-option
description: Use when adding, renaming or changing the default of a per-worker TOML config option in firestarter (WorkerConfig, misc/config.toml, README config example).
---

# Add or change a worker config option

1. `src/config.rs` — add the field to `WorkerConfig` with `#[serde(default = "default_xxx")]` (or `Option<T>`), and a
   small `default_xxx()` fn near the others. Reuse `default_bool/num/zero/vec_str` when the value fits. Enum values
   use `#[serde(rename = "kebab-case")]`. Derived/parsed values go in `#[serde(skip, default = ...)]` fields filled in
   `parse_config` (see `exec_start_cmd`, `run_upgrader`).
2. Validation lives in `parse_config`. Existing code uses `expect`/`unwrap` (panics); prefer returning an
   `io::Error` for new checks, but don't refactor the old ones in the same change.
3. Use the value where behavior changes — find the consumer with `rg "config\.<field>|self\.config\.<field>" src`.
   Daemon-side options are read in `daemon.rs`; monitor/worker-side in `monitor.rs` / `worker.rs` / `process.rs`.
4. Docs: add the option with a comment to `misc/config.toml` AND the example block in `README.md` (they are the same
   text), and mention behavior in `docs/architecture.md` if it is more than a value.
5. Tests: extend `config::test_worker_config_defaults` (default value) and, if you touched `misc/config.toml`,
   `config::test_parse_sample_config`.

Verify: `scripts/check.sh`; if runtime behavior changed, also `scripts/smoke.sh` (edit the generated config in the
script to exercise the option).
