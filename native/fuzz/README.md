# Fuzz targets for the native engine (ADDENDUM_4.md D6)

Two coverage-guided [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
targets. Each asserts that nothing in it panics:

* `parse`: `parse::parse` on arbitrary bytes. Any reported TCP payload
  offset must stay inside the frame.
* `engine`: `Engine::feed` on arbitrary frame and timestamp sequences, then
  every query the engine serves (`slow_clusters`, `snapshot_from`, `sweep`,
  `flush`).

```
# from native/, with a nightly toolchain and cargo-fuzz installed
# (rustup toolchain install nightly; cargo install cargo-fuzz)
export PYO3_PYTHON=/path/to/python3.12        # pyo3 links libpython
export LD_LIBRARY_PATH="$($PYO3_PYTHON -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))')"
cargo +nightly fuzz run parse  -- -max_total_time=600 -max_len=4096
cargo +nightly fuzz run engine -- -max_total_time=600 -max_len=4096
```

Corpora and crash artifacts stay local (`.gitignore`). The property tests in
`native/tests/properties.rs` cover the same claims on every `cargo test`.
Run summaries are recorded in `docs/PROGRESS.md` under "Phase 15 details".
