# Contributing to Gono Cloud

Thank you for helping. This guide lists what a change needs before it can be merged. For larger
changes, such as a new feature or a change to the protocol, open an issue first so that the
approach can be agreed on before you spend time on it.

Security problems are not reported here: see [SECURITY.md](SECURITY.md).

## Repository

The repository is a monorepo; today it holds the server (`crates/server/`), its packaging
(`packaging/server/`), the black-box acceptance suite (`acceptance/`) and the documentation
(`docs/`). [docs/repository-layout.md](docs/repository-layout.md) describes the layout and the
rules every component follows, among them per-component release tags and backward-compatible
protocol changes.

## Building

You need Rust 1.100 or newer (the `rust-version` of the workspace); CI uses the latest stable
release. SQLite is compiled in, so no system libraries are needed.

```sh
cargo build
cargo run -- --config config.toml serve   # copy config.example.toml to config.toml first
```

`acceptance/scripts/run-new.sh --serve` starts a throwaway installation with test accounts and
prints where to find their credentials.

## Checks

Run these before sending a change; CI runs the same on Linux:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The tests that need a database run on SQLite. For changes to SQL, the schema or
`gono_server_core::db`, run them on MySQL as well (CI does, in the `mysql` job): with
`GONO_TEST_MYSQL_URL`, every test gets a new database on that server.
`acceptance/scripts/mysql-instance.sh` starts a throwaway MySQL 5.7 on `127.0.0.1:3317` (from
Homebrew's `mysql@5.7`, or `MYSQL_BASEDIR`):

```sh
acceptance/scripts/mysql-instance.sh start
GONO_TEST_MYSQL_URL=$(acceptance/scripts/mysql-instance.sh url) cargo test --workspace --locked
```

A schema change goes into both `crates/server/core/migrations/sqlite/` and `.../mysql/`.

For changes to the server's behavior, also run the acceptance suite, which builds the server,
starts it on a throwaway installation and talks to it over HTTP only:

```sh
acceptance/scripts/run-new.sh
RUN_LITMUS=1 acceptance/scripts/run-new.sh       # also the litmus WebDAV suite, if installed
DB_BACKEND=mysql GONO_ACCEPT_MYSQL_URL=$(acceptance/scripts/mysql-instance.sh url) \
  acceptance/scripts/run-new.sh                  # on a new MySQL database (needs the mysql client)
acceptance/scripts/nextcloudcmd-scenarios.sh     # Nextcloud desktop client, if installed
```

Every test must pass, except the ones listed in `acceptance/new-expected-failures.txt` (the
list is empty today). The suite has its own workspace and must never depend on a crate of this
repository; [acceptance/README.md](acceptance/README.md) explains its options, including how to
run it through a reverse proxy.

For changes to `packaging/server/`:

```sh
shellcheck -s sh packaging/server/*.sh
```

`packaging/server/test-install.sh` installs a system service and creates a system user, so it
runs only in CI, where the `install` job exercises the install script on Linux.
`packaging/server/test-relay.sh` sets the relay up behind nginx in the same way and checks its
probes (the `relay` job). To run either on a Linux workstation, use a throwaway container with
systemd as its init (podman, rootless works), with an archive and the probe built for Linux:

```sh
cargo zigbuild --release -p gono-server --target x86_64-unknown-linux-musl
cargo zigbuild --release -p gono-server-relay --example relay-probe --target x86_64-unknown-linux-musl
packaging/server/package.sh x86_64-unknown-linux-musl target/x86_64-unknown-linux-musl/release/gono-cloud dist
packaging/server/test-in-container.sh packaging/server/test-relay.sh packaging/server/cloud.server.sh \
  dist/gono-cloud-*-x86_64-unknown-linux-musl.tar.gz target/x86_64-unknown-linux-musl/release/examples/relay-probe
```

For changes to how `gono-connect` dials (`crates/client/connect`), also run the dials under UDP
filters on Linux, as root (`unshare`) or with pasta installed (rootless); CI runs it as the
`udp-paths` job:

```sh
cargo build -p gono-connect --example udp-paths
sudo crates/client/connect/scripts/test-udp-paths.sh target/debug/examples/udp-paths
```

## Code

- Format with `rustfmt` and keep clippy quiet; the workspace lints are in the root
  `Cargo.toml`. `unsafe` code is not allowed.
- Comment what is not obvious from the code: why something is done, invariants, security
  decisions. Code comments and documentation are written in English.
- Add tests with the change: unit tests next to the code, integration tests in the crate's
  `tests/`, and an acceptance test for behavior a client can observe.
- Keep the protocol backward compatible: released clients must keep working with a newer
  server.
- Never log passwords, tokens or app passwords, and keep secrets in `SecretString`.
- Note user-visible changes in [crates/server/CHANGELOG.md](crates/server/CHANGELOG.md) under
  "Unreleased".

## Commits

- One topic per commit; a pull request may have several.
- Write the message in English, starting with one of these prefixes and an imperative summary:
  `Feat:`, `Fix:`, `Docs:`, `Refactor:`, `Perf:`, `Style:`. For example
  `Fix: Keep the ETag of a folder after a failed MOVE`. Explain the why in the body when it is
  not obvious.
- Do not commit generated files, build output or local configuration; `.gitignore` covers the
  usual ones.

## License

Gono Cloud is licensed under either of the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
