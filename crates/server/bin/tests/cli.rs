//! End-to-end tests of the `gono-cloud` binary.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const PASSWORD: &str = "correct horse battery staple";

fn gono_cloud() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gono-cloud"));
    command
        .env_remove("GONO_CLOUD_CONFIG")
        .env_remove("GONO_CLOUD_LOG");
    command
}

fn run(command: &mut Command) -> Output {
    command.output().expect("run gono-cloud")
}

fn run_with_stdin(command: &mut Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gono-cloud");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A temporary installation directory with a config file.
struct Instance {
    dir: tempfile::TempDir,
    addr: SocketAddr,
}

impl Instance {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let addr = free_port();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                r#"
                [server]
                bind = "{addr}"
                base_url = "http://{addr}"

                [storage]
                data_dir = "data"

                [db]
                path = "db/gono-cloud.db"
                "#
            ),
        )
        .unwrap();
        Self { dir, addr }
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("db/gono-cloud.db")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = gono_cloud();
        command.arg("--config").arg(self.config()).args(args);
        command
    }

    fn init(&self) -> Output {
        run_with_stdin(
            &mut self.command(&["init", "--password-stdin"]),
            &format!("{PASSWORD}\n"),
        )
    }

    /// Adds a `[relay]` table that runs the relay on a free loopback port, and returns it.
    fn enable_relay(&self) -> SocketAddr {
        let relay = free_port();
        let mut config = std::fs::read_to_string(self.config()).unwrap();
        config.push_str(&format!(
            r#"
            [relay]
            enabled = true
            public_url = "https://relay.example.com"
            bind = "{relay}"
            "#
        ));
        std::fs::write(self.config(), config).unwrap();
        relay
    }
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn example_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../config.example.toml")
}

#[test]
fn help_lists_every_subcommand() {
    let output = run(gono_cloud().arg("--help"));
    assert!(output.status.success());
    let help = text(&output.stdout);
    for command in [
        "serve",
        "relay",
        "init",
        "config",
        "user",
        "app-password",
        "device",
        "s3",
        "rescan",
    ] {
        assert!(help.contains(command), "missing {command}:\n{help}");
    }
    assert!(help.contains("GONO_CLOUD_CONFIG"), "{help}");
}

#[test]
fn config_check_accepts_the_example() {
    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(example_config()));
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("Configuration OK"), "{stdout}");
    assert!(stdout.contains("127.0.0.1:16102"), "{stdout}");
    assert!(!stdout.contains("warning"), "{stdout}");
}

#[test]
fn config_check_reads_the_path_from_the_environment() {
    let output = run(gono_cloud()
        .args(["config", "check"])
        .env("GONO_CLOUD_CONFIG", example_config()));
    assert!(output.status.success(), "{}", text(&output.stderr));
}

#[test]
fn config_check_reports_every_invalid_value() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        r#"
        [server]
        bind = "0.0.0.0:16102"
        base_url = "https://cloud.example.com/sub"

        [storage]
        data_dir = "data"

        [db]
        path = "gono-cloud.db"

        [notify_push]
        ping_interval_secs = 0
        "#,
    )
    .unwrap();

    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(&config));
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    for key in [
        "server.bind",
        "server.base_url",
        "notify_push.ping_interval_secs",
    ] {
        assert!(stderr.contains(key), "missing {key}:\n{stderr}");
    }
}

#[test]
fn config_check_rejects_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let example = std::fs::read_to_string(example_config()).unwrap();
    std::fs::write(&config, example.replace("[db]", "[db]\nmax_conections = 4")).unwrap();

    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(&config));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("max_conections"));
}

/// `config check` shows the mail server and names its password file, never the password, and
/// `serve` does not start without that file.
#[test]
fn config_check_shows_the_mail_server_but_not_its_password() {
    let instance = Instance::new();
    let mut config = std::fs::read_to_string(instance.config()).unwrap();
    config.push_str(
        r#"
        [smtp]
        enabled = true
        host = "smtp.example.com"
        port = 587
        security = "starttls"
        username = "cloud@example.com"
        password_file = "smtp-password"
        from = "Gono Cloud <cloud@example.com>"
        "#,
    );
    std::fs::write(instance.config(), config).unwrap();
    let password_file = instance.dir.path().join("smtp-password");

    let check = run(&mut instance.command(&["config", "check"]));
    assert!(check.status.success(), "{}", text(&check.stderr));
    let shown = text(&check.stdout);
    for expected in [
        "smtp.enabled                    true",
        "smtp.host                       smtp.example.com",
        "smtp.port                       587",
        "smtp.security                   starttls",
        "smtp.username                   cloud@example.com",
        "smtp.from                       Gono Cloud <cloud@example.com>",
    ] {
        assert!(shown.contains(expected), "{expected} in {shown}");
    }
    assert!(
        shown.contains(&format!("{} (missing)", password_file.display())),
        "{shown}"
    );
    assert!(!shown.contains("warning"), "{shown}");

    assert!(instance.init().status.success());
    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    assert!(
        text(&serve.stderr).contains("smtp.password_file"),
        "{}",
        text(&serve.stderr)
    );

    std::fs::write(&password_file, "very secret\n").unwrap();
    let shown = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(!shown.contains("(missing)"), "{shown}");
    assert!(
        !shown.contains("very secret"),
        "the password is never shown: {shown}"
    );

    // Plain SMTP is for a mail server on this host only.
    let config = std::fs::read_to_string(instance.config())
        .unwrap()
        .replace("security = \"starttls\"", "security = \"none\"");
    std::fs::write(instance.config(), config).unwrap();
    let refused = run(&mut instance.command(&["config", "check"]));
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("smtp.security"),
        "{}",
        text(&refused.stderr)
    );
}

/// `config check` shows the mini program and names the file of its AppSecret, never the
/// secret, and `serve` does not start without that file or with an empty one.
#[test]
fn config_check_shows_the_mini_program_but_not_its_secret() {
    let instance = Instance::new();
    let mut config = std::fs::read_to_string(instance.config()).unwrap();
    config.push_str(
        r#"
        [wechat]
        enabled = true
        app_id = "wxd930ea5d5a258f4f"
        secret_file = "wechat-secret"
        qr_url_prefix = "https://cloud.example.com/q/"
        "#,
    );
    std::fs::write(instance.config(), config).unwrap();
    let secret_file = instance.dir.path().join("wechat-secret");

    let check = run(&mut instance.command(&["config", "check"]));
    assert!(check.status.success(), "{}", text(&check.stderr));
    let shown = text(&check.stdout);
    for expected in [
        "wechat.enabled                  true",
        "wechat.app_id                   wxd930ea5d5a258f4f",
        "wechat.qr_url_prefix            https://cloud.example.com/q/",
        "wechat.verify_file              (none)",
    ] {
        assert!(shown.contains(expected), "{expected} in {shown}");
    }
    assert!(
        shown.contains(&format!("{} (missing)", secret_file.display())),
        "{shown}"
    );

    assert!(instance.init().status.success());
    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    assert!(
        text(&serve.stderr).contains("wechat.secret_file"),
        "{}",
        text(&serve.stderr)
    );
    std::fs::write(&secret_file, "\n").unwrap();
    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    assert!(
        text(&serve.stderr).contains("is empty"),
        "{}",
        text(&serve.stderr)
    );

    std::fs::write(&secret_file, "0123456789abcdef0123456789abcdef\n").unwrap();
    let shown = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(!shown.contains("(missing)"), "{shown}");
    assert!(
        !shown.contains("0123456789abcdef"),
        "the secret is never shown: {shown}"
    );

    // A link prefix the console would not take is refused.
    let config = std::fs::read_to_string(instance.config())
        .unwrap()
        .replace("https://cloud.example.com/q/", "http://cloud.example.com/q");
    std::fs::write(instance.config(), config).unwrap();
    let refused = run(&mut instance.command(&["config", "check"]));
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("wechat.qr_url_prefix"),
        "{}",
        text(&refused.stderr)
    );
}

#[test]
fn config_check_shows_the_redirect_uris_but_not_the_client_secrets() {
    let instance = Instance::new();
    let mut config = std::fs::read_to_string(instance.config()).unwrap();
    config.push_str(
        r#"
        [oauth.github]
        enabled = true
        client_id = "Ov23liAbCdEf"
        client_secret_file = "github-secret"
        "#,
    );
    std::fs::write(instance.config(), config).unwrap();
    let secret_file = instance.dir.path().join("github-secret");
    let check = run(&mut instance.command(&["config", "check"]));
    assert!(check.status.success(), "{}", text(&check.stderr));
    let shown = text(&check.stdout);
    for expected in [
        "oauth.google.enabled            false",
        "oauth.github.enabled            true",
        "oauth.github.client_id          Ov23liAbCdEf",
        "oauth.github.allow_signup       false",
        &format!(
            "oauth.github redirect URI       http://{}/login/oauth/github/callback",
            instance.addr
        ),
    ] {
        assert!(shown.contains(expected), "{expected} in {shown}");
    }
    assert!(
        shown.contains(&format!("{} (missing)", secret_file.display())),
        "{shown}"
    );
    // `serve` reads the secret when it starts and refuses to start without it.
    assert!(instance.init().status.success());
    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    assert!(
        text(&serve.stderr).contains("oauth.github.client_secret_file"),
        "{}",
        text(&serve.stderr)
    );
    std::fs::write(&secret_file, "s3cr3t-of-the-app\n").unwrap();
    let shown = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(!shown.contains("s3cr3t-of-the-app"), "{shown}");
}

#[test]
fn missing_config_files_get_a_hint() {
    let output = run(gono_cloud().args(["config", "check", "--config", "/nonexistent.toml"]));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("--config"));
}

#[test]
fn init_creates_the_first_admin_exactly_once() {
    let instance = Instance::new();

    let output = instance.init();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("admin"), "{stdout}");
    assert!(instance.db().exists());
    assert!(instance.dir.path().join("data").is_dir());
    for stream in [&output.stdout, &output.stderr] {
        assert!(!text(stream).contains(PASSWORD), "password leaked");
    }

    let again = instance.init();
    assert!(!again.status.success());
    assert!(
        text(&again.stderr).contains("already contains users"),
        "{}",
        text(&again.stderr)
    );
}

#[test]
fn init_needs_a_terminal_or_password_stdin() {
    let instance = Instance::new();
    let output = run(instance.command(&["init"]).stdin(Stdio::null()));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("--password-stdin"));
}

#[test]
fn init_rejects_weak_passwords_without_echoing_them() {
    let instance = Instance::new();
    let output = run_with_stdin(
        &mut instance.command(&["init", "--password-stdin"]),
        "short\n",
    );
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("at least 8 characters"), "{stderr}");
    assert!(!stderr.contains("short\n") && !stderr.contains("\"short\""));
}

#[test]
fn serve_requires_an_initialized_database() {
    let instance = Instance::new();
    let output = run(&mut instance.command(&["serve"]));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("gono-cloud init"));
    assert!(
        !instance.db().exists(),
        "serve must not create the database"
    );
}

/// Rows of the admin's `files` table, as `(rel_path, size)`, ordered by path.
async fn file_rows(instance: &Instance) -> Vec<(String, i64)> {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    let rows =
        sqlx::query_as("SELECT rel_path, size FROM files WHERE owner_id = 1 ORDER BY rel_path")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows
}

#[tokio::test]
async fn rescan_reconciles_changes_made_behind_the_servers_back() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let files = instance.dir.path().join("data/files/1");
    std::fs::create_dir_all(files.join("docs")).unwrap();
    std::fs::write(files.join("docs/a.txt"), "hello").unwrap();
    std::fs::write(files.join("Cafe\u{301}.txt"), "nfd").unwrap();

    let dry = run(&mut instance.command(&["rescan", "admin", "--dry-run"]));
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    let report = text(&dry.stdout);
    assert!(report.contains("Dry run"), "{report}");
    assert!(
        report.contains("would rename to NFC: /Caf\u{e9}.txt"),
        "{report}"
    );
    assert!(report.contains("would add:    /docs"), "{report}");
    assert!(
        file_rows(&instance).await.is_empty(),
        "a dry run changes nothing"
    );
    assert!(
        std::fs::read_dir(&files)
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == "Cafe\u{301}.txt")
    );

    let done = run(&mut instance.command(&["rescan", "admin"]));
    assert!(done.status.success(), "{}", text(&done.stderr));
    let report = text(&done.stdout);
    assert!(
        report.contains("renamed to NFC:   /Caf\u{e9}.txt"),
        "{report}"
    );
    assert_eq!(
        file_rows(&instance).await,
        [
            (String::new(), 8),
            ("Caf\u{e9}.txt".to_owned(), 3),
            ("docs".to_owned(), 5),
            ("docs/a.txt".to_owned(), 5),
        ]
    );
    let again = run(&mut instance.command(&["rescan", "--all"]));
    assert!(text(&again.stdout).contains("Everything was up to date."));

    std::fs::remove_file(files.join("docs/a.txt")).unwrap();
    let scoped = run(&mut instance.command(&["rescan", "admin", "--path", "/docs"]));
    assert!(scoped.status.success(), "{}", text(&scoped.stderr));
    assert!(text(&scoped.stdout).contains("removed:  /docs/a.txt"));
    assert_eq!(file_rows(&instance).await[0], (String::new(), 3));

    let missing = run(&mut instance.command(&["rescan", "admin", "--path", "/nope"]));
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stderr).contains("does not exist"));
}

/// `rescan --checksums` computes the MD5s that files changed behind the server's back lack;
/// a dry run only counts them.
#[tokio::test]
async fn rescan_fills_in_missing_checksums() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let files = instance.dir.path().join("data/files/1");
    std::fs::create_dir_all(files.join("docs")).unwrap();
    std::fs::write(files.join("docs/a.txt"), "hello").unwrap();
    std::fs::write(files.join("b.txt"), "hello world").unwrap();
    let md5s = || async {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
            .await
            .unwrap();
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT rel_path, lower(hex(md5)) FROM files WHERE owner_id = 1 AND is_dir = 0 \
             ORDER BY rel_path",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        pool.close().await;
        rows
    };

    let dry = run(&mut instance.command(&["rescan", "admin", "--checksums", "--dry-run"]));
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    assert!(
        text(&dry.stdout).contains("files without an MD5: 0"),
        "nothing is recorded in a dry run yet: {}",
        text(&dry.stdout)
    );
    let done = run(&mut instance.command(&["rescan", "admin", "--checksums"]));
    assert!(done.status.success(), "{}", text(&done.stderr));
    let report = text(&done.stdout);
    assert!(report.contains("MD5s computed: 2, skipped"), "{report}");
    assert_eq!(
        md5s().await,
        [
            (
                "b.txt".to_owned(),
                Some("5eb63bbbe01eeed093cb22bb8f5acdc3".to_owned())
            ),
            (
                "docs/a.txt".to_owned(),
                Some("5d41402abc4b2a76b9719d911017c592".to_owned())
            ),
        ]
    );
    let again = run(&mut instance.command(&["rescan", "--all", "--checksums", "--dry-run"]));
    assert!(text(&again.stdout).contains("files without an MD5: 0"));
}

/// The next text frame within ten seconds (pings are answered while reading).
#[cfg(unix)]
async fn next_text(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<String> {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => return Some(text.to_string()),
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

/// A rescan run next to the server reaches notify_push clients through the change log.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn rescan_changes_are_pushed_by_a_running_server() {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let instance = Instance::new();
    assert!(instance.init().status.success());
    let services = run(&mut instance.command(&["user", "services", "admin", "--enable", "webdav"]));
    assert!(services.status.success(), "{}", text(&services.stderr));
    let add = run(&mut instance.command(&["app-password", "add", "admin", "--label", "push"]));
    let password = app_password_from(&add);
    let mut child = instance
        .command(&["serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let addr = instance.addr;
    wait_for_get(&mut child, addr, "/healthz");

    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/push/ws"))
        .await
        .unwrap();
    socket.send(Message::text("admin")).await.unwrap();
    socket.send(Message::text(password)).await.unwrap();
    assert_eq!(
        next_text(&mut socket).await.as_deref(),
        Some("authenticated")
    );

    std::fs::write(instance.dir.path().join("data/files/1/dropped.txt"), "x").unwrap();
    let rescan = run(&mut instance.command(&["rescan", "admin"]));
    assert!(rescan.status.success(), "{}", text(&rescan.stderr));
    assert_eq!(next_text(&mut socket).await.as_deref(), Some("notify_file"));

    child.kill().unwrap();
    child.wait().unwrap();
}

/// Extracts the value of the `App password: <value>` line.
fn app_password_from(output: &Output) -> String {
    let stdout = text(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("App password: "))
        .unwrap_or_else(|| panic!("no app password in output:\n{stdout}"))
        .to_owned()
}

#[test]
fn users_can_be_managed() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let add = run_with_stdin(
        &mut instance.command(&[
            "user",
            "add",
            "alice",
            "--display-name",
            "Alice Example",
            "--password-stdin",
        ]),
        &format!("{PASSWORD}\n"),
    );
    assert!(add.status.success(), "{}", text(&add.stderr));
    assert!(instance.dir.path().join("data/files/2").is_dir());
    assert!(instance.dir.path().join("data/uploads/2").is_dir());

    let duplicate = run_with_stdin(
        &mut instance.command(&["user", "add", "alice", "--password-stdin"]),
        &format!("{PASSWORD}\n"),
    );
    assert!(!duplicate.status.success());
    assert!(text(&duplicate.stderr).contains("already exists"));

    for args in [
        &["user", "disable", "alice"][..],
        &["user", "enable", "alice"],
    ] {
        let output = run(&mut instance.command(args));
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
    let set_password = run_with_stdin(
        &mut instance.command(&["user", "set-password", "alice", "--password-stdin"]),
        "another good password\n",
    );
    assert!(
        set_password.status.success(),
        "{}",
        text(&set_password.stderr)
    );

    let list = run(&mut instance.command(&["user", "list"]));
    assert!(list.status.success());
    let listing = text(&list.stdout);
    assert!(listing.contains("Alice Example"), "{listing}");
    assert!(
        listing
            .lines()
            .any(|line| line.starts_with("1 ") && line.contains("admin"))
    );

    std::fs::write(instance.dir.path().join("data/files/2/kept.txt"), "kept").unwrap();
    let delete = run(&mut instance.command(&["user", "delete", "alice"]));
    assert!(delete.status.success(), "{}", text(&delete.stderr));
    assert!(!instance.dir.path().join("data/files/2").exists());
    let deleted: Vec<_> = std::fs::read_dir(instance.dir.path().join("data/deleted"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].join("files/kept.txt").is_file());

    let missing = run(&mut instance.command(&["user", "delete", "alice"]));
    assert!(!missing.status.success());
    assert!(text(&missing.stderr).contains("does not exist"));

    // The only admin can be neither disabled nor deleted.
    for args in [
        &["user", "disable", "admin"][..],
        &["user", "delete", "admin"],
    ] {
        let output = run(&mut instance.command(args));
        assert!(!output.status.success(), "{args:?}");
        assert!(
            text(&output.stderr).contains("last enabled admin"),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
}

/// The line of `user list` that shows one account.
fn listed(instance: &Instance, username: &str) -> String {
    let list = run(&mut instance.command(&["user", "list"]));
    assert!(list.status.success(), "{}", text(&list.stderr));
    text(&list.stdout)
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(username))
        .unwrap_or_else(|| panic!("{username} is not listed"))
        .to_owned()
}

#[test]
fn admins_can_be_promoted_and_demoted_and_renamed() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let add = run_with_stdin(
        &mut instance.command(&["user", "add", "alice", "--password-stdin"]),
        &format!("{PASSWORD}\n"),
    );
    assert!(add.status.success(), "{}", text(&add.stderr));

    // The only admin cannot be demoted.
    let demote = run(&mut instance.command(&["user", "demote", "admin"]));
    assert!(!demote.status.success());
    assert!(
        text(&demote.stderr).contains("last enabled admin"),
        "{}",
        text(&demote.stderr)
    );

    // Columns: ID, USERNAME, DISPLAY NAME (one word here), ADMIN, ENABLED, SERVICES, CREATED.
    let admin_column = |username: &str| {
        let line = listed(&instance, username);
        line.split_whitespace().nth(3).unwrap().to_owned()
    };
    let promote = run(&mut instance.command(&["user", "promote", "alice"]));
    assert!(promote.status.success(), "{}", text(&promote.stderr));
    assert_eq!(admin_column("alice"), "yes");
    let demote = run(&mut instance.command(&["user", "demote", "admin"]));
    assert!(demote.status.success(), "{}", text(&demote.stderr));
    assert_eq!(admin_column("admin"), "no");

    let rename =
        run(&mut instance.command(&["user", "set-display-name", "alice", "Alice Example"]));
    assert!(rename.status.success(), "{}", text(&rename.stderr));
    assert!(listed(&instance, "alice").contains("Alice Example"));
    let invalid = run(&mut instance.command(&["user", "set-display-name", "alice", "  "]));
    assert!(!invalid.status.success());
    assert!(text(&invalid.stderr).contains("invalid display name"));
    let missing = run(&mut instance.command(&["user", "promote", "nobody"]));
    assert!(!missing.status.success());
    assert!(text(&missing.stderr).contains("does not exist"));
}

#[test]
fn services_start_off_and_can_be_switched() {
    let instance = Instance::new();
    let init = instance.init();
    assert!(init.status.success());
    assert!(text(&init.stdout).contains("user services admin --enable all"));
    // Columns: ID, USERNAME, DISPLAY NAME (one word here), ADMIN, ENABLED, SERVICES, CREATED.
    let services_column = || {
        let line = listed(&instance, "admin");
        line.split_whitespace().nth(5).unwrap().to_owned()
    };
    assert_eq!(services_column(), "none");

    let shown = |args: &[&str]| {
        let output = run(&mut instance.command(args));
        assert!(output.status.success(), "{}", text(&output.stderr));
        text(&output.stdout)
    };
    // The relay brings direct connections along.
    let table = shown(&["user", "services", "admin", "--enable", "webdav,relay"]);
    assert!(table.contains("relay") && table.contains("on"), "{table}");
    assert_eq!(services_column(), "webdav,direct,relay");
    // Without direct connections there is no relay either.
    shown(&["user", "services", "admin", "--disable", "direct"]);
    assert_eq!(services_column(), "webdav");
    shown(&[
        "user",
        "services",
        "admin",
        "--enable",
        "all",
        "--disable",
        "s3",
    ]);
    assert_eq!(services_column(), "files,webdav,direct,relay");
    let table = shown(&["user", "services", "admin"]);
    assert!(
        table
            .lines()
            .any(|line| line.starts_with("s3") && line.ends_with("off")),
        "{table}"
    );

    let unknown = run(&mut instance.command(&["user", "services", "admin", "--enable", "ftp"]));
    assert!(!unknown.status.success());
    assert!(
        text(&unknown.stderr).contains("unknown service"),
        "{}",
        text(&unknown.stderr)
    );
}

#[tokio::test]
async fn identities_are_listed_and_unlinked_but_the_last_way_in_stays() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let shown = |args: &[&str]| {
        let output = run(&mut instance.command(args));
        assert!(output.status.success(), "{}", text(&output.stderr));
        text(&output.stdout)
    };
    assert!(
        shown(&["user", "identities", "admin"]).contains("admin has no third-party identities"),
    );
    // A WeChat identity, as the mini program binds one, and an account without a password.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    for sql in [
        "UPDATE id_sequences SET last_id = last_id + 1 WHERE name = 'external_identities'",
        "INSERT INTO external_identities (id, user_id, provider, realm, subject, label, \
         created_at, last_seen_at) VALUES (1, 1, 'wechat', 'wxd930ea5d5a258f4f', 'oAdmin', '', \
         1800000000, 1800000000)",
        "UPDATE users SET password_hash = NULL WHERE id = 1",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    pool.close().await;
    let listed = shown(&["user", "identities", "admin"]);
    assert!(
        listed.contains("PROVIDER")
            && listed.contains("wechat")
            && listed.contains("wxd930ea5d5a258f4f"),
        "{listed}"
    );
    assert!(
        !listed.contains("oAdmin"),
        "subjects are never shown: {listed}"
    );
    assert!(
        listed.contains("admin has no web login password"),
        "{listed}"
    );

    // The last way in stays until the account has a password.
    let refused = run(&mut instance.command(&["user", "unlink", "admin", "wechat"]));
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("user set-password admin"),
        "{}",
        text(&refused.stderr)
    );
    let unknown = run(&mut instance.command(&["user", "unlink", "admin", "facebook"]));
    assert!(!unknown.status.success());
    let set = run_with_stdin(
        &mut instance.command(&["user", "set-password", "admin", "--password-stdin"]),
        &format!("{PASSWORD}\n"),
    );
    assert!(set.status.success(), "{}", text(&set.stderr));
    let unlinked = shown(&["user", "unlink", "admin", "wechat"]);
    assert!(
        unlinked.contains("Unbound the wechat identity of admin"),
        "{unlinked}"
    );
    assert!(shown(&["user", "identities", "admin"]).contains("no third-party identities"));
    assert!(shown(&["user", "unlink", "admin", "wechat"]).contains("admin has no wechat identity"));

    // The audit log names the command line.
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    let kinds: Vec<(String, String)> =
        sqlx::query_as("SELECT kind, actor FROM audit_log WHERE user_id = 1 ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    assert_eq!(
        kinds,
        [
            ("password.set".to_owned(), "cli".to_owned()),
            ("identity.unbound".to_owned(), "cli".to_owned())
        ]
    );
}

#[test]
fn app_passwords_are_shown_once_and_can_be_revoked() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let add = run(&mut instance.command(&[
        "app-password",
        "add",
        "admin",
        "--label",
        "phone",
        "--scope",
        "/Photos=/Media/Photos:view",
        "--scope",
        "/Inbox=/Inbox:full",
    ]));
    assert!(add.status.success(), "{}", text(&add.stderr));
    let password = app_password_from(&add);
    assert_eq!(password.len(), 29, "{password}");
    assert!(!text(&add.stderr).contains(&password));

    let list = run(&mut instance.command(&["app-password", "list", "admin"]));
    assert!(list.status.success());
    let listing = text(&list.stdout);
    assert!(listing.contains("phone"), "{listing}");
    assert!(listing.contains("/Photos=/Media/Photos:view"), "{listing}");
    assert!(listing.contains("/Inbox=/Inbox:full"), "{listing}");
    assert!(
        !listing.contains(&password),
        "list must never show the value"
    );

    let nested = run(&mut instance.command(&[
        "app-password",
        "add",
        "admin",
        "--label",
        "nested",
        "--scope",
        "/=/:view",
        "--scope",
        "/a=/a:full",
    ]));
    assert!(!nested.status.success());
    assert!(
        text(&nested.stderr).contains("nested"),
        "{}",
        text(&nested.stderr)
    );

    let full = run(&mut instance.command(&["app-password", "add", "admin", "--label", "laptop"]));
    assert!(full.status.success());
    assert!(
        text(&full.stdout).contains("/=/:full"),
        "{}",
        text(&full.stdout)
    );

    let delete = run(&mut instance.command(&["app-password", "delete", "admin", "1"]));
    assert!(delete.status.success(), "{}", text(&delete.stderr));
    let again = run(&mut instance.command(&["app-password", "delete", "admin", "1"]));
    assert!(!again.status.success());

    let db = std::fs::read(instance.db()).unwrap();
    assert!(
        !db.windows(password.len())
            .any(|window| window == password.as_bytes()),
        "the plaintext app password must not be stored"
    );
}

#[tokio::test]
async fn the_two_step_key_is_created_once_and_its_loss_stops_serve() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let key = instance.dir.path().join("two-factor.key");
    let bytes = std::fs::read(&key).expect("init creates the key");
    assert_eq!(bytes.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "{mode:o}");
    }
    let check = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(
        check.contains("two_factor.key_file") && !check.contains("(missing)"),
        "{check}"
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    sqlx::query("INSERT INTO two_factor (user_id, secret, enabled_at) VALUES (1, x'00', 0)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // The secrets cannot be read without the key: serve does not start.
    std::fs::remove_file(&key).unwrap();
    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    let logs = format!("{}{}", text(&serve.stdout), text(&serve.stderr));
    assert!(logs.contains("two_factor.key_file"), "{logs}");
    assert!(logs.contains("reset-two-factor"), "{logs}");

    let reset = run(&mut instance.command(&["user", "reset-two-factor", "admin"]));
    assert!(reset.status.success(), "{}", text(&reset.stderr));
    assert!(text(&reset.stdout).contains("Reset the two-step verification of admin"));
    let again = run(&mut instance.command(&["user", "reset-two-factor", "admin"]));
    assert!(text(&again.stdout).contains("has no two-step verification"));
}

#[tokio::test]
async fn devices_can_be_listed_and_revoked_after_a_confirmation() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let key = "01".repeat(32);
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    // Ids come from `id_sequences`, as the server allocates them.
    let next_id = |table: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE id_sequences SET last_id = last_id + 1 WHERE name = ?")
                .bind(table)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query_scalar::<_, i64>("SELECT last_id FROM id_sequences WHERE name = ?")
                .bind(table)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    let password = next_id("app_passwords").await;
    sqlx::query(
        "INSERT INTO app_passwords (id, user_id, token_hash, label, created_at) \
         VALUES (?, 1, randomblob(32), 'Phone', 0)",
    )
    .bind(password)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, user_id, endpoint_id, app_password_id, product, platform, \
         name, registered_at) VALUES (?, 1, ?, ?, 'input-show', 'android', 'Phone', 0)",
    )
    .bind(next_id("devices").await)
    .bind(vec![1u8; 32])
    .bind(password)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let list = run(&mut instance.command(&["device", "list", "admin"]));
    assert!(list.status.success(), "{}", text(&list.stderr));
    let listed = text(&list.stdout);
    assert!(
        listed.contains(&key) && listed.contains("Phone"),
        "{listed}"
    );
    // Device credentials are not app passwords.
    let passwords = text(&run(&mut instance.command(&["app-password", "list", "admin"])).stdout);
    assert!(!passwords.contains("Phone"), "{passwords}");

    // Without a terminal, only --confirm with the endpoint ID again revokes.
    let unconfirmed = run(&mut instance.command(&["device", "revoke", "admin", &key]));
    assert!(!unconfirmed.status.success());
    assert!(
        text(&unconfirmed.stderr).contains("--confirm"),
        "{}",
        text(&unconfirmed.stderr)
    );
    let wrong = run(&mut instance.command(&[
        "device",
        "revoke",
        "admin",
        &key,
        "--confirm",
        &"02".repeat(32),
    ]));
    assert!(!wrong.status.success());
    let revoked =
        run(&mut instance.command(&["device", "revoke", "admin", &key, "--confirm", &key]));
    assert!(revoked.status.success(), "{}", text(&revoked.stderr));
    assert!(
        text(&revoked.stdout).contains("Revoked Phone."),
        "{}",
        text(&revoked.stdout)
    );
    let again = run(&mut instance.command(&["device", "revoke", "admin", &key, "--confirm", &key]));
    assert!(
        text(&again.stdout).contains("revoked already"),
        "{}",
        text(&again.stdout)
    );
    let listed = text(&run(&mut instance.command(&["device", "list", "admin"])).stdout);
    let row = listed.lines().find(|line| line.contains(&key)).unwrap();
    assert!(!row.trim_end().ends_with('-'), "a revocation time: {row}");
}

#[cfg(unix)]
#[test]
fn serve_answers_health_checks_and_stops_on_sigterm() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let mut child = instance
        .command(&["serve"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let response = wait_for_get(&mut child, instance.addr, "/healthz");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok\n"), "{response}");

    let logs = terminate(child);
    assert!(logs.contains("listening"), "{logs}");
    assert!(logs.contains("received SIGTERM"), "{logs}");
    assert!(
        !logs.contains("relay"),
        "the relay is off by default: {logs}"
    );
    assert!(!logs.contains(PASSWORD));
}

#[test]
fn the_relay_command_needs_the_relay_enabled() {
    let instance = Instance::new();
    let output = run(&mut instance.command(&["relay"]));
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("relay.enabled is false"), "{stderr}");
}

#[test]
fn config_check_warns_while_remote_access_needs_no_two_step_verification() {
    let instance = Instance::new();
    instance.enable_relay();
    let check = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(
        check.contains("connect.require_two_factor") && check.contains(" false\n"),
        "{check}"
    );
    assert!(
        check.contains("warning: connect.require_two_factor is false"),
        "{check}"
    );

    let mut config = std::fs::read_to_string(instance.config()).unwrap();
    config.push_str("\n[connect]\nrequire_two_factor = true\n");
    std::fs::write(instance.config(), config).unwrap();
    let check = text(&run(&mut instance.command(&["config", "check"])).stdout);
    assert!(
        !check.contains("warning: connect.require_two_factor"),
        "{check}"
    );
}

#[cfg(unix)]
#[test]
fn serve_runs_the_relay_and_stops_it_on_sigterm() {
    let instance = Instance::new();
    let relay = instance.enable_relay();
    assert!(instance.init().status.success());

    let mut child = instance
        .command(&["serve"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_get(&mut child, instance.addr, "/healthz");
    // The probe devices use to detect captive portals, which the reverse proxy forwards.
    let probe = wait_for_get(&mut child, relay, "/generate_204");
    assert!(probe.starts_with("HTTP/1.1 204"), "{probe}");
    // A loopback origin serves remote connectivity, whose relay admits the directory's devices.
    let discovery = wait_for_get(&mut child, instance.addr, "/gono/v1/connect");
    assert!(discovery.starts_with("HTTP/1.1 200"), "{discovery}");
    // Without a [connect] table, the development default: no two-step verification needed
    // (plan R10), and a warning that says so.
    assert!(
        discovery.contains("\"two_factor_required\":false"),
        "{discovery}"
    );

    let logs = terminate(child);
    assert!(logs.contains("relay listening"), "{logs}");
    assert!(logs.contains("relay stopped"), "{logs}");
    assert!(logs.contains("remote connectivity enabled"), "{logs}");
    assert!(
        logs.contains("connect.require_two_factor is false"),
        "{logs}"
    );
}

#[cfg(unix)]
#[test]
fn the_relay_runs_alone_without_a_database() {
    let instance = Instance::new();
    let relay = instance.enable_relay();

    let mut child = instance
        .command(&["relay"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let probe = wait_for_get(&mut child, relay, "/generate_204");
    assert!(probe.starts_with("HTTP/1.1 204"), "{probe}");
    assert!(
        http_get(instance.addr, "/healthz").is_none(),
        "the file server must not run"
    );

    let logs = terminate(child);
    assert!(logs.contains("relay listening"), "{logs}");
    assert!(logs.contains("relay stopped"), "{logs}");
    // On a host of its own it cannot read the device directory: the operator is told.
    assert!(logs.contains("relay.allowed_endpoints is empty"), "{logs}");
    assert!(!instance.db().exists(), "no database is created");
}

/// Sends SIGTERM to `child`, waits until it exits successfully and returns its log.
#[cfg(unix)]
fn terminate(child: Child) -> String {
    let mut child = child;
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "server did not stop after SIGTERM"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    let logs = text(&output.stdout);
    assert!(output.status.success(), "{logs}\n{}", text(&output.stderr));
    logs
}

/// Polls `GET <path>` on `addr` until it answers.
#[cfg(unix)]
fn wait_for_get(child: &mut Child, addr: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("server exited early with {status}");
        }
        if let Some(response) = http_get(addr, path) {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "server did not come up on {addr}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

#[test]
fn s3_keys_and_buckets_can_be_managed() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let ok = |args: &[&str]| {
        let output = run(&mut instance.command(args));
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
        text(&output.stdout)
    };
    let fails = |args: &[&str]| {
        let output = run(&mut instance.command(args));
        assert!(!output.status.success(), "{args:?} should fail");
        text(&output.stderr)
    };

    let created = ok(&["s3", "bucket", "create", "admin", "photos"]);
    assert!(created.contains("/Buckets/photos"), "{created}");
    assert!(!created.contains("//"), "{created}");
    assert!(
        instance
            .dir
            .path()
            .join("data/files/1/Buckets/photos")
            .is_dir()
    );
    assert!(fails(&["s3", "bucket", "create", "admin", "photos"]).contains("exists"));
    assert!(
        fails(&["s3", "bucket", "create", "admin", "Bad_Name"]).contains("invalid bucket name")
    );

    std::fs::create_dir(instance.dir.path().join("data/files/1/Docs")).unwrap();
    ok(&["s3", "bucket", "bind", "admin", "docs", "/Docs"]);
    assert!(fails(&["s3", "bucket", "bind", "admin", "missing", "/Nope"]).contains("no folder"));
    let buckets = ok(&["s3", "bucket", "list", "admin"]);
    assert!(
        buckets.contains("photos") && buckets.contains("/Docs"),
        "{buckets}"
    );

    let key = ok(&[
        "s3",
        "key",
        "create",
        "admin",
        "--label",
        "app",
        "--bucket",
        "photos:view",
    ]);
    let access_key_id = key
        .lines()
        .find_map(|line| line.strip_prefix("Access key id: "))
        .unwrap_or_else(|| panic!("no access key id:\n{key}"));
    let secret = key
        .lines()
        .find_map(|line| line.strip_prefix("Secret key:"))
        .map(str::trim)
        .unwrap_or_else(|| panic!("no secret:\n{key}"));
    assert_eq!(access_key_id.len(), 20);
    assert_eq!(secret.len(), 40);
    assert!(key.contains("photos:view"), "{key}");
    assert!(key.contains("the S3 API is off"), "{key}");
    assert!(
        fails(&[
            "s3", "key", "create", "admin", "--label", "x", "--bucket", "nope"
        ])
        .contains("no bucket nope")
    );
    let keys = ok(&["s3", "key", "list", "admin"]);
    assert!(
        keys.contains(access_key_id) && !keys.contains(secret),
        "{keys}"
    );
    // S3 keys are not app passwords.
    assert!(!ok(&["app-password", "list", "admin"]).contains("app"));

    let set = ok(&[
        "s3",
        "bucket",
        "set",
        "admin",
        "photos",
        "--anonymous",
        "public-read",
        "--list",
    ]);
    assert!(set.contains("anonymous listing on"), "{set}");
    assert!(set.contains("s3.allow_anonymous = false"), "{set}");
    assert!(
        fails(&[
            "s3",
            "bucket",
            "set",
            "admin",
            "photos",
            "--anonymous",
            "public"
        ])
        .contains("expected private, acl or public-read")
    );

    ok(&["s3", "bucket", "unbind", "admin", "docs"]);
    assert!(
        instance.dir.path().join("data/files/1/Docs").is_dir(),
        "the folder stays"
    );
    ok(&["s3", "key", "delete", "admin", "1"]);
    assert!(fails(&["s3", "key", "delete", "admin", "1"]).contains("no S3 access key"));
}

/// The command line on a MySQL database (only with `GONO_TEST_MYSQL_URL`, see
/// `gono_server_core::db::testing`): `init` needs a database without the schema, `serve` one
/// with it, the password comes from `db.password_file`, and `config check` shows the settings
/// without it.
#[tokio::test]
async fn mysql_installations_are_initialized_and_managed() {
    use gono_server_core::db::{Backend, testing};

    if testing::backend() != Backend::MySql {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let database = testing::config(dir.path()).await.url.unwrap();
    let name = database.path().trim_start_matches('/').to_owned();

    // An account of its own with a password and the privileges docs/deployment.md lists, as
    // an installation has.
    let root = testing::mysql_server().unwrap();
    sqlx::any::install_default_drivers();
    let admin = sqlx::AnyPool::connect(root.as_str()).await.unwrap();
    // The host the server sees the tests connect from, which the account is limited to as an
    // installation's is: 127.0.0.1 (or localhost) for a server on this machine, but the
    // gateway of the container network for CI's MySQL in a service container.
    let host = sqlx::query_scalar::<_, gono_server_core::db::Text>(
        "SELECT SUBSTRING_INDEX(USER(), '@', -1)",
    )
    .fetch_one(&admin)
    .await
    .unwrap()
    .0;
    assert!(
        host.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_')),
        "unexpected client host {host:?}"
    );
    let account = format!("u{}", &name[name.len() - 12..]);
    let secret = "pa'ss w0rd";
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE USER '{account}'@'{host}' IDENTIFIED BY 'pa''ss w0rd'"
    )))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES \
         ON `{name}`.* TO '{account}'@'{host}'"
    )))
    .execute(&admin)
    .await
    .unwrap();
    std::fs::write(dir.path().join("mysql-password"), format!("{secret}\n")).unwrap();

    let mut url = database.clone();
    url.set_username(&account).unwrap();
    let instance = Instance::new();
    let config = std::fs::read_to_string(instance.config()).unwrap().replace(
        "path = \"db/gono-cloud.db\"",
        &format!(
            "backend = \"mysql\"\nurl = \"{url}\"\npassword_file = \"{}\"",
            dir.path().join("mysql-password").display()
        ),
    );
    std::fs::write(instance.config(), config).unwrap();

    let check = run(&mut instance.command(&["config", "check"]));
    assert!(check.status.success(), "{}", text(&check.stderr));
    let shown = text(&check.stdout);
    assert!(
        shown.contains("db.backend") && shown.contains("mysql"),
        "{shown}"
    );
    assert!(shown.contains(url.as_str()), "{shown}");
    assert!(
        !shown.contains("w0rd"),
        "the password is never shown: {shown}"
    );

    let serve = run(&mut instance.command(&["serve"]));
    assert!(!serve.status.success());
    assert!(
        text(&serve.stderr).contains("gono-cloud init"),
        "{}",
        text(&serve.stderr)
    );

    let init = instance.init();
    assert!(init.status.success(), "{}", text(&init.stderr));
    assert!(text(&init.stdout).contains(&format!("MySQL {url}")));
    assert!(!instance.db().exists(), "no SQLite file");
    let again = instance.init();
    assert!(!again.status.success());
    assert!(text(&again.stderr).contains("already contains users"));

    let add = run_with_stdin(
        &mut instance.command(&["user", "add", "alice", "--password-stdin"]),
        &format!("{PASSWORD}\n"),
    );
    assert!(add.status.success(), "{}", text(&add.stderr));
    let list = text(&run(&mut instance.command(&["user", "list"])).stdout);
    assert!(list.contains("admin") && list.contains("alice"), "{list}");

    // A wrong password is refused by MySQL.
    std::fs::write(dir.path().join("mysql-password"), "wrong\n").unwrap();
    let refused = run(&mut instance.command(&["user", "list"]));
    assert!(!refused.status.success());

    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP USER '{account}'@'{host}'"
    )))
    .execute(&admin)
    .await;
}
