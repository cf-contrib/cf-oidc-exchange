//! The binary's command line: what it refuses before it reaches the broker or
//! the keychain. The commands themselves are tested against a stub broker in
//! `src/app/exec.rs`.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

/// Returns a cf-sts command with none of its settings in the environment.
fn cf_sts() -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("cf-sts");
    for name in ["CF_STS_CLI_URL", "CF_STS_CLI_PROFILE", "CF_STS_CLI_TTL"] {
        cmd.env_remove(name);
    }
    cmd
}

#[test]
fn shows_help_without_a_command() {
    cf_sts()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Get started:"));
}

#[test]
fn prints_the_release_it_comes_from() {
    cf_sts()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("cf-sts {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn needs_the_broker_url() {
    cf_sts()
        .args(["exec", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "no broker URL; pass --url or set CF_STS_CLI_URL",
        ));
}

#[test]
fn takes_the_url_from_the_environment_and_refuses_plain_http() {
    cf_sts()
        .args(["whoami"])
        .env("CF_STS_CLI_URL", "http://cf-sts.example.com")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "--url must use https: http://cf-sts.example.com",
        ));
}

#[test]
fn exec_needs_a_command() {
    cf_sts()
        .args(["exec", "--url", "https://cf-sts.example.com"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("<COMMAND>"));
}

#[test]
fn is_either_quiet_or_verbose() {
    cf_sts()
        .args(["whoami", "-q", "-v"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}
