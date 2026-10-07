use std::ffi::OsString;

use clap::{Args, Parser, Subcommand};

/// Examples shown at the end of each command's help.
const PROGRAM_HELP: &str = "Get started:
  cf-sts login --url https://cf-sts.example.com   # sign in once
  cf-sts exec --url https://cf-sts.example.com \\
    --profile example-org/app:tofu-plan -- tofu plan

Or set CF_STS_CLI_URL and CF_STS_CLI_PROFILE, e.g. in the repo's dev shell:
  cf-sts exec -- tofu plan";
const LOGIN_EXAMPLES: &str = "Examples:
  cf-sts login                # in your browser
  cf-sts login --no-browser   # print the link, e.g. over SSH with port 8250 forwarded";
const LOGOUT_EXAMPLES: &str = "Examples:
  cf-sts logout";
const WHOAMI_EXAMPLES: &str = "Examples:
  cf-sts whoami                      # who, and until when
  cf-sts whoami -q || cf-sts login   # sign in only if needed
  cf-sts whoami --json               # for scripts and agents";
const EXEC_EXAMPLES: &str = "Examples:
  cf-sts exec --profile example-org/app:tofu-plan -- tofu plan
  cf-sts exec -- nix develop --command tofu -chdir=deployment/terraform plan -lock=false
  cf-sts exec --ttl 30m -- wrangler deploy
  cf-sts exec -- $SHELL              # a shell whose token is revoked when it exits";

/// Program is the main entry point for the cf-sts CLI.
#[derive(Debug, Parser)]
#[command(
    name = "cf-sts",
    about = "Short-lived Cloudflare credentials from your cf-sts broker.",
    long_about = "Sign in through the identity provider your cf-sts broker names, then run commands with short-lived Cloudflare credentials from it: the same environment the cf-sts GitHub Action sets, revoked when the command exits.",
    after_help = PROGRAM_HELP,
    arg_required_else_help = true,
    version
)]
pub struct Program {
    /// Command specifies the subcommand to execute.
    #[command(subcommand)]
    pub command: ProgramCommand,
}

/// ProgramArgs holds the shared global flags available to every subcommand.
#[derive(Debug, Args)]
pub struct ProgramArgs {
    /// URL of the broker. Required: there's no config file.
    #[arg(
        help = "Broker URL, e.g. https://cf-sts.example.com.",
        env = "CF_STS_CLI_URL",
        long
    )]
    pub url: Option<String>,

    /// Print warnings and errors only.
    #[arg(
        help = "Print warnings and errors only.",
        long,
        short,
        conflicts_with = "verbose"
    )]
    pub quiet: bool,

    /// Print details for debugging.
    #[arg(
        help = "Print details for debugging, like the requests made. Never a secret.",
        long,
        short
    )]
    pub verbose: bool,
}

/// Top-level subcommand dispatched by [`Program`].
#[derive(Debug, Subcommand)]
pub enum ProgramCommand {
    /// Sign in through your identity provider.
    #[command(
        name = "login",
        after_help = LOGIN_EXAMPLES,
        about = "Sign in through your identity provider (browser).",
        long_about = "Sign in at the identity provider the broker's metadata names, in your browser, and keep the ID token in the OS keychain under the broker's URL. It's the only thing cf-sts keeps between runs, and the only command that opens a browser or waits for you.",
        next_display_order = 1
    )]
    Login(LoginCommandArgs),

    /// Forget the stored login.
    #[command(
        name = "logout",
        after_help = LOGOUT_EXAMPLES,
        about = "Forget the stored login.",
        long_about = "Remove the ID token stored for the broker from the OS keychain. Being signed out already is fine.",
        next_display_order = 2
    )]
    Logout(LogoutCommandArgs),

    /// Show who you're signed in as, and until when.
    #[command(
        name = "whoami",
        after_help = WHOAMI_EXAMPLES,
        about = "Show who you're signed in as, and until when.",
        long_about = "Print the email, subject and issuer of the stored login, and when it expires. Fails when you're not signed in or the login has expired, so a script or an agent can check before `exec`.",
        next_display_order = 3
    )]
    Whoami(WhoamiCommandArgs),

    /// Run a command with Cloudflare credentials.
    #[command(
        name = "exec",
        after_help = EXEC_EXAMPLES,
        about = "Run a command with Cloudflare credentials, revoked when it exits.",
        long_about = "Exchange the stored login for what the profile grants, and run the command with the environment the cf-sts action sets: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID, and CLOUDFLARE_R2_* for a profile with a bucket. Variables the profile doesn't grant are removed.\n\nThe command's exit code is cf-sts's, or 128+n if signal n killed it. However it exits, the token is revoked; R2 credentials can't be, and expire. Ctrl-C reaches the command, not cf-sts; SIGTERM and SIGHUP are forwarded to it.",
        next_display_order = 4
    )]
    Exec(ExecCommandArgs),
}

impl ProgramCommand {
    /// Returns the shared global flags of the subcommand.
    pub fn parent(&self) -> &ProgramArgs {
        match self {
            ProgramCommand::Login(args) => &args.parent,
            ProgramCommand::Logout(args) => &args.parent,
            ProgramCommand::Whoami(args) => &args.parent,
            ProgramCommand::Exec(args) => &args.parent,
        }
    }
}

/// LoginCommandArgs defines the arguments for the LoginCommand.
#[derive(Debug, Args)]
pub struct LoginCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Print the sign-in link instead of opening a browser.
    #[arg(help = "Print the sign-in link instead of opening a browser.", long)]
    pub no_browser: bool,
}

/// LogoutCommandArgs defines the arguments for the LogoutCommand.
#[derive(Debug, Args)]
pub struct LogoutCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,
}

/// WhoamiCommandArgs defines the arguments for the WhoamiCommand.
#[derive(Debug, Args)]
pub struct WhoamiCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Print JSON.
    #[arg(help = "Print JSON, for scripts and agents.", long)]
    pub json: bool,
}

/// ExecCommandArgs defines the arguments for the ExecCommand.
#[derive(Debug, Args)]
pub struct ExecCommandArgs {
    /// Shared global flags.
    #[command(flatten)]
    pub parent: ProgramArgs,

    /// Profile to ask for.
    #[arg(
        help = "Profile to ask for. Otherwise exactly one profile must match.",
        env = "CF_STS_CLI_PROFILE",
        long
    )]
    pub profile: Option<String>,

    /// Requested lifetime.
    #[arg(
        help = "Requested lifetime such as 15m or 1h, capped at the profile's max_ttl.",
        env = "CF_STS_CLI_TTL",
        long
    )]
    pub ttl: Option<String>,

    /// The command to run, and its arguments.
    #[arg(
        help = "The command to run, and its arguments, after --.",
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<OsString>,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Program::command().debug_assert();
    }

    #[test]
    fn exec_takes_the_command_after_its_own_flags() {
        let program = Program::parse_from([
            "cf-sts",
            "exec",
            "--url",
            "https://cf-sts.example.com",
            "--profile",
            "example-org/app:tofu-plan",
            "--",
            "tofu",
            "-chdir=deployment/terraform",
            "plan",
        ]);
        let ProgramCommand::Exec(args) = program.command else {
            panic!("not exec");
        };
        assert_eq!(args.profile.as_deref(), Some("example-org/app:tofu-plan"));
        assert_eq!(
            args.command,
            ["tofu", "-chdir=deployment/terraform", "plan"]
        );
    }
}
