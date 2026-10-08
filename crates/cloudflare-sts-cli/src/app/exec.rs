use std::{io::Write, time::Duration};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::net::TcpListener;

use crate::{
    app::args::*,
    log::{debug, info, notice, warn},
    sts::*,
};

/// How long `login` waits for the person to sign in.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// Open shows the person the sign-in link: in a browser, or a test signing
/// in as one.
pub type Open = Box<dyn FnMut(&str) -> Result<()>>;

/// Sign in through an identity provider the broker lists.
pub struct LoginCommand {
    /// Store the ID token is kept in.
    pub store: Box<dyn Store>,
    /// Opens the sign-in link, unless `--no-browser`.
    pub open: Open,
    /// Loopback port the provider redirects to: fixed, since the app's
    /// redirect URI names it. `0` picks any, for the tests.
    pub port: u16,
}

impl LoginCommand {
    /// Execute the LoginCommand with the provided arguments.
    pub async fn execute(&mut self, args: &LoginCommandArgs) -> Result<()> {
        let broker = Broker::new(&BrokerUrl::parse(args.parent.url.as_deref())?);
        let provider = args.provider.as_deref().filter(|p| !p.is_empty());
        let login = broker.identity_provider(provider).await?;
        debug(format!(
            "identity provider {}: issuer {}, client {}",
            login.name, login.issuer, login.client_id
        ));
        let provider = Provider::discover(&login.issuer).await?;

        let listener = TcpListener::bind(("127.0.0.1", self.port))
            .await
            .map_err(|err| {
                hinted(
                    format!(
                        "can't listen on 127.0.0.1:{} for the sign-in: {err}",
                        self.port
                    ),
                    "another 'cloudflare-sts login' may be running",
                )
            })?;
        let port = listener.local_addr()?.port();
        let sign_in = Authorization::new(
            &login.client_id,
            &format!("http://127.0.0.1:{port}/callback"),
        )?;
        let link = provider.link(&sign_in);

        if args.no_browser {
            notice(format!("open this link to sign in: {link}"));
        } else {
            info(format!("opening {link} in your browser"));
            if (self.open)(&link).is_err() {
                notice(format!("open this link to sign in: {link}"));
            }
        }
        info(format!(
            "waiting for the sign-in on {} …",
            sign_in.redirect_uri
        ));

        let code = tokio::time::timeout(SIGN_IN_TIMEOUT, callback(&listener, &sign_in.state))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "no sign-in within {} minutes",
                    SIGN_IN_TIMEOUT.as_secs() / 60
                )
            })??;
        let identity = Identity::parse(provider.redeem(&sign_in, &code).await?)?;
        sign_in.check(&identity, &login.issuer)?;

        self.store.save(broker.url(), identity.token())?;
        info(format!(
            "signed in as {} (expires {})",
            identity.who(),
            rfc3339(identity.claims().exp)
        ));
        Ok(())
    }
}

/// Forget the stored login.
pub struct LogoutCommand {
    /// Store the ID token is kept in.
    pub store: Box<dyn Store>,
}

impl LogoutCommand {
    /// Execute the LogoutCommand with the provided arguments.
    pub fn execute(&mut self, args: &LogoutCommandArgs) -> Result<()> {
        let url = BrokerUrl::parse(args.parent.url.as_deref())?;
        if self.store.delete(&url)? {
            info(format!("signed out of {url}"));
        } else {
            info(format!("not signed in to {url}"));
        }
        Ok(())
    }
}

/// Show who the stored login is for, and until when.
pub struct WhoamiCommand {
    /// Store the ID token is kept in.
    pub store: Box<dyn Store>,
    /// Where the answer is written: stdout.
    pub writer: Box<dyn Write>,
}

impl WhoamiCommand {
    /// Execute the WhoamiCommand with the provided arguments. Fails when
    /// there's no login or it has expired, so a script or an agent can check
    /// before `exec`; `-q` prints nothing but that.
    pub fn execute(&mut self, args: &WhoamiCommandArgs) -> Result<()> {
        let url = BrokerUrl::parse(args.parent.url.as_deref())?;
        let identity = stored(self.store.as_ref(), &url)?;
        let claims = identity.claims();
        let expires = rfc3339(claims.exp);
        let lapsed = identity.is_expired();

        if !args.parent.quiet {
            let w = &mut self.writer;
            if args.json {
                let answer = json!({
                    "email": claims.email,
                    "sub": claims.sub,
                    "issuer": claims.iss,
                    "broker": url.as_str(),
                    "expires_at": expires,
                    "expired": lapsed,
                });
                writeln!(w, "{answer:#}")?;
            } else {
                let left = if lapsed {
                    "expired".to_string()
                } else {
                    format!("in {}", until(claims.exp))
                };
                if let Some(email) = &claims.email {
                    writeln!(w, "email    {email}")?;
                }
                writeln!(w, "subject  {}", claims.sub)?;
                writeln!(w, "issuer   {}", claims.iss)?;
                writeln!(w, "broker   {url}")?;
                writeln!(w, "expires  {expires} ({left})")?;
            }
        }
        if lapsed {
            return Err(expired(claims.exp));
        }
        Ok(())
    }
}

/// Run a command with Cloudflare credentials, revoked when it exits.
pub struct ExecCommand {
    /// Store the ID token is kept in.
    pub store: Box<dyn Store>,
}

impl ExecCommand {
    /// Execute the ExecCommand with the provided arguments, and return the
    /// command's exit code.
    pub async fn execute(&mut self, args: &ExecCommandArgs) -> Result<u8> {
        let broker = Broker::new(&BrokerUrl::parse(args.parent.url.as_deref())?);
        let identity = current(self.store.as_ref(), broker.url())?;
        let profile = args.profile.clone().filter(|p| !p.is_empty());
        let ttl = args.ttl.clone().filter(|t| !t.is_empty());
        debug(format!(
            "exchanging at {} for profile {}",
            broker.url(),
            profile.as_deref().unwrap_or("(the one that matches)")
        ));

        let response = broker.exchange(identity.token(), profile, ttl).await?;
        let credentials = Credentials::try_from(response)?;
        // From here a token may exist, so nothing returns before it's revoked.
        let signals = Signals::listen();
        for line in credentials.granted() {
            info(line);
        }
        let code = match (signals, child(&args.command, &credentials)) {
            (Ok(signals), Ok(child)) => run_child(child, signals).await,
            (Err(err), _) | (_, Err(err)) => Err(err),
        };

        if let Some(bucket) = &credentials.bucket {
            info(format!(
                "R2 temporary credentials can't be revoked; they expire at {}",
                expires_on(bucket)
            ));
        }
        if let Some(token) = &credentials.token {
            match broker.revoke(&token.value).await {
                Ok(()) => info(format!("revoked token {}", token.id)),
                Err(err) => warn(format!(
                    "revoking token {} failed ({err:#}); it expires on its own",
                    token.id
                )),
            }
        }
        code.context("running the command failed")
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, ffi::OsString, fs, path::PathBuf, rc::Rc};

    use clap::Parser;
    use serde_json::{Value, json};

    use super::*;
    use crate::sts::stub::{self, Memory, Stub, jwt};

    /// Parses `args` as cloudflare-sts's command line, against `stub`'s broker.
    fn parse(stub: &Stub, args: &[&str]) -> ProgramCommand {
        let mut line = vec!["cloudflare-sts", args[0], "--url", stub.base()];
        line.extend(&args[1..]);
        Program::parse_from(line).command
    }

    /// A store shared with the test, holding a login for `stub`'s broker.
    fn signed_in(stub: &Stub, claims: Value) -> Shared {
        let store = Shared::default();
        let mut all = json!({ "iss": stub.issuer(), "sub": "user-0001", "email": "alice@example.com", "aud": stub::CLIENT_ID, "exp": chrono::Utc::now().timestamp() + 3600 });
        for (key, value) in claims.as_object().unwrap() {
            all[key] = value.clone();
        }
        store.save(&stub.url(), &jwt(all)).unwrap();
        store
    }

    /// Shared is a [`Memory`] store the test keeps a hold on.
    #[derive(Clone, Default)]
    struct Shared(Rc<Memory>);

    impl Store for Shared {
        fn load(&self, broker: &BrokerUrl) -> Result<Option<String>> {
            self.0.load(broker)
        }
        fn save(&self, broker: &BrokerUrl, id_token: &str) -> Result<()> {
            self.0.save(broker, id_token)
        }
        fn delete(&self, broker: &BrokerUrl) -> Result<bool> {
            self.0.delete(broker)
        }
    }

    /// Writer is a buffer the test keeps a hold on.
    #[derive(Clone, Default)]
    struct Writer(Rc<RefCell<Vec<u8>>>);

    impl Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Writer {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).unwrap()
        }
    }

    /// Signs in as a browser would: follows the link to the provider, which
    /// redirects to the loopback with a code.
    fn browser() -> Open {
        Box::new(|link: &str| {
            let link = link.to_string();
            tokio::spawn(async move { reqwest::get(link).await });
            Ok(())
        })
    }

    async fn login(stub: &Stub, store: &Shared) -> Result<()> {
        login_with(stub, store, &[]).await
    }

    async fn login_with(stub: &Stub, store: &Shared, flags: &[&str]) -> Result<()> {
        let mut line = vec!["login"];
        line.extend(flags);
        let ProgramCommand::Login(args) = parse(stub, &line) else {
            unreachable!()
        };
        let mut command = LoginCommand {
            store: Box::new(store.clone()),
            open: browser(),
            port: 0,
        };
        command.execute(&args).await
    }

    #[tokio::test]
    async fn login_signs_in_with_pkce_and_stores_the_id_token() {
        let stub = Stub::start().await;
        let store = Shared::default();
        login(&stub, &store).await.unwrap();

        let identity = current(&store, &stub.url()).unwrap();
        assert_eq!(identity.who(), "alice@example.com");
        assert!(identity.is_for(stub::CLIENT_ID));

        // The provider saw the challenge, then the verifier that makes it.
        let (authorize, token) = stub.sign_in();
        assert_eq!(authorize["client_id"], stub::CLIENT_ID);
        assert_eq!(authorize["code_challenge_method"], "S256");
        assert_eq!(authorize["scope"], SCOPES);
        assert_eq!(token["grant_type"], "authorization_code");
        assert_eq!(
            challenge(&token["code_verifier"]),
            authorize["code_challenge"]
        );
        assert_eq!(token["redirect_uri"], authorize["redirect_uri"]);
        assert!(!token.contains_key("client_secret"));
    }

    #[tokio::test]
    async fn login_needs_the_provider_named_when_the_broker_has_several() {
        let stub = Stub::start().await;
        stub.identity_providers(&["access", "okta"]);
        let store = Shared::default();
        let err = login(&stub, &store).await.unwrap_err().to_string();
        assert!(
            err.contains("several identity providers: access, okta"),
            "{err}"
        );
        assert!(stub.sign_in().0.is_empty(), "no sign-in was started");

        login_with(&stub, &store, &["--provider", "okta"])
            .await
            .unwrap();
        assert!(store.load(&stub.url()).unwrap().is_some());
    }

    #[tokio::test]
    async fn login_refuses_an_id_token_for_another_sign_in() {
        let stub = Stub::start().await;
        stub.claims(json!({ "nonce": "another-sign-ins" }));
        let store = Shared::default();
        let err = login(&stub, &store).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "the provider's ID token isn't for this sign-in"
        );
        assert!(store.load(&stub.url()).unwrap().is_none());
    }

    #[tokio::test]
    async fn login_says_why_the_provider_refused() {
        let stub = Stub::start().await;
        stub.deny_sign_in();
        let err = login(&stub, &Shared::default()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "the provider refused the sign-in (access_denied): not an account member"
        );
    }

    #[tokio::test]
    async fn logout_forgets_the_login() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        let ProgramCommand::Logout(args) = parse(&stub, &["logout"]) else {
            unreachable!()
        };
        let mut command = LogoutCommand {
            store: Box::new(store.clone()),
        };
        command.execute(&args).unwrap();
        assert!(store.load(&stub.url()).unwrap().is_none());
        // Signed out already is fine.
        command.execute(&args).unwrap();
    }

    fn whoami(stub: &Stub, store: &Shared, flags: &[&str]) -> (Result<()>, String) {
        let mut line = vec!["whoami"];
        line.extend(flags);
        let ProgramCommand::Whoami(args) = parse(stub, &line) else {
            unreachable!()
        };
        let writer = Writer::default();
        let mut command = WhoamiCommand {
            store: Box::new(store.clone()),
            writer: Box::new(writer.clone()),
        };
        (command.execute(&args), writer.text())
    }

    #[tokio::test]
    async fn whoami_says_who_and_until_when() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        let (result, text) = whoami(&stub, &store, &[]);
        result.unwrap();
        assert!(
            text.starts_with("email    alice@example.com\nsubject  user-0001\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!("broker   {}\n", stub.base())),
            "{text}"
        );
        assert!(
            text.contains("(in 59m)") || text.contains("(in 1h0m)"),
            "{text}"
        );

        let (result, text) = whoami(&stub, &store, &["--json"]);
        result.unwrap();
        let answer: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(answer["email"], "alice@example.com");
        assert_eq!(answer["expired"], false);

        let (result, text) = whoami(&stub, &store, &["-q"]);
        result.unwrap();
        assert_eq!(text, "");
    }

    #[tokio::test]
    async fn whoami_fails_without_a_login_or_once_it_has_expired() {
        let stub = Stub::start().await;
        let (result, _) = whoami(&stub, &Shared::default(), &[]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("not signed in to")
        );

        let store = signed_in(&stub, json!({ "exp": 1_790_000_000 }));
        let (result, text) = whoami(&stub, &store, &[]);
        assert!(text.ends_with("(expired)\n"), "{text}");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("your login expired at")
        );
    }

    /// Returns a file the child writes to, unique to the test.
    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cloudflare-sts-cli-{}-{name}", std::process::id()))
    }

    async fn exec(stub: &Stub, store: &Shared, script: &str) -> Result<u8> {
        let ProgramCommand::Exec(args) = parse(
            stub,
            &[
                "exec",
                "--profile",
                "example-org/app:tofu-plan",
                "--",
                "sh",
                "-c",
                script,
            ],
        ) else {
            unreachable!()
        };
        let mut command = ExecCommand {
            store: Box::new(store.clone()),
        };
        command.execute(&args).await
    }

    #[tokio::test]
    async fn exec_runs_the_command_with_the_actions_variables_then_revokes() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        let file = scratch("env");
        let names = VARIABLES.map(|name| format!("${name}")).join("|");
        let script = format!("printf '%s' \"{names}\" > {}", file.display());
        assert_eq!(exec(&stub, &store, &script).await.unwrap(), 0);

        let seen = fs::read_to_string(&file).unwrap();
        fs::remove_file(&file).unwrap();
        assert_eq!(
            seen.split('|').collect::<Vec<_>>(),
            [
                "stub-cloudflare-token",
                "0123456789abcdef0123456789abcdef",
                "stub-r2-access-key-id",
                "stub-r2-secret-access-key",
                "stub-r2-session-token",
                "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
                "org-terraform-state",
                "[\"github.com/example-org/app/\"]",
                "github.com/example-org/app/",
            ]
        );
        let form = stub.exchanges().pop().unwrap();
        assert_eq!(form["profile"], "example-org/app:tofu-plan");
        assert_eq!(stub.revoked(), ["stub-cloudflare-token"]);
    }

    #[tokio::test]
    async fn exec_passes_the_exit_code_through_and_still_revokes() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        assert_eq!(exec(&stub, &store, "exit 3").await.unwrap(), 3);
        assert_eq!(stub.revoked().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_answers_128_plus_the_signal_that_killed_the_command() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        assert_eq!(exec(&stub, &store, "kill -TERM $$").await.unwrap(), 143);
        assert_eq!(stub.revoked().len(), 1);
    }

    #[tokio::test]
    async fn exec_revokes_when_the_command_cant_start() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({}));
        let ProgramCommand::Exec(mut args) = parse(&stub, &["exec", "--", "true"]) else {
            unreachable!()
        };
        args.command = vec![OsString::from("cloudflare-sts-no-such-command")];
        let mut command = ExecCommand {
            store: Box::new(store.clone()),
        };
        assert_eq!(command.execute(&args).await.unwrap(), 127);
        assert_eq!(stub.revoked().len(), 1);
    }

    #[tokio::test]
    async fn exec_has_nothing_to_revoke_for_a_profile_with_only_a_bucket() {
        let stub = Stub::start().await;
        let mut response = stub.response();
        let body = response.as_object_mut().unwrap();
        body.remove("access_token");
        body.remove("token_id");
        stub.respond(response);
        let store = signed_in(&stub, json!({}));
        assert_eq!(exec(&stub, &store, "true").await.unwrap(), 0);
        assert!(stub.revoked().is_empty());
    }

    #[tokio::test]
    async fn exec_refuses_an_expired_login_without_asking_the_broker() {
        let stub = Stub::start().await;
        let store = signed_in(&stub, json!({ "exp": 1_790_000_000 }));
        let err = exec(&stub, &store, "true").await.unwrap_err();
        assert!(
            err.to_string().starts_with("your login expired at"),
            "{err}"
        );
        assert!(stub.exchanges().is_empty());
    }
}
