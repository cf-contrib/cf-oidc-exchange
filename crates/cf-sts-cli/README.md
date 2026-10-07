# cf-sts CLI

> The command-line half of [cf-sts](../..), for people and the agents working
> on their machines: sign in once, then run a command with short-lived
> Cloudflare credentials from the broker, revoked when it exits. CI has the
> [action](../../action).

> [!NOTE]
> **Pre-1.0.** Signing in through Cloudflare Access for SaaS hasn't been tried
> end to end yet ([#53](https://github.com/cf-contrib/cf-sts/issues/53)).

```sh
nix profile install github:cf-contrib/cf-sts

cf-sts login --url https://cf-sts.example.com
cf-sts exec --url https://cf-sts.example.com --profile example-org/app:tofu-plan -- tofu plan
```

It needs a [broker](../cf-sts-api) whose policy names a [`login`](../cf-sts-api#people) provider, and a profile for people.

## Commands

| Command | |
|---|---|
| `cf-sts login [--no-browser]` | Signs in at the identity provider the broker's metadata names, in your browser, and keeps the ID token in the OS keychain under the broker's URL. |
| `cf-sts logout` | Removes it. |
| `cf-sts whoami [--json]` | Shows who you're signed in as, and until when. Fails when you're not, or the login has expired: `cf-sts whoami -q \|\| cf-sts login`. |
| `cf-sts exec [--profile P] [--ttl D] -- <command…>` | Exchanges the login for what the profile grants, runs the command with it, and revokes the token when the command exits. |

| Flag | Environment | |
|---|---|---|
| `--url` | `CF_STS_CLI_URL` | Required. The broker's URL. There's no config file. |
| `--profile` | `CF_STS_CLI_PROFILE` | `exec`: the profile to ask for. Otherwise exactly one profile must match. |
| `--ttl` | `CF_STS_CLI_TTL` | `exec`: the requested lifetime, capped at the profile's `max_ttl`. |
| `-q`, `-v` | | Only warnings and errors on stderr, or also details for debugging. |

## `exec`

The command gets the environment the action sets, under the same names:
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, and for a profile with a
bucket `CLOUDFLARE_R2_ACCESS_KEY_ID`, `CLOUDFLARE_R2_SECRET_ACCESS_KEY`,
`CLOUDFLARE_R2_SESSION_TOKEN`, `CLOUDFLARE_R2_ENDPOINT`, `CLOUDFLARE_R2_BUCKET`,
`CLOUDFLARE_R2_PREFIXES` and `CLOUDFLARE_R2_PREFIX` (see the
[action's README](../../action#r2-over-the-s3-api)). Those the profile doesn't
grant are removed, so a token left in your shell can't stand in for one.

```
$ cf-sts exec --profile example-org/app:tofu-plan -- tofu plan
cf-sts: minted token 3f2a… (profile example-org/app:tofu-plan, expires 2026-10-07T12:15:00Z)
cf-sts: issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ (profile example-org/app:tofu-plan, expires 2026-10-07T12:15:00Z)
…
cf-sts: R2 temporary credentials can't be revoked; they expire at 2026-10-07T12:15:00Z
cf-sts: revoked token 3f2a…
```

- **Exit code:** the command's, or `128+n` if signal `n` killed it; `127` if it isn't found. A failed revoke is a warning, and doesn't change it: the token expires, and the broker's cron deletes it.
- **Signals:** Ctrl-C reaches the command through the terminal, not cf-sts, which waits for it and then revokes. `SIGTERM` and `SIGHUP` are forwarded to it. `SIGKILL` can't be caught, so the TTL is the backstop.
- **A shell:** `cf-sts exec -- $SHELL` gives one whose token is revoked when you exit it.

## In a repo

cf-sts is a personal tool, like `gh`: installed once, not a dependency of the
repos it's used in, so CI never builds it. `nix develop` keeps the rest of your
PATH, so it works in a dev shell, which can carry the settings:

```nix
devShells.default = pkgs.mkShell {
  packages = [ pkgs.opentofu pkgs.jq ];
  CF_STS_CLI_URL = "https://cf-sts.example.com";
  CF_STS_CLI_PROFILE = "example-org/app:tofu-plan";
};
```

```sh
nix develop
cf-sts exec -- tofu -chdir=deployment/terraform plan -lock=false
```

A tofu S3 backend reads `CLOUDFLARE_R2_*` the way it does in CI: a
`credential_process` in its shared config file that prints them as AWS's JSON,
e.g. `jq -n -f backend.jq`.

## Rules

- **No secret on argv, stdout or stderr.** The Cloudflare token and R2 keys reach the command's environment only.
- **Nothing persists but the ID token,** in the OS keychain (Keychain on macOS, the Secret Service on Linux, Credential Manager on Windows).
- **Nothing but `login` opens a browser or waits for you.** An expired login fails at once: `your login expired at …; run 'cf-sts login'`.

## AI agents

An agent working on your machine uses your login. `exec` keeps the token out
of its context: it sees the command's output, never the credentials. It can
check `cf-sts whoami --json` first, and ask you to sign in. The broker sees
you: the token is yours, its audit log names you, and the profile's grants are
the only limit, so keep people's profiles read-only.

## Development

```sh
cargo test -p cf-sts-cli   # against a stub broker and identity provider
nix build .#default        # as people install it
```
