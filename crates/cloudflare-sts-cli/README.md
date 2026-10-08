# cloudflare-sts CLI

> The command-line half of [cloudflare-sts](../..), for people and the agents working
> on their machines: sign in once, then run a command with short-lived
> Cloudflare credentials from the broker, revoked when it exits. CI has the
> [action](../../action).

> [!NOTE]
> **Pre-1.0.** Signing in through Cloudflare Access for SaaS hasn't been tried
> end to end yet ([#53](https://github.com/cf-contrib/cloudflare-sts/issues/53)).

```sh
nix profile install github:cf-contrib/cloudflare-sts

cloudflare-sts login --url https://cloudflare-sts-api.example.com
cloudflare-sts exec --url https://cloudflare-sts-api.example.com --profile example-org/app:tofu-plan -- tofu plan
```

It needs a [broker](../cloudflare-sts-api) with a provider people sign in with, one with a [`client_id`](../cloudflare-sts-api#people), and a profile for people.

## Commands

| Command | |
|---|---|
| `cloudflare-sts login [--provider P] [--no-browser]` | Signs in at an identity provider the broker's metadata lists, in your browser, and keeps the ID token in the OS keychain under the broker's URL, with a refresh token where the provider issues them. With several, `--provider` picks one; it fails rather than asks. |
| `cloudflare-sts logout` | Removes them. |
| `cloudflare-sts whoami [--json]` | Shows who you're signed in as, until when, and whether the login renews. Renews it as `exec` would, and fails when you're not signed in, or the login has expired and can't be renewed: `cloudflare-sts whoami -q \|\| cloudflare-sts login`. |
| `cloudflare-sts exec [--profile P] [--ttl D] -- <command…>` | Exchanges the login for what the profile grants, runs the command with it, and revokes the token when the command exits. A login that has expired, or is about to, is renewed first, where it can be. |

| Flag | Environment | |
|---|---|---|
| `--url` | `CLOUDFLARE_STS_CLI_URL` | Required. The broker's URL. There's no config file. |
| `--profile` | `CLOUDFLARE_STS_CLI_PROFILE` | `exec`: the profile to ask for. Otherwise exactly one profile must match. |
| `--ttl` | `CLOUDFLARE_STS_CLI_TTL` | `exec`: the requested lifetime, capped at the profile's `max_ttl`. |
| `--provider` | `CLOUDFLARE_STS_CLI_PROVIDER` | `login`: the identity provider, by the broker's name for it. Needed only when it has several. |
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
$ cloudflare-sts exec --profile example-org/app:tofu-plan -- tofu plan
cloudflare-sts: minted token 3f2a… (profile example-org/app:tofu-plan, expires 2026-10-07T12:15:00Z)
cloudflare-sts: issued R2 credentials for bucket org-terraform-state under github.com/example-org/app/ (profile example-org/app:tofu-plan, expires 2026-10-07T12:15:00Z)
…
cloudflare-sts: R2 temporary credentials can't be revoked; they expire at 2026-10-07T12:15:00Z
cloudflare-sts: revoked token 3f2a…
```

- **Exit code:** the command's, or `128+n` if signal `n` killed it; `127` if it isn't found. A failed revoke is a warning, and doesn't change it: the token expires, and the broker's cron deletes it.
- **Signals:** Ctrl-C reaches the command through the terminal, not cloudflare-sts, which waits for it and then revokes. `SIGTERM` and `SIGHUP` are forwarded to it. `SIGKILL` can't be caught, so the TTL is the backstop.
- **A shell:** `cloudflare-sts exec -- $SHELL` gives one whose token is revoked when you exit it.

## In a repo

cloudflare-sts is a personal tool, like `gh`: installed once, not a dependency of the
repos it's used in, so CI never builds it. `nix develop` keeps the rest of your
PATH, so it works in a dev shell, which can carry the settings:

```nix
devShells.default = pkgs.mkShell {
  packages = [ pkgs.opentofu pkgs.jq ];
  CLOUDFLARE_STS_CLI_URL = "https://cloudflare-sts-api.example.com";
  CLOUDFLARE_STS_CLI_PROFILE = "example-org/app:tofu-plan";
};
```

```sh
nix develop
cloudflare-sts exec -- tofu -chdir=deployment/terraform plan -lock=false
```

A tofu S3 backend reads `CLOUDFLARE_R2_*` the way it does in CI: a
`credential_process` in its shared config file that prints them as AWS's JSON,
e.g. `jq -n -f backend.jq`.

## Rules

- **No secret on argv, stdout or stderr.** The Cloudflare token and R2 keys reach the command's environment only.
- **Nothing persists but the login:** the ID token, and its refresh token where the provider issues one, in the OS keychain (Keychain on macOS, the Secret Service on Linux, Credential Manager on Windows), each in its own entry.
- **Nothing but `login` opens a browser or waits for you.** An expired login is renewed with its refresh token, with no browser, or else fails at once: `your login expired at …; run 'cloudflare-sts login'`.

## Staying signed in

Some providers' ID tokens are short-lived: Cloudflare Access's last 5 minutes.
Where the provider issues refresh tokens, `login` asks for `offline_access`,
and `exec` and `whoami` trade the refresh token for a new ID token when the
stored one has expired, or will within a minute, as the public client, with no
secret. The provider checks you again each time: Access against the
application's policy, until the refresh token itself expires. `login` asks for
one only where the provider's Discovery document lists the `refresh_token`
grant, or Access's `refresh_tokens`: asking one that doesn't fails the
sign-in.

For Access, set the application's refresh token lifetime, and the
`refresh_tokens` grant type that goes with it: terraform-cloudflare-access's
[`saas-oidc`](https://github.com/tf-contrib/terraform-cloudflare-access/tree/main/modules/saas-oidc)
does both from `refresh_token_lifetime`. Keep it under the organization's
session duration, which otherwise wins.

## AI agents

An agent working on your machine uses your login. `exec` keeps the token out
of its context: it sees the command's output, never the credentials. It can
check `cloudflare-sts whoami --json` first, and ask you to sign in. The broker sees
you: the token is yours, its audit log names you, and the profile's grants are
the only limit, so keep people's profiles read-only.

## Development

```sh
cargo test -p cloudflare-sts-cli   # against a stub broker and identity provider
nix build .#default        # as people install it
```
