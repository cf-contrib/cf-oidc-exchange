# cf-sts Access module

> Signing people in to [cf-sts](../../../..) through Cloudflare Access: an
> Access for SaaS OIDC application that the [CLI](../../../../crates/cf-sts-cli)
> signs in to, its policy, and the provider the [broker's module](../..)
> takes for it.

```hcl
module "cf_sts_access" {
  source = "git::https://github.com/cf-contrib/cf-sts.git//deployment/terraform/modules/access?ref=v0.16.0" # x-release-please-version

  account_id = var.account_id
  team_name  = "example" # example.cloudflareaccess.com
  emails     = ["alice@example.com", "bob@example.com"]
}

module "cf_sts" {
  source = "git::https://github.com/cf-contrib/cf-sts.git//deployment/terraform?ref=v0.16.0" # x-release-please-version

  # ...
  oidc_providers = [
    # ... CI's providers
    module.cf_sts_access.provider,
  ]

  profiles = [
    {
      name     = "infra-admins:tofu-plan"
      provider = module.cf_sts_access.provider.name
      claims   = [{ email = "alice@example.com" }, { email = "bob@example.com" }]
      max_ttl  = "1h"
      bucket   = { name = "org-terraform-state", permission = "object-read-only" }
    },
  ]
}
```

Then, on each person's machine:

```sh
cf-sts login --url https://cf-sts.example.com
cf-sts exec --url https://cf-sts.example.com --profile infra-admins:tofu-plan -- tofu plan
```

## What it creates

- **The application:** Access for SaaS, OIDC, as a public client. The CLI
  proves itself with PKCE (`authorization_code_with_pkce`, with
  `allow_pkce_without_client_secret`), so it has no secret to keep. It
  redirects to `http://127.0.0.1:8250/callback`, where the CLI listens, and
  grants `openid email profile`. It's hidden from the App Launcher. A sign-in
  lasts `token_lifetime`, 8h by default: Access's ID tokens expire with its
  access tokens, whose own default, 5m, would have people sign in again every
  five minutes.
- **Its policy:** the `emails` you give, and no one else, can sign in.
- **The `provider` output:** what the broker's `oidc_providers` takes for it.
  Its `issuer` is the application's own,
  `https://<team_name>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client_id>`,
  its `client_id` is the one people sign in as, which is also its tokens'
  audience, and its one claim set pins that issuer. Who gets what is up to the
  profiles, which match people by `email`.

Access decides who can sign in; the broker's profiles decide what each person
gets. Keep people's profiles to what they need locally, such as read-only
state, and leave applies to CI.

## Prerequisites

- A Zero Trust organization on the account, with a team name: the free plan
  will do. Choosing a plan is a dashboard step.
- At least one login method in it, such as one-time PIN or GitHub. Pass their
  IDs as `identity_provider_ids` to allow only those; with exactly one, Access
  skips the choice.
- The deploy token needs **Account → Access: Apps and Policies: Edit**.

## After applying

Access generates a client secret for every OIDC application, and returns it
only when it's created, so it's in Terraform state. Nothing uses it: the CLI
signs in with PKCE alone. Regenerate it once in the dashboard (Zero Trust →
Access → Applications → the application → Edit) so the copy in state is a dead
one.

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `account_id` | yes | | Account with the Zero Trust organization. |
| `team_name` | yes | | The team name, as in `<team_name>.cloudflareaccess.com`. |
| `emails` | yes | | Who may sign in. At least one. |
| `name` | no | `cf-sts` | The application's name, shown at sign-in, and its policy's prefix. |
| `token_lifetime` | no | `8h` | How long a sign-in lasts, `1m` to `24h`. Access's ID tokens expire with its access tokens. |
| `provider_name` | no | `com.cloudflare.access` | The broker's name for the provider, which profiles name. |
| `identity_provider_ids` | no | `[]` | The login methods allowed, by ID. Empty allows every one. |
| `redirect_uris` | no | `["http://127.0.0.1:8250/callback"]` | Where Access may send the code. The CLI's. |
| `scopes` | no | `["openid", "email", "profile"]` | The scopes the application grants. The CLI's. |

## Outputs

| Name | Description |
|---|---|
| `provider` | `{ name, issuer, client_id, claims }`, for the broker module's `oidc_providers`. |
| `issuer` | The application's OIDC issuer. |
| `client_id` | The client ID people sign in as, and its ID tokens' audience. |
| `application_id` | The Access application's ID. |

## Notes

- Tried end to end against Access, with one-time PIN: its ID tokens carry
  `email`, `sub`, and the application's `iss`, and with Access's default access
  token lifetime they expired after 5 minutes.
- `tofu test` plans the module with a mocked provider: the application's
  settings, the policy, the login methods, and the input checks. Access
  assigns the client ID, so the issuer built from it is Cloudflare's
  documented format rather than tested.
