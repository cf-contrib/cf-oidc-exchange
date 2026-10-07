# Plans the module with a mocked provider: no credentials or network needed.
# Covers the application as the CLI needs it, a public client with PKCE, who
# may sign in, the login methods, and the provider it hands the broker. The
# client ID is Access's, so it's unknown until apply, and the mock can't make
# one up inside saas_app: the issuer built from it is Cloudflare's documented
# https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client-id>.
mock_provider "cloudflare" {}

variables {
  account_id = "0123456789abcdef0123456789abcdef"
  team_name  = "example"
  emails     = ["alice@example.com", "bob@example.com"]
}

run "is_a_public_pkce_client_for_the_cli" {
  command = plan

  assert {
    condition     = cloudflare_zero_trust_access_application.this.type == "saas"
    error_message = "the application should be Access for SaaS"
  }

  assert {
    condition = (
      cloudflare_zero_trust_access_application.this.saas_app.auth_type == "oidc" &&
      tolist(cloudflare_zero_trust_access_application.this.saas_app.grant_types) == tolist(["authorization_code_with_pkce"]) &&
      cloudflare_zero_trust_access_application.this.saas_app.allow_pkce_without_client_secret
    )
    error_message = "the application should be an OIDC public client: PKCE, and no client secret"
  }

  assert {
    condition     = tolist(cloudflare_zero_trust_access_application.this.saas_app.redirect_uris) == tolist(["http://127.0.0.1:8250/callback"])
    error_message = "the redirect should be where the CLI listens"
  }

  assert {
    condition     = toset(cloudflare_zero_trust_access_application.this.saas_app.scopes) == toset(["openid", "email", "profile"])
    error_message = "the scopes should be what the CLI asks for"
  }
}

run "keeps_a_sign_in_for_a_working_day" {
  command = plan

  assert {
    condition     = cloudflare_zero_trust_access_application.this.saas_app.access_token_lifetime == "8h"
    error_message = "a sign-in should last 8h by default, not Access's 5m"
  }
}

run "takes_a_token_lifetime" {
  command = plan

  variables {
    token_lifetime = "30m"
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.this.saas_app.access_token_lifetime == "30m"
    error_message = "token_lifetime should set the access token lifetime"
  }
}

run "rejects_a_token_lifetime_over_a_day" {
  command = plan

  variables {
    token_lifetime = "25h"
  }

  expect_failures = [var.token_lifetime]
}

run "rejects_a_token_lifetime_in_seconds" {
  command = plan

  variables {
    token_lifetime = "300s"
  }

  expect_failures = [var.token_lifetime]
}

run "lets_in_only_the_given_emails" {
  command = plan

  assert {
    condition = (
      cloudflare_zero_trust_access_policy.this.decision == "allow" &&
      toset([for rule in cloudflare_zero_trust_access_policy.this.include : rule.email.email]) == toset(["alice@example.com", "bob@example.com"])
    )
    error_message = "the policy should allow exactly the given emails"
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.this.policies[0].id == cloudflare_zero_trust_access_policy.this.id
    error_message = "the application should use the policy"
  }
}

run "hands_the_broker_a_provider_for_people" {
  command = plan

  assert {
    condition     = output.provider.name == "com.cloudflare.access"
    error_message = "the provider should have the broker's name for Access"
  }
}

run "names_the_provider_as_told" {
  command = plan

  variables {
    provider_name = "com.cloudflare.access.admins"
  }

  assert {
    condition     = output.provider.name == "com.cloudflare.access.admins"
    error_message = "the provider should take provider_name"
  }
}

run "allows_every_login_method_by_default" {
  command = plan

  assert {
    condition     = cloudflare_zero_trust_access_application.this.allowed_idps == null && !cloudflare_zero_trust_access_application.this.auto_redirect_to_identity
    error_message = "without identity_provider_ids, every login method should be offered"
  }
}

run "skips_the_choice_with_one_login_method" {
  command = plan

  variables {
    identity_provider_ids = ["99999999-8888-7777-6666-555555555555"]
  }

  assert {
    condition = (
      cloudflare_zero_trust_access_application.this.allowed_idps == toset(["99999999-8888-7777-6666-555555555555"]) &&
      cloudflare_zero_trust_access_application.this.auto_redirect_to_identity
    )
    error_message = "with one login method, it should be the only one and go straight to it"
  }
}

run "rejects_a_team_domain" {
  command = plan

  variables {
    team_name = "example.cloudflareaccess.com"
  }

  expect_failures = [var.team_name]
}

run "rejects_no_one" {
  command = plan

  variables {
    emails = []
  }

  expect_failures = [var.emails]
}
