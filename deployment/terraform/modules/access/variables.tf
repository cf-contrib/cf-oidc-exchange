variable "account_id" {
  type        = string
  description = "Cloudflare account ID, with a Zero Trust organization: the application and its policy are created here."
}

variable "team_name" {
  type        = string
  description = "The Zero Trust organization's team name, as in <team_name>.cloudflareaccess.com: the issuer's host."

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.team_name))
    error_message = "team_name must be the bare team name, such as example for example.cloudflareaccess.com."
  }
}

variable "emails" {
  type        = list(string)
  description = "Who may sign in: the Access policy lets in these emails and no one else. The broker's profiles still decide what each of them gets."

  validation {
    condition     = length(var.emails) > 0
    error_message = "emails must name at least one person."
  }
}

variable "name" {
  type        = string
  description = "The Access application's name, shown at sign-in, and its policy's prefix."
  default     = "cf-sts"
}

variable "token_lifetime" {
  type        = string
  description = "How long a sign-in lasts: the application's access token lifetime, which its ID tokens follow, so how long until cf-sts login again. Minutes or hours, from 1m to 24h. Access's own default is 5m."
  default     = "8h"

  validation {
    # In minutes, 1 to 1440: a malformed value isn't a number of them at all.
    condition = try(alltrue([
      for minutes in [tonumber(regex("^([0-9]+)[mh]$", var.token_lifetime)[0]) * (endswith(var.token_lifetime, "h") ? 60 : 1)] :
      minutes >= 1 && minutes <= 1440
    ]), false)
    error_message = "token_lifetime must be minutes or hours, such as 30m or 8h, from 1m to 24h."
  }
}

variable "provider_name" {
  type        = string
  description = "The broker's name for the provider, which profiles name as their provider and minted tokens carry."
  default     = "com.cloudflare.access"
}

variable "identity_provider_ids" {
  type        = list(string)
  description = "The Access login methods people may use, by ID: one-time PIN, GitHub, and so on. Empty allows every one the organization has; exactly one skips the choice."
  default     = []
}

variable "redirect_uris" {
  type        = list(string)
  description = "Where Access may send the authorization code. The cf-sts CLI listens on http://127.0.0.1:8250/callback."
  default     = ["http://127.0.0.1:8250/callback"]
}

variable "scopes" {
  type        = list(string)
  description = "The OIDC scopes the application grants. The cf-sts CLI asks for openid, email and profile."
  default     = ["openid", "email", "profile"]
}
