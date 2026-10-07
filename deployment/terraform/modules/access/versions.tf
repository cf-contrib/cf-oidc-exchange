# The cloudflare provider is configured by the caller, as for the broker's
# module.
terraform {
  required_version = ">= 1.9.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.10"
    }
  }
}
