output "provider" {
  value = {
    name      = var.provider_name
    issuer    = local.issuer
    client_id = local.client_id
    claims    = [{ iss = local.issuer }]
  }
  description = "The broker's provider for people, for the broker module's oidc_providers: its issuer, and the client_id people sign in as, which is its audience. Its claim set pins the application's own issuer; profiles name the people."
}

output "issuer" {
  value       = local.issuer
  description = "The application's OIDC issuer."
}

output "client_id" {
  value       = local.client_id
  description = "The application's client ID, which people sign in as, and its ID tokens' audience."
}

output "application_id" {
  value       = cloudflare_zero_trust_access_application.this.id
  description = "The Access application's ID."
}
