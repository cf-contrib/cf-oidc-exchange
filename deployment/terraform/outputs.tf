output "url" {
  value       = local.broker_url
  description = "The broker's URL: use it as the action's url. It's the policy's issuer, and providers' audience unless they name another."
}

output "worker_name" {
  value       = cloudflare_worker.this.name
  description = "Deployed Worker script name."
}

output "release_tag" {
  value       = var.worker_dir != null ? "local" : data.github_release.this[0].release_tag
  description = "cloudflare-sts release that was deployed, or \"local\" for worker_dir."
}

output "worker_modules_sha256" {
  value = {
    "index.js"      = sha256(local.index_js)
    "index_bg.wasm" = sha256(local.wasm_base64)
  }
  description = "SHA-256 of each module the Worker version uploads (the wasm's of its base64 text): the plan shows the modules themselves only as a sensitive value."
}
