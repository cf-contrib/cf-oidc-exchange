{
  description = "cf-sts - exchange an OIDC identity for short-lived Cloudflare credentials.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        cli = (pkgs.lib.importTOML ./crates/cf-sts-cli/Cargo.toml).package;
      in
      {
        # The CLI, for people: `nix profile install github:cf-contrib/cf-sts`.
        # A personal tool, like gh, not a dependency of the repos it's used in.
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cli.name;
          inherit (cli) version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
            # The Worker's Cloudflare client, which the workspace's lock file
            # holds though the CLI doesn't use it.
            outputHashes."cloudflare-0.1.0" = "sha256-e0BWzgtSwRL48FAoiXOzMhbY04C5SDw9FJFE1xy8w54=";
          };
          cargoBuildFlags = [
            "--package"
            cli.name
          ];
          # The tests run in CI, with the rest of the workspace's.
          doCheck = false;
          meta = {
            inherit (cli) description;
            homepage = "https://github.com/cf-contrib/cf-sts";
            license = pkgs.lib.licenses.mit;
            mainProgram = "cf-sts";
            platforms = pkgs.lib.platforms.unix;
          };
        };

        devShells.default = pkgs.mkShell {
          name = "cf-sts";
          packages = [
            # The action, and the TypeSpec the Worker's API is compiled from.
            pkgs.nodejs_24
            # The Rust Worker.
            pkgs.pkg-config
            pkgs.worker-build
            rust-toolchain
            # Both.
            pkgs.wrangler
            pkgs.opentofu
          ];
        };
      }
    );
}
