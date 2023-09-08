{
  description = "MPC PoC";

  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/release-22.11;
    flake-utils.url = github:numtide/flake-utils;
  };

  outputs = inputs@{ self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells.default = with pkgs; mkShell {
          nativeBuildInputs = [
            ninja
            cmake
            clang-tools_16
            bear
          ];
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
