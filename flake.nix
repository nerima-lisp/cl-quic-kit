{
  description = "Common Lisp QUIC toolkit";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in {
      checks = forEachSystem (pkgs: {
        bootstrap = pkgs.runCommand "cl-quic-kit-bootstrap-tests" {
          nativeBuildInputs = [ pkgs.sbcl ];
          src = ./.;
        } ''
          cd "$src"
          sbcl --non-interactive --load t/run.lisp
          touch "$out"
        '';
      });

      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.sbcl ];
        };
      });
    };
}
