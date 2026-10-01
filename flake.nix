{
  description = "Common Lisp QUIC toolkit";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.cl-crypto-kit.url = "github:nerima-lisp/cl-crypto-kit";

  outputs = { self, nixpkgs, cl-crypto-kit }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in {
      checks = forEachSystem (pkgs: {
        bootstrap = pkgs.runCommand "cl-quic-kit-bootstrap-tests" {
          nativeBuildInputs = [ pkgs.sbcl ];
          CL_SOURCE_REGISTRY = "${cl-crypto-kit}/";
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
