{
  description = "Common Lisp QUIC toolkit";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.cl-crypto-kit.url = "github:nerima-lisp/cl-crypto-kit/takeokunn-crypto-integration";
  inputs.cl-tls-kit.url = "github:nerima-lisp/cl-tls-kit/takeokunn-tls13-handshake";
  inputs.cl-tls-kit.inputs.cl-crypto-kit.url = "github:nerima-lisp/cl-crypto-kit/takeokunn-crypto-integration";

  outputs = { self, nixpkgs, cl-crypto-kit, cl-tls-kit }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems
        (system: f system (import nixpkgs { inherit system; }));
    in {
      checks = forEachSystem (system: pkgs:
        let
          crypto = cl-crypto-kit.packages.${system}.default;
          tls = cl-tls-kit.packages.${system}.default;
        in {
        bootstrap = pkgs.runCommand "cl-quic-kit-bootstrap-tests" {
          nativeBuildInputs = [ pkgs.sbcl ];
          CL_SOURCE_REGISTRY = "${tls}/share/common-lisp/source//:${crypto}/share/common-lisp/source//";
          src = ./.;
        } ''
          cd "$src"
          export HOME="$TMPDIR"
          export XDG_CACHE_HOME="$TMPDIR/.cache"
          mkdir -p "$XDG_CACHE_HOME"
          sbcl --non-interactive --load t/run.lisp
          touch "$out"
        '';
      });

      devShells = forEachSystem (system: pkgs:
        let
          crypto = cl-crypto-kit.packages.${system}.default;
          tls = cl-tls-kit.packages.${system}.default;
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.sbcl ];
            CL_SOURCE_REGISTRY = "${tls}/share/common-lisp/source//:${crypto}/share/common-lisp/source//";
          };
        });
    };
}
