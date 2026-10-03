{
  description = "Common Lisp QUIC toolkit";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.cl-crypto-kit.url = "github:nerima-lisp/cl-crypto-kit/takeokunn-crypto-integration";
  inputs.cl-tls-kit.url = "github:nerima-lisp/cl-tls-kit/takeokunn-tls13-handshake";
  inputs.cl-tls-kit.inputs.cl-crypto-kit.follows = "cl-crypto-kit";

  outputs = { self, nixpkgs, cl-crypto-kit, cl-tls-kit }:
    let
      systems = [ "x86_64-linux" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems
        (system: f system (import nixpkgs { inherit system; }));
    in {
      checks = forEachSystem (system: pkgs:
        let
          crypto = cl-crypto-kit.packages.${system}.default;
          tls = cl-tls-kit.packages.${system}.default;
        in {
        bootstrap = pkgs.runCommand "cl-quic-kit-bootstrap-tests" {
          nativeBuildInputs = [ pkgs.sbcl pkgs.caddy pkgs.openssl pkgs.stdenv.cc ];
          CL_SOURCE_REGISTRY = "${tls}/share/common-lisp/source//:${crypto}/share/common-lisp/source//";
          src = ./.;
        } ''
          cd "$src"
          export HOME="$TMPDIR"
          export XDG_CACHE_HOME="$TMPDIR/.cache"
          mkdir -p "$XDG_CACHE_HOME"
          ${pkgs.openssl}/bin/openssl ecparam -name prime256v1 -genkey \
            -noout -out "$TMPDIR/self.key"
          ${pkgs.openssl}/bin/openssl req -x509 -new -sha256 \
            -key "$TMPDIR/self.key" -out "$TMPDIR/self.crt" -days 1 \
            -subj '/CN=localhost' \
            -addext 'subjectAltName=DNS:localhost' \
            -addext 'basicConstraints=critical,CA:TRUE' \
            -addext 'keyUsage=critical,keyCertSign,digitalSignature'
          printf '%s\n' \
            '{' \
            '  admin off' \
            '  auto_https off' \
            '  servers {' \
            '    protocols h1 h2 h3' \
            '  }' \
            '}' \
            'localhost:18443 {' \
            '  bind 127.0.0.1' \
            "  tls $TMPDIR/self.crt $TMPDIR/self.key" \
            '  respond "ok"' \
            '}' > "$TMPDIR/Caddyfile"
          ${pkgs.stdenv.cc}/bin/cc -std=c11 -Wall -Wextra -O2 \
            t/udp-proxy.c -o "$TMPDIR/udp-proxy"
          cleanup() {
            if [ -n "''${proxy_pid:-}" ]; then
              kill "$proxy_pid" 2>/dev/null || true
              wait "$proxy_pid" 2>/dev/null || true
            fi
            if [ -n "''${caddy_pid:-}" ]; then
              kill "$caddy_pid" 2>/dev/null || true
              wait "$caddy_pid" 2>/dev/null || true
            fi
          }
          trap cleanup EXIT HUP INT TERM
          sbcl --non-interactive --load t/run.lisp
          ${pkgs.caddy}/bin/caddy run --config "$TMPDIR/Caddyfile" \
            --adapter caddyfile > "$TMPDIR/caddy.log" 2>&1 &
          caddy_pid=$!
          attempts=0
          while ! grep -q 'serving initial configuration' "$TMPDIR/caddy.log"; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 200 ]; then
              cat "$TMPDIR/caddy.log"
              exit 1
            fi
            if ! kill -0 "$caddy_pid" 2>/dev/null; then
              cat "$TMPDIR/caddy.log"
              exit 1
            fi
            sleep 0.05
          done
          if ! HOME="$TMPDIR" XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            CADDY_ROOT="$TMPDIR/self.crt" QUIC_PORT=18443 \
            sbcl --non-interactive --load t/http3-loopback.lisp; then
            cat "$TMPDIR/caddy.log"
            exit 1
          fi
          proxy_pid=
          "$TMPDIR/udp-proxy" 18444 18443 1 20 0 > "$TMPDIR/proxy.log" 2>&1 &
          proxy_pid=$!
          attempts=0
          while ! grep -q 'udp-proxy listening' "$TMPDIR/proxy.log"; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 200 ]; then
              cat "$TMPDIR/proxy.log"
              exit 1
            fi
            if ! kill -0 "$proxy_pid" 2>/dev/null; then
              cat "$TMPDIR/proxy.log"
              exit 1
            fi
            sleep 0.05
          done
          if ! HOME="$TMPDIR" XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            CADDY_ROOT="$TMPDIR/self.crt" QUIC_PORT=18444 \
            sbcl --non-interactive --load t/http3-loopback.lisp; then
            cat "$TMPDIR/caddy.log"
            cat "$TMPDIR/proxy.log"
            exit 1
          fi
          grep -q 'udp-proxy dropped server packet' "$TMPDIR/proxy.log"
          grep -q 'loss=20% mutate-1rtt=0' "$TMPDIR/proxy.log"
          kill "$proxy_pid" 2>/dev/null || true
          wait "$proxy_pid" 2>/dev/null || true
          proxy_pid=
          "$TMPDIR/udp-proxy" 18445 18443 0 0 1 > "$TMPDIR/malformed-proxy.log" 2>&1 &
          proxy_pid=$!
          attempts=0
          while ! grep -q 'udp-proxy listening' "$TMPDIR/malformed-proxy.log"; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 200 ]; then
              cat "$TMPDIR/malformed-proxy.log"
              exit 1
            fi
            if ! kill -0 "$proxy_pid" 2>/dev/null; then
              cat "$TMPDIR/malformed-proxy.log"
              exit 1
            fi
            sleep 0.05
          done
          if ! HOME="$TMPDIR" XDG_CACHE_HOME="$XDG_CACHE_HOME" \
            CADDY_ROOT="$TMPDIR/self.crt" QUIC_PORT=18445 \
            EXPECT_CONNECTION_CLOSE=1 \
            sbcl --non-interactive --load t/http3-loopback.lisp; then
            cat "$TMPDIR/caddy.log"
            cat "$TMPDIR/malformed-proxy.log"
            exit 1
          fi
          grep -q 'udp-proxy mutated server 1-rtt packet' "$TMPDIR/malformed-proxy.log"
          # Caddy's Caddyfile does not expose QUIC Retry forcing. The
          # deterministic RFC 9001 Appendix A.4 Retry vector and client restart
          # path are executed by t/protection.lisp loaded from t/run.lisp.
          echo 'Caddy Retry forcing is unavailable in its Caddyfile; RFC 9001 Appendix A.4 vector passed.'
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
