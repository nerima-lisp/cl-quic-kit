# Changelog

## 0.2.1

- Bounded client and server UDP receive work to 64 datagrams per poll by default, with a configurable positive integer budget.

## 0.2.0

- Added a client API to accept peer-initiated streams and read peer `CONNECTION_CLOSE` reasons, a Retry-based QUIC server listener, TLS 1.3 server handshakes, server stream I/O, and graceful server shutdown.
- Preserved server connection admission and draining, released consumed receive payload, and continued Retry admission when both bounded caches reached capacity by evicting paired token and CID entries.
- Pinned the server source connection ID from the first decryptable Initial and reset that pin after Retry; discarded later packets with a different source connection ID (RFC 9000 §7.2).
- Hardened client packet handling by discarding packets addressed to unknown connection IDs, ignoring all four Retry Unused bits, dropping invalid or replayed Retry packets, and discarding late or mismatched Version Negotiation packets.
- Returned stream receive credit according to each configured receive window after reads, and reported `FINAL_SIZE_ERROR` when a final size conflicts with received data or a previously declared final size.
- Enforced the selected AEAD's integrity limit (2^52 failed decryptions for AES-GCM; 2^36 for ChaCha20-Poly1305), checked reserved bits after authentication, and discarded packets too short to contain a header-protection sample.
- Emitted stream- and connection-level blocked frames when their flow-control windows were exhausted, preserving packet order and encryption levels.
- Tracked server shutdown separately from UDP descriptor closure so a failed close could be retried without closing an already closed socket.
- Redacted secret-bearing QUIC structures and frame and stream payloads in printed representations, and replaced caller-supplied values in audited type errors with fixed classifications.
- Exposed `client-receive-frames` to apply a packet's decoded frame list at its encryption level and record its packet number for ACK processing.
- Kept owned client UDP socket cleanup running when QUIC close reports an error, and rounded rational RTT EWMA values to the nearest nanosecond.
