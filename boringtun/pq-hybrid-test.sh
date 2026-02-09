#!/usr/bin/env bash
#
# pq-hybrid-test.sh — Tests the hybrid PQ handshake (X25519 + ML-KEM-768)
#
# Unlike the PSK-slot approach (pq-psk-tool), the hybrid handshake embeds
# ML-KEM-768 key exchange directly into the WireGuard Noise IK protocol.
# No separate out-of-band key exchange step is needed — peers just connect
# and the handshake automatically uses both X25519 and ML-KEM-768.
#
# Message types:
#   Type 5 — PQ Handshake Init    (1332 bytes, vs 148 for classical)
#   Type 6 — PQ Handshake Response (1180 bytes, vs  92 for classical)
#
# Usage:
#   ./pq-hybrid-test.sh demo                Build & show PQ vs vanilla packet sizes
#   sudo ./pq-hybrid-test.sh local-tunnel   Full tunnel test with PQ handshake
#   sudo ./pq-hybrid-test.sh compare        Side-by-side vanilla vs PQ tunnels

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build boringtun-cli with PQ feature
build_pq() {
    cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" \
        --features boringtun/pq 2>/dev/null
    echo "$PROJECT_ROOT/target/debug/boringtun-cli"
}

# Build boringtun-cli without PQ (vanilla)
build_vanilla() {
    cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>/dev/null
    echo "$PROJECT_ROOT/target/debug/boringtun-cli"
}

WORKDIR="${PQ_WORKDIR:-/tmp/pq-hybrid-test}"
mkdir -p "$WORKDIR"

case "${1:-demo}" in
    demo)
        echo "=== Hybrid PQ WireGuard Demo ==="
        echo ""
        echo "The hybrid approach adds ML-KEM-768 to the WireGuard Noise IK handshake."
        echo "Both X25519 (classical) and ML-KEM-768 (post-quantum) shared secrets are"
        echo "mixed into the session key derivation via HMAC-BLAKE2s."
        echo ""
        echo "Security guarantee: session keys are secure if EITHER X25519 OR ML-KEM-768"
        echo "remains unbroken (hybrid argument)."
        echo ""
        echo "Packet sizes:"
        echo "  Classical Handshake Init:     148 bytes (type 1)"
        echo "  PQ Hybrid Handshake Init:    1332 bytes (type 5)  [+1184 = ML-KEM-768 ek]"
        echo "  Classical Handshake Response:   92 bytes (type 2)"
        echo "  PQ Hybrid Handshake Response: 1180 bytes (type 6)  [+1088 = ML-KEM-768 ct]"
        echo ""
        echo "Both fit within a standard 1500-byte MTU."
        echo ""

        echo "--- Vanilla mode tests ---"
        cargo test -p boringtun --lib noise::tests \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 | tail -5
        echo ""

        echo "--- PQ hybrid mode tests ---"
        cargo test -p boringtun --lib noise::tests \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" --features pq 2>&1 | tail -5
        echo ""
        echo "All tests passed."
        echo ""
        echo "To test a real tunnel, run: sudo $0 local-tunnel"
        ;;

    local-tunnel)
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: local-tunnel requires root. Run with sudo."
            exit 1
        fi

        BORINGTUN="$(build_pq)"
        echo "=== Hybrid PQ WireGuard Tunnel Test ==="
        echo ""

        cleanup() {
            echo ""
            echo "--- Cleaning up ---"
            kill "$PID_A" "$PID_B" 2>/dev/null || true
            wait "$PID_A" "$PID_B" 2>/dev/null || true
            rm -f "$WORKDIR"/wg_*.key "$WORKDIR"/*.log
            echo "Done."
        }
        trap cleanup EXIT

        # Step 1: Generate WireGuard keys for both peers
        echo "--- Generating WireGuard keypairs ---"
        WG_A_PRIV=$(wg genkey)
        WG_A_PUB=$(echo "$WG_A_PRIV" | wg pubkey)
        WG_B_PRIV=$(wg genkey)
        WG_B_PUB=$(echo "$WG_B_PRIV" | wg pubkey)
        echo "Peer A pubkey: $WG_A_PUB"
        echo "Peer B pubkey: $WG_B_PUB"
        echo ""

        # Step 2: Start boringtun peers (PQ hybrid handshake happens automatically)
        echo "--- Starting boringtun peers (PQ hybrid) ---"

        echo "$WG_A_PRIV" > "$WORKDIR/wg_a.key"
        echo "$WG_B_PRIV" > "$WORKDIR/wg_b.key"

        # Start peer A (utun interface)
        WG_LOG_LEVEL=debug "$BORINGTUN" utun8 \
            --foreground \
            --disable-drop-privileges \
            2>"$WORKDIR/peer_a.log" &
        PID_A=$!
        sleep 1

        # Start peer B (utun interface)
        WG_LOG_LEVEL=debug "$BORINGTUN" utun9 \
            --foreground \
            --disable-drop-privileges \
            2>"$WORKDIR/peer_b.log" &
        PID_B=$!
        sleep 1

        # Step 3: Configure peers via wg (no PSK needed — PQ is in the handshake)
        echo "--- Configuring WireGuard peers ---"

        wg set utun8 \
            private-key "$WORKDIR/wg_a.key" \
            listen-port 51820 \
            peer "$WG_B_PUB" \
                endpoint 127.0.0.1:51821 \
                allowed-ips 10.0.0.2/32

        wg set utun9 \
            private-key "$WORKDIR/wg_b.key" \
            listen-port 51821 \
            peer "$WG_A_PUB" \
                endpoint 127.0.0.1:51820 \
                allowed-ips 10.0.0.1/32

        # Assign IP addresses
        ifconfig utun8 10.0.0.1 10.0.0.2
        ifconfig utun9 10.0.0.2 10.0.0.1

        echo "Peer A: utun8 = 10.0.0.1, listening on :51820"
        echo "Peer B: utun9 = 10.0.0.2, listening on :51821"
        echo ""

        # Step 4: Show configuration
        echo "--- WireGuard Status ---"
        wg show utun8
        echo ""
        wg show utun9
        echo ""

        # Step 5: Test connectivity
        echo "--- Testing tunnel connectivity ---"
        if ping -c 3 -W 2 10.0.0.2 > /dev/null 2>&1; then
            echo "SUCCESS: Ping through PQ hybrid WireGuard tunnel works!"
            echo ""
            echo "The tunnel handshake used ML-KEM-768 + X25519 (hybrid PQ)."
            echo "No out-of-band key exchange was needed — PQ protection is automatic."
            echo ""

            # Check logs for PQ handshake evidence
            echo "--- Handshake log evidence ---"
            if grep -q "pq_handshake_initiation\|pq_handshake_response" "$WORKDIR/peer_a.log" "$WORKDIR/peer_b.log" 2>/dev/null; then
                echo "Confirmed: PQ handshake messages (type 5/6) were used."
                grep "pq_handshake" "$WORKDIR/peer_a.log" "$WORKDIR/peer_b.log" 2>/dev/null | head -4
            else
                echo "Note: Check logs at $WORKDIR/peer_*.log for handshake details."
            fi
            echo ""
            echo "Press Ctrl+C to stop."
            wg show utun8
            wg show utun9
            wait
        else
            echo "FAILURE: Ping did not succeed."
            echo ""
            echo "Peer A log (last 10 lines):"
            tail -10 "$WORKDIR/peer_a.log"
            echo ""
            echo "Peer B log (last 10 lines):"
            tail -10 "$WORKDIR/peer_b.log"
            exit 1
        fi
        ;;

    compare)
        #
        # Side-by-side: vanilla tunnel vs PQ hybrid tunnel
        # Builds both binaries, starts two tunnel pairs, pings both
        #
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: compare requires root. Run with sudo."
            exit 1
        fi

        # Build vanilla first, copy binary, then build PQ
        BORINGTUN_VANILLA="$(build_vanilla)"
        cp "$BORINGTUN_VANILLA" "$WORKDIR/boringtun-vanilla"
        BORINGTUN_VANILLA="$WORKDIR/boringtun-vanilla"
        BORINGTUN_PQ="$(build_pq)"

        echo "=== Vanilla vs PQ Hybrid Comparison ==="
        echo ""

        cleanup() {
            echo ""
            echo "--- Cleaning up ---"
            kill "$PID_VA" "$PID_VB" "$PID_PA" "$PID_PB" 2>/dev/null || true
            wait "$PID_VA" "$PID_VB" "$PID_PA" "$PID_PB" 2>/dev/null || true
            rm -f "$WORKDIR"/*.key "$WORKDIR"/*.log "$WORKDIR/boringtun-vanilla"
            echo "Done."
        }
        trap cleanup EXIT

        # --- Vanilla tunnel (utun10/11, ports 51830/51831, 10.0.1.x) ---
        echo "--- [1/2] Setting up VANILLA tunnel ---"
        V_A_PRIV=$(wg genkey); V_A_PUB=$(echo "$V_A_PRIV" | wg pubkey)
        V_B_PRIV=$(wg genkey); V_B_PUB=$(echo "$V_B_PRIV" | wg pubkey)
        echo "$V_A_PRIV" > "$WORKDIR/va.key"; echo "$V_B_PRIV" > "$WORKDIR/vb.key"

        WG_LOG_LEVEL=debug "$BORINGTUN_VANILLA" utun10 --foreground --disable-drop-privileges 2>"$WORKDIR/va.log" &
        PID_VA=$!; sleep 1
        WG_LOG_LEVEL=debug "$BORINGTUN_VANILLA" utun11 --foreground --disable-drop-privileges 2>"$WORKDIR/vb.log" &
        PID_VB=$!; sleep 1

        wg set utun10 private-key "$WORKDIR/va.key" listen-port 51830 peer "$V_B_PUB" endpoint 127.0.0.1:51831 allowed-ips 10.0.1.2/32
        wg set utun11 private-key "$WORKDIR/vb.key" listen-port 51831 peer "$V_A_PUB" endpoint 127.0.0.1:51830 allowed-ips 10.0.1.1/32
        ifconfig utun10 10.0.1.1 10.0.1.2
        ifconfig utun11 10.0.1.2 10.0.1.1
        echo "Vanilla: utun10=10.0.1.1, utun11=10.0.1.2"
        echo ""

        # --- PQ hybrid tunnel (utun12/13, ports 51832/51833, 10.0.2.x) ---
        echo "--- [2/2] Setting up PQ HYBRID tunnel ---"
        P_A_PRIV=$(wg genkey); P_A_PUB=$(echo "$P_A_PRIV" | wg pubkey)
        P_B_PRIV=$(wg genkey); P_B_PUB=$(echo "$P_B_PRIV" | wg pubkey)
        echo "$P_A_PRIV" > "$WORKDIR/pa.key"; echo "$P_B_PRIV" > "$WORKDIR/pb.key"

        WG_LOG_LEVEL=debug "$BORINGTUN_PQ" utun12 --foreground --disable-drop-privileges 2>"$WORKDIR/pa.log" &
        PID_PA=$!; sleep 1
        WG_LOG_LEVEL=debug "$BORINGTUN_PQ" utun13 --foreground --disable-drop-privileges 2>"$WORKDIR/pb.log" &
        PID_PB=$!; sleep 1

        wg set utun12 private-key "$WORKDIR/pa.key" listen-port 51832 peer "$P_B_PUB" endpoint 127.0.0.1:51833 allowed-ips 10.0.2.2/32
        wg set utun13 private-key "$WORKDIR/pb.key" listen-port 51833 peer "$P_A_PUB" endpoint 127.0.0.1:51832 allowed-ips 10.0.2.1/32
        ifconfig utun12 10.0.2.1 10.0.2.2
        ifconfig utun13 10.0.2.2 10.0.2.1
        echo "PQ Hybrid: utun12=10.0.2.1, utun13=10.0.2.2"
        echo ""

        # Test both
        echo "--- Testing connectivity ---"
        VANILLA_OK=false
        PQ_OK=false

        if ping -c 3 -W 2 10.0.1.2 > /dev/null 2>&1; then VANILLA_OK=true; fi
        if ping -c 3 -W 2 10.0.2.2 > /dev/null 2>&1; then PQ_OK=true; fi

        echo ""
        echo "=== Results ==="
        echo ""
        printf "  %-25s %s\n" "Vanilla (X25519 only):" "$( $VANILLA_OK && echo 'PASS' || echo 'FAIL' )"
        printf "  %-25s %s\n" "PQ Hybrid (X25519+ML-KEM):" "$( $PQ_OK && echo 'PASS' || echo 'FAIL' )"
        echo ""

        if $VANILLA_OK && $PQ_OK; then
            echo "Both tunnels working. The PQ hybrid tunnel provides post-quantum"
            echo "protection with no user-visible difference in behavior."
            echo ""
            echo "--- Vanilla tunnel (utun10) ---"
            wg show utun10
            echo ""
            echo "--- PQ hybrid tunnel (utun12) ---"
            wg show utun12
            echo ""
            echo "Press Ctrl+C to stop."
            wait
        else
            if ! $VANILLA_OK; then
                echo "Vanilla tunnel failed:"
                tail -5 "$WORKDIR/va.log"
            fi
            if ! $PQ_OK; then
                echo "PQ tunnel failed:"
                tail -5 "$WORKDIR/pa.log"
            fi
            exit 1
        fi
        ;;

    test)
        echo "=== Running PQ Hybrid Tests ==="
        echo ""
        echo "--- Vanilla mode tests ---"
        cargo test -p boringtun --lib noise::tests \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 | tail -5
        echo ""
        echo "--- PQ hybrid mode tests ---"
        cargo test -p boringtun --lib noise::tests \
            --manifest-path "$PROJECT_ROOT/Cargo.toml" --features pq 2>&1 | tail -5
        echo ""
        echo "All tests passed."
        ;;

    *)
        echo "Usage: $0 {demo|local-tunnel|compare|test}"
        echo ""
        echo "Commands:"
        echo "  demo          Show PQ vs vanilla differences and run unit tests"
        echo "  local-tunnel  Create a PQ hybrid WireGuard tunnel (requires sudo)"
        echo "  compare       Side-by-side vanilla vs PQ hybrid tunnels (requires sudo)"
        echo "  test          Run unit tests for both vanilla and PQ modes"
        exit 1
        ;;
esac
