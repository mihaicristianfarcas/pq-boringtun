#!/usr/bin/env bash
#
# psk-exchange.sh — Automates ML-KEM-768 PSK exchange for WireGuard
#
# This script demonstrates the PSK-slot approach to post-quantum WireGuard:
# 1. Peer A generates an ML-KEM-768 keypair
# 2. Peer A sends the encapsulation key to Peer B (out-of-band)
# 3. Peer B encapsulates, gets a shared secret (PSK) and ciphertext
# 4. Peer B sends the ciphertext back to Peer A (out-of-band)
# 5. Peer A decapsulates, recovers the same shared secret (PSK)
# 6. Both peers configure the PSK in WireGuard
#
# Usage (local demo):
#   ./psk-exchange.sh demo
#
# Usage (local tunnel test):
#   sudo ./psk-exchange.sh local-tunnel
#
# Usage (real deployment):
#   On Peer A: ./psk-exchange.sh keygen
#   Transfer mlkem_ek.b64 to Peer B
#   On Peer B: ./psk-exchange.sh encaps
#   Transfer mlkem_ct.b64 back to Peer A
#   On Peer A: ./psk-exchange.sh decaps
#   Both peers now have psk.hex — configure via:
#     wg set <iface> peer <PUBKEY> preshared-key psk.hex

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Build the tool if needed
cargo build -p pq-psk-tool --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>/dev/null
TOOL="$PROJECT_ROOT/target/debug/pq-psk-tool"

# Build boringtun-cli if needed for tunnel tests
build_boringtun() {
    cargo build -p boringtun-cli --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>/dev/null
    echo "$PROJECT_ROOT/target/debug/boringtun-cli"
}

WORKDIR="${PSK_WORKDIR:-/tmp/pq-psk-exchange}"
mkdir -p "$WORKDIR"

case "${1:-demo}" in
    keygen)
        echo "=== Step 1: Generating ML-KEM-768 keypair ==="
        "$TOOL" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
        echo ""
        echo "Next: Transfer $WORKDIR/mlkem_ek.b64 to the peer, then run:"
        echo "  $0 encaps"
        ;;

    encaps)
        echo "=== Step 2: Encapsulating shared secret ==="
        "$TOOL" encaps "$WORKDIR/mlkem_ek.b64" -c "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.hex"
        echo ""
        echo "Next: Transfer $WORKDIR/mlkem_ct.b64 back to the keygen peer, then run:"
        echo "  $0 decaps"
        ;;

    decaps)
        echo "=== Step 3: Decapsulating shared secret ==="
        "$TOOL" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.hex"
        echo ""
        echo "Done! Configure the PSK in WireGuard:"
        echo "  wg set <iface> peer <PUBKEY> preshared-key $WORKDIR/psk.hex"
        ;;

    demo)
        echo "=== PSK-Slot Post-Quantum WireGuard Demo ==="
        echo "Simulating full ML-KEM-768 key exchange locally..."
        echo ""

        echo "--- Peer A: Generating ML-KEM-768 keypair ---"
        "$TOOL" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
        echo ""

        echo "--- Peer B: Encapsulating (using Peer A's public key) ---"
        "$TOOL" encaps "$WORKDIR/mlkem_ek.b64" -c "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk_b.hex"
        echo ""

        echo "--- Peer A: Decapsulating (using ciphertext from Peer B) ---"
        "$TOOL" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk_a.hex"
        echo ""

        echo "--- Verification ---"
        if diff -q "$WORKDIR/psk_a.hex" "$WORKDIR/psk_b.hex" > /dev/null 2>&1; then
            echo "SUCCESS: Both peers derived the same 32-byte PSK"
            echo "PSK (hex): $(cat "$WORKDIR/psk_a.hex")"
        else
            echo "FAILURE: PSKs do not match!"
            exit 1
        fi
        echo ""
        echo "To use in a real tunnel, run: sudo $0 local-tunnel"
        ;;

    local-tunnel)
        #
        # Full local tunnel test:
        # - Creates two boringtun utun interfaces on localhost
        # - Performs ML-KEM-768 PSK exchange
        # - Configures both peers with the PQ-derived PSK
        # - Sends a ping through the tunnel to prove it works
        #
        # Requires: sudo (for utun creation)
        #
        if [ "$(id -u)" -ne 0 ]; then
            echo "Error: local-tunnel requires root. Run with sudo."
            exit 1
        fi

        BORINGTUN="$(build_boringtun)"
        echo "=== Local PQ-PSK WireGuard Tunnel Test ==="
        echo ""

        cleanup() {
            echo ""
            echo "--- Cleaning up ---"
            kill "$PID_A" "$PID_B" 2>/dev/null || true
            wait "$PID_A" "$PID_B" 2>/dev/null || true
            rm -f "$WORKDIR"/wg_*.key "$WORKDIR"/psk*.hex
            rm -f "$WORKDIR"/mlkem_*.b64
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

        # Step 2: ML-KEM-768 PSK exchange
        echo "--- ML-KEM-768 PSK Exchange ---"
        "$TOOL" keygen -e "$WORKDIR/mlkem_ek.b64" -d "$WORKDIR/mlkem_dk.b64"
        "$TOOL" encaps "$WORKDIR/mlkem_ek.b64" -c "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk.hex"
        "$TOOL" decaps "$WORKDIR/mlkem_dk.b64" "$WORKDIR/mlkem_ct.b64" -p "$WORKDIR/psk_verify.hex"

        if ! diff -q "$WORKDIR/psk.hex" "$WORKDIR/psk_verify.hex" > /dev/null 2>&1; then
            echo "FATAL: PSK mismatch!"
            exit 1
        fi
        PSK_HEX=$(cat "$WORKDIR/psk.hex")
        # Convert hex PSK to base64 for wg set
        PSK_B64=$(echo "$PSK_HEX" | xxd -r -p | base64)
        echo "PQ-derived PSK: $PSK_HEX"
        echo ""

        # Step 3: Start boringtun peers
        echo "--- Starting boringtun peers ---"

        # Write private keys to temp files (wg set reads from files)
        echo "$WG_A_PRIV" > "$WORKDIR/wg_a.key"
        echo "$WG_B_PRIV" > "$WORKDIR/wg_b.key"
        echo "$PSK_B64" > "$WORKDIR/psk_b64.key"

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

        # Step 4: Configure peers via wg
        echo "--- Configuring WireGuard peers ---"

        # Configure peer A
        wg set utun8 \
            private-key "$WORKDIR/wg_a.key" \
            listen-port 51820 \
            peer "$WG_B_PUB" \
                preshared-key "$WORKDIR/psk_b64.key" \
                endpoint 127.0.0.1:51821 \
                allowed-ips 10.0.0.2/32

        # Configure peer B
        wg set utun9 \
            private-key "$WORKDIR/wg_b.key" \
            listen-port 51821 \
            peer "$WG_A_PUB" \
                preshared-key "$WORKDIR/psk_b64.key" \
                endpoint 127.0.0.1:51820 \
                allowed-ips 10.0.0.1/32

        # Assign IP addresses
        ifconfig utun8 10.0.0.1 10.0.0.2
        ifconfig utun9 10.0.0.2 10.0.0.1

        echo "Peer A: utun8 = 10.0.0.1, listening on :51820"
        echo "Peer B: utun9 = 10.0.0.2, listening on :51821"
        echo ""

        # Step 5: Show configuration
        echo "--- WireGuard Status ---"
        wg show utun8
        echo ""
        wg show utun9
        echo ""

        # Step 6: Test connectivity
        echo "--- Testing tunnel connectivity ---"
        if ping -c 3 -W 2 10.0.0.2 > /dev/null 2>&1; then
            echo "SUCCESS: Ping through PQ-PSK WireGuard tunnel works!"
            echo ""
            echo "The tunnel is using a post-quantum ML-KEM-768 derived PSK."
            echo "Press Ctrl+C to stop."
            echo ""
            # Keep running so user can inspect
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

    *)
        echo "Usage: $0 {demo|keygen|encaps|decaps|local-tunnel}"
        echo ""
        echo "Commands:"
        echo "  demo          Run ML-KEM-768 key exchange locally (no tunnel)"
        echo "  local-tunnel  Create a full WireGuard tunnel with PQ-derived PSK (requires sudo)"
        echo "  keygen        Step 1 of multi-peer exchange"
        echo "  encaps        Step 2 of multi-peer exchange"
        echo "  decaps        Step 3 of multi-peer exchange"
        exit 1
        ;;
esac
