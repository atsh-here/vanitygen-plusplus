#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/splittaproot_vanitygen"
PATTERN="bc1pp"

echo "[1/6] Running standalone Taproot search with stop-on-first..."
standalone_output="$($BIN -1 "$PATTERN")"
standalone_output="$(printf '%s\n' "$standalone_output" | tr -d '\r')"
printf '%s\n' "$standalone_output"

standalone_addr="$(printf '%s\n' "$standalone_output" | sed -n 's/^BTC Address: //p' | tail -n1)"
standalone_priv="$(printf '%s\n' "$standalone_output" | sed -n 's/^BTC Privkey (hex): //p' | tail -n1)"

if [[ -z "$standalone_addr" || -z "$standalone_priv" ]]; then
  echo "Failed to parse standalone output" >&2
  exit 1
fi

if [[ "$standalone_addr" != ${PATTERN}* ]]; then
  echo "Standalone output does not match pattern $PATTERN" >&2
  exit 1
fi

echo "[2/6] Deriving address from standalone internal private key..."
derived_from_standalone="$($BIN derive-internal "$standalone_priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
if [[ "$derived_from_standalone" != "$standalone_addr" ]]; then
  echo "Standalone derivation mismatch" >&2
  exit 1
fi

echo "[3/6] Running original Taproot code path with stop-on-first..."
original_output="$($SCRIPT_DIR/original_taproot_ref "$PATTERN")"
original_output="$(printf '%s\n' "$original_output" | tr -d '\r')"
printf '%s\n' "$original_output"

original_addr="$(printf '%s\n' "$original_output" | sed -n 's/^BTC Address: //p' | tail -n1)"
original_priv="$(printf '%s\n' "$original_output" | sed -n 's/^BTC Privkey (hex): //p' | tail -n1)"

if [[ -z "$original_addr" || -z "$original_priv" ]]; then
  echo "Failed to parse original Taproot output" >&2
  exit 1
fi

if [[ "$original_addr" != ${PATTERN}* ]]; then
  echo "Original output does not match pattern $PATTERN" >&2
  exit 1
fi

echo "[4/6] Verifying original private key derivation with standalone math..."
derived_from_original="$($BIN derive-internal "$original_priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
if [[ "$derived_from_original" != "$original_addr" ]]; then
  echo "Derivation mismatch: standalone math != original output" >&2
  echo "expected: $original_addr" >&2
  echo "got:      $derived_from_original" >&2
  exit 1
fi

echo "[5/6] Running split-key flow (Alice keygen + Bob mine)..."
alice_output="$($BIN alice-gen)"
alice_priv="$(printf '%s\n' "$alice_output" | sed -n 's/^Alice Privkey (hex): //p' | tail -n1)"
alice_pub="$(printf '%s\n' "$alice_output" | sed -n 's/^Alice Pubkey (hex): //p' | tail -n1)"

if [[ -z "$alice_priv" || -z "$alice_pub" ]]; then
  echo "Failed to parse Alice keygen output" >&2
  exit 1
fi

bob_output="$($BIN bob-mine --alice-pub "$alice_pub" -1 "$PATTERN")"
printf '%s\n' "$bob_output"

split_addr="$(printf '%s\n' "$bob_output" | sed -n 's/^BTC Address: //p' | tail -n1)"
bob_part="$(printf '%s\n' "$bob_output" | sed -n 's/^Bob PrivkeyPart (hex): //p' | tail -n1)"

if [[ -z "$split_addr" || -z "$bob_part" ]]; then
  echo "Failed to parse Bob split output" >&2
  exit 1
fi

if [[ "$split_addr" != ${PATTERN}* ]]; then
  echo "Split output does not match pattern $PATTERN" >&2
  exit 1
fi

echo "[6/6] Combining split private parts and verifying final key..."
combine_output="$($BIN combine --alice-priv "$alice_priv" --bob-part "$bob_part" --expected "$split_addr")"
printf '%s\n' "$combine_output"

if ! printf '%s\n' "$combine_output" | grep -q '^Verification: OK$'; then
  echo "Split combine verification failed" >&2
  exit 1
fi

echo "Cross-check OK: split Taproot flow and original Taproot math are consistent."
