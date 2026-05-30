#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATTERN="bc1pp"

echo "[1/4] Running standalone taproot search with stop-on-first..."
standalone_output="$($SCRIPT_DIR/taproot_vanitygen -1 "$PATTERN")"
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

echo "[2/4] Deriving address from standalone private key..."
derived_from_standalone="$($SCRIPT_DIR/taproot_vanitygen --derive "$standalone_priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
if [[ "$derived_from_standalone" != "$standalone_addr" ]]; then
  echo "Standalone derivation mismatch" >&2
  exit 1
fi

echo "[3/4] Running original Taproot code path with stop-on-first..."
original_output="$("$SCRIPT_DIR/original_taproot_ref" "$PATTERN")"
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

echo "[4/4] Verifying original private key derivation with standalone math..."
derived_from_original="$($SCRIPT_DIR/taproot_vanitygen --derive "$original_priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
if [[ "$derived_from_original" != "$original_addr" ]]; then
  echo "Derivation mismatch: standalone math != original output" >&2
  echo "expected: $original_addr" >&2
  echo "got:      $derived_from_original" >&2
  exit 1
fi

echo "Cross-check OK: standalone taproot derivation matches original implementation."
