#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/taproot_optimized_vanitygen"
TAPROOT_BIN="$SCRIPT_DIR/../taproot/taproot_vanitygen"
SPLIT_BIN="$SCRIPT_DIR/../splittaproot/splittaproot_vanitygen"
PATTERN="${PATTERN:-bc1pp}"
ROUNDS="${ROUNDS:-3}"

if [[ ! -x "$BIN" ]]; then
  echo "Missing optimized binary: $BIN" >&2
  exit 1
fi
if [[ ! -x "$TAPROOT_BIN" ]]; then
  echo "Missing original taproot binary: $TAPROOT_BIN" >&2
  exit 1
fi
if [[ ! -x "$SPLIT_BIN" ]]; then
  echo "Missing original splittaproot binary: $SPLIT_BIN" >&2
  exit 1
fi

echo "[1/5] Taproot mining + derivation cross-check (${ROUNDS} rounds)"
for _ in $(seq 1 "$ROUNDS"); do
  out="$($BIN -1 --backend gpu "$PATTERN")"
  addr="$(printf '%s\n' "$out" | sed -n 's/^BTC Address: //p' | tail -n1)"
  priv="$(printf '%s\n' "$out" | sed -n 's/^BTC Privkey (hex): //p' | tail -n1)"
  [[ -n "$addr" && -n "$priv" ]]
  [[ "$addr" == ${PATTERN}* ]]

  derived_opt="$($BIN --derive "$priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
  derived_orig="$($TAPROOT_BIN --derive "$priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
  [[ "$derived_opt" == "$addr" ]]
  [[ "$derived_orig" == "$addr" ]]
done

echo "[2/5] Split flow: alice + bob + combine"
alice_out="$($BIN alice-gen)"
alice_priv="$(printf '%s\n' "$alice_out" | sed -n 's/^Alice Privkey (hex): //p' | tail -n1)"
alice_pub="$(printf '%s\n' "$alice_out" | sed -n 's/^Alice Pubkey (hex): //p' | tail -n1)"
[[ -n "$alice_priv" && -n "$alice_pub" ]]

bob_out="$($BIN bob-mine --alice-pub "$alice_pub" -1 "$PATTERN")"
split_addr="$(printf '%s\n' "$bob_out" | sed -n 's/^BTC Address: //p' | tail -n1)"
bob_part="$(printf '%s\n' "$bob_out" | sed -n 's/^Bob PrivkeyPart (hex): //p' | tail -n1)"
[[ -n "$split_addr" && -n "$bob_part" ]]
[[ "$split_addr" == ${PATTERN}* ]]

combine_out="$($BIN combine --alice-priv "$alice_priv" --bob-part "$bob_part" --expected "$split_addr")"
printf '%s\n' "$combine_out"

if ! printf '%s\n' "$combine_out" | grep -q '^Verification: OK$'; then
  echo "Combine verification failed" >&2
  exit 1
fi

echo "[3/5] Combined Internal Privkey derives same final address"
combined_internal_priv="$(printf '%s\n' "$combine_out" | sed -n 's/^Combined Internal Privkey (hex): //p' | tail -n1)"
[[ -n "$combined_internal_priv" ]]
combined_derived="$($BIN --derive "$combined_internal_priv" | sed -n 's/^BTC Address: //p' | tail -n1)"
[[ "$combined_derived" == "$split_addr" ]]

echo "[4/5] Original splittaproot combine sanity"
orig_alice="$($SPLIT_BIN alice-gen)"
orig_alice_priv="$(printf '%s\n' "$orig_alice" | sed -n 's/^Alice Privkey (hex): //p' | tail -n1)"
orig_alice_pub="$(printf '%s\n' "$orig_alice" | sed -n 's/^Alice Pubkey (hex): //p' | tail -n1)"
orig_bob="$($SPLIT_BIN bob-mine --alice-pub "$orig_alice_pub" -1 "$PATTERN")"
orig_addr="$(printf '%s\n' "$orig_bob" | sed -n 's/^BTC Address: //p' | tail -n1)"
orig_part="$(printf '%s\n' "$orig_bob" | sed -n 's/^Bob PrivkeyPart (hex): //p' | tail -n1)"
orig_combine="$($SPLIT_BIN combine --alice-priv "$orig_alice_priv" --bob-part "$orig_part" --expected "$orig_addr")"
if ! printf '%s\n' "$orig_combine" | grep -q '^Verification: OK$'; then
  echo "Original split combine verification failed" >&2
  exit 1
fi

echo "[5/5] Cross-check complete: optimized and original taproot/splittaproot flows are consistent."
