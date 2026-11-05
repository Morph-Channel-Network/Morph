#!/usr/bin/env bash
# Sourced by development harnesses. Only public, no-value fixture files may be
# copied here; explicitly supplied protected key paths retain their permissions.
MORPH_FIXTURE_KEY_DIR=""

morph_reject_raw_private_keys() {
  local variable
  for variable in MORPH_DEVNET_PRIVATE_KEY MORPH_ALICE_PRIVATE_KEY MORPH_BOB_PRIVATE_KEY \
    MORPH_CHANNEL_PRIVATE_KEY MORPH_OPERATOR_B_PRIVATE_KEY MORPH_HUB_INVOICE_PRIVATE_KEY \
    MORPH_AGENT_BISCUIT_PRIVATE_KEY MORPH_AGENT_RECEIPT_PRIVATE_KEY \
    MORPH_AGENT_DEVNET_PAYER_PRIVATE_KEY MORPH_AGENT_PAYER_PRIVATE_KEY; do
    if [[ -v "$variable" ]]; then
      printf 'raw private-key environment input is unsupported; use a *_PRIVATE_KEY_FILE path\n' >&2
      return 1
    fi
  done
}

morph_fixture_keys_init() {
  morph_reject_raw_private_keys || return
  MORPH_FIXTURE_KEY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/morph-fixture-keys.XXXXXXXX")" || return
  chmod 700 "$MORPH_FIXTURE_KEY_DIR"
}

morph_fixture_key_file() {
  local variable="$1" source="$2" filename="$3" destination
  if [ -n "${!variable:-}" ]; then
    # The Rust/SDK loader validates user-provided paths without repairing them.
    export "$variable"
    return
  fi
  [ -f "$source" ] && [ ! -L "$source" ] || {
    printf 'missing regular public devnet fixture key file\n' >&2
    return 1
  }
  [ "$(wc -c <"$source")" -le 256 ] || {
    printf 'public devnet fixture key file exceeds 256 bytes\n' >&2
    return 1
  }
  destination="$MORPH_FIXTURE_KEY_DIR/$filename"
  install -m 600 -- "$source" "$destination" || return
  printf -v "$variable" '%s' "$destination"
  export "$variable"
}

morph_fixture_keys_cleanup() {
  if [ -n "${MORPH_FIXTURE_KEY_DIR:-}" ]; then
    rm -rf -- "$MORPH_FIXTURE_KEY_DIR"
  fi
}
