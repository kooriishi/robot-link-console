#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$(rustc -vV | awk -F': ' '$1 == "host" {print $2}')"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/net-helper/target}"
if [[ -z "$TARGET" ]]; then
  echo "无法确定 Rust 构建目标" >&2
  exit 1
fi
cargo build --manifest-path "$ROOT/net-helper/Cargo.toml" --release
mkdir -p "$ROOT/src-tauri/binaries"
install -m 0755 "$CARGO_TARGET_DIR/release/robolink-net-helper" \
  "$ROOT/src-tauri/binaries/robolink-net-helper-$TARGET"
printf 'Built network helper for %s\n' "$TARGET"
