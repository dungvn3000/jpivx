#!/bin/sh
# Build the JNI shield library (native/shield-jni) and copy it into the
# resources tree so `mvn package` bundles it into the shaded jpivx.jar.
#
# Output layout (consumed by dev.jpivx.wallet.crypto.ShieldKeys):
#   src/main/resources/native/<os>-<arch>/libjpivx_shield_jni.{dylib,so,dll}
#
# Usage:  native/build-native.sh          (from the jpivx repo root, or anywhere)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
JP_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CRATE_DIR="$SCRIPT_DIR/shield-jni"

# --- detect platform dir (must match ShieldKeys.platformDir()) -------------
case "$(uname -s)" in
    Darwin) OS_PART=macos; LIB_EXT=dylib ;;
    Linux)  OS_PART=linux; LIB_EXT=so ;;
    MINGW*|MSYS*|CYGWIN*) OS_PART=windows; LIB_EXT=dll ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) ARCH_PART=aarch64 ;;
    x86_64|amd64)  ARCH_PART=x86_64 ;;
    *) ARCH_PART=$(uname -m) ;;
esac

case "$LIB_EXT" in
    dll) LIB_NAME="jpivx_shield_jni.dll" ;;
    *)   LIB_NAME="libjpivx_shield_jni.$LIB_EXT" ;;
esac

DEST_DIR="$JP_ROOT/src/main/resources/native/$OS_PART-$ARCH_PART"

echo ">> cargo build --release (shield-jni)"
cargo build --release --manifest-path "$CRATE_DIR/Cargo.toml"

echo ">> copying $LIB_NAME -> resources/native/$OS_PART-$ARCH_PART/"
mkdir -p "$DEST_DIR"
cp "$CRATE_DIR/target/release/$LIB_NAME" "$DEST_DIR/$LIB_NAME"

echo "OK: $DEST_DIR/$LIB_NAME"
