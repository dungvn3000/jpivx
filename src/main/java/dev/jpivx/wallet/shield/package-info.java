/**
 * Shield (Sapling) sync: binary stream parsing, batch orchestration, and the
 * JNI {@code handle_blocks} result types.
 *
 * <p>{@link dev.jpivx.wallet.shield.ShieldStreamParser} is a byte-faithful port
 * of the Rust kit's {@code sync::parse_next_blocks};
 * {@link dev.jpivx.wallet.shield.ShieldSyncService} mirrors the kit's WASM
 * consumer merge semantics ({@code updated + new − spent}).
 */
package dev.jpivx.wallet.shield;
