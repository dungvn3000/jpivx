/**
 * Shield (Sapling) sync and spending: binary stream parsing, batch
 * orchestration, the JNI {@code handle_blocks} result types, and the two send
 * facades — {@link dev.jpivx.wallet.shield.ShieldSendService} (spend notes)
 * and {@link dev.jpivx.wallet.shield.ShieldingService} (transparent&rarr;shield).
 *
 * <p>{@link dev.jpivx.wallet.shield.ShieldStreamParser} is a byte-faithful port
 * of the Rust kit's {@code sync::parse_next_blocks};
 * {@link dev.jpivx.wallet.shield.ShieldSyncService} mirrors the kit's WASM
 * consumer merge semantics ({@code updated + new − spent}).
 */
package dev.jpivx.wallet.shield;
