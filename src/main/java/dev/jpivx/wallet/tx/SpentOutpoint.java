package dev.jpivx.wallet.tx;

/**
 * A reference to a UTXO consumed by a transparent send — the {@code (txid, vout)}
 * pair the wallet uses to mark its UTXO set after broadcast.
 *
 * <p>Mirrors {@code transparent::builder::SpentOutpoint} of the Rust kit.
 */
public record SpentOutpoint(String txid, int vout) {}
