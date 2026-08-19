package dev.jpivx.wallet.tx;

import java.util.List;

/**
 * Result of building a transparent transaction.
 *
 * <p>Mirrors {@code transparent::builder::TransparentTransactionResult} of the
 * Rust {@code pivx-wallet-kit}.
 *
 * @param txhex  the signed transaction as a lowercase hex string
 * @param spent  UTXOs consumed by this tx — remove from the wallet after broadcast
 * @param amount the value sent to the recipient, in satoshis
 * @param fee    the fee paid, in satoshis
 */
public record TransparentTransactionResult(String txhex, List<SpentOutpoint> spent, long amount, long fee) {}
