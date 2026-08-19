package dev.jpivx.wallet.core;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A transparent unspent transaction output.
 *
 * <p>Mirrors {@code wallet::SerializedUTXO} of the Rust {@code pivx-wallet-kit},
 * with an extra {@code hd_index} field that records which HD derivation index
 * the UTXO belongs to. This lets the builder sign each input with the correct
 * private key when a wallet has generated multiple receive addresses.
 *
 * <p>JSON backward-compatible: old wallets without {@code hd_index} default
 * to 0 (the standard receive address).
 */
public record Utxo(
        @JsonProperty("txid") String txid,
        @JsonProperty("vout") int vout,
        @JsonProperty("amount") long amount,
        @JsonProperty("script") String script,
        @JsonProperty("height") int height,
        @JsonProperty("hd_index") int hdIndex
) {
    public Utxo {
        if (txid == null) txid = "";
        if (script == null) script = "";
    }

    /** Convenience constructor for backward compat — defaults hdIndex to 0. */
    public Utxo(String txid, int vout, long amount, String script, int height) {
        this(txid, vout, amount, script, height, 0);
    }
}
