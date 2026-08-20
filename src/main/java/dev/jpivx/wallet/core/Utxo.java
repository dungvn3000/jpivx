package dev.jpivx.wallet.core;

import com.grack.nanojson.JsonObject;

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
        String txid,
        int vout,
        long amount,
        String script,
        int height,
        int hdIndex
) {
    public Utxo {
        if (txid == null) txid = "";
        if (script == null) script = "";
    }

    /** Convenience constructor for backward compat — defaults hdIndex to 0. */
    public Utxo(String txid, int vout, long amount, String script, int height) {
        this(txid, vout, amount, script, height, 0);
    }

    /** Read the kit's {@code SerializedUTXO} JSON shape (missing {@code hd_index} → 0). */
    public static Utxo fromJson(JsonObject o) {
        return new Utxo(
                o.getString("txid", ""),
                o.getInt("vout", 0),
                o.getLong("amount", 0),
                o.getString("script", ""),
                o.getInt("height", 0),
                o.getInt("hd_index", 0));
    }

    /** Write the kit's {@code SerializedUTXO} JSON shape (field order matches the Rust struct). */
    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.put("txid", txid);
        o.put("vout", vout);
        o.put("amount", amount);
        o.put("script", script);
        o.put("height", height);
        o.put("hd_index", hdIndex);
        return o;
    }
}
