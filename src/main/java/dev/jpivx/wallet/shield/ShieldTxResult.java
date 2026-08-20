package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonObject;

import java.util.List;

/**
 * Output of the JNI {@code createShieldTransaction} bridge — mirrors
 * {@code sapling::builder::TransactionResult} from the Rust kit.
 *
 * @param txhex      signed transaction hex (broadcast-ready)
 * @param nullifiers nullifiers of the spent notes (remove from wallet)
 * @param amount     amount sent, in satoshi
 * @param fee        fee paid, in satoshi
 */
public record ShieldTxResult(
        String txhex,
        List<String> nullifiers,
        long amount,
        long fee) {

    /** Parse the bridge's JSON result; a missing nullifier array reads as empty. */
    public static ShieldTxResult fromJson(JsonObject o) {
        return new ShieldTxResult(
                o.getString("txhex", ""),
                ShieldJson.stringList(o.getArray("nullifiers")),
                o.getLong("amount", 0),
                o.getLong("fee", 0));
    }
}
