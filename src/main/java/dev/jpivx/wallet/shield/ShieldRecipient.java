package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;

import java.util.List;

import dev.jpivx.wallet.tx.CoinSelector;

/**
 * One recipient of a shield send — the multi-output entry point of
 * {@link ShieldSendService}: paying several destinations (any mix of shield
 * and transparent) from the wallet's notes in a single transaction.
 *
 * <p>Mirrors the kit's {@code sapling::builder::ShieldRecipient} serde shape
 * ({@code {address, amount, memo}}).
 *
 * @param address   {@code ps1...} (shield) or {@code D...} (transparent)
 * @param amountSat value in satoshi; transparent destinations must clear the
 *                  546-sat dust threshold (nodes reject sub-dust transparent
 *                  outputs as nonstandard; shield outputs have no dust rule)
 * @param memo      memo text ({@code ""} for none) — travels encrypted in
 *                  shield outputs only, ignored for transparent destinations
 */
public record ShieldRecipient(String address, long amountSat, String memo) {

    public ShieldRecipient {
        if (address == null || address.isBlank()) {
            throw new IllegalArgumentException("recipient address is required");
        }
        if (memo == null) {
            throw new IllegalArgumentException("memo must not be null (use \"\" for none)");
        }
        if (amountSat <= 0) {
            throw new IllegalArgumentException("recipient amount must be positive: "
                    + amountSat + " sat: " + address);
        }
        if (!ShieldSendService.isShieldDestination(address)
                && amountSat < CoinSelector.DUST_THRESHOLD) {
            throw new IllegalArgumentException("recipient amount " + amountSat
                    + " sat is below the dust threshold (" + CoinSelector.DUST_THRESHOLD
                    + " sat) for transparent destination " + address);
        }
    }

    /** A recipient with no memo. */
    public ShieldRecipient(String address, long amountSat) {
        this(address, amountSat, "");
    }

    /** This recipient in the kit's {@code ShieldRecipient} JSON shape. */
    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.put("address", address);
        o.put("amount", amountSat);
        o.put("memo", memo);
        return o;
    }

    /** A recipient list as the kit's JSON array shape. */
    public static JsonArray toJsonArray(List<ShieldRecipient> recipients) {
        JsonArray arr = new JsonArray();
        for (ShieldRecipient r : recipients) {
            arr.add(r.toJson());
        }
        return arr;
    }
}
