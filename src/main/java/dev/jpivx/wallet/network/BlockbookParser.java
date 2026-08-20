package dev.jpivx.wallet.network;

import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.jpivx.wallet.core.Utxo;

/**
 * Parse a Blockbook API v2 {@code /api/v2/utxo/{address}} response into a list
 * of {@link Utxo}s.
 *
 * <p>Mirrors {@code wallet::parse_blockbook_utxos} of the Rust kit. Accepts
 * amounts as either a string ({@code "12345"}) or a JSON number — both forms
 * appear in the wild. UTXOs with empty txids or zero amounts are skipped.
 *
 * <p><b>Confirmed vs unconfirmed</b>: by default only confirmed UTXOs
 * ({@code height > 0}) are kept. Pass {@code false} for {@code confirmedOnly}
 * to include mempool entries.
 *
 * <p><b>Deduplication</b>: the API may return the same {@code (txid, vout)}
 * pair twice (once confirmed, once unconfirmed). We deduplicate by
 * {@code (txid, vout)}, keeping the first occurrence.
 *
 * <p><b>HD index tagging</b>: each parsed UTXO is tagged with an {@code hdIndex}
 * so the builder knows which private key to sign with when the wallet has
 * generated multiple receive addresses.
 */
public final class BlockbookParser {

    private BlockbookParser() {
        throw new AssertionError("no instances");
    }

    public static List<Utxo> parseBlockbookUtxos(JsonNode raw) {
        return parseBlockbookUtxos(raw, true, 0);
    }

    public static List<Utxo> parseBlockbookUtxos(JsonNode raw, boolean confirmedOnly) {
        return parseBlockbookUtxos(raw, confirmedOnly, 0);
    }

    /**
     * Parse a Blockbook UTXO JSON array, tagging each UTXO with the given
     * {@code hdIndex}.
     *
     * @param raw          the JSON array node from Blockbook
     * @param confirmedOnly if {@code true}, skip UTXOs with {@code height <= 0}
     * @param hdIndex      the HD derivation index to tag each UTXO with
     * @return parsed UTXOs (duplicates by {@code (txid, vout)} removed)
     */
    public static List<Utxo> parseBlockbookUtxos(JsonNode raw, boolean confirmedOnly, int hdIndex) {
        List<Utxo> utxos = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (JsonNode u : raw) {
            String txid = u.path("txid").asString("");
            int vout = u.path("vout").asInt(0);
            long amount = 0;
            JsonNode valueNode = u.path("value");
            if (valueNode.isString()) {
                try {
                    amount = Long.parseUnsignedLong(valueNode.asString());
                } catch (NumberFormatException ignored) {
                    amount = 0;
                }
            } else if (valueNode.isNumber()) {
                amount = valueNode.asLong(0);
            }
            int height = u.path("height").asInt(0);

            if (txid.isEmpty() || amount == 0) {
                continue;
            }
            if (confirmedOnly && height <= 0) {
                continue;
            }
            String key = txid + ":" + vout;
            if (!seen.add(key)) {
                continue;
            }
            utxos.add(new Utxo(txid, vout, amount, "", height, hdIndex));
        }
        return utxos;
    }
}
