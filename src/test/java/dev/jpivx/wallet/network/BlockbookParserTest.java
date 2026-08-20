package dev.jpivx.wallet.network;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import dev.jpivx.wallet.core.Utxo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port of {@code parse_blockbook_utxos_handles_string_and_number_values} and
 * {@code parse_blockbook_utxos_skips_zero_and_empty} from
 * {@code tests/integration.rs}.
 */
class BlockbookParserTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parseBlockbookUtxosHandlesStringAndNumberValues() throws Exception {
        String json = "["
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"500000000\",\"height\":5000000},"
                + "{\"txid\":\"" + "b".repeat(64) + "\",\"vout\":2,\"value\":100000000,\"height\":5100000}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw);
        assertEquals(2, utxos.size());
        assertEquals(500_000_000L, utxos.get(0).amount());
        assertEquals(0, utxos.get(0).vout());
        assertEquals(100_000_000L, utxos.get(1).amount());
        assertEquals(2, utxos.get(1).vout());
    }

    @Test
    void parseBlockbookUtxosSkipsZeroAndEmpty() throws Exception {
        String json = "["
                + "{\"txid\":\"\",\"vout\":0,\"value\":\"100\",\"height\":1000},"
                + "{\"txid\":\"" + "c".repeat(64) + "\",\"vout\":0,\"value\":\"0\",\"height\":1000},"
                + "{\"txid\":\"" + "d".repeat(64) + "\",\"vout\":1,\"value\":\"42\",\"height\":2000}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw);
        assertEquals(1, utxos.size());
        assertEquals("d".repeat(64), utxos.get(0).txid());
        assertEquals(1, utxos.get(0).vout());
        assertEquals(42L, utxos.get(0).amount());
    }

    @Test
    void parseBlockbookUtxosScriptsAreEmpty() throws Exception {
        String json = "[{\"txid\":\"" + "e".repeat(64) + "\",\"vout\":0,\"value\":\"1000\",\"height\":1000}]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw);
        assertEquals(1, utxos.size());
        assertTrue(utxos.get(0).script().isEmpty());
    }

    @Test
    void filtersOutUnconfirmedUtxosByDefault() throws Exception {
        // One confirmed (height > 0) + one unconfirmed (height == 0).
        String json = "["
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":5000000,\"confirmations\":100},"
                + "{\"txid\":\"" + "b".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":0,\"confirmations\":0}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw);
        assertEquals(1, utxos.size(), "unconfirmed UTXO (height=0) must be filtered out by default");
        assertEquals("a".repeat(64), utxos.get(0).txid());
        assertEquals(10_000_000L, utxos.get(0).amount());
    }

    @Test
    void includesUnconfirmedWhenFlagIsFalse() throws Exception {
        String json = "["
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":5000000},"
                + "{\"txid\":\"" + "b".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":0}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw, false);
        assertEquals(2, utxos.size(), "confirmedOnly=false should include unconfirmed UTXOs");
    }

    @Test
    void deduplicatesConfirmedAndUnconfirmedSameOutpoint() throws Exception {
        // Same (txid, vout) appearing as both confirmed and unconfirmed.
        // The confirmed entry (height > 0) is kept; the unconfirmed duplicate is dropped.
        String json = "["
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":5000000,\"confirmations\":100},"
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":0,\"confirmations\":0}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw, false);
        assertEquals(1, utxos.size(), "duplicate (txid, vout) must be deduplicated");
        assertEquals(5_000_000, utxos.get(0).height());
    }

    @Test
    void deduplicatesExactDuplicates() throws Exception {
        String json = "["
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":5000000},"
                + "{\"txid\":\"" + "a".repeat(64) + "\",\"vout\":0,\"value\":\"10000000\",\"height\":5000000}"
                + "]";
        JsonNode raw = MAPPER.readTree(json);
        List<Utxo> utxos = BlockbookParser.parseBlockbookUtxos(raw);
        assertEquals(1, utxos.size(), "exact duplicates must be deduplicated");
    }
}
