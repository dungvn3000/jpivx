package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonWriter;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Pins the JSON the shield JNI bridge receives, byte for byte.
 *
 * <p>The golden strings were captured from the previous Jackson-based
 * implementation before the switch to nanojson, so they double as proof that
 * the migration did not alter the wire format the Rust kit parses — including
 * the details that are easy to lose: a {@code null} memo stays an explicit
 * JSON null, record field order is preserved, and the opaque {@code note} blob
 * keeps its original key order instead of being reordered by the JSON library.
 */
class ShieldWireFormatTest {

    private static final String NOTES_JSON =
            "[{\"note\":{\"value\":123456789,\"rseed\":{\"AfterZip212\":[1,2,3]},\"nested\":{\"b\":2,\"a\":1}},"
            + "\"witness\":\"deadbeef\",\"nullifier\":\"cafe01\",\"memo\":null,\"height\":42},"
            + "{\"note\":{},\"witness\":\"\",\"nullifier\":\"ab\",\"memo\":\"hello \\\"x\\\"\\né\",\"height\":0}]";

    @Test
    void blocksJsonMatchesTheBridgeWireFormat() {
        List<ShieldBlock> blocks = List.of(
                new ShieldBlock(100, List.of(new byte[] {0x01, (byte) 0xab}, new byte[] {})),
                new ShieldBlock(101, List.of()));
        assertEquals("[{\"height\":100,\"txs\":[\"01ab\",\"\"]},{\"height\":101,\"txs\":[]}]",
                ShieldSyncService.toBlocksJson(blocks));
    }

    @Test
    void notesSurviveJsonRoundTripUnchanged() throws Exception {
        List<SerializedNote> notes =
                SerializedNote.fromJsonArray(JsonParser.array().from(NOTES_JSON));

        assertEquals(2, notes.size());
        assertEquals(42, notes.get(0).height());
        assertNull(notes.get(0).memo(), "JSON null memo must read back as null");
        assertEquals("hello \"x\"\né", notes.get(1).memo());

        assertEquals(NOTES_JSON, JsonWriter.string(SerializedNote.toJsonArray(notes)),
                "notes must re-serialize byte-identically for the Rust kit");
    }

    @Test
    void shieldBalanceReadsValueFromTheOpaqueNoteBlob() throws Exception {
        List<SerializedNote> notes =
                SerializedNote.fromJsonArray(JsonParser.array().from(NOTES_JSON));
        ShieldState state = new ShieldState(0, "", notes);
        // 123456789 from the first note; the second note has no value field.
        assertEquals(123_456_789L, state.getShieldBalance());
    }
}
