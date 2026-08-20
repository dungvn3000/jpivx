package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import dev.jpivx.wallet.crypto.BIP39Service;
import dev.jpivx.wallet.crypto.ShieldKeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-verification of the JNI {@code handleBlocks} bridge against the Rust
 * kit's own integration test
 * ({@code handle_blocks_with_unrelated_key_advances_tree_and_extracts_nullifier}).
 *
 * <p>Feeds the real mainnet shield fixture ({@code tests/fixtures/tx_shield.hex},
 * mirrored at {@code src/test/resources/fixtures/}) through the bridge with the
 * shared BIP39 test mnemonic's extfvk — an unrelated key for that tx — and
 * checks:
 * <ul>
 *   <li>zero decrypted notes</li>
 *   <li>exactly one nullifier, equal to the kit's golden value</li>
 *   <li>the commitment tree advanced (2 output commitments appended)</li>
 * </ul>
 *
 * <p>Skipped when the native shield library is not loaded.
 */
class ShieldKeysHandleBlocksTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /** Golden value printed by the kit (see shield-jni's print_handle_blocks_golden_vectors). */
    private static final String EXPECTED_NULLIFIER =
            "4374852b940d2ff264d172d231f8a49434f62dc6da3d4060bcdd19cdcfd55071";

    /** Hex length of the resulting tree after 2 appends onto the empty tree (kit: 134). */
    private static final int EXPECTED_TREE_AFTER_LEN = 134;

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    private static String fixtureHex(String name) throws Exception {
        try (InputStream in = ShieldKeysHandleBlocksTest.class
                .getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found: " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }

    @Test
    @EnabledIf("shieldAvailable")
    void handleBlocksMatchesRustKitGoldenNullifier() throws Exception {
        String txHex = fixtureHex("tx_shield.hex");
        // Sanity: the hex actually parses to bytes.
        HexFormat.of().parseHex(txHex);

        String extfvk = ShieldKeys.extfvk(BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC)));
        String treeHex = "000000"; // empty Sapling tree (kit-compatible encoding)

        String blocksJson = "[{\"height\":5000000,\"txs\":[\"" + txHex + "\"]}]";
        String resultJson = ShieldKeys.handleBlocks(treeHex, blocksJson, extfvk, "[]");

        HandleBlocksResult result = HandleBlocksResult.fromJson(JsonParser.object().from(resultJson));

        assertTrue(result.newNotes().isEmpty(), "unrelated key decrypts nothing");
        assertTrue(result.updatedNotes().isEmpty(), "no pre-existing notes to advance");
        assertEquals(List.of(EXPECTED_NULLIFIER), result.nullifiers());
        assertNotEquals(treeHex, result.commitmentTree());
        assertEquals(EXPECTED_TREE_AFTER_LEN, result.commitmentTree().length());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void shieldSyncServiceToBlocksJsonUsesLowercaseHex() throws Exception {
        List<ShieldBlock> blocks = List.of(
                new ShieldBlock(123, List.of(HexFormat.of().parseHex("03aabbcc"))));
        String json = ShieldSyncService.toBlocksJson(blocks);
        assertEquals("[{\"height\":123,\"txs\":[\"03aabbcc\"]}]", json);
    }
}
